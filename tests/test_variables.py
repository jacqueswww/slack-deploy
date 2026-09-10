#!/usr/bin/env python3
"""Variable typing, notes, scope precedence, and the orphan sweep."""
import sys
from datetime import date

import yaml

import harness
from harness import WORK

import db

STORE = None
PROJECT_ID = None


def yaml_types_round_trip():
    global STORE
    STORE = harness.new_store()
    src = WORK / 'vars.yml'
    src.write_text('a_str: hello\nan_int: 7\na_bool: true\n'
                   'a_date: 2026-01-01\na_list: [1, 2]\na_map: {x: 1}\n')
    db.vars_import(STORE, 'project', 1, src)
    got = STORE.vars_for('project', 1)
    assert got == {'a_str': 'hello', 'an_int': 7, 'a_bool': True,
                   'a_date': date(2026, 1, 1), 'a_list': [1, 2],
                   'a_map': {'x': 1}}, got
    assert yaml.safe_load(db.vars_export_text(STORE, 'project', 1)) == got


def explicit_types_beat_bare_yaml():
    """Read as bare YAML a password of "no" becomes False and 0123 becomes 123."""
    for text, kind, want in (('no', 'string', 'no'), ('no', 'bool', False),
                             ('0123', 'string', '0123'), ('7', 'int', 7),
                             ('7', 'string', '7'), ('1.5', 'float', 1.5),
                             ('2026-01-01', 'date', date(2026, 1, 1)),
                             ('2026-01-01', 'string', '2026-01-01'),
                             ('{a: 1}', 'yaml', {'a': 1})):
        got = db.coerce_value(text, kind)
        assert got == want and type(got) is type(want), f'{text!r} as {kind} -> {got!r}'
    for text, kind in (('maybe', 'bool'), ('x', 'int'), ('nope', 'date'),
                       ('x', 'nosuchtype')):
        try:
            db.coerce_value(text, kind)
            raise AssertionError(f'{text!r} as {kind} must be rejected')
        except ValueError:
            pass


def stored_type_is_reported():
    STORE.set('project', 1, 'is_live', db.coerce_value('no', 'bool'))
    STORE.set('project', 1, 'zip_code', db.coerce_value('0123', 'string'))
    kinds = {s['name']: s['type'] for s in STORE.names('project', 1)}
    assert kinds['is_live'] == 'bool' and kinds['zip_code'] == 'string', kinds
    assert kinds['a_date'] == 'date' and kinds['a_map'] == 'mapping', kinds
    assert STORE.get('project', 1, 'zip_code') == '0123', 'leading zero must survive'


def notes_live_beside_the_value():
    STORE.set('project', 1, 'noted', 'value', note='ask the platform team')
    notes = {s['name']: s['note'] for s in STORE.names('project', 1)}
    assert notes['noted'] == 'ask the platform team', notes
    STORE.set('project', 1, 'noted', 'new value')
    assert {s['name']: s['note'] for s in
            STORE.names('project', 1)}['noted'] == 'ask the platform team', \
        're-setting the value must keep the note'
    STORE.set_note('project', 1, 'noted', '')
    assert {s['name']: s['note'] for s in
            STORE.names('project', 1)}['noted'] is None, 'an empty note clears it'


def global_scope_never_reaches_ansible():
    STORE.set('environment', 99, 'pg_password', 'hunter2')
    STORE.set(db.GLOBAL_SCOPE, 0, 'slack_bot_token', 'xoxb-must-not-leak')
    merged = STORE.extra_vars(1, 99)
    assert 'slack_bot_token' not in merged, 'global scope must never reach ansible'
    assert merged['pg_password'] == 'hunter2'
    assert merged['a_str'] == 'hello', 'project scope should be merged in'
    assert merged['is_live'] is False, 'a bool must stay a bool through the merge'


def environment_scope_wins():
    STORE.set('project', 1, 'shared', 'from-project')
    STORE.set('environment', 99, 'shared', 'from-environment')
    assert STORE.extra_vars(1, 99)['shared'] == 'from-environment'


def orphan_sweep_drops_secrets_of_deleted_rows():
    """scope_id has no cross-file foreign key, so deletions must be swept by hand."""
    global PROJECT_ID
    with db.deploy_conn() as conn:
        PROJECT_ID = conn.execute(
            "INSERT INTO project (name, working_dir) VALUES ('p','/tmp')").lastrowid
        eid = conn.execute('INSERT INTO environment (project_id, name, inventory, '
                           "playbook) VALUES (?,'e','h','p.yml')",
                           (PROJECT_ID,)).lastrowid
    STORE.set('environment', eid, 'old_secret', 'leftover')
    with db.deploy_conn() as conn:
        conn.execute('DELETE FROM environment WHERE id=?', (eid,))
        new_eid = conn.execute('INSERT INTO environment (project_id, name, inventory, '
                               "playbook) VALUES (?,'e2','h','p.yml')",
                               (PROJECT_ID,)).lastrowid
    assert STORE.orphan_sweep(), 'the sweep should report what it removed'
    assert STORE.get('environment', new_eid, 'old_secret') is None, \
        'a recreated environment must not inherit the deleted one\'s secrets'
    assert STORE.get('environment', 99, 'pg_password') is None, \
        'it should also drop secrets whose scope row never existed'


def yaml_aliases_are_refused():
    """A few hundred bytes of nested aliases expand to gigabytes when copied to JSON."""
    bomb = 'a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n'
    for attempt in (lambda: db.coerce_value(bomb, 'yaml'),
                    lambda: db.load_yaml(bomb)):
        try:
            attempt()
            raise AssertionError('aliases must be refused')
        except yaml.YAMLError:
            pass
    bad = WORK / 'bomb.yml'
    bad.write_text(bomb)
    try:
        db.vars_import(STORE, 'project', 1, bad)
        raise AssertionError('aliases must be refused on import too')
    except yaml.YAMLError:
        pass
    assert db.load_yaml('a: 1\nb: [1, 2]\n') == {'a': 1, 'b': [1, 2]}


def import_rejects_a_non_mapping():
    bad = WORK / 'bad.yml'
    bad.write_text('- just\n- a\n- list\n')
    try:
        db.vars_import(STORE, 'project', 1, bad)
        raise AssertionError('a non-mapping vars file must be rejected')
    except ValueError:
        pass


if __name__ == '__main__':
    sys.exit(harness.run(
        yaml_types_round_trip, explicit_types_beat_bare_yaml, stored_type_is_reported,
        notes_live_beside_the_value, global_scope_never_reaches_ansible,
        environment_scope_wins, orphan_sweep_drops_secrets_of_deleted_rows,
        yaml_aliases_are_refused, import_rejects_a_non_mapping))
