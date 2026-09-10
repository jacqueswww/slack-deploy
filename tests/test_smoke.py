#!/usr/bin/env python3
"""Runnable checks for the security-critical paths. python tests/test_smoke.py"""
import os
import shutil
import sys
import tempfile
import time
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = Path(tempfile.mkdtemp(prefix='slack-deploy-test-'))
os.environ['SLACK_DEPLOY_DATA'] = str(WORK / 'data')
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

import db            # noqa: E402
import runner        # noqa: E402
import scheduler     # noqa: E402
import manage        # noqa: E402

GOOD = 'a shared passphrase long enough'


def stray_agents():
    """ansible-runner's ssh_key= wraps the run in an ssh-agent that outlives it,
    leaving the decrypted key resident in memory. We must never leave one."""
    found = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            argv = (proc / 'cmdline').read_bytes().decode('utf-8', 'replace')
        except OSError:
            continue
        if 'ssh-agent' in argv and str(WORK) in argv:
            found.append(proc.name)
    return found
BAD = 'not the right passphrase!!'


def check_locking():
    store = db.init(GOOD)
    store.set('environment', 99, 'pg_password', 'hunter2-in-the-clear')
    store.close()

    try:
        db.SecretStore.unlock(BAD)
        raise AssertionError('wrong global password must not open the store')
    except db.Locked:
        pass

    store = db.SecretStore.unlock(GOOD)
    assert store.get('environment', 99, 'pg_password') == 'hunter2-in-the-clear'

    # nothing readable on disk without the password
    raw = db.SECRETS_DB.read_bytes()
    assert b'hunter2' not in raw and b'pg_password' not in raw
    return store


def check_init_never_overwrites(store):
    """A second init must refuse, and leave the salt and secrets untouched."""
    salt_before = db.KDF_FILE.read_bytes()
    try:
        db.init('a completely different passphrase')
        raise AssertionError('init must refuse when a store already exists')
    except FileExistsError as exc:
        assert 'secrets.db' in str(exc), exc
    assert db.KDF_FILE.read_bytes() == salt_before, 'init must not rewrite the salt'
    assert store.get('environment', 99, 'pg_password') == 'hunter2-in-the-clear'
    assert db.initialised(), 'initialised() should report the existing paths'


def check_yaml_types(store):
    src = WORK / 'vars.yml'
    src.write_text('a_str: hello\nan_int: 7\na_bool: true\n'
                   'a_date: 2026-01-01\na_list: [1, 2]\na_map: {x: 1}\n')
    db.vars_import(store, 'project', 1, src)
    got = store.vars_for('project', 1)
    assert got == {'a_str': 'hello', 'an_int': 7, 'a_bool': True,
                   'a_date': date(2026, 1, 1), 'a_list': [1, 2],
                   'a_map': {'x': 1}}, got
    import yaml
    assert yaml.safe_load(db.vars_export_text(store, 'project', 1)) == got


def check_value_types(store):
    """Explicit types, because bare YAML mangles passwords."""
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
    store.set('project', 1, 'is_live', db.coerce_value('no', 'bool'))
    store.set('project', 1, 'zip_code', db.coerce_value('0123', 'string'))
    kinds = {s['name']: s['type'] for s in store.names('project', 1)}
    assert kinds['is_live'] == 'bool' and kinds['zip_code'] == 'string', kinds
    assert store.get('project', 1, 'zip_code') == '0123', 'leading zero must survive'


def check_scope_isolation(store):
    store.set(db.GLOBAL_SCOPE, 0, 'slack_bot_token', 'xoxb-must-not-leak')
    merged = store.extra_vars(1, 99)
    assert 'slack_bot_token' not in merged, 'global scope must never reach ansible'
    assert merged['pg_password'] == 'hunter2-in-the-clear'
    assert merged['a_str'] == 'hello'
    assert merged['is_live'] is False, 'a bool must stay a bool through the merge'


def check_orphan_sweep(store):
    with db.deploy_conn() as conn:
        pid = conn.execute("INSERT INTO project (name, working_dir) VALUES ('p','/tmp')"
                           ).lastrowid
        eid = conn.execute('INSERT INTO environment (project_id, name, inventory, '
                           "playbook) VALUES (?,'e','h','p.yml')", (pid,)).lastrowid
    store.set('environment', eid, 'old_secret', 'leftover')
    with db.deploy_conn() as conn:
        conn.execute('DELETE FROM environment WHERE id=?', (eid,))
        new_eid = conn.execute('INSERT INTO environment (project_id, name, inventory, '
                               "playbook) VALUES (?,'e2','h','p.yml')", (pid,)).lastrowid
    swept = store.orphan_sweep()
    assert store.get('environment', new_eid, 'old_secret') is None, \
        'a recreated environment must not inherit the deleted one\'s secrets'
    assert store.get('environment', 99, 'pg_password') is None, \
        'the sweep should also drop secrets whose scope row never existed'
    assert swept, 'sweep should report what it removed'
    return pid


def check_deploy_file_and_redaction(store, pid):
    """A real ansible run against localhost, so extravars delivery is proven."""
    checkout = WORK / 'checkout'
    checkout.mkdir(exist_ok=True)
    (checkout / 'hosts').write_text('[local]\nlocalhost ansible_connection=local\n')
    (checkout / 'site.yml').write_text(
        '- hosts: local\n'
        '  gather_facts: false\n'
        '  tasks:\n'
        '    - name: the encrypted variable must arrive\n'
        '      assert:\n'
        '        that: db_password == "super-secret-value"\n'
        '      tags: [deploy]\n'
        '    - name: a date valued variable must survive the trip\n'
        '      assert:\n'
        '        that: cert_expiry == "2026-01-01"\n'
        '      tags: [deploy]\n')

    with db.deploy_conn() as conn:
        conn.execute('UPDATE project SET working_dir=? WHERE id=?', (str(checkout), pid))
        eid = conn.execute('INSERT INTO environment (project_id, name, inventory, '
                           "playbook, tags) VALUES (?,'live','hosts','site.yml',"
                           "'deploy')", (pid,)).lastrowid
        project = dict(conn.execute('SELECT * FROM project WHERE id=?', (pid,)).fetchone())
        env = dict(conn.execute('SELECT * FROM environment WHERE id=?', (eid,)).fetchone())

    store.set('environment', eid, 'db_password', 'super-secret-value',
              note='the note is stored beside the value')
    store.set('environment', eid, 'cert_expiry', date(2026, 1, 1))
    store.cred_set('environment', eid, 'ssh_key', 'test-key',
                   *db.generate_ssh_key('test'))
    before = set(db.RUN_DIR.iterdir())
    job_id = runner.deploy(project, env, store, 'tester')
    with db.deploy_conn() as conn:
        job = dict(conn.execute('SELECT * FROM job WHERE id=?', (job_id,)).fetchone())

    assert job['status'] == 'ok', job['log']
    assert 'ok=2' in job['log'], job['log']
    assert 'super-secret-value' not in job['log'], 'secret leaked into the stored log'
    assert 'PRIVATE KEY' not in job['log'], 'ssh key leaked into the stored log'
    assert set(db.RUN_DIR.iterdir()) == before, \
        'the private data dir and the key file must both be removed'
    assert not stray_agents(), \
        f'{stray_agents()} ssh-agent(s) left holding the deploy key'

    kwargs = runner.runner_kwargs(project, env)
    assert kwargs['playbook'] == str(checkout / 'site.yml'), kwargs
    assert kwargs['cmdline'] == '--tags deploy', kwargs
    for bad, why in ((dict(env, playbook='--become-user=root'), 'leading dash'),
                     (dict(env, tags='deploy; rm -rf /'), 'shell metacharacters'),
                     (dict(env, playbook='../../../etc/passwd'), 'path traversal')):
        try:
            runner.runner_kwargs(project, bad)
            raise AssertionError(f'{why} must be rejected')
        except ValueError:
            pass

    notes = {s['name']: s['note'] for s in store.names('environment', eid)}
    assert notes['db_password'] == 'the note is stored beside the value', notes
    store.set('environment', eid, 'db_password', 'changed-value')
    kept = {s['name']: s['note'] for s in store.names('environment', eid)}
    assert kept['db_password'] == notes['db_password'], 're-setting must keep the note'
    store.set_note('environment', eid, 'db_password', '')
    assert {s['name']: s['note'] for s in
            store.names('environment', eid)}['db_password'] is None


def check_redaction_helper():
    text = 'ok=1 password: sesame-open-up and short: ab'
    out = runner.redact(text, ['sesame-open-up', 'ab'])
    assert 'sesame-open-up' not in out
    assert 'ab' in out, 'values under 4 chars are too noisy to redact'


def check_totp():
    secret = db.new_totp_secret()
    now = time.time()
    assert db.totp_verify(secret, db.totp_at(secret, int(now // 30)), now)
    assert db.totp_verify(secret, db.totp_at(secret, int(now // 30) - 1), now)
    assert not db.totp_verify(secret, db.totp_at(secret, int(now // 30) + 5), now)
    assert not db.totp_verify(secret, 'nope', now)
    assert not db.totp_verify(secret, '', now)
    assert not db.totp_verify(None, '123456', now)


def check_schedule_due():
    row = {'enabled': 1, 'at_time': '02:00', 'weekdays': '*', 'last_run_on': None}
    assert scheduler.is_due(row, datetime(2026, 1, 5, 2, 0))
    assert not scheduler.is_due(row, datetime(2026, 1, 5, 1, 59))
    assert not scheduler.is_due({**row, 'enabled': 0}, datetime(2026, 1, 5, 3, 0))
    assert not scheduler.is_due({**row, 'last_run_on': '2026-01-05'},
                                datetime(2026, 1, 5, 3, 0)), 'must fire once a day'
    assert scheduler.is_due({**row, 'last_run_on': '2026-01-04'},
                            datetime(2026, 1, 5, 3, 0))
    assert not scheduler.is_due({**row, 'weekdays': '5,6'},
                                datetime(2026, 1, 5, 3, 0))  # Monday
    assert scheduler.is_due({**row, 'weekdays': '0'}, datetime(2026, 1, 5, 3, 0))


def check_backup_and_prune(store):
    # a stray file a future migration might drop in, and a live deploy's temp file
    (db.DATA / 'notes.txt').write_text('keep me')
    (db.RUN_DIR / 'inflight.yml').write_text('pg: plaintext-in-flight')
    path, _ = scheduler.backup(store)
    import zipfile
    with zipfile.ZipFile(path) as zf:
        names = sorted(zf.namelist())
        blob = zf.read('secrets.db')
    assert names == ['deploy.db', 'kdf.json', 'notes.txt', 'secrets.db'], names
    assert 'inflight.yml' not in str(names), 'run/ holds plaintext, must be excluded'
    assert b'hunter2' not in blob, 'backup must keep secrets.db encrypted'
    assert path.stat().st_mode & 0o777 == 0o600
    (db.RUN_DIR / 'inflight.yml').unlink()
    old = db.BACKUP_DIR / f'{date.today() - timedelta(days=91)}.zip'
    old.write_bytes(b'x')
    keep = db.BACKUP_DIR / f'{date.today() - timedelta(days=89)}.zip'
    keep.write_bytes(b'x')
    removed = scheduler.prune()
    assert old.name in removed and keep.exists(), removed


def check_restore_from_backup(store):
    """A backup zip alone must be enough to get the secrets back."""
    import zipfile
    path, _ = scheduler.backup(store)
    restored = WORK / 'restored'
    with zipfile.ZipFile(path) as zf:
        zf.extractall(restored)
    saved = os.environ['SLACK_DEPLOY_DATA']
    try:
        for mod in (db,):
            mod.DATA, mod.DEPLOY_DB = restored, restored / 'deploy.db'
            mod.SECRETS_DB, mod.KDF_FILE = restored / 'secrets.db', restored / 'kdf.json'
        back = db.SecretStore.unlock(GOOD)
        assert back.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
        back.close()
    finally:
        os.environ['SLACK_DEPLOY_DATA'] = saved
        db.DATA = Path(saved)
        db.DEPLOY_DB, db.SECRETS_DB = db.DATA / 'deploy.db', db.DATA / 'secrets.db'
        db.KDF_FILE = db.DATA / 'kdf.json'


def check_cipher_settings():
    conn = db._open_secrets(db.key_from_passphrase(GOOD))
    try:
        assert conn.execute('PRAGMA cipher_memory_security').fetchone()[0] == '1', \
            'memory security is off by default in SQLCipher 4 and must be on'
        assert conn.execute('PRAGMA cipher_hmac_algorithm').fetchone()[0] == \
            'HMAC_SHA512'
        assert conn.execute('PRAGMA cipher_page_size').fetchone()[0] == '4096'
    finally:
        conn.close()
    salt, params = db.read_kdf()
    assert params['n'] == 2 ** 18 and params['dklen'] == 32, params
    assert params['maxmem'] >= 128 * params['r'] * params['n'], 'maxmem too low'


def check_kdf_params_are_honoured():
    """An old store keeps opening after the module constants are raised."""
    salt, _ = db.read_kdf()
    weak = dict(db.KEY_SCRYPT, n=2 ** 14, maxmem=64 * 1024 * 1024)
    db.write_kdf(salt, weak)
    assert db.read_kdf()[1]['n'] == 2 ** 14
    a = db.derive_key(GOOD, salt, weak)
    b = db.key_from_passphrase(GOOD)
    assert bytes(a) == bytes(b), 'derivation must use the stored params, not the constant'
    assert bytes(a) != bytes(db.derive_key(GOOD, salt)), 'params must actually change the key'
    db.write_kdf(salt)  # put it back


def check_param_migration():
    got = manage.parse_playbook_params('-i project.hosts project.yml -b --tags deploy')
    assert got == {'inventory': 'project.hosts', 'playbook': 'project.yml',
                   'tags': 'deploy', 'limit_hosts': None, 'become': 1}, got
    assert manage.parse_playbook_params('-i h p.yml -e evil=1') is None, \
        'unrecognised argv must be refused, not silently dropped'
    assert manage.parse_playbook_params('p.yml') is None


def check_rekey(store):
    store.close()
    new = 'a different long passphrase'
    db.rekey(GOOD, new)
    try:
        db.SecretStore.unlock(GOOD)
        raise AssertionError('old global password must stop working')
    except db.Locked:
        pass
    rekeyed = db.SecretStore.unlock(new)
    assert rekeyed.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
    assert rekeyed.vars_for('project', 1)['a_str'] == 'hello'
    rekeyed.close()


def main():
    try:
        store = check_locking()
        check_init_never_overwrites(store)
        check_yaml_types(store)
        check_value_types(store)
        check_scope_isolation(store)
        pid = check_orphan_sweep(store)
        check_deploy_file_and_redaction(store, pid)
        check_redaction_helper()
        check_totp()
        check_schedule_due()
        check_backup_and_prune(store)
        check_restore_from_backup(store)
        check_cipher_settings()
        check_kdf_params_are_honoured()
        check_param_migration()
        check_rekey(store)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print('all checks passed')


if __name__ == '__main__':
    main()
