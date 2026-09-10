#!/usr/bin/env python3
"""Schema migrations and the config.ini import."""
import sqlite3
import sys
from pathlib import Path

import harness

import db
import manage


def migrations_are_recorded():
    harness.new_store().close()
    with db.deploy_conn() as conn:
        applied = [r[0] for r in conn.execute(
            'SELECT version FROM schema_migrations ORDER BY version')]
        assert applied == [p.stem for p in
                           sorted((db.MIGRATIONS / 'deploy').glob('*.sql'))], applied
        assert not db.pending(conn, 'deploy'), 'nothing should be left pending'
        assert db.migrate(conn, 'deploy') == [], 'a second run must be a no-op'


def both_databases_migrate_separately():
    store = db.SecretStore.unlock(harness.GOOD)
    try:
        assert not db.pending(store._conn, 'secrets')
        with db.deploy_conn() as conn:
            deploy_versions = {r[0] for r in
                               conn.execute('SELECT version FROM schema_migrations')}
        secret_versions = {r[0] for r in store._exec(
            'SELECT version FROM schema_migrations', fetch=True)}
        assert secret_versions and secret_versions != deploy_versions, \
            'each database tracks its own migrations'
    finally:
        store.close()


def old_playbook_params_map_onto_columns():
    got = manage.parse_playbook_params('-i project.hosts project.yml -b --tags deploy')
    assert got == {'inventory': 'project.hosts', 'playbook': 'project.yml',
                   'tags': 'deploy', 'limit_hosts': None, 'become': 1}, got
    got = manage.parse_playbook_params('--inventory h site.yml --limit web --tags a,b')
    assert got == {'inventory': 'h', 'playbook': 'site.yml', 'tags': 'a,b',
                   'limit_hosts': 'web', 'become': 0}, got


def unmappable_params_are_refused_not_dropped():
    for raw in ('-i h p.yml -e injected=1',
                '-i h p.yml --vault-password-file /tmp/x',
                '-i h p.yml -M /tmp/evil',
                'p.yml',
                '-i h'):
        assert manage.parse_playbook_params(raw) is None, \
            f'{raw!r} must be refused rather than silently truncated'


def a_failing_migration_leaves_nothing_behind():
    """Half a script applied but unrecorded would make every later run fail."""
    mig = harness.WORK / 'migrations'
    (mig / 'deploy').mkdir(parents=True)
    bad = mig / 'deploy' / '900_half.sql'
    bad.write_text('CREATE TABLE half (x);\nINSERT INTO nope VALUES (1);\n')
    saved, db.MIGRATIONS = db.MIGRATIONS, mig
    try:
        with db.deploy_conn() as conn:
            try:
                db.migrate(conn, 'deploy')
                raise AssertionError('the broken script must fail')
            except sqlite3.OperationalError:
                pass
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert 'half' not in tables, 'the CREATE must have been rolled back'
            assert db.pending(conn, 'deploy') == [bad], 'and nothing recorded'
            bad.write_text('CREATE TABLE half (x);\n')
            assert db.migrate(conn, 'deploy') == ['900_half']
            assert not db.pending(conn, 'deploy')
    finally:
        db.MIGRATIONS = saved


if __name__ == '__main__':
    sys.exit(harness.run(
        migrations_are_recorded, both_databases_migrate_separately,
        old_playbook_params_map_onto_columns,
        unmappable_params_are_refused_not_dropped,
        a_failing_migration_leaves_nothing_behind))
