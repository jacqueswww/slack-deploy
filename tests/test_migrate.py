#!/usr/bin/env python3
"""Schema migrations."""
import sqlite3
import sys

import harness

import db


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
        for kind, applied in (('deploy', deploy_versions), ('secrets', secret_versions)):
            on_disk = {f.stem for f in (db.MIGRATIONS / kind).glob('*.sql')}
            assert applied == on_disk, (kind, applied, on_disk)
        assert secret_versions != deploy_versions, 'each database has its own chain'
        secret_tables = {r[0] for r in store._exec(
            "SELECT name FROM sqlite_master WHERE type='table'", fetch=True)}
        with db.deploy_conn() as conn:
            deploy_tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        assert 'secret' in secret_tables and 'secret' not in deploy_tables
        assert 'user' in deploy_tables and 'user' not in secret_tables, \
            'each database gets its own schema'
    finally:
        store.close()


def a_store_from_before_the_squash_still_gets_schema_changes():
    """0001 is every table as CREATE TABLE IF NOT EXISTS, so it is a no-op on an
    existing store: a change to a table already there lands only if a later
    migration rebuilds it. Without 0002, environment.inventory stays NOT NULL and
    a hosts-only environment is a 500 on that install but not on a fresh one."""
    old_db = harness.WORK / 'presquash.db'
    conn = sqlite3.connect(old_db)
    conn.executescript(
        'CREATE TABLE project (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT '
        'UNIQUE, working_dir TEXT, branch TEXT, created_at TEXT);\n'
        'CREATE TABLE environment (id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE, '
        'name TEXT NOT NULL, inventory TEXT NOT NULL, playbook TEXT NOT NULL, '
        'tags TEXT, limit_hosts TEXT, become INTEGER NOT NULL DEFAULT 0, '
        'UNIQUE(project_id, name));\n'
        "INSERT INTO project (name) VALUES ('p');\n"
        'INSERT INTO environment (project_id, name, inventory, playbook) '
        "VALUES (1, 'live', 'hosts', 'site.yml');")
    try:
        applied = db.migrate(conn, 'deploy')
        assert '0002_environment_inventory_optional' in applied, applied
        notnull = {r[1]: r[3] for r in conn.execute('PRAGMA table_info(environment)')}
        assert notnull['inventory'] == 0, 'a hosts-only environment must be insertable'
        assert notnull['playbook'] == 1, 'the rest of the constraints must survive'
        assert list(conn.execute('SELECT name, inventory FROM environment')) == \
            [('live', 'hosts')], 'the rebuild must carry the rows over'
        conn.execute('INSERT INTO environment (project_id, name, inventory, playbook) '
                     "VALUES (1, 'hostsonly', NULL, 's.yml')")
        assert db.migrate(conn, 'deploy') == [], 'a second run must be a no-op'
        conn.commit()
    finally:
        conn.close()
    # a fresh connection, because PRAGMA foreign_keys is ignored inside a
    # transaction - deploy_conn() sets it on a new handle for the same reason
    conn = sqlite3.connect(old_db)
    try:
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('DELETE FROM project WHERE id=1')
        assert conn.execute('SELECT count(*) FROM environment').fetchone()[0] == 0, \
            'the cascade must survive the rebuild'
    finally:
        conn.close()


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
        a_store_from_before_the_squash_still_gets_schema_changes,
        a_failing_migration_leaves_nothing_behind))
