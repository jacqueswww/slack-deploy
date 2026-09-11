#!/usr/bin/env python3
"""Daily backups, retention, restore, and the schedule due-check."""
import sys
import zipfile
from datetime import date, datetime, timedelta

import argparse

import harness
from harness import GOOD, WORK

import db
import manage
import scheduler

STORE = None


def payload_names(path, passphrase=GOOD):
    _, payload = scheduler.open_backup(path, passphrase)
    with payload as zf:
        return sorted(zf.namelist())


def backup_covers_the_whole_data_dir():
    global STORE
    STORE = harness.new_store()
    STORE.set(db.GLOBAL_SCOPE, 0, 'slack_bot_token', 'xoxb-must-not-leak')
    STORE.set('environment', 1, 'pg_password', 'hunter2-in-the-clear')
    with db.deploy_conn() as conn:
        conn.execute("INSERT INTO user (username, pw_hash, pw_salt, totp_secret) "
                     "VALUES ('carol', x'00', x'00', 'PLAINTEXTSEED')")
    # a stray file a later version might drop in, and a live deploy's temp file
    (db.DATA / 'notes.txt').write_text('keep me')
    (db.RUN_DIR / 'inflight.yml').write_text('pg: plaintext-in-flight')
    path, _ = scheduler.backup(STORE)
    with zipfile.ZipFile(path) as zf:
        assert sorted(zf.namelist()) == ['data.enc', 'kdf.json'], zf.namelist()
    assert payload_names(path) == ['deploy.db', 'notes.txt', 'secrets.db']
    raw = path.read_bytes()
    for leak in (b'hunter2', b'PLAINTEXTSEED', b'carol', b'SQLite format 3', b'keep me'):
        assert leak not in raw, f'{leak} readable in the backup without the password'
    assert path.stat().st_mode & 0o777 == 0o600, oct(path.stat().st_mode)
    (db.RUN_DIR / 'inflight.yml').unlink()


def run_dir_is_excluded():
    """run/ holds the plaintext extra-vars of a deploy that is mid-flight."""
    assert db.RUN_DIR.name in scheduler.SKIP_DIRS
    (db.RUN_DIR / 'inflight.yml').write_text('pg: plaintext-in-flight')
    try:
        path, _ = scheduler.backup(STORE)
        assert 'inflight.yml' not in payload_names(path)
    finally:
        (db.RUN_DIR / 'inflight.yml').unlink()


def backups_live_beside_data_not_inside_it():
    assert db.BACKUP_DIR.parent == db.DATA.parent, \
        'backups/ inside data/ would make each backup contain the last'
    assert db.BACKUP_DIR.name not in [p.name for p in db.DATA.iterdir()]


def a_backup_alone_can_be_restored():
    """kdf.json carries the salt; without it the passphrase cannot become a key."""
    path, _ = scheduler.backup(STORE)
    restored = WORK / 'restored'
    kdf, payload = scheduler.open_backup(path, GOOD)
    with payload as zf:
        zf.extractall(restored)
    (restored / 'kdf.json').write_bytes(kdf)
    saved = (db.DATA, db.DEPLOY_DB, db.SECRETS_DB, db.KDF_FILE)
    try:
        db.DATA, db.DEPLOY_DB = restored, restored / 'deploy.db'
        db.SECRETS_DB, db.KDF_FILE = restored / 'secrets.db', restored / 'kdf.json'
        back = db.SecretStore.unlock(GOOD)
        assert back.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
        back.close()
    finally:
        db.DATA, db.DEPLOY_DB, db.SECRETS_DB, db.KDF_FILE = saved


def retention_prunes_by_date():
    old = db.BACKUP_DIR / f'{date.today() - timedelta(days=91)}.zip'
    keep = db.BACKUP_DIR / f'{date.today() - timedelta(days=89)}.zip'
    junk = db.BACKUP_DIR / 'not-a-date.zip'
    stale_partial = db.BACKUP_DIR / f'{date.today() - timedelta(days=1)}.partial'
    stale_staging = db.BACKUP_DIR / f'.staging-{date.today() - timedelta(days=1)}'
    todays_partial = db.BACKUP_DIR / f'{date.today()}.partial'
    for f in (old, keep, junk, stale_partial, todays_partial):
        f.write_bytes(b'x')
    stale_staging.mkdir()
    with db.deploy_conn() as conn:
        old_job = conn.execute("INSERT INTO job (kind, status, started_at) VALUES "
                               "('deploy','ok', date('now','-91 days'))").lastrowid
        new_job = conn.execute("INSERT INTO job (kind, status) VALUES ('deploy','ok')"
                               ).lastrowid
    removed = scheduler.prune()
    assert old.name in removed, removed
    assert keep.exists(), '89 days old is inside the 90 day window'
    assert junk.exists(), 'a file that is not a date should be left alone'
    assert not stale_partial.exists() and not stale_staging.exists(), \
        'debris of a killed backup must go'
    assert todays_partial.exists(), 'a backup in flight right now must be left alone'
    todays_partial.unlink()
    with db.deploy_conn() as conn:
        left = {r[0] for r in conn.execute('SELECT id FROM job')}
    assert old_job not in left and new_job in left, 'job logs follow the same retention'


def schedule_inputs_must_be_canonical():
    scheduler.validate('02:00', '*')
    scheduler.validate('23:59', '0,6')
    for at, days in (('2:00', '*'), ('24:00', '*'), ('02:00', '7'), ('02:00', 'mon'),
                     ('', '*')):
        try:
            scheduler.validate(at, days)
            raise AssertionError(f'{at!r} {days!r} must be refused')
        except ValueError:
            pass


def schedule_fires_once_a_day():
    row = {'enabled': 1, 'at_time': '02:00', 'weekdays': '*', 'last_run_on': None}
    assert scheduler.is_due(row, datetime(2026, 1, 5, 2, 0))
    assert scheduler.is_due(row, datetime(2026, 1, 5, 23, 59))
    assert not scheduler.is_due(row, datetime(2026, 1, 5, 1, 59)), 'not yet due'
    assert not scheduler.is_due({**row, 'enabled': 0}, datetime(2026, 1, 5, 3, 0))
    assert not scheduler.is_due({**row, 'last_run_on': '2026-01-05'},
                                datetime(2026, 1, 5, 3, 0)), 'already ran today'
    assert scheduler.is_due({**row, 'last_run_on': '2026-01-04'},
                            datetime(2026, 1, 5, 3, 0)), 'ran yesterday, due again'


def schedule_honours_weekdays():
    row = {'enabled': 1, 'at_time': '02:00', 'weekdays': '*', 'last_run_on': None}
    monday = datetime(2026, 1, 5, 3, 0)
    assert monday.weekday() == 0
    assert scheduler.is_due({**row, 'weekdays': '0'}, monday)
    assert scheduler.is_due({**row, 'weekdays': '0,1,2,3,4'}, monday)
    assert not scheduler.is_due({**row, 'weekdays': '5,6'}, monday)


def only_one_process_owns_the_scheduler():
    assert scheduler._elected(1234), 'the first caller should win'
    assert not scheduler._elected(5678), 'a second process must not double-fire'
    assert scheduler._elected(1234), 'the holder keeps it on the next tick'


def restore_refuses_while_the_bot_runs():
    path, _ = scheduler.backup(STORE)
    try:
        scheduler.restore(path, GOOD)
        raise AssertionError('a live heartbeat means open files; restore must refuse')
    except RuntimeError:
        pass
    assert db.DATA.exists() and not (db.DATA.parent / '.restoring-data').exists()


def restore_refuses_a_zip_that_is_not_a_backup():
    bogus = WORK / 'bogus.zip'
    with zipfile.ZipFile(bogus, 'w') as zf:
        zf.writestr('deploy.db', b'x')
    try:
        scheduler.restore(bogus, GOOD)
        raise AssertionError('a plain zip must be refused')
    except ValueError:
        pass


def a_tampered_or_foreign_backup_refuses_to_restore():
    """The seal is the only thing standing between a doctored deploy.db (a new admin,
    a project pointed at a hostile repo) and the next Slack deploy."""
    path, _ = scheduler.backup(STORE)
    try:
        scheduler.open_backup(path, 'not the passphrase at all')
        raise AssertionError('the wrong global password must not open a backup')
    except db.Locked:
        pass
    with zipfile.ZipFile(path) as zf:
        kdf, blob = zf.read('kdf.json'), bytearray(zf.read('data.enc'))
    blob[40] ^= 0x01
    forged = WORK / 'forged.zip'
    with zipfile.ZipFile(forged, 'w') as zf:
        zf.writestr('kdf.json', kdf)
        zf.writestr('data.enc', bytes(blob))
    try:
        scheduler.restore(forged, GOOD)
        raise AssertionError('one flipped bit must be refused')
    except db.Locked:
        pass
    assert db.DATA.exists() and not (db.DATA.parent / '.restoring-data').exists()


def restore_swaps_the_data_dir_and_keeps_the_old_one():
    """The zip wins, the previous state survives as a directory beside it."""
    path, _ = scheduler.backup(STORE)
    STORE.set(db.GLOBAL_SCOPE, 0, 'added_after_backup', 'gone-after-restore')
    (db.DATA / 'notes.txt').unlink()
    STORE.close()                                  # "stop the bot"
    with db.deploy_conn() as conn:
        conn.execute("UPDATE scheduler_lock SET heartbeat_at=datetime('now','-1 hour')")
    old = scheduler.restore(path, GOOD)
    assert old.exists() and (old / 'secrets.db').exists(), old
    assert old.stat().st_mode & 0o777 == 0o700
    assert (db.DATA / 'notes.txt').read_text() == 'keep me', 'extra files come back too'
    assert (db.DATA / 'run').is_dir()
    assert db.DATA.stat().st_mode & 0o777 == 0o700
    assert (db.DATA / 'secrets.db').stat().st_mode & 0o777 == 0o600
    back = db.SecretStore.unlock(GOOD)
    try:
        assert back.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
        assert back.get(db.GLOBAL_SCOPE, 0, 'added_after_backup') is None
    finally:
        back.close()


def import_backs_up_the_current_state_first():
    """`manage.py import` on an older zip: a -pre-import zip of today's state lands in
    backups/ and opens with the passphrase, then the zip's contents take over."""
    store = db.SecretStore.unlock(GOOD)
    older, _ = scheduler.backup(store, day='older')
    store.set(db.GLOBAL_SCOPE, 0, 'set_after_older', 'only-in-the-pre-import-zip')
    store.close()
    with db.deploy_conn() as conn:
        conn.execute("UPDATE scheduler_lock SET heartbeat_at=datetime('now','-1 hour')")
    real_ask, manage.ask_passphrase = manage.ask_passphrase, \
        lambda *a, **k: bytearray(GOOD.encode())
    try:
        manage.cmd_import(argparse.Namespace(zip=str(older), yes=True))
    finally:
        manage.ask_passphrase = real_ask
    safety = sorted(db.BACKUP_DIR.glob('*-pre-import.zip'))
    assert len(safety) == 1, safety
    _, payload = scheduler.open_backup(safety[0], GOOD)
    with payload as zf:
        assert 'secrets.db' in zf.namelist() and 'deploy.db' in zf.namelist()
    back = db.SecretStore.unlock(GOOD)
    try:
        assert back.get(db.GLOBAL_SCOPE, 0, 'set_after_older') is None, \
            'data/ must now be the older zip'
        assert back.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
    finally:
        back.close()
    assert scheduler._stamp(safety[0].stem) == date.today(), 'pre-import zips age out too'


def a_store_that_cannot_be_opened_does_not_block_an_import():
    """The states import exists to recover from - a lost password for this machine,
    a deleted secrets.db - are exactly the ones that cannot be backed up first."""
    store = db.SecretStore.unlock(GOOD)
    good_zip, _ = scheduler.backup(store, day='importable')
    store.close()
    with db.deploy_conn() as conn:
        conn.execute("UPDATE scheduler_lock SET heartbeat_at=datetime('now','-1 hour')")
    db.SECRETS_DB.unlink()                     # the store is now unopenable
    real_ask, manage.ask_passphrase = manage.ask_passphrase, \
        lambda *a, **k: bytearray(GOOD.encode())
    before = set(db.BACKUP_DIR.glob('*-pre-import.zip'))
    try:
        manage.cmd_import(argparse.Namespace(zip=str(good_zip), yes=True))
    finally:
        manage.ask_passphrase = real_ask
    assert set(db.BACKUP_DIR.glob('*-pre-import.zip')) == before, \
        'nothing to back up, but the import must still happen'
    back = db.SecretStore.unlock(GOOD)
    try:
        assert back.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-not-leak'
    finally:
        back.close()


if __name__ == '__main__':
    sys.exit(harness.run(
        backup_covers_the_whole_data_dir, run_dir_is_excluded,
        backups_live_beside_data_not_inside_it, a_backup_alone_can_be_restored,
        retention_prunes_by_date, schedule_inputs_must_be_canonical,
        schedule_fires_once_a_day,
        schedule_honours_weekdays, only_one_process_owns_the_scheduler,
        restore_refuses_while_the_bot_runs, restore_refuses_a_zip_that_is_not_a_backup,
        a_tampered_or_foreign_backup_refuses_to_restore,
        restore_swaps_the_data_dir_and_keeps_the_old_one,
        import_backs_up_the_current_state_first,
        a_store_that_cannot_be_opened_does_not_block_an_import))
