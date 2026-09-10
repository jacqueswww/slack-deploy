#!/usr/bin/env python3
"""Daily backups, retention, restore, and the schedule due-check."""
import sys
import zipfile
from datetime import date, datetime, timedelta

import harness
from harness import GOOD, WORK

import db
import scheduler

STORE = None


def backup_covers_the_whole_data_dir():
    global STORE
    STORE = harness.new_store()
    STORE.set(db.GLOBAL_SCOPE, 0, 'slack_bot_token', 'xoxb-must-not-leak')
    STORE.set('environment', 1, 'pg_password', 'hunter2-in-the-clear')
    # a stray file a later version might drop in, and a live deploy's temp file
    (db.DATA / 'notes.txt').write_text('keep me')
    (db.RUN_DIR / 'inflight.yml').write_text('pg: plaintext-in-flight')
    path, _ = scheduler.backup(STORE)
    with zipfile.ZipFile(path) as zf:
        names = sorted(zf.namelist())
        blob = zf.read('secrets.db')
    assert names == ['deploy.db', 'kdf.json', 'notes.txt', 'secrets.db'], names
    assert b'hunter2' not in blob, 'secrets.db must stay encrypted inside the zip'
    assert path.stat().st_mode & 0o777 == 0o600, oct(path.stat().st_mode)
    (db.RUN_DIR / 'inflight.yml').unlink()


def run_dir_is_excluded():
    """run/ holds the plaintext extra-vars of a deploy that is mid-flight."""
    assert db.RUN_DIR.name in scheduler.SKIP_DIRS
    (db.RUN_DIR / 'inflight.yml').write_text('pg: plaintext-in-flight')
    try:
        path, _ = scheduler.backup(STORE)
        with zipfile.ZipFile(path) as zf:
            assert 'inflight.yml' not in zf.namelist(), zf.namelist()
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
    with zipfile.ZipFile(path) as zf:
        zf.extractall(restored)
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
    for f in (old, keep, junk):
        f.write_bytes(b'x')
    removed = scheduler.prune()
    assert old.name in removed, removed
    assert keep.exists(), '89 days old is inside the 90 day window'
    assert junk.exists(), 'a file that is not a date should be left alone'


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


if __name__ == '__main__':
    sys.exit(harness.run(
        backup_covers_the_whole_data_dir, run_dir_is_excluded,
        backups_live_beside_data_not_inside_it, a_backup_alone_can_be_restored,
        retention_prunes_by_date, schedule_fires_once_a_day,
        schedule_honours_weekdays, only_one_process_owns_the_scheduler))
