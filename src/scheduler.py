"""One poller thread that spawns a worker per due schedule row."""
import logging
import os
import shutil
import sqlite3
import threading
import zipfile
from datetime import date, datetime, timedelta

from db import BACKUP_DIR, DATA, DEPLOY_DB, RUN_DIR, SECRETS_DB, deploy_conn
import runner

logger = logging.getLogger(__name__)

POLL_SECONDS = 60
HEARTBEAT_STALE = '-180 seconds'
RETENTION_DAYS = 90

SNAPSHOTTED = {DEPLOY_DB.name, SECRETS_DB.name}
# run/ holds the plaintext extra-vars of a deploy that is mid-flight
SKIP_DIRS = {RUN_DIR.name}
SKIP_SUFFIXES = ('-wal', '-shm', '-journal', '.partial', '.rekey', '.staging')


def extra_files():
    """Everything else under data/ - kdf.json is the one a restore cannot skip."""
    for item in sorted(DATA.rglob('*')):
        rel = item.relative_to(DATA)
        if not item.is_file() or rel.parts[0] in SKIP_DIRS:
            continue
        if rel.name in SNAPSHOTTED or rel.name.endswith(SKIP_SUFFIXES):
            continue
        yield item, rel


# --- backups --------------------------------------------------------------

def backup(store=None, day=None):
    """One zip per day of the whole data dir, bar backups/ and run/.

    secrets.db goes in still SQLCipher-encrypted; kdf.json carries the salt and
    KDF params, without which the passphrase cannot be turned back into a key.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    day = day or date.today().isoformat()
    zip_path = BACKUP_DIR / f'{day}.zip'
    staged = BACKUP_DIR / f'.staging-{day}'
    staged.mkdir(exist_ok=True)
    try:
        # deploy.db is WAL, so never a raw copy - VACUUM INTO gives a clean file
        snap = staged / 'deploy.db'
        snap.unlink(missing_ok=True)
        with sqlite3.connect(DEPLOY_DB) as conn:
            conn.execute('VACUUM INTO ?', (str(snap),))
        if SECRETS_DB.exists():
            if store is not None:
                with store.begin_immediate():
                    shutil.copy2(SECRETS_DB, staged / 'secrets.db')
            else:
                # no key here, so no write lock; take the journal too, which
                # makes even a copy caught mid-write recoverable
                shutil.copy2(SECRETS_DB, staged / 'secrets.db')
                for suffix in ('-journal', '-wal', '-shm'):
                    side = SECRETS_DB.with_name(SECRETS_DB.name + suffix)
                    if side.exists():
                        shutil.copy2(side, staged / side.name)
        tmp_zip = zip_path.with_suffix('.partial')
        with zipfile.ZipFile(tmp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(staged.iterdir()):
                zf.write(item, item.name)
            for item, rel in extra_files():
                zf.write(item, str(rel))
        tmp_zip.chmod(0o600)
        tmp_zip.replace(zip_path)
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    pruned = prune(RETENTION_DAYS)
    return zip_path, pruned


def prune(days=RETENTION_DAYS, today=None):
    cutoff = (today or date.today()) - timedelta(days=days)
    removed = []
    for item in BACKUP_DIR.glob('*.zip'):
        try:
            stamp = date.fromisoformat(item.stem)
        except ValueError:
            continue
        if stamp < cutoff:
            item.unlink()
            removed.append(item.name)
    return removed


# --- due logic (pure, so it is testable) ----------------------------------

def is_due(row, now):
    if not row['enabled']:
        return False
    if row['last_run_on'] == now.date().isoformat():
        return False
    if row['weekdays'] != '*' and str(now.weekday()) not in row['weekdays'].split(','):
        return False
    return now.strftime('%H:%M') >= row['at_time']


# --- election + loop ------------------------------------------------------

def _elected(pid):
    with deploy_conn() as conn:
        conn.execute(
            "INSERT INTO scheduler_lock (id, pid, heartbeat_at) "
            "VALUES (1, ?, datetime('now')) ON CONFLICT(id) DO UPDATE SET "
            "pid=excluded.pid, heartbeat_at=excluded.heartbeat_at "
            "WHERE scheduler_lock.pid=excluded.pid "
            f"OR scheduler_lock.heartbeat_at < datetime('now','{HEARTBEAT_STALE}')",
            (pid,))
        row = conn.execute('SELECT pid FROM scheduler_lock WHERE id=1').fetchone()
    return row and row['pid'] == pid


def run_due(store, now=None):
    now = now or datetime.now()
    fired = []
    with deploy_conn() as conn:
        rows = [dict(r) for r in conn.execute('SELECT * FROM schedule')]
    for row in rows:
        if not is_due(row, now):
            continue
        with deploy_conn() as conn:
            # claim it before spawning, so a slow job cannot double-fire
            changed = conn.execute(
                'UPDATE schedule SET last_run_on=? WHERE id=? AND '
                'coalesce(last_run_on,"") != ?',
                (now.date().isoformat(), row['id'], now.date().isoformat())).rowcount
        if not changed:
            continue
        fired.append(row)
        runner.spawn(_dispatch, row, store)
    return fired


def _dispatch(row, store):
    try:
        if row['kind'] == 'backup':
            backup(store)
        elif row['kind'] == 'git-pull':
            with deploy_conn() as conn:
                sql = 'SELECT * FROM project'
                args = ()
                if row['target_id']:
                    sql += ' WHERE id=?'
                    args = (row['target_id'],)
                projects = [dict(r) for r in conn.execute(sql, args)]
            for project in projects:
                runner.git_sync(project, store, actor='scheduler')
        else:
            logger.warning('unknown schedule kind %s', row['kind'])
    except Exception:
        logger.exception('scheduled %s failed', row['kind'])


def start(store, stop=None):
    stop = stop or threading.Event()

    def loop():
        while True:
            try:
                if _elected(os.getpid()):
                    run_due(store)
            except Exception:
                logger.exception('scheduler tick failed')
            if stop.wait(POLL_SECONDS):
                return

    thread = threading.Thread(target=loop, daemon=True, name='scheduler')
    thread.start()
    return thread, stop
