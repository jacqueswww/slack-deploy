"""One poller thread that spawns a worker per due schedule row."""
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import zipfile
from datetime import date, datetime, timedelta
from pathlib import Path

import db
from db import BACKUP_DIR, DATA, DEPLOY_DB, KDF_FILE, RUN_DIR, SECRETS_DB, deploy_conn
import runner

logger = logging.getLogger(__name__)

POLL_SECONDS = 60
KINDS = ('backup', 'git-pull')
HEARTBEAT_STALE = '-180 seconds'
RETENTION_DAYS = 90

SNAPSHOTTED = {DEPLOY_DB.name, SECRETS_DB.name}
# run/ holds the plaintext extra-vars of a deploy that is mid-flight
SKIP_DIRS = {RUN_DIR.name}
SKIP_SUFFIXES = ('-wal', '-shm', '-journal', '.partial', '.rekey', '.staging')
REQUIRED = ('deploy.db', 'secrets.db')   # inside the sealed payload
SEALED = 'data.enc'


def extra_files():
    """Everything else under data/, bar kdf.json which travels in the clear."""
    for item in sorted(DATA.rglob('*')):
        rel = item.relative_to(DATA)
        if not item.is_file() or rel.parts[0] in SKIP_DIRS or rel.name == KDF_FILE.name:
            continue
        if rel.name in SNAPSHOTTED or rel.name.endswith(SKIP_SUFFIXES):
            continue
        yield item, rel


# --- backups --------------------------------------------------------------

def backup(store, day=None):
    """One zip per day: kdf.json in the clear beside one AES-GCM sealed payload.

    The payload holds deploy.db (users, job logs), secrets.db (still SQLCipher
    encrypted) and anything else under data/ bar run/. It is sealed under a subkey
    of the store key, so a copied backup yields nothing without the global
    password and a tampered one refuses to restore. kdf.json stays outside
    because it carries the salt the password needs to become that key again.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.chmod(0o700)
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
        with store.begin_immediate():
            shutil.copy2(SECRETS_DB, staged / 'secrets.db')
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(staged.iterdir()):
                zf.write(item, item.name)
            for item, rel in extra_files():
                zf.write(item, str(rel))
        kdf = KDF_FILE.read_bytes()
        tmp_zip = zip_path.with_suffix('.partial')
        with zipfile.ZipFile(tmp_zip, 'w') as zf:
            zf.writestr(KDF_FILE.name, kdf)
            zf.writestr(SEALED, db.seal(db.backup_key(store._key), payload.getvalue(),
                                        aad=kdf))
        tmp_zip.chmod(0o600)
        tmp_zip.replace(zip_path)
    finally:
        shutil.rmtree(staged, ignore_errors=True)
    pruned = prune(RETENTION_DAYS)
    return zip_path, pruned


def open_backup(zip_path, passphrase):
    """(kdf.json bytes, ZipFile of the payload). Tries the previous salt too, for a
    backup taken while a rekey was mid-flight."""
    with zipfile.ZipFile(zip_path) as zf:
        if sorted(zf.namelist()) != sorted([KDF_FILE.name, SEALED]):
            raise ValueError(f'{zip_path} is not a slack-deploy backup')
        kdf, blob = zf.read(KDF_FILE.name), zf.read(SEALED)
    cfg = json.loads(kdf)
    error = None
    for candidate in (cfg, cfg.get('previous')):
        if not candidate:
            continue
        key = db._kdf_key(candidate, passphrase)
        try:
            plain = db.unseal(db.backup_key(key), blob, aad=kdf)
            return kdf, zipfile.ZipFile(io.BytesIO(plain))
        except db.Locked as exc:
            error = exc
        finally:
            db.wipe(key)
    raise error


def _stamp(name):
    """Date a backup name starts with: 2026-01-05, 2026-01-05-143000, 2026-01-05-pre-restore."""
    try:
        return date.fromisoformat(name.removeprefix('.staging-')[:10])
    except ValueError:
        return None


def prune(days=RETENTION_DAYS, today=None):
    """Old zips, old job logs, and the debris of a backup that was killed mid-way."""
    today = today or date.today()
    cutoff = today - timedelta(days=days)
    removed = []
    for item in BACKUP_DIR.glob('*.zip'):
        stamp = _stamp(item.stem)
        if stamp and stamp < cutoff:
            item.unlink()
            removed.append(item.name)
    for item in BACKUP_DIR.glob('.staging-*'):
        if _stamp(item.name) != today:
            shutil.rmtree(item, ignore_errors=True)
    for item in BACKUP_DIR.glob('*.partial'):
        if _stamp(item.stem) != today:
            item.unlink()
    with deploy_conn() as conn:
        conn.execute('DELETE FROM job WHERE started_at < ?', (cutoff.isoformat(),))
    return removed


# --- restore --------------------------------------------------------------

def scheduler_alive():
    """A fresh heartbeat means the bot is up and has the old files open."""
    if not DEPLOY_DB.exists():
        return False
    with deploy_conn() as conn:
        row = conn.execute("SELECT 1 FROM scheduler_lock WHERE heartbeat_at > "
                           "datetime('now', ?)", (HEARTBEAT_STALE,)).fetchone()
    return bool(row)


def restore(zip_path, passphrase):
    """Replace data/ with a backup zip. The old directory is kept beside the new
    one as data.replaced-<stamp>; returns it, or None on a machine without data/."""
    zip_path = Path(zip_path)
    kdf, payload = open_backup(zip_path, passphrase)
    with payload as zf:
        missing = [n for n in REQUIRED if n not in zf.namelist()]
        if missing or zf.testzip():
            raise ValueError(f'{zip_path} is not a complete backup (missing {missing})')
        staged = DATA.parent / f'.restoring-{DATA.name}'
        shutil.rmtree(staged, ignore_errors=True)
        staged.mkdir(mode=0o700, parents=True)
        zf.extractall(staged)      # zipfile strips ../ and leading / itself
    (staged / KDF_FILE.name).write_bytes(kdf)
    for item in staged.rglob('*'):
        item.chmod(0o700 if item.is_dir() else 0o600)
    conn = sqlite3.connect(staged / 'deploy.db')
    try:
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError(f'{zip_path}: deploy.db fails its integrity check')
    finally:
        conn.close()
    (staged / RUN_DIR.name).mkdir(mode=0o700, exist_ok=True)
    if scheduler_alive():
        shutil.rmtree(staged, ignore_errors=True)
        raise RuntimeError('the bot is running and holds the current files open; '
                           'stop it (and the web app) first')
    old = None
    if DATA.exists():
        old = DATA.parent / f'{DATA.name}.replaced-{datetime.now():%Y%m%d-%H%M%S}'
        os.rename(DATA, old)
    os.rename(staged, DATA)
    return old


# --- due logic (pure, so it is testable) ----------------------------------

def validate(at_time, weekdays):
    """is_due compares both as text, so they must be canonical: 02:00 not 2:00."""
    if not re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', at_time or ''):
        raise ValueError(f'time must be HH:MM: {at_time!r}')
    if weekdays != '*' and not set(weekdays.split(',')) <= set('0123456'):
        raise ValueError(f'weekdays must be * or 0-6 comma separated: {weekdays!r}')


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
            projects = [p for p in db.projects()
                        if not row['target_id'] or p['id'] == row['target_id']]
            if not projects:
                logger.warning('schedule %s: no project matches target %s',
                               row['id'], row['target_id'])
            for project in projects:
                runner.git_sync(project, store, actor='scheduler')
        else:
            logger.warning('unknown schedule kind %s', row['kind'])
    except Exception:
        logger.exception('scheduled %s failed', row['kind'])


def start(store):
    def loop():
        while True:
            try:
                if _elected(os.getpid()):
                    run_due(store)
            except Exception:
                logger.exception('scheduler tick failed')
            time.sleep(POLL_SECONDS)

    threading.Thread(target=loop, daemon=True, name='scheduler').start()
