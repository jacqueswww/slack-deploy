"""Two-database store: plaintext deploy.db, SQLCipher-encrypted secrets.db."""
import base64
import hashlib
import hmac
import json
import struct
import time
from datetime import date, datetime
import os
import sqlite3
import threading
from pathlib import Path

import yaml
from sqlcipher3 import dbapi2 as sqlcipher

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get('SLACK_DEPLOY_DATA') or ROOT / 'data')
DEPLOY_DB = DATA / 'deploy.db'
SECRETS_DB = DATA / 'secrets.db'
KDF_FILE = DATA / 'kdf.json'
RUN_DIR = DATA / 'run'
BACKUP_DIR = DATA.parent / 'backups'   # sibling of data/, never inside it

MIN_PASSPHRASE = 20

# Database key: maxed out. 256 MiB / ~0.7s per derivation, paid once per daemon
# start and once per web login, never per request. dklen must stay 32 (AES-256).
KEY_SCRYPT = {'n': 2 ** 18, 'r': 8, 'p': 1, 'maxmem': 512 * 1024 * 1024, 'dklen': 32}
# User passwords stay cheaper: changing these invalidates every stored hash, and
# they guard an account, not the encrypted store.
PW_SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024, 'dklen': 32}
KDF_KEYS = ('n', 'r', 'p', 'maxmem', 'dklen')

# SQLCipher 4 defaults to memory_security OFF: no mlock, no wipe of key material.
# The algorithms are already the strongest available; pinned so a library upgrade
# cannot silently weaken an existing database.
CIPHER_PRAGMAS = (
    'PRAGMA cipher_memory_security = ON',
    'PRAGMA cipher_default_hmac_algorithm = HMAC_SHA512',
    'PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512',
)
GLOBAL_SCOPE = 'global'
MIGRATIONS = ROOT / 'migrations'

MIGRATION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def pending(conn, kind):
    conn.executescript(MIGRATION_TABLE)
    done = {r[0] for r in conn.execute('SELECT version FROM schema_migrations')}
    return [p for p in sorted((MIGRATIONS / kind).glob('*.sql'))
            if p.stem not in done]


def migrate(conn, kind):
    """Apply migrations/<kind>/*.sql in filename order, once each."""
    applied = []
    for path in pending(conn, kind):
        conn.executescript(path.read_text())
        conn.execute('INSERT INTO schema_migrations (version) VALUES (?)', (path.stem,))
        conn.commit()
        applied.append(path.stem)
    return applied


class Locked(Exception):
    """Wrong global password, or the store could not be opened."""


def harden_process():
    """Block core dumps and same-uid ptrace/proc-mem reads of the derived key."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        import ctypes
        ctypes.CDLL('libc.so.6', use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
    except Exception:
        pass


# --- key derivation -------------------------------------------------------

_derive_lock = threading.Lock()


def derive_key(passphrase, salt, params=None):
    params = params or KEY_SCRYPT
    # half a gig a go; serialise so concurrent logins cannot stack allocations
    with _derive_lock:
        return bytearray(hashlib.scrypt(passphrase.encode(), salt=salt, **params))


def read_kdf():
    """Salt and the params the store was actually built with, not today's."""
    cfg = json.loads(KDF_FILE.read_text())
    params = {k: cfg[k] for k in KDF_KEYS if k in cfg}
    return bytes.fromhex(cfg['salt']), (params or KEY_SCRYPT)


def write_kdf(salt, params=None):
    KDF_FILE.write_text(json.dumps({'salt': salt.hex(), **(params or KEY_SCRYPT)}))
    KDF_FILE.chmod(0o600)


def key_from_passphrase(passphrase):
    salt, params = read_kdf()
    return derive_key(passphrase, salt, params)


# --- connections ----------------------------------------------------------

def deploy_conn():
    conn = sqlite3.connect(DEPLOY_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _open_secrets(key, path=None, create=False):
    path = Path(path or SECRETS_DB)
    if create:
        conn = sqlcipher.connect(str(path), timeout=30)
    else:
        # mode=rw so a wrong path errors instead of creating an empty store.
        conn = sqlcipher.connect(f'file:{path}?mode=rw', uri=True, timeout=30)
    conn.row_factory = sqlcipher.Row
    for pragma in CIPHER_PRAGMAS:
        conn.execute(pragma)
    # Pragmas take no bound parameters; the raw-key form avoids any quoting
    # hazard, which otherwise echoes passphrase bytes into exception text.
    conn.execute('PRAGMA key = "x\'%s\'"' % bytes(key).hex())
    try:
        conn.execute('SELECT count(*) FROM sqlite_master').fetchone()
    except sqlcipher.DatabaseError as exc:
        conn.close()
        raise Locked('incorrect global password') from exc
    return conn


class SecretStore:
    """Owns the derived key and one serialised connection to secrets.db."""

    def __init__(self, key):
        self._key = bytearray(key)
        self._lock = threading.Lock()
        self._conn = _open_secrets(self._key)

    @classmethod
    def unlock(cls, passphrase):
        return cls(key_from_passphrase(passphrase))

    @property
    def key_hex(self):
        return bytes(self._key).hex()

    @classmethod
    def from_key_hex(cls, key_hex):
        return cls(bytes.fromhex(key_hex))

    def close(self):
        with self._lock:
            self._conn.close()
        for i in range(len(self._key)):
            self._key[i] = 0

    def _retry(self):
        self._conn = _open_secrets(self._key)

    def _exec(self, sql, args=(), fetch=None):
        with self._lock:
            for attempt in (1, 2):
                try:
                    cur = self._conn.execute(sql, args)
                    out = cur.fetchall() if fetch else None
                    self._conn.commit()
                    return out
                except sqlcipher.DatabaseError:
                    if attempt == 2:
                        raise
                    self._retry()

    # secrets are stored as YAML scalars so dates/dicts/lists round-trip
    def get(self, scope, scope_id, name):
        rows = self._exec(
            'SELECT value FROM secret WHERE scope=? AND scope_id=? AND name=?',
            (scope, scope_id, name), fetch=True)
        return yaml.safe_load(rows[0]['value']) if rows else None

    def set(self, scope, scope_id, name, value, actor=None, note=None):
        """note=None leaves any existing note alone; pass '' to clear it."""
        self._exec(
            'INSERT INTO secret (scope, scope_id, name, value, updated_by, note) '
            'VALUES (?,?,?,?,?,?) ON CONFLICT(scope, scope_id, name) DO UPDATE SET '
            'value=excluded.value, updated_by=excluded.updated_by, '
            "updated_at=datetime('now'), "
            'note=coalesce(excluded.note, secret.note)',
            (scope, scope_id, name, yaml.safe_dump(value, default_flow_style=False),
             actor, note))

    def set_note(self, scope, scope_id, name, note):
        self._exec('UPDATE secret SET note=? WHERE scope=? AND scope_id=? AND name=?',
                   (note or None, scope, scope_id, name))

    def delete(self, scope, scope_id, name):
        self._exec('DELETE FROM secret WHERE scope=? AND scope_id=? AND name=?',
                   (scope, scope_id, name))

    def delete_scope(self, scope, scope_id):
        self._exec('DELETE FROM secret WHERE scope=? AND scope_id=?', (scope, scope_id))

    def names(self, scope, scope_id):
        rows = self._exec(
            'SELECT name, value, updated_at, updated_by, note FROM secret '
            'WHERE scope=? AND scope_id=? ORDER BY name', (scope, scope_id), fetch=True)
        out = []
        for row in rows:
            item = dict(row)
            item['type'] = type_name(yaml.safe_load(item.pop('value')))
            out.append(item)
        return out

    # --- credentials: ssh keys and tokens, not ansible variables ---

    def cred_set(self, scope, scope_id, kind, name, secret, public=None, actor=None):
        self._exec(
            'INSERT INTO credential (scope, scope_id, kind, name, secret, public, '
            'updated_by) VALUES (?,?,?,?,?,?,?) '
            'ON CONFLICT(scope, scope_id, kind) DO UPDATE SET name=excluded.name, '
            'secret=excluded.secret, public=excluded.public, '
            "updated_by=excluded.updated_by, updated_at=datetime('now')",
            (scope, scope_id, kind, name, secret, public, actor))

    def cred_delete(self, scope, scope_id, kind):
        self._exec('DELETE FROM credential WHERE scope=? AND scope_id=? AND kind=?',
                   (scope, scope_id, kind))

    def cred_list(self, scope=None, scope_id=None):
        sql = ('SELECT id, scope, scope_id, kind, name, public, updated_at, '
               'updated_by FROM credential')
        args = ()
        if scope is not None:
            sql += ' WHERE scope=? AND scope_id=?'
            args = (scope, scope_id)
        return [dict(r) for r in self._exec(sql + ' ORDER BY scope, kind', args,
                                            fetch=True)]

    def cred_resolve(self, kind, project_id=None, environment_id=None):
        """Most specific credential of this kind: environment, then project, then global."""
        for scope, scope_id in (('environment', environment_id),
                                ('project', project_id), (GLOBAL_SCOPE, 0)):
            if scope != GLOBAL_SCOPE and not scope_id:
                continue
            rows = self._exec(
                'SELECT * FROM credential WHERE scope=? AND scope_id=? AND kind=?',
                (scope, scope_id, kind), fetch=True)
            if rows:
                return dict(rows[0])
        return None

    def vars_for(self, scope, scope_id):
        rows = self._exec('SELECT name, value FROM secret WHERE scope=? AND scope_id=?',
                          (scope, scope_id), fetch=True)
        return {r['name']: yaml.safe_load(r['value']) for r in rows}

    def extra_vars(self, project_id, environment_id):
        """Project vars overlaid by environment vars. Global scope is never included."""
        merged = self.vars_for('project', project_id)
        merged.update(self.vars_for('environment', environment_id))
        return merged

    def begin_immediate(self):
        """Write lock, so a byte copy of secrets.db is consistent."""
        return _WriteLock(self)

    def orphan_sweep(self):
        """Drop secrets whose owning row is gone; rowids get reused."""
        with deploy_conn() as dc:
            projects = {r[0] for r in dc.execute('SELECT id FROM project')}
            envs = {r[0] for r in dc.execute('SELECT id FROM environment')}
        removed = 0
        for scope, live in (('project', projects), ('environment', envs)):
            rows = self._exec('SELECT DISTINCT scope_id FROM secret WHERE scope=?',
                              (scope,), fetch=True)
            for r in rows:
                if r['scope_id'] not in live:
                    self.delete_scope(scope, r['scope_id'])
                    removed += 1
            creds = self._exec('SELECT DISTINCT scope_id FROM credential WHERE scope=?',
                               (scope,), fetch=True)
            for r in creds:
                if r['scope_id'] not in live:
                    self._exec('DELETE FROM credential WHERE scope=? AND scope_id=?',
                               (scope, r['scope_id']))
                    removed += 1
        return removed


class _WriteLock:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        self._store._lock.acquire()
        self._store._conn.execute('BEGIN IMMEDIATE')
        return self

    def __exit__(self, *exc):
        try:
            self._store._conn.execute('COMMIT')
        finally:
            self._store._lock.release()


def generate_ssh_key(comment='slack-deploy'):
    """New ed25519 keypair. Returns (openssh private, openssh public)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return private, f'{public} {comment}'


VAR_TYPES = ('string', 'int', 'float', 'bool', 'date', 'yaml')


def coerce_value(text, vartype='string'):
    """Explicit type, because bare YAML turns a password of "no" into False."""
    if vartype == 'string':
        return '' if text is None else str(text)
    text = (text or '').strip()
    if vartype == 'int':
        return int(text)
    if vartype == 'float':
        return float(text)
    if vartype == 'bool':
        low = text.lower()
        if low in ('true', 'yes', 'on', '1'):
            return True
        if low in ('false', 'no', 'off', '0'):
            return False
        raise ValueError(f'not a boolean: {text!r}')
    if vartype == 'date':
        return date.fromisoformat(text)
    if vartype == 'yaml':
        return yaml.safe_load(text)
    raise ValueError(f'unknown type: {vartype!r}')


def type_name(value):
    """Label for a stored value, so the screen can show what it will send."""
    if isinstance(value, bool):
        return 'bool'
    if isinstance(value, datetime):
        return 'datetime'
    if isinstance(value, date):
        return 'date'
    if isinstance(value, int):
        return 'int'
    if isinstance(value, float):
        return 'float'
    if isinstance(value, dict):
        return 'mapping'
    if isinstance(value, (list, tuple)):
        return 'list'
    return 'string'


# --- vars YAML ------------------------------------------------------------

def vars_import(store, scope, scope_id, path, actor=None):
    doc = yaml.safe_load(Path(path).read_text())
    if not isinstance(doc, dict):
        raise ValueError('vars file must be a YAML mapping of name -> value')
    for name, value in doc.items():
        store.set(scope, scope_id, str(name), value, actor)
    return sorted(doc)


def vars_export_text(store, scope, scope_id):
    return yaml.safe_dump(store.vars_for(scope, scope_id), default_flow_style=False,
                          sort_keys=True)


# --- users ----------------------------------------------------------------

def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    return hashlib.scrypt(password.encode(), salt=salt, **PW_SCRYPT), salt


def check_password(password, pw_hash, salt):
    return hmac.compare_digest(hash_password(password, salt)[0], pw_hash)


# --- TOTP (RFC 6238, stdlib only) -----------------------------------------

TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_SKEW = 1  # accept one step either side, for clock drift


def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip('=')


def totp_at(secret, counter):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_verify(secret, code, now=None):
    if not secret or not code or not code.strip().isdigit():
        return False
    counter = int((now if now is not None else time.time()) // TOTP_STEP)
    code = code.strip()
    return any(hmac.compare_digest(totp_at(secret, counter + drift), code)
               for drift in range(-TOTP_SKEW, TOTP_SKEW + 1))


def totp_qr_svg(uri):
    """Inline SVG, so the secret never travels in a URL or lands in an access log."""
    import io
    import qrcode
    import qrcode.image.svg
    code = qrcode.QRCode(box_size=10, border=2,
                         error_correction=qrcode.constants.ERROR_CORRECT_M)
    code.add_data(uri)
    buf = io.BytesIO()
    code.make_image(image_factory=qrcode.image.svg.SvgPathImage).save(buf)
    # drop the xml declaration so it can be embedded straight into the page
    return buf.getvalue().decode().split('?>', 1)[-1].strip()


def totp_uri(secret, username, issuer='slack-deploy'):
    from urllib.parse import quote
    return (f'otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}'
            f'&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_STEP}')


# --- audit ----------------------------------------------------------------

def audit(actor, action, detail=None):
    """Never record secret values here - names and ids only."""
    with deploy_conn() as conn:
        conn.execute('INSERT INTO audit (actor, action, detail) VALUES (?,?,?)',
                     (actor, action, detail))


# --- init -----------------------------------------------------------------

def initialised():
    """Paths that already exist, so init can refuse instead of overwriting."""
    return [p for p in (KDF_FILE, DEPLOY_DB, SECRETS_DB) if p.exists()]


REFUSE_INIT = (
    'init never overwrites an existing store. To change the global password use '
    '"make rekey"; to start over, move data/ and backups/ aside first.'
)


def init(passphrase):
    found = initialised()
    if found:
        raise FileExistsError('already initialised: '
                              + ', '.join(str(p) for p in found) + '. ' + REFUSE_INIT)
    if len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(f'global password must be at least {MIN_PASSPHRASE} characters')
    for d in (DATA, RUN_DIR, BACKUP_DIR):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
    write_kdf(os.urandom(16))
    with deploy_conn() as conn:
        migrate(conn, 'deploy')
    DEPLOY_DB.chmod(0o600)
    key = key_from_passphrase(passphrase)
    conn = _open_secrets(key, create=True)
    migrate(conn, 'secrets')
    conn.close()
    SECRETS_DB.chmod(0o600)
    return SecretStore(key)


def rekey(old_passphrase, new_passphrase):
    """Never PRAGMA rekey: it rewrites every page and is not crash-atomic."""
    if len(new_passphrase) < MIN_PASSPHRASE:
        raise ValueError(f'global password must be at least {MIN_PASSPHRASE} characters')
    old_key = key_from_passphrase(old_passphrase)
    conn = _open_secrets(old_key)
    new_salt = os.urandom(16)
    new_key = derive_key(new_passphrase, new_salt)
    tmp = SECRETS_DB.with_suffix('.rekey')
    tmp.unlink(missing_ok=True)
    try:
        conn.execute('ATTACH DATABASE ? AS fresh KEY "x\'%s\'"' % bytes(new_key).hex(),
                     (str(tmp),))
        conn.execute("SELECT sqlcipher_export('fresh')")
        conn.execute('DETACH DATABASE fresh')
        conn.close()
        tmp.chmod(0o600)
        os.replace(tmp, SECRETS_DB)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    write_kdf(new_salt)  # also upgrades an old store to today's KDF params
