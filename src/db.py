"""Two-database store: plaintext deploy.db, SQLCipher-encrypted secrets.db."""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
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
DATA = Path(os.environ.get('HOISTY_DATA') or ROOT / 'data')
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
# they guard an account, not the encrypted store. dklen is 64: the first 32 bytes
# are the stored verifier, the last 32 wrap the user's TOTP seed and are never
# stored. scrypt's final PBKDF2 step makes the first block independent of dklen,
# so hashes made with dklen=32 still verify.
PW_SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024, 'dklen': 64}
MIN_PASSWORD = 12
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
SCOPES = ('global', 'project', 'environment')
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
    """Apply migrations/<kind>/*.sql in filename order, once each.

    Script and version row go in one transaction, so a failing statement leaves
    nothing half-applied for the next run to trip over."""
    applied = []
    for path in pending(conn, kind):
        if not re.fullmatch(r'\w+', path.stem):
            raise ValueError(f'bad migration name: {path.name}')
        try:
            conn.executescript(
                f"BEGIN;\n{path.read_text()}\n"
                f"INSERT INTO schema_migrations (version) VALUES ('{path.stem}');\nCOMMIT;")
        except Exception:
            conn.rollback()
            raise
        applied.append(path.stem)
    return applied


class Locked(Exception):
    """Wrong global password, or the store could not be opened."""


def harden_process():
    """Block core dumps and same-uid ptrace/proc-mem reads of the derived key, and
    refuse to run on a crypto library that gives wrong answers."""
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
    crypto_self_test()


# Known answers: RFC 7914 section 12 for scrypt, NIST GCM test case 2 for AES-GCM.
# A library swapped for one that "works" but returns something else fails here
# before a passphrase is ever typed into it.
_SCRYPT_KAT = ('password', b'NaCl', dict(n=1024, r=8, p=16, dklen=64),
               'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e'
               '22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')
_GCM_KAT = (bytes(16), bytes(12), bytes(16),
            '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf')


def crypto_self_test():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pw, salt, params, want = _SCRYPT_KAT
    if hashlib.scrypt(pw.encode(), salt=salt, **params).hex() != want:
        raise SystemExit('scrypt known-answer test failed: refusing to run')
    key, nonce, plain, want = _GCM_KAT
    if AESGCM(key).encrypt(nonce, plain, None).hex() != want:
        raise SystemExit('AES-GCM known-answer test failed: refusing to run')
    if not hmac.compare_digest(hashlib.sha256(b'abc').hexdigest(),
                               'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'):
        raise SystemExit('SHA-256 known-answer test failed: refusing to run')


# --- key derivation -------------------------------------------------------

_derive_lock = threading.Lock()


def wipe(buf):
    """Zero a bytearray in place; the one thing Python lets us scrub."""
    buf[:] = bytes(len(buf))


def _libc():
    import ctypes
    return ctypes.CDLL('libc.so.6', use_errno=True)


def _lock_pages(buf, lock=True):
    """mlock the page holding a key bytearray so it is never written to swap.
    Best effort: RLIMIT_MEMLOCK allows a few pages even for an unprivileged uid."""
    import ctypes
    try:
        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        fn = _libc().mlock if lock else _libc().munlock
        return fn(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf))) == 0
    except Exception:
        return False


def _as_bytes(passphrase):
    if isinstance(passphrase, (bytes, bytearray, memoryview)):
        return passphrase
    return passphrase.encode()


def derive_key(passphrase, salt, params=None):
    """The key as a bytearray, so whoever owns it can wipe() it. A str passphrase
    and scrypt's own bytes result are immutable and stay in the heap until reused;
    the CLI passes a bytearray it wipes, PR_SET_DUMPABLE=0 guards the rest."""
    params = params or KEY_SCRYPT
    # half a gig a go; serialise so concurrent logins cannot stack allocations
    with _derive_lock:
        return bytearray(hashlib.scrypt(_as_bytes(passphrase), salt=salt, **params))


def _kdf_key(cfg, passphrase):
    params = {k: cfg[k] for k in KDF_KEYS if k in cfg}
    return derive_key(passphrase, bytes.fromhex(cfg['salt']), params or KEY_SCRYPT)


def write_kdf(salt, params=None, previous=None):
    """previous= keeps the old salt alongside while a rekey is mid-flight."""
    cfg = {'salt': salt.hex(), **(params or KEY_SCRYPT)}
    if previous:
        cfg['previous'] = {k: previous[k] for k in ('salt', *KDF_KEYS) if k in previous}
    KDF_FILE.write_text(json.dumps(cfg))
    KDF_FILE.chmod(0o600)


def open_store(passphrase):
    """(key, conn, kdf) for whichever salt opens the store: the current one, or
    the previous one a rekey that died between its two writes left behind."""
    cfg = json.loads(KDF_FILE.read_text())
    error = None
    for candidate in (cfg, cfg.get('previous')):
        if not candidate:
            continue
        key = _kdf_key(candidate, passphrase)
        try:
            return key, _open_secrets(key), candidate
        except Locked as exc:
            error = exc
    raise error


# --- connections ----------------------------------------------------------

def deploy_conn():
    conn = sqlite3.connect(DEPLOY_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _open_secrets(key, path=None, create=False):
    path = Path(path or SECRETS_DB)
    # check_same_thread off: SecretStore serialises every use behind its own lock
    # and is handed between request, scheduler and deploy threads
    if create:
        conn = sqlcipher.connect(str(path), timeout=30, check_same_thread=False)
    else:
        # mode=rw so a wrong path errors instead of creating an empty store.
        conn = sqlcipher.connect(f'file:{path}?mode=rw', uri=True, timeout=30,
                                 check_same_thread=False)
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

    def __init__(self, key, conn=None):
        # takes ownership of a bytearray, so the only long-lived copy of the key
        # is the one close() wipes
        self._key = key if isinstance(key, bytearray) else bytearray(key)
        self.locked_in_ram = _lock_pages(self._key)
        self._lock = threading.Lock()
        self._conn = conn or _open_secrets(self._key)

    @classmethod
    def unlock(cls, passphrase):
        key, conn, _ = open_store(passphrase)
        return cls(key, conn)

    def clone(self):
        """Own connection and key copy for a worker thread that outlives the request."""
        return SecretStore(bytearray(self._key))

    def close(self):
        with self._lock:
            self._conn.close()
        wipe(self._key)
        _lock_pages(self._key, lock=False)

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
                except sqlcipher.OperationalError:
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
        """Drop secrets whose owning row is gone: there is no foreign key across files."""
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
        try:
            self._store._conn.execute('BEGIN IMMEDIATE')
        except BaseException:
            self._store._lock.release()
            raise
        return self

    def __exit__(self, *exc):
        try:
            self._store._conn.execute('COMMIT')
        finally:
            self._store._lock.release()


def backup_key(store_key):
    """A subkey for sealing backups, so the database key itself never leaves SQLCipher."""
    return hmac.new(bytes(store_key), b'hoisty backup', hashlib.sha256).digest()


def seal(key, data, aad=b''):
    """nonce || AES-256-GCM(data). Confidentiality and integrity in one: a tampered
    or foreign blob fails to open rather than restoring quietly."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def unseal(key, blob, aad=b''):
    """Raises Locked when the key or the bytes are wrong."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise Locked('wrong global password or a tampered backup') from exc


def generate_ssh_key(comment='hoisty'):
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
        return load_yaml(text)
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

class _NoAliasLoader(yaml.SafeLoader):
    """An alias tree a few hundred bytes long expands to gigabytes when the merged
    vars are copied into JSON for ansible, so user YAML may not use them."""
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError('YAML aliases (*name) are not allowed')
        return super().compose_node(parent, index)


def load_yaml(text):
    return yaml.load(text, Loader=_NoAliasLoader)


def vars_import(store, scope, scope_id, path, actor=None):
    doc = load_yaml(Path(path).read_text())
    if not isinstance(doc, dict):
        raise ValueError('vars file must be a YAML mapping of name -> value')
    for name, value in doc.items():
        store.set(scope, scope_id, str(name), value, actor)
    return sorted(doc)


def vars_export_text(store, scope, scope_id):
    return yaml.safe_dump(store.vars_for(scope, scope_id), default_flow_style=False,
                          sort_keys=True)


# --- users ----------------------------------------------------------------

def _pw(password, salt):
    out = hashlib.scrypt(password.encode(), salt=salt, **PW_SCRYPT)
    return out[:32], out[32:]


def check_password_strength(password):
    if len(password or '') < MIN_PASSWORD:
        raise ValueError(f'password must be at least {MIN_PASSWORD} characters')


def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    return _pw(password, salt)[0], salt


def check_password(password, pw_hash, salt):
    """The TOTP wrapping key on success, None otherwise."""
    verifier, wrap = _pw(password, salt)
    return wrap if hmac.compare_digest(verifier, pw_hash) else None


TOTP_WRAPPED = 'v1:'


def wrap_totp(secret, wrap_key):
    """The seed lives in the plaintext database, so it is sealed under a key only
    the user's password yields: a stolen deploy.db is not a second factor."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    box = AESGCM(bytes(wrap_key)).encrypt(nonce, secret.encode(), b'totp')
    return TOTP_WRAPPED + base64.b64encode(nonce + box).decode()


def unwrap_totp(stored, wrap_key):
    """None when there is no seed or the key does not fit. A bare (unwrapped) seed
    from before sealing is returned as is; the login re-wraps it."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not stored:
        return None
    if not stored.startswith(TOTP_WRAPPED):
        return stored
    raw = base64.b64decode(stored[len(TOTP_WRAPPED):])
    try:
        return AESGCM(bytes(wrap_key)).decrypt(raw[:12], raw[12:], b'totp').decode()
    except InvalidTag:
        return None


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


def totp_uri(secret, username, issuer='hoisty'):
    from urllib.parse import quote
    return (f'otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}'
            f'&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_STEP}')


# --- deploy.db reads shared by bot, web, scheduler and the CLI ----------------

def projects(name=None):
    with deploy_conn() as conn:
        sql, args = 'SELECT * FROM project', ()
        if name:
            sql, args = sql + ' WHERE name=?', (name,)
        return [dict(r) for r in conn.execute(sql + ' ORDER BY name', args)]


def environments():
    with deploy_conn() as conn:
        return [dict(r) for r in conn.execute(
            'SELECT e.*, p.name AS project_name FROM environment e '
            'JOIN project p ON p.id=e.project_id ORDER BY p.name, e.name')]


# --- hosts: a project's targets, written out as inventory and known_hosts -----

# fullmatch, never match: `$` also matches before a trailing newline, and a name
# ending in one would split the generated inventory or known_hosts line in two.
HOST_NAME = re.compile(r'[A-Za-z0-9._-]+')
HOST_ADDRESS = re.compile(r'[A-Za-z0-9._:-]+')            # hostname, IPv4 or IPv6
HOST_GROUP = re.compile(r'[A-Za-z0-9_]+')
HOST_KEY_TYPES = ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                  'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521')


def check_host(name, address=None, groups=None, ssh_host_key=None, ssh_user=None):
    """(name, address, groups, key, user), each a strict token: every one becomes
    part of a generated inventory or known_hosts line."""
    if not HOST_NAME.fullmatch(name or ''):
        raise ValueError('host name may only contain letters, digits, . _ -')
    address = (address or '').strip() or None
    if address and not HOST_ADDRESS.fullmatch(address):
        raise ValueError('address must be a hostname or IP')
    user = (ssh_user or '').strip() or None
    if user and not HOST_NAME.fullmatch(user):
        raise ValueError('login user may only contain letters, digits, . _ -')
    # all three reach ssh as an argument, where a leading dash is an option
    for field, value in (('name', name), ('address', address), ('user', user)):
        if value and value.startswith('-'):
            raise ValueError(f'host {field} may not start with "-": {value}')
    names = [g for g in (groups or '').replace(' ', '').split(',') if g]
    if any(not HOST_GROUP.fullmatch(g) for g in names):
        raise ValueError('groups: comma-separated names of letters, digits, _')
    key = ' '.join((ssh_host_key or '').split()[:2]) or None     # drop any comment
    if key:
        kind, _, blob = key.partition(' ')
        try:
            valid = kind in HOST_KEY_TYPES and bool(base64.b64decode(blob, validate=True))
        except (binascii.Error, ValueError):
            valid = False
        if not valid:
            raise ValueError('ssh host key must be "<type> <base64>" as ssh-keyscan prints it')
    return name, address, ','.join(names) or None, key, user


def fingerprint(ssh_host_key):
    """SHA256:... as ssh-keygen -lf prints it, for checking against the console."""
    blob = base64.b64decode(ssh_host_key.split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def hosts(project_id):
    with deploy_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            'SELECT * FROM host WHERE project_id=? ORDER BY name', (project_id,))]
    for row in rows:
        row['fingerprint'] = fingerprint(row['ssh_host_key']) if row['ssh_host_key'] else None
    return rows


def host_set(project_id, name, address=None, groups=None, ssh_host_key=None,
             ssh_user=None):
    """A key of None keeps whatever is pinned: the web form's key box is always
    empty, so overwriting would silently unpin the host on any other edit. Remove
    a pin by deleting the host and adding it again."""
    name, address, groups, key, user = check_host(name, address, groups,
                                                  ssh_host_key, ssh_user)
    with deploy_conn() as conn:
        conn.execute(
            'INSERT INTO host (project_id, name, address, groups, ssh_host_key, '
            'ssh_user) VALUES (?,?,?,?,?,?) ON CONFLICT(project_id, name) DO UPDATE SET '
            'address=excluded.address, groups=excluded.groups, '
            'ssh_host_key=coalesce(excluded.ssh_host_key, host.ssh_host_key), '
            "ssh_user=excluded.ssh_user, updated_at=datetime('now')",
            (project_id, name, address, groups, key, user))
        if key is None:
            key = conn.execute('SELECT ssh_host_key FROM host WHERE project_id=? AND '
                               'name=?', (project_id, name)).fetchone()[0]
    return name, key


def host_delete(project_id, name):
    with deploy_conn() as conn:
        return conn.execute('DELETE FROM host WHERE project_id=? AND name=?',
                            (project_id, name)).rowcount


# --- audit ----------------------------------------------------------------

def audit(actor, action, detail=None):
    """Never record secret values here - names and ids only. Also written to the
    process log: the audit table lives in deploy.db, which whoever owns the uid
    can edit, so a collector off the box is the copy that counts."""
    # one line per event, whatever a username contains, so a log cannot be forged
    logging.getLogger('audit').info('%s %s %s', *(re.sub(r'\s+', ' ', str(v))
                                                  for v in (actor, action, detail or '')))
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
    salt = os.urandom(16)
    write_kdf(salt)
    with deploy_conn() as conn:
        migrate(conn, 'deploy')
    DEPLOY_DB.chmod(0o600)
    key = derive_key(passphrase, salt)
    conn = _open_secrets(key, create=True)
    migrate(conn, 'secrets')
    conn.close()
    SECRETS_DB.chmod(0o600)
    return SecretStore(key)


def rekey(old_passphrase, new_passphrase):
    """Never PRAGMA rekey: it rewrites every page and is not crash-atomic.

    Build the new file beside the old, then swap. kdf.json carries both salts
    until the swap is done, so a crash anywhere leaves a store one of the two
    passphrases still opens (see open_store)."""
    if len(new_passphrase) < MIN_PASSPHRASE:
        raise ValueError(f'global password must be at least {MIN_PASSPHRASE} characters')
    old_key, conn, old_cfg = open_store(old_passphrase)
    new_salt = os.urandom(16)
    new_key = derive_key(new_passphrase, new_salt)
    tmp = SECRETS_DB.with_suffix('.rekey')
    tmp.unlink(missing_ok=True)
    try:
        write_kdf(new_salt, previous=old_cfg)
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
    finally:
        wipe(old_key)
        wipe(new_key)
    write_kdf(new_salt)  # also upgrades an old store to today's KDF params
