#!/usr/bin/env python3
"""Encryption at rest, key derivation, rekey, and refusing to clobber a store."""
import sys

import harness
from harness import BAD, GOOD

import db

STORE = None


def encryption_at_rest():
    global STORE
    STORE = harness.new_store()
    STORE.set('environment', 99, 'pg_password', 'hunter2-in-the-clear')
    raw = db.SECRETS_DB.read_bytes()
    assert b'hunter2' not in raw, 'the value must not be readable on disk'
    assert b'pg_password' not in raw, 'not even the name should be readable'


def wrong_password_is_refused():
    try:
        db.SecretStore.unlock(BAD)
        raise AssertionError('the wrong global password must not open the store')
    except db.Locked:
        pass
    reopened = db.SecretStore.unlock(GOOD)
    assert reopened.get('environment', 99, 'pg_password') == 'hunter2-in-the-clear'
    reopened.close()


def cipher_settings_are_maxed():
    conn = db._open_secrets(db.key_from_passphrase(GOOD))
    try:
        assert conn.execute('PRAGMA cipher_memory_security').fetchone()[0] == '1', \
            'SQLCipher 4 defaults this off; it is what mlocks and wipes key material'
        assert conn.execute('PRAGMA cipher_hmac_algorithm').fetchone()[0] == 'HMAC_SHA512'
        assert conn.execute('PRAGMA cipher_kdf_algorithm').fetchone()[0] == \
            'PBKDF2_HMAC_SHA512'
        assert conn.execute('PRAGMA cipher_plaintext_header_size').fetchone()[0] == '0'
    finally:
        conn.close()
    _, params = db.read_kdf()
    assert params['n'] == 2 ** 18 and params['dklen'] == 32, params
    assert params['maxmem'] >= 128 * params['r'] * params['n'], 'maxmem too low'


def stored_kdf_params_win():
    """Raising the module constant must never lock anyone out of an old store."""
    salt, _ = db.read_kdf()
    weak = dict(db.KEY_SCRYPT, n=2 ** 14, maxmem=64 * 1024 * 1024)
    db.write_kdf(salt, weak)
    try:
        assert db.read_kdf()[1]['n'] == 2 ** 14
        from_store = db.derive_key(GOOD, salt, weak)
        assert bytes(from_store) == bytes(db.key_from_passphrase(GOOD)), \
            'derivation must use the params on disk, not the current constant'
        assert bytes(from_store) != bytes(db.derive_key(GOOD, salt)), \
            'different params must produce a different key'
    finally:
        db.write_kdf(salt)


def init_never_overwrites():
    salt_before = db.KDF_FILE.read_bytes()
    try:
        db.init('a completely different passphrase')
        raise AssertionError('init must refuse when a store already exists')
    except FileExistsError as exc:
        assert 'secrets.db' in str(exc), exc
    assert db.KDF_FILE.read_bytes() == salt_before, 'init must not rewrite the salt'
    assert STORE.get('environment', 99, 'pg_password') == 'hunter2-in-the-clear'
    assert db.initialised(), 'initialised() should list the existing paths'


def rekey_swaps_the_password():
    STORE.set(db.GLOBAL_SCOPE, 0, 'slack_bot_token', 'xoxb-must-survive')
    STORE.close()
    new = 'a different long passphrase'
    db.rekey(GOOD, new)
    try:
        db.SecretStore.unlock(GOOD)
        raise AssertionError('the old global password must stop working')
    except db.Locked:
        pass
    rekeyed = db.SecretStore.unlock(new)
    assert rekeyed.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-survive'
    rekeyed.close()


def short_passwords_are_refused():
    for bad in ('short', 'x' * (db.MIN_PASSPHRASE - 1)):
        try:
            db.rekey('a different long passphrase', bad)
            raise AssertionError(f'{bad!r} is under the {db.MIN_PASSPHRASE} char floor')
        except ValueError:
            pass


if __name__ == '__main__':
    sys.exit(harness.run(
        encryption_at_rest, wrong_password_is_refused, cipher_settings_are_maxed,
        stored_kdf_params_win, init_never_overwrites, rekey_swaps_the_password,
        short_passwords_are_refused))
