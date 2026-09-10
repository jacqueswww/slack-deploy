#!/usr/bin/env python3
"""Encryption at rest, key derivation, rekey, and refusing to clobber a store."""
import json
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


def the_crypto_library_gives_known_answers():
    """A swapped or backdoored libcrypto that still 'works' must not be trusted."""
    db.crypto_self_test()
    real = db._SCRYPT_KAT
    db._SCRYPT_KAT = real[:3] + ('00' * 64,)
    try:
        db.crypto_self_test()
        raise AssertionError('a wrong scrypt answer must refuse to start')
    except SystemExit:
        pass
    finally:
        db._SCRYPT_KAT = real
    real = db._GCM_KAT
    db._GCM_KAT = real[:3] + ('00' * 32,)
    try:
        db.crypto_self_test()
        raise AssertionError('a wrong AES-GCM answer must refuse to start')
    except SystemExit:
        pass
    finally:
        db._GCM_KAT = real


def the_key_is_locked_in_ram_and_the_passphrase_is_wipeable():
    """A bytearray passphrase derives the same key as the str, so the CLI can wipe
    it; the key page is mlocked so it never reaches swap."""
    weak = dict(db.KEY_SCRYPT, n=2 ** 10, maxmem=64 * 1024 * 1024)
    salt = bytes(16)
    typed = bytearray(GOOD.encode())
    assert db.derive_key(typed, salt, weak) == db.derive_key(GOOD, salt, weak)
    db.wipe(typed)
    assert not any(typed)
    assert STORE.locked_in_ram, 'mlock of the key page failed'
    lck = open('/proc/self/status').read().split('VmLck:')[1].split('\n')[0].strip()
    assert lck != '0 kB', lck
    twin = db.SecretStore.unlock(bytearray(GOOD.encode()))
    assert twin.get('environment', 99, 'pg_password') == 'hunter2-in-the-clear'
    twin.close()


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


def a_clone_has_its_own_key_and_wipes_it():
    """Worker threads get a clone, so closing it cannot pull the key from under a session."""
    store = db.SecretStore.unlock('a different long passphrase')
    twin = store.clone()
    assert twin._key == store._key and twin._key is not store._key
    assert twin.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-survive'
    twin.close()
    assert not any(twin._key), 'close must zero the key'
    assert store.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-survive', \
        'the original keeps working'
    store.close()
    assert not any(store._key)


def short_passwords_are_refused():
    for bad in ('short', 'x' * (db.MIN_PASSPHRASE - 1)):
        try:
            db.rekey('a different long passphrase', bad)
            raise AssertionError(f'{bad!r} is under the {db.MIN_PASSPHRASE} char floor')
        except ValueError:
            pass


def a_rekey_that_dies_before_the_swap_still_opens():
    """kdf.json must carry both salts until secrets.db has been replaced."""
    current, wanted = 'a different long passphrase', 'a third long passphrase!!'
    real = db.os.replace

    def power_cut(*a):
        raise OSError('power cut')
    db.os.replace = power_cut
    try:
        db.rekey(current, wanted)
        raise AssertionError('the simulated crash must propagate')
    except OSError:
        pass
    finally:
        db.os.replace = real
    assert 'previous' in json.loads(db.KDF_FILE.read_text()), 'both salts must be on disk'
    store = db.SecretStore.unlock(current)     # opens via the previous salt
    assert store.get(db.GLOBAL_SCOPE, 0, 'slack_bot_token') == 'xoxb-must-survive'
    store.close()
    db.rekey(current, wanted)                  # the rerun finishes the job
    assert 'previous' not in json.loads(db.KDF_FILE.read_text())
    db.SecretStore.unlock(wanted).close()


def a_rekey_that_dies_after_the_swap_still_opens():
    """Crash between replacing secrets.db and the final kdf.json write."""
    current, wanted = 'a third long passphrase!!', 'the fourth long passphrase'
    real = db.write_kdf

    def dies_on_final_write(salt, params=None, previous=None):
        if previous is None:
            raise OSError('power cut')
        real(salt, params, previous)
    db.write_kdf = dies_on_final_write
    try:
        db.rekey(current, wanted)
        raise AssertionError('the simulated crash must propagate')
    except OSError:
        pass
    finally:
        db.write_kdf = real
    assert 'previous' in json.loads(db.KDF_FILE.read_text())
    db.SecretStore.unlock(wanted).close()      # the new file, the new salt
    try:
        db.SecretStore.unlock(current)
        raise AssertionError('the old passphrase must not open the new file')
    except db.Locked:
        pass
    db.rekey(wanted, 'a fifth and final passphrase')
    assert 'previous' not in json.loads(db.KDF_FILE.read_text())
    db.SecretStore.unlock('a fifth and final passphrase').close()


if __name__ == '__main__':
    sys.exit(harness.run(
        encryption_at_rest, the_crypto_library_gives_known_answers,
        the_key_is_locked_in_ram_and_the_passphrase_is_wipeable,
        wrong_password_is_refused, cipher_settings_are_maxed,
        stored_kdf_params_win, init_never_overwrites, rekey_swaps_the_password,
        a_clone_has_its_own_key_and_wipes_it, short_passwords_are_refused,
        a_rekey_that_dies_before_the_swap_still_opens,
        a_rekey_that_dies_after_the_swap_still_opens))
