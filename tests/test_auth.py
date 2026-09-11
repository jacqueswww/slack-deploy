#!/usr/bin/env python3
"""TOTP two-factor and user password hashing."""
import sys
import time

import harness

import db


def totp_accepts_the_current_code():
    secret = db.new_totp_secret()
    now = time.time()
    assert len(secret) >= 32, secret
    assert db.totp_verify(secret, db.totp_at(secret, int(now // 30)), now)
    assert len(db.totp_at(secret, 0)) == db.TOTP_DIGITS


def totp_tolerates_clock_drift():
    secret = db.new_totp_secret()
    now = time.time()
    step = int(now // 30)
    for drift in (-1, 0, 1):
        assert db.totp_verify(secret, db.totp_at(secret, step + drift), now), drift
    for drift in (-2, 2, 5):
        assert not db.totp_verify(secret, db.totp_at(secret, step + drift), now), drift


def totp_rejects_rubbish():
    secret = db.new_totp_secret()
    now = time.time()
    for code in ('', None, 'abcdef', '12345', 'nope', '   '):
        assert not db.totp_verify(secret, code, now), code
    assert not db.totp_verify(None, '123456', now), 'no secret means no pass'
    assert not db.totp_verify('', '123456', now)


def totp_uri():
    secret = db.new_totp_secret()
    uri = db.totp_uri(secret, 'jacques@example')
    assert uri.startswith('otpauth://totp/slack-deploy:'), uri
    assert f'secret={secret}' in uri and 'digits=6' in uri and 'period=30' in uri
    assert '@' not in uri.split('?')[0].split(':')[-1], 'the label must be url encoded'


def passwords_hash_and_verify():
    pw_hash, salt = db.hash_password('correct horse battery')
    assert len(salt) == 16 and len(pw_hash) == 32
    wrap = db.check_password('correct horse battery', pw_hash, salt)
    assert wrap and len(wrap) == 32 and wrap != pw_hash, 'success yields the wrapping key'
    assert db.check_password('correct horse batter', pw_hash, salt) is None
    assert db.check_password('', pw_hash, salt) is None
    again, other_salt = db.hash_password('correct horse battery')
    assert other_salt != salt and again != pw_hash, 'each hash must be freshly salted'
    import hashlib
    legacy = hashlib.scrypt(b'correct horse battery', salt=salt,
                            **dict(db.PW_SCRYPT, dklen=32))
    assert legacy == pw_hash, 'hashes stored with dklen=32 must still verify'
    for weak in ('', 'short', 'x' * (db.MIN_PASSWORD - 1)):
        try:
            db.check_password_strength(weak)
            raise AssertionError(f'{weak!r} must be refused')
        except ValueError:
            pass
    db.check_password_strength('x' * db.MIN_PASSWORD)


def totp_seeds_are_sealed_under_the_password():
    """deploy.db is plaintext; a copy of it must not be a second factor."""
    secret = db.new_totp_secret()
    pw_hash, salt = db.hash_password('correct horse battery')
    wrap = db.check_password('correct horse battery', pw_hash, salt)
    stored = db.wrap_totp(secret, wrap)
    assert stored.startswith(db.TOTP_WRAPPED) and secret not in stored, stored
    assert db.unwrap_totp(stored, wrap) == secret
    assert db.unwrap_totp(stored, bytes(32)) is None, 'the wrong key yields nothing'
    assert db.unwrap_totp(None, wrap) is None
    assert db.unwrap_totp(secret, wrap) == secret, 'an unsealed seed passes through once'
    assert db.wrap_totp(secret, wrap) != stored, 'a fresh nonce every time'


def password_params_are_separate_from_the_key():
    """Raising KEY_SCRYPT must not invalidate every stored password hash."""
    assert db.PW_SCRYPT is not db.KEY_SCRYPT
    assert db.KEY_SCRYPT['n'] > db.PW_SCRYPT['n'], \
        'the database key is the one that gets maxed out'


def the_first_admin_has_no_2fa_yet():
    harness.new_store().close()
    pw_hash, salt = db.hash_password('adminpassword123')
    with db.deploy_conn() as conn:
        conn.execute('INSERT INTO user (username, pw_hash, pw_salt, is_admin) '
                     "VALUES ('jacques',?,?,1)", (pw_hash, salt))
        row = dict(conn.execute("SELECT * FROM user WHERE username='jacques'").fetchone())
    assert row['totp_confirmed'] == 0 and row['totp_secret'] is None, \
        'every account must register 2FA on first login'


if __name__ == '__main__':
    sys.exit(harness.run(
        totp_accepts_the_current_code, totp_tolerates_clock_drift,
        totp_rejects_rubbish, totp_uri, passwords_hash_and_verify,
        totp_seeds_are_sealed_under_the_password,
        password_params_are_separate_from_the_key, the_first_admin_has_no_2fa_yet))
