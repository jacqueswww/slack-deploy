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


def totp_uri_and_qr():
    secret = db.new_totp_secret()
    uri = db.totp_uri(secret, 'jacques@example')
    assert uri.startswith('otpauth://totp/slack-deploy:'), uri
    assert f'secret={secret}' in uri and 'digits=6' in uri and 'period=30' in uri
    assert '@' not in uri.split('?')[0].split(':')[-1], 'the label must be url encoded'
    svg = db.totp_qr_svg(uri)
    assert svg.startswith('<svg') and svg.endswith('</svg>'), svg[:60]
    assert '<?xml' not in svg, 'the declaration must be stripped so it can be inlined'
    assert secret not in svg, 'the secret is encoded in the paths, not written out'


def passwords_hash_and_verify():
    pw_hash, salt = db.hash_password('correct horse battery')
    assert len(salt) == 16 and len(pw_hash) == 32
    assert db.check_password('correct horse battery', pw_hash, salt)
    assert not db.check_password('correct horse batter', pw_hash, salt)
    assert not db.check_password('', pw_hash, salt)
    again, other_salt = db.hash_password('correct horse battery')
    assert other_salt != salt and again != pw_hash, 'each hash must be freshly salted'


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
        totp_rejects_rubbish, totp_uri_and_qr, passwords_hash_and_verify,
        password_params_are_separate_from_the_key, the_first_admin_has_no_2fa_yet))
