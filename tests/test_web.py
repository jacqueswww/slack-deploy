#!/usr/bin/env python3
"""The web login chain over real HTTP: password, 2FA, global password, CSRF,
throttling, and that disabling or promoting a user bites mid-session."""
import http.client
import re
import socket
import sys
import time
import urllib.parse

import cherrypy

import harness
from harness import GOOD, BAD

import db
import web

PASSWORD = 'correct horse battery'
CTX = {}


class Client:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def request(self, method, path, data=None, extra=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        headers = {'Cookie': self.cookie} if self.cookie else {}
        headers.update(extra or {})
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request(method, path, body, headers)
        r = conn.getresponse()
        text = r.read().decode('utf-8', 'replace')
        if r.getheader('Set-Cookie'):
            self.cookie = r.getheader('Set-Cookie').split(';', 1)[0]
        out = (r.status, r.getheader('Location') or '', text, dict(r.getheaders()))
        conn.close()
        return out

    def get(self, path):
        return self.request('GET', path)

    def post(self, path, **data):
        return self.request('POST', path, data)


def csrf_of(text):
    return re.search(r'name="csrf" value="([^"]+)"', text).group(1)


def code_now():
    return db.totp_at(CTX['secret'], int(time.time() // 30))


def _setup():
    harness.new_store().close()
    CTX['secret'] = db.new_totp_secret()
    pw_hash, salt = db.hash_password(PASSWORD)
    with db.deploy_conn() as conn:
        CTX['uid'] = conn.execute(
            'INSERT INTO user (username, pw_hash, pw_salt, totp_secret, totp_confirmed) '
            "VALUES ('alice',?,?,?,1)", (pw_hash, salt, CTX['secret'])).lastrowid
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    web.app('127.0.0.1', port)
    cherrypy.engine.start()
    CTX['c'] = Client(port)


def anonymous_is_sent_to_login():
    _setup()
    c = CTX['c']
    status, location, _, headers = c.get('/')
    assert status in (302, 303) and location.endswith('/login'), (status, location)
    assert headers.get('Cache-Control') == 'no-store', headers
    assert headers.get('X-Frame-Options') == 'DENY', headers
    assert headers.get('Referrer-Policy') == 'same-origin', headers
    assert "script-src 'none'" in headers.get('Content-Security-Policy', ''), headers
    status, _, text, headers = c.get('/login')
    nonce = re.search(r'<script nonce="([^"]+)">', text).group(1)
    csp = headers['Content-Security-Policy']
    assert f"script-src 'nonce-{nonce}'" in csp and f"style-src 'nonce-{nonce}'" in csp, csp
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp, csp
    assert 'onclick=' not in text and 'style="' not in text, 'inline handlers break the CSP'
    status, _, _, headers = c.get('/static/logo.png')
    assert status == 200 and 'Cache-Control' not in headers, 'static is public and cacheable'
    status, _, _, _ = c.get('/static/jquery.min.js')
    assert status == 404, 'no third-party script'


def a_real_browser_can_actually_log_in():
    """Regression: Referrer-Policy: no-referrer makes a browser send
    "Origin: null" on every POST (Fetch, "append a request Origin header"), and
    rejecting that 403'd the login form in every real browser. curl sends no
    Origin at all, which is why nothing here noticed."""
    c = CTX['c']
    status, _, _, headers = c.get('/login')
    assert headers.get('Referrer-Policy') == 'same-origin', headers.get('Referrer-Policy')
    status, location, _, _ = c.request(
        'POST', '/login', {'username': 'alice', 'password': PASSWORD},
        extra={'Origin': 'null'})
    assert status in (302, 303), f'a null origin must not be refused: {status}'
    status, _, text, _ = c.request(
        'POST', '/login', {'username': 'alice', 'password': PASSWORD},
        extra={'Origin': 'http://evil.example'})
    assert status == 403 and 'cross-origin' in text, 'a real other origin still goes'
    status, location, _, _ = c.request(
        'POST', '/login', {'username': 'alice', 'password': PASSWORD},
        extra={'Origin': f'http://127.0.0.1:{c.port}'})
    assert status in (302, 303), 'our own origin must pass'
    web._failures.clear()


def nothing_destructive_submits_without_asking():
    """A delete here is not recoverable: a secret value is gone unless a backup
    has it, and one credential per scope and kind means generating or pasting
    replaces the private key that was there."""
    import re
    from pathlib import Path
    templates = Path(__file__).resolve().parent.parent / 'src' / 'templates'
    unguarded = []
    for page in sorted(templates.glob('*.html')):
        for tag in re.findall(r'<button[^>]*>', page.read_text(), re.S):
            destructive = any(
                f'name="{name}"' in tag for name in ('delete', 'generate')
            )
            if destructive and 'data-confirm' not in tag:
                unguarded.append(f'{page.name}: {" ".join(tag.split())[:70]}')
    assert not unguarded, 'destructive buttons with no confirmation: ' + str(unguarded)
    # and the handler that reads the attribute is still wired up
    layout = (templates / 'layout.html').read_text()
    assert "data-confirm" in layout and 'closest' in layout, \
        'the delegated confirm handler must still be in the page'


def plain_http_off_loopback_is_refused():
    for host in ('0.0.0.0', '10.0.0.5', 'deploy.example'):
        try:
            web.app(host, 1)
            raise AssertionError(f'{host} without TLS must be refused')
        except ValueError:
            pass
    assert web._loopback('127.0.0.1') and web._loopback('::1') and web._loopback('localhost')


def unknown_users_cost_the_same_as_wrong_passwords():
    c = CTX['c']
    status, _, text, _ = c.post('/login', username='nobody', password='x')
    assert status == 200 and 'Invalid credentials' in text
    web._failures.clear()


def lockouts_escalate_until_a_success():
    now = time.time()
    for _ in range(web.MAX_FAILURES):
        web._failed('probe')
    first = web._failures['probe']['until'] - now
    for _ in range(web.MAX_FAILURES):
        web._failed('probe')
    second = web._failures['probe']['until'] - now
    assert web.LOCKOUT - 2 < first <= web.LOCKOUT + 1, first
    assert 2 * web.LOCKOUT - 2 < second <= 2 * web.LOCKOUT + 1, second
    for _ in range(web.MAX_FAILURES * 10):
        web._failed('probe')
    assert web._failures['probe']['until'] - now <= web.MAX_LOCKOUT + 1
    web._passed('probe')
    assert 'probe' not in web._failures


def wrong_passwords_are_throttled():
    c = CTX['c']
    for _ in range(web.MAX_FAILURES):
        status, _, text, _ = c.post('/login', username='alice', password='nope')
        assert status == 200 and 'Invalid credentials' in text
    status, _, text, _ = c.post('/login', username='alice', password=PASSWORD)
    assert 'Too many failed attempts' in text, 'the lockout must hold even for the right password'
    web._failures.clear()


def the_password_only_reaches_the_2fa_prompt():
    c = CTX['c']
    status, location, _, _ = c.post('/login', username='alice', password=PASSWORD)
    assert status in (302, 303) and location.endswith('/totp'), (status, location)
    status, location, _, _ = c.get('/secrets')
    assert location.endswith('/totp'), 'nothing past 2FA without a code'


def the_seed_is_sealed_on_first_login():
    """The row was created with a bare seed; a login re-wraps it under the password."""
    with db.deploy_conn() as conn:
        stored = conn.execute('SELECT totp_secret FROM user WHERE id=?',
                              (CTX['uid'],)).fetchone()[0]
    assert stored.startswith(db.TOTP_WRAPPED) and CTX['secret'] not in stored, stored
    with db.deploy_conn() as conn:
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    assert CTX['secret'].encode() not in db.DEPLOY_DB.read_bytes(), \
        'the seed must not be readable from a copy of deploy.db'


def posts_need_the_csrf_token():
    status, _, _, _ = CTX['c'].post('/totp', code=code_now())
    assert status == 403, status


def wrong_codes_are_throttled():
    c = CTX['c']
    csrf = csrf_of(c.get('/totp')[2])
    CTX['csrf'] = csrf
    for _ in range(web.MAX_FAILURES):
        status, _, text, _ = c.post('/totp', code='000000', csrf=csrf)
        assert status == 200 and 'Incorrect code' in text, text[-300:]
    status, _, text, _ = c.post('/totp', code=code_now(), csrf=csrf)
    assert 'Too many failed attempts' in text
    web._failures.clear()


def the_code_only_reaches_the_global_password():
    c = CTX['c']
    status, location, _, _ = c.post('/totp', code=code_now(), csrf=CTX['csrf'])
    assert status in (302, 303) and location.endswith('/unlock'), (status, location)
    status, location, _, _ = c.get('/secrets')
    assert location.endswith('/unlock'), 'no secrets without the global password'


def the_global_password_unlocks():
    c = CTX['c']
    status, _, text, _ = c.post('/unlock', passphrase=BAD, csrf=CTX['csrf'])
    assert 'Incorrect global password' in text
    status, location, _, _ = c.post('/unlock', passphrase=GOOD, csrf=CTX['csrf'])
    assert status in (302, 303) and location.endswith('/'), (status, location)
    status, _, text, _ = c.get('/')
    assert status == 200 and 'Environments' in text
    assert len(web._stores) == 1, 'the unlocked store lives server-side, once per session'
    CTX['store'] = next(iter(web._stores.values()))
    assert any(CTX['store']._key), 'the store holds the live key'


def only_admins_reveal():
    c = CTX['c']
    status, _, text, _ = c.get('/secrets?scope=global&scope_id=0')
    assert status == 200 and 'reveal' not in text, 'no reveal button for a plain user'
    status, _, _, _ = c.post('/secrets', scope='global', scope_id=0, name='probe',
                             reveal=1, csrf=CTX['csrf'])
    assert status == 403, status
    status, _, _, _ = c.post('/secrets', scope='global', scope_id=0, name='probe',
                             value='must-not-leak', csrf=CTX['csrf'])
    assert status == 403, 'a plain user cannot set variables either'


def promotion_bites_on_the_next_request():
    with db.deploy_conn() as conn:
        conn.execute('UPDATE user SET is_admin=1 WHERE id=?', (CTX['uid'],))
    c = CTX['c']
    status, _, _, _ = c.post('/secrets', scope='global', scope_id=0, name='probe',
                             value='must-not-leak', csrf=CTX['csrf'])
    assert status in (302, 303), status
    status, _, text, _ = c.post('/secrets', scope='global', scope_id=0, name='probe',
                                reveal=1, csrf=CTX['csrf'])
    assert status == 200 and 'must-not-leak' in text, 'an admin reveals by POST'
    status, _, text, _ = c.get('/secrets?scope=global&scope_id=0&reveal=probe')
    assert status == 200 and 'must-not-leak' not in text, 'never by GET'


def admins_can_download_a_backup():
    status, _, body, headers = CTX['c'].post('/backup', csrf=CTX['csrf'])
    assert status == 200 and headers.get('Content-Type') == 'application/zip', headers
    assert 'attachment' in headers.get('Content-Disposition', ''), headers
    assert body.startswith('PK'), 'a zip should come back'
    assert 'must-not-leak' not in body, 'the download must not carry a plaintext secret'
    assert 'SQLite format' not in body and 'alice' not in body, 'deploy.db must be sealed too'


def bad_input_is_a_400_not_a_500():
    c = CTX['c']
    assert c.get('/secrets?scope=bogus&scope_id=0')[0] == 400
    assert c.get('/secrets?scope=project&scope_id=abc')[0] == 400
    assert c.get('/secrets?scope=global&scope_id=')[0] == 200, 'empty means global'
    status, _, _, _ = c.post('/schedules', kind='backup', at_time='2:00', weekdays='*',
                             enabled=1, csrf=CTX['csrf'])
    assert status == 400, status
    status, _, _, _ = c.post('/users', username='bob', csrf=CTX['csrf'])
    assert status == 400, 'a user without a password must be refused'
    status, _, _, _ = c.post('/users', username='bob', password='short', csrf=CTX['csrf'])
    assert status == 400, 'a short password must be refused'
    status, _, _, _ = c.post('/schedules', kind='rm-rf', at_time='02:00', weekdays='*',
                             enabled=1, csrf=CTX['csrf'])
    assert status == 400, 'an unknown schedule kind must be refused'
    for field, value in (('working_dir', 'relative/path'), ('working_dir', str(db.DATA)),
                         ('git_remote', 'ext::sh -c id'), ('git_remote', '/tmp/repo')):
        form = {'name': 'p', 'working_dir': '/srv/checkout', 'branch': 'main',
                'git_remote': 'https://github.com/o/r.git', field: value}
        status, _, _, _ = c.post('/project', csrf=CTX['csrf'], **form)
        assert status == 400, (field, value, status)


def admins_maintain_a_projects_hosts():
    c = CTX['c']
    status, _, _, _ = c.post('/project', name='hosted', working_dir='/srv/hosted',
                             branch='main', git_remote='', csrf=CTX['csrf'])
    assert status in (302, 303), status
    with db.deploy_conn() as conn:
        pid = conn.execute("SELECT id FROM project WHERE name='hosted'").fetchone()[0]
    status, _, _, _ = c.post('/host', project_id=pid, name='web1', address='10.0.0.5',
                             groups='web', ssh_host_key='', csrf=CTX['csrf'])
    assert status in (302, 303), status
    status, _, _, _ = c.post('/host', project_id=pid, name='bad host', csrf=CTX['csrf'])
    assert status == 400, 'a name with a space would break the generated inventory'
    status, _, text, _ = c.get(f'/project?id={pid}')
    assert status == 200 and 'web1' in text and '10.0.0.5' in text and 'not pinned' in text
    status, _, _, _ = c.post('/host', project_id=pid, name='web1', delete=1, csrf=CTX['csrf'])
    assert status in (302, 303) and db.hosts(pid) == [], db.hosts(pid)
    status, _, _, _ = c.post('/host', project_id=pid, name='web1', delete=1, csrf=CTX['csrf'])
    assert status == 404, 'deleting nothing must not report success or audit a fake event'
    status, _, _, _ = c.post('/host', project_id=pid, delete=1, csrf=CTX['csrf'])
    assert status == 404, status


def a_password_reset_voids_the_sealed_seed():
    c = CTX['c']
    status, _, _, _ = c.post('/users', username='bob', password='bobs-long-password',
                             csrf=CTX['csrf'])
    assert status in (302, 303), status
    with db.deploy_conn() as conn:
        bob = conn.execute("SELECT id FROM user WHERE username='bob'").fetchone()[0]
        conn.execute("UPDATE user SET totp_secret='v1:whatever', totp_confirmed=1 "
                     'WHERE id=?', (bob,))
    status, _, _, _ = c.post('/users', id=bob, password='bobs-newer-password',
                             csrf=CTX['csrf'])
    assert status in (302, 303), status
    with db.deploy_conn() as conn:
        row = dict(conn.execute('SELECT * FROM user WHERE id=?', (bob,)).fetchone())
    assert row['totp_secret'] is None and row['totp_confirmed'] == 0, \
        'a seed sealed under the old password is unusable, so 2FA must re-register'


def relock_codes_are_throttled():
    c = CTX['c']
    for _ in range(web.MAX_FAILURES):
        status, _, text, _ = c.post('/relock', code='000000', ajax=1, csrf=CTX['csrf'])
        assert status == 200 and '"ok": false' in text, text
    status, _, text, _ = c.post('/relock', code=code_now(), ajax=1, csrf=CTX['csrf'])
    assert 'Too many failed attempts' in text, text
    web._failures.clear()
    status, _, text, _ = c.post('/relock', code=code_now(), ajax=1, csrf=CTX['csrf'])
    assert '"ok": true' in text, text


def disabling_cuts_the_session_off():
    c = CTX['c']
    with db.deploy_conn() as conn:
        conn.execute('UPDATE user SET disabled=1 WHERE id=?', (CTX['uid'],))
    status, location, _, _ = c.get('/')
    assert location.endswith('/login'), 'a disabled user must be thrown out at once'
    with db.deploy_conn() as conn:
        conn.execute('UPDATE user SET disabled=0 WHERE id=?', (CTX['uid'],))
    status, location, _, _ = c.get('/')
    assert location.endswith('/login'), 'the session itself must be gone'
    assert web._stores == {}, 'ending the session must drop its store'
    assert bytes(CTX['store']._key) == bytes(len(CTX['store']._key)), \
        'and the dropped store must have wiped its key'


def orphaned_stores_are_swept():
    """A session that dies without a last request must not leave a live key."""
    web._stores['no-such-session'] = orphan = db.SecretStore.unlock(GOOD)
    CTX['c'].get('/login')                 # public: no sweep
    assert 'no-such-session' in web._stores
    CTX['c'].get('/')                      # guarded: sweeps
    assert 'no-such-session' not in web._stores and not any(orphan._key)


if __name__ == '__main__':
    code = harness.run(
        anonymous_is_sent_to_login, a_real_browser_can_actually_log_in,
        nothing_destructive_submits_without_asking,
        plain_http_off_loopback_is_refused,
        unknown_users_cost_the_same_as_wrong_passwords, lockouts_escalate_until_a_success,
        wrong_passwords_are_throttled,
        the_password_only_reaches_the_2fa_prompt, the_seed_is_sealed_on_first_login,
        posts_need_the_csrf_token,
        wrong_codes_are_throttled, the_code_only_reaches_the_global_password,
        the_global_password_unlocks, only_admins_reveal,
        promotion_bites_on_the_next_request, admins_can_download_a_backup,
        bad_input_is_a_400_not_a_500, admins_maintain_a_projects_hosts,
        a_password_reset_voids_the_sealed_seed,
        relock_codes_are_throttled,
        disabling_cuts_the_session_off, orphaned_stores_are_swept)
    # the server thread is not a daemon: without this a failed check hangs the process
    cherrypy.engine.exit()
    sys.exit(code)
