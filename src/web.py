"""CherryPy UI. Login -> 2FA -> global password. 5min soft lock, 2h hard logout."""
import json
import logging
import os
import secrets as pysecrets
import time
from pathlib import Path

import cherrypy
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

import db
import runner
import scheduler
from db import Locked, SecretStore, audit, deploy_conn

logger = logging.getLogger(__name__)

# tunable for ops and tests; defaults are the 2h hard / 5min soft the design calls for
HARD_SECONDS = int(os.environ.get('SLACK_DEPLOY_HARD_SECONDS', 2 * 3600))
SOFT_SECONDS = int(os.environ.get('SLACK_DEPLOY_SOFT_SECONDS', 5 * 60))
UNLOCK_MAX_FAILURES = 5
UNLOCK_LOCKOUT = 300

HERE = Path(__file__).resolve().parent
env = Environment(loader=FileSystemLoader(str(HERE / 'templates')),
                  autoescape=select_autoescape(['html']))

# Module-level, not per-session or per-IP: a per-session counter is bypassed by
# dropping the cookie, and everyone arrives over an SSH forward as 127.0.0.1.
_failures = {'count': 0, 'until': 0.0}

PUBLIC = ('/login',)
PRE_2FA = ('/login', '/totp', '/totp_setup', '/logout')
PRE_UNLOCK = PRE_2FA + ('/unlock', '/relock')


def render(template, **ctx):
    s = cherrypy.session
    return env.get_template(template).render(
        username=s.get('username'), is_admin=s.get('is_admin'),
        unlocked=bool(s.get('key_hex')), csrf=s.get('csrf'),
        soft_seconds=SOFT_SECONDS, **ctx)


def store():
    key_hex = cherrypy.session.get('key_hex')
    if not key_hex:
        raise cherrypy.HTTPRedirect('/unlock')
    return SecretStore.from_key_hex(key_hex)


def actor():
    return cherrypy.session.get('username') or 'anonymous'


def _rows(sql, args=()):
    with deploy_conn() as conn:
        return [dict(r) for r in conn.execute(sql, args)]


def _row(sql, args=()):
    rows = _rows(sql, args)
    if not rows:
        raise cherrypy.HTTPError(404)
    return rows[0]


def _write(sql, args=()):
    with deploy_conn() as conn:
        return conn.execute(sql, args).lastrowid


def require_admin():
    if not cherrypy.session.get('is_admin'):
        raise cherrypy.HTTPError(403, 'admin only')


# --- request guard --------------------------------------------------------

def guard():
    path = cherrypy.request.path_info.rstrip('/') or '/'
    s = cherrypy.session

    if cherrypy.request.method == 'POST':
        origin = cherrypy.request.headers.get('Origin')
        if origin and origin.split('//')[-1] != cherrypy.request.headers.get('Host'):
            raise cherrypy.HTTPError(403, 'cross-origin POST rejected')
        if path not in PUBLIC:
            sent = cherrypy.request.params.get('csrf')
            if not sent or not pysecrets.compare_digest(str(sent), s.get('csrf') or ''):
                raise cherrypy.HTTPError(403, 'invalid CSRF token')

    if path in PUBLIC:
        return

    started = s.get('login_at')
    if started and time.time() - started > HARD_SECONDS:
        s.clear()
        cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/login?expired=1')

    if s.get('pending_user') and not s.get('user_id'):
        if path not in PRE_2FA:
            raise cherrypy.HTTPRedirect('/totp')
        return
    if not s.get('user_id'):
        raise cherrypy.HTTPRedirect('/login')

    last_seen = s.get('last_seen', 0)
    if time.time() - last_seen > SOFT_SECONDS:
        if path not in ('/relock', '/logout'):
            raise cherrypy.HTTPRedirect('/relock')
    elif path != '/relock':
        s['last_seen'] = time.time()

    if not s.get('key_hex') and path not in PRE_UNLOCK:
        raise cherrypy.HTTPRedirect('/unlock')


def harden_cookie():
    cookie = cherrypy.response.cookie.get('session_id')
    if cookie is not None:
        cookie['samesite'] = 'Strict'  # CherryPy 18 has no samesite option itself


cherrypy.tools.guard = cherrypy.Tool('before_handler', guard, priority=60)
cherrypy.tools.harden_cookie = cherrypy.Tool('before_finalize', harden_cookie)


class Root:

    # --- auth -------------------------------------------------------------
    @cherrypy.expose
    def login(self, username=None, password=None, expired=None):
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='login', expired=expired, error=None)
        rows = _rows('SELECT * FROM user WHERE username=? AND disabled=0', (username,))
        if not rows or not db.check_password(password, rows[0]['pw_hash'],
                                             rows[0]['pw_salt']):
            audit(username, 'login-failed')
            return render('auth.html', stage='login', expired=None,
                          error='Invalid credentials')
        user = rows[0]
        cherrypy.session.regenerate()
        cherrypy.session.update({
            'pending_user': user['id'], 'username': user['username'],
            'is_admin': bool(user['is_admin']), 'login_at': time.time(),
            'csrf': pysecrets.token_urlsafe(32)})
        raise cherrypy.HTTPRedirect('/totp_setup' if not user['totp_confirmed']
                                    else '/totp')

    @cherrypy.expose
    def totp_setup(self, code=None, csrf=None):
        """First login: every user must register 2FA before going further."""
        user_id = cherrypy.session.get('pending_user') or cherrypy.session.get('user_id')
        user = _row('SELECT * FROM user WHERE id=?', (user_id,))
        if user['totp_confirmed']:
            raise cherrypy.HTTPRedirect('/totp')
        secret = cherrypy.session.get('totp_pending')
        if not secret:
            secret = db.new_totp_secret()
            cherrypy.session['totp_pending'] = secret
        if cherrypy.request.method == 'POST':
            if db.totp_verify(secret, code):
                _write('UPDATE user SET totp_secret=?, totp_confirmed=1 WHERE id=?',
                       (secret, user_id))
                cherrypy.session.pop('totp_pending', None)
                audit(user['username'], '2fa-registered')
                return self._complete_login(user_id)
            return self._totp_setup_page(secret, user,
                                         'That code did not match, try the next one')
        return self._totp_setup_page(secret, user, None)

    def _totp_setup_page(self, secret, user, error):
        uri = db.totp_uri(secret, user['username'])
        return render('auth.html', stage='totp_setup', expired=None, error=error,
                      secret=secret, uri=uri, qr=db.totp_qr_svg(uri))

    @cherrypy.expose
    def totp(self, code=None, csrf=None):
        user_id = cherrypy.session.get('pending_user')
        if not user_id:
            raise cherrypy.HTTPRedirect('/')
        user = _row('SELECT * FROM user WHERE id=?', (user_id,))
        if not user['totp_confirmed']:
            raise cherrypy.HTTPRedirect('/totp_setup')
        if cherrypy.request.method == 'POST':
            if db.totp_verify(user['totp_secret'], code):
                return self._complete_login(user_id)
            audit(user['username'], '2fa-failed')
            return render('auth.html', stage='totp', expired=None,
                          error='Incorrect code')
        return render('auth.html', stage='totp', expired=None, error=None)

    def _complete_login(self, user_id):
        cherrypy.session.pop('pending_user', None)
        cherrypy.session.update({'user_id': user_id, 'last_seen': time.time()})
        audit(cherrypy.session.get('username'), 'login')
        raise cherrypy.HTTPRedirect('/unlock')

    @cherrypy.expose
    def unlock(self, passphrase=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='unlock', expired=None, error=None)
        if time.time() < _failures['until']:
            wait = int(_failures['until'] - time.time())
            return render('auth.html', stage='unlock', expired=None,
                          error=f'Too many failed attempts, retry in {wait}s')
        try:
            unlocked = SecretStore.unlock(passphrase or '')
        except Exception as exc:
            if not isinstance(exc, Locked):
                logger.exception('unlock failed unexpectedly')
            _failures['count'] += 1
            if _failures['count'] >= UNLOCK_MAX_FAILURES:
                _failures.update(count=0, until=time.time() + UNLOCK_LOCKOUT)
            audit(actor(), 'unlock-failed')
            return render('auth.html', stage='unlock', expired=None,
                          error='Incorrect global password')
        _failures['count'] = 0
        # keep the file-specific derived key, never the shared human passphrase
        cherrypy.session['key_hex'] = unlocked.key_hex
        unlocked.close()
        audit(actor(), 'unlock')
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def relock(self, code=None, ajax=None, csrf=None):
        """Soft lock: 5 minutes idle, reopened with a 2FA code only."""
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='relock', expired=None, error=None)
        user = _row('SELECT * FROM user WHERE id=?', (cherrypy.session['user_id'],))
        ok = db.totp_verify(user['totp_secret'], code)
        if ok:
            cherrypy.session['last_seen'] = time.time()
        else:
            audit(user['username'], '2fa-failed', 'soft unlock')
        if ajax:
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return json.dumps({'ok': ok}).encode()
        if not ok:
            return render('auth.html', stage='relock', expired=None,
                          error='Incorrect code')
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def logout(self):
        audit(actor(), 'logout')
        cherrypy.session.clear()
        cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/login')

    # --- dashboard --------------------------------------------------------
    @cherrypy.expose
    def index(self):
        return render('index.html',
                      projects=_rows('SELECT * FROM project ORDER BY name'),
                      environments=_rows(
                          'SELECT e.*, p.name AS project_name FROM environment e '
                          'JOIN project p ON p.id=e.project_id ORDER BY p.name, e.name'),
                      jobs=_rows('SELECT j.*, p.name AS project_name, e.name AS env_name '
                                 'FROM job j LEFT JOIN project p ON p.id=j.project_id '
                                 'LEFT JOIN environment e ON e.id=j.environment_id '
                                 'ORDER BY j.id DESC LIMIT 25'))

    # --- projects ---------------------------------------------------------
    @cherrypy.expose
    def project(self, id=None, name=None, working_dir=None, branch='master',
                git_remote=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('project.html',
                          project=_row('SELECT * FROM project WHERE id=?', (id,))
                          if id else None)
        require_admin()
        if delete:
            _write('DELETE FROM project WHERE id=?', (id,))
            st = store()
            st.orphan_sweep()
            st.close()
            audit(actor(), 'project-delete', f'id={id}')
        elif id:
            _write('UPDATE project SET name=?, working_dir=?, branch=?, git_remote=? '
                   'WHERE id=?', (name, working_dir, branch, git_remote or None, id))
            audit(actor(), 'project-update', f'id={id}')
        else:
            new_id = _write('INSERT INTO project (name, working_dir, branch, '
                            'git_remote) VALUES (?,?,?,?)',
                            (name, working_dir, branch, git_remote or None))
            audit(actor(), 'project-create', f'id={new_id}')
        raise cherrypy.HTTPRedirect('/')

    # --- environments -----------------------------------------------------
    @cherrypy.expose
    def environment(self, id=None, project_id=None, name=None, inventory=None,
                    playbook=None, tags=None, limit_hosts=None, become=None,
                    delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('environment.html',
                          env=_row('SELECT * FROM environment WHERE id=?', (id,))
                          if id else None,
                          projects=_rows('SELECT * FROM project ORDER BY name'))
        require_admin()
        if delete:
            _write('DELETE FROM environment WHERE id=?', (id,))
            st = store()
            st.orphan_sweep()
            st.close()
            audit(actor(), 'environment-delete', f'id={id}')
            raise cherrypy.HTTPRedirect('/')
        for field, value in (('inventory', inventory), ('playbook', playbook),
                             ('tags', tags), ('limit_hosts', limit_hosts)):
            if value and value.startswith('-'):
                raise cherrypy.HTTPError(400, f'{field} may not start with "-"')
        args = (project_id, name, inventory, playbook, tags or None,
                limit_hosts or None, 1 if become else 0)
        if id:
            _write('UPDATE environment SET project_id=?, name=?, inventory=?, '
                   'playbook=?, tags=?, limit_hosts=?, become=? WHERE id=?', args + (id,))
            audit(actor(), 'environment-update', f'id={id}')
        else:
            new_id = _write('INSERT INTO environment (project_id, name, inventory, '
                            'playbook, tags, limit_hosts, become) VALUES (?,?,?,?,?,?,?)',
                            args)
            audit(actor(), 'environment-create', f'id={new_id}')
        raise cherrypy.HTTPRedirect('/')

    # --- deploys ----------------------------------------------------------
    @cherrypy.expose
    def deploy(self, environment_id=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        env_row = _row('SELECT e.*, p.name AS project_name FROM environment e '
                       'JOIN project p ON p.id=e.project_id WHERE e.id=?',
                       (environment_id,))
        project = _row('SELECT * FROM project WHERE id=?', (env_row['project_id'],))
        runner.spawn(_deploy_and_close, project, env_row, store(), actor())
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def sync(self, project_id=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        project = _row('SELECT * FROM project WHERE id=?', (project_id,))
        runner.spawn(_sync_and_close, project, store(), actor())
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def credentials(self, scope='global', scope_id=0, kind='ssh_key', name=None,
                    secret=None, generate=None, delete=None, csrf=None):
        st = store()
        try:
            if cherrypy.request.method == 'POST':
                require_admin()
                scope_id = int(scope_id)
                if delete:
                    st.cred_delete(scope, scope_id, kind)
                    audit(actor(), 'cred-delete', f'{scope}/{scope_id}/{kind}')
                elif generate:
                    private, public = db.generate_ssh_key(name or 'slack-deploy')
                    st.cred_set(scope, scope_id, 'ssh_key', name or 'slack-deploy',
                                private, public, actor())
                    audit(actor(), 'cred-generate', f'{scope}/{scope_id}/ssh_key')
                else:
                    st.cred_set(scope, scope_id, kind, name, secret, None, actor())
                    audit(actor(), 'cred-set', f'{scope}/{scope_id}/{kind}')
                raise cherrypy.HTTPRedirect('/credentials')
            return render('credentials.html', creds=st.cred_list(),
                          projects=_rows('SELECT * FROM project ORDER BY name'),
                          environments=_rows(
                              'SELECT e.*, p.name AS project_name FROM environment e '
                              'JOIN project p ON p.id=e.project_id ORDER BY p.name'))
        finally:
            st.close()

    @cherrypy.expose
    def job(self, id):
        return render('job.html', job=_row('SELECT * FROM job WHERE id=?', (id,)))

    # --- secrets ----------------------------------------------------------
    @cherrypy.expose
    def secrets(self, scope='global', scope_id=0, name=None, value=None, note=None,
                vartype='string', note_only=None, delete=None, reveal=None, csrf=None):
        st = store()
        error = None
        try:
            if cherrypy.request.method == 'POST':
                require_admin()
                if delete:
                    st.delete(scope, int(scope_id), name)
                    audit(actor(), 'secret-delete', f'{scope}/{scope_id}/{name}')
                elif note_only:
                    st.set_note(scope, int(scope_id), name, note)
                    audit(actor(), 'secret-note', f'{scope}/{scope_id}/{name}')
                else:
                    try:
                        typed = db.coerce_value(value, vartype)
                    except ValueError as exc:
                        error = f'{name}: {exc}'
                    if error is None:
                        st.set(scope, int(scope_id), name, typed, actor(), note)
                        audit(actor(), 'secret-set',
                              f'{scope}/{scope_id}/{name} type={vartype}')
                if error is None:
                    raise cherrypy.HTTPRedirect(
                        f'/secrets?scope={scope}&scope_id={scope_id}')
            shown = None
            if reveal:
                shown = yaml.safe_dump(st.get(scope, int(scope_id), reveal))
                audit(actor(), 'secret-reveal', f'{scope}/{scope_id}/{reveal}')
            return render('secrets.html', scope=scope, scope_id=int(scope_id),
                          secrets=st.names(scope, int(scope_id)),
                          revealed=reveal, shown=shown, error=error,
                          var_types=db.VAR_TYPES,
                          projects=_rows('SELECT * FROM project ORDER BY name'),
                          environments=_rows(
                              'SELECT e.*, p.name AS project_name FROM environment e '
                              'JOIN project p ON p.id=e.project_id ORDER BY p.name'))
        finally:
            st.close()

    @cherrypy.expose
    def vars_import(self, scope=None, scope_id=None, varsfile=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        doc = yaml.safe_load(varsfile.file.read().decode())
        if not isinstance(doc, dict):
            raise cherrypy.HTTPError(400, 'vars file must be a YAML mapping')
        st = store()
        try:
            for key, val in doc.items():
                st.set(scope, int(scope_id), str(key), val, actor())
        finally:
            st.close()
        audit(actor(), 'vars-import', f'{scope}/{scope_id} names={sorted(doc)}')
        raise cherrypy.HTTPRedirect(f'/secrets?scope={scope}&scope_id={scope_id}')

    @cherrypy.expose
    def vars_export(self, scope=None, scope_id=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        st = store()
        try:
            body = db.vars_export_text(st, scope, int(scope_id))
        finally:
            st.close()
        audit(actor(), 'vars-export', f'{scope}/{scope_id}')
        cherrypy.response.headers.update({
            'Content-Type': 'application/x-yaml',
            'Cache-Control': 'no-store',
            'Content-Disposition': f'attachment; filename="{scope}-{scope_id}-vars.yml"'})
        return body.encode()

    # --- users ------------------------------------------------------------
    @cherrypy.expose
    def users(self, id=None, username=None, password=None, slack_user_id=None,
              is_admin=None, disabled=None, reset_2fa=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('users.html',
                          users=_rows('SELECT * FROM user ORDER BY username'))
        require_admin()
        if delete:
            _write('DELETE FROM user WHERE id=?', (id,))
        elif reset_2fa:
            _write('UPDATE user SET totp_secret=NULL, totp_confirmed=0 WHERE id=?', (id,))
            audit(actor(), '2fa-reset', f'id={id}')
        elif id:
            _write('UPDATE user SET slack_user_id=?, is_admin=?, disabled=? WHERE id=?',
                   (slack_user_id or None, 1 if is_admin else 0,
                    1 if disabled else 0, id))
            if password:
                pw_hash, salt = db.hash_password(password)
                _write('UPDATE user SET pw_hash=?, pw_salt=? WHERE id=?',
                       (pw_hash, salt, id))
        else:
            pw_hash, salt = db.hash_password(password)
            _write('INSERT INTO user (username, pw_hash, pw_salt, slack_user_id, '
                   'is_admin) VALUES (?,?,?,?,?)',
                   (username, pw_hash, salt, slack_user_id or None,
                    1 if is_admin else 0))
        audit(actor(), 'user-change', f'id={id} username={username}')
        raise cherrypy.HTTPRedirect('/users')

    # --- schedules --------------------------------------------------------
    @cherrypy.expose
    def schedules(self, id=None, kind=None, target_id=None, at_time=None,
                  weekdays='*', enabled=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('schedules.html',
                          schedules=_rows('SELECT * FROM schedule ORDER BY at_time'),
                          projects=_rows('SELECT * FROM project ORDER BY name'))
        require_admin()
        if delete:
            _write('DELETE FROM schedule WHERE id=?', (id,))
        elif id:
            _write('UPDATE schedule SET kind=?, target_id=?, at_time=?, weekdays=?, '
                   'enabled=? WHERE id=?',
                   (kind, target_id or None, at_time, weekdays, 1 if enabled else 0, id))
        else:
            _write('INSERT INTO schedule (kind, target_id, at_time, weekdays, enabled, '
                   'created_by) VALUES (?,?,?,?,?,?)',
                   (kind, target_id or None, at_time, weekdays,
                    1 if enabled else 0, actor()))
        audit(actor(), 'schedule-change', f'id={id} kind={kind}')
        raise cherrypy.HTTPRedirect('/schedules')


def _sync_and_close(project, st, who):
    try:
        runner.git_sync(project, st, who)
    finally:
        st.close()


def _deploy_and_close(project, env_row, st, who):
    try:
        runner.deploy(project, env_row, st, who)
    finally:
        st.close()


def run(host='127.0.0.1', port=8080):
    """No global password at startup: the key only ever lives in a user session."""
    cherrypy.config.update({
        'environment': 'production',    # no tracebacks in responses, no autoreload,
        'server.socket_host': host,     # no access log on stdout
        'server.socket_port': port,
        'tools.sessions.on': True,      # RamSession default; never FileSession
        'tools.sessions.timeout': HARD_SECONDS // 60,
        'tools.sessions.persistent': False,   # session cookie, nothing on disk
        'tools.sessions.secure': host != '127.0.0.1',
        'tools.sessions.httponly': True,
        'tools.guard.on': True,
        'tools.harden_cookie.on': True,
    })
    scheduler.start(None)
    cherrypy.quickstart(Root(), '/', {
        '/static': {'tools.staticdir.on': True,
                    'tools.staticdir.dir': str(HERE / 'static'),
                    'tools.guard.on': False,
                    'tools.sessions.on': False}})
