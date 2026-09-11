"""CherryPy UI. Login -> 2FA -> global password. 10min soft lock, 2h hard logout."""
import ipaddress
import json
import logging
import os
import secrets as pysecrets
import threading
import time
from pathlib import Path

import cherrypy
import yaml
from cherrypy.lib import static
from jinja2 import Environment, FileSystemLoader, select_autoescape

import db
import runner
import scheduler
from db import Locked, SecretStore, audit, deploy_conn

logger = logging.getLogger(__name__)

# tunable for ops and tests; defaults are the 2h hard / 10min soft the design calls for
HARD_SECONDS = int(os.environ.get('HOISTY_HARD_SECONDS', 2 * 3600))
SOFT_SECONDS = int(os.environ.get('HOISTY_SOFT_SECONDS', 10 * 60))
MAX_FAILURES = 5
LOCKOUT = 300
MAX_LOCKOUT = 3600
MAX_BODY = 1024 * 1024
# a login that finds no such user still runs scrypt, so the reply takes as long
_NO_USER = {'pw_hash': bytes(32), 'pw_salt': bytes(16)}

HERE = Path(__file__).resolve().parent
env = Environment(loader=FileSystemLoader(str(HERE / 'templates')),
                  autoescape=select_autoescape(['html']))

# Module-level, not per-session or per-IP: a per-session counter is bypassed by
# dropping the cookie, and everyone arrives over an SSH forward as 127.0.0.1.
# One counter per factor: 'login' (password), 'totp' (code), 'unlock' (global).
_failures = {}


def _locked(name):
    """Seconds left on this factor's lockout, 0 when open."""
    return max(0, int(_failures.get(name, {}).get('until', 0) - time.time()))


def _failed(name):
    """Each lockout doubles, up to an hour, until something succeeds: a six-digit
    code brute-forced at five guesses per five minutes lands within a year."""
    f = _failures.setdefault(name, {'count': 0, 'until': 0.0, 'rounds': 0})
    f['count'] += 1
    if f['count'] >= MAX_FAILURES:
        f['rounds'] += 1
        hold = min(LOCKOUT * 2 ** (f['rounds'] - 1), MAX_LOCKOUT)
        f.update(count=0, until=time.time() + hold)
        logger.warning('%s locked out for %ss after %s failures (round %s)',
                       name, hold, MAX_FAILURES, f['rounds'])


def _passed(name):
    _failures.pop(name, None)

PUBLIC = ('/login',)
PRE_2FA = ('/login', '/totp', '/totp_setup', '/logout')
PRE_UNLOCK = PRE_2FA + ('/unlock', '/relock')


# Unlocked stores live here, keyed by session id, never inside the session: a
# SecretStore owns a bytearray it wipes on close, a session value would be an
# immutable str nothing can scrub.
_stores = {}
_stores_lock = threading.Lock()


def _store_for(sid):
    with _stores_lock:
        return _stores.get(sid)


def _drop(sid):
    with _stores_lock:
        st = _stores.pop(sid, None)
    if st:
        st.close()


def _sweep():
    """A session that timed out without a last request leaves its store behind."""
    live = cherrypy.lib.sessions.RamSession.cache
    for sid in list(_stores):
        if sid not in live:
            _drop(sid)


def _end_session():
    _drop(cherrypy.session.id)
    cherrypy.session.clear()
    cherrypy.lib.sessions.expire()


def render(template, **ctx):
    s = cherrypy.session
    cherrypy.request.csp_nonce = nonce = pysecrets.token_urlsafe(16)
    return env.get_template(template).render(
        username=s.get('username'), is_admin=s.get('is_admin'),
        unlocked=_store_for(s.id) is not None, csrf=s.get('csrf'), nonce=nonce,
        soft_seconds=SOFT_SECONDS, **ctx)


def store():
    st = _store_for(cherrypy.session.id)
    if st is None:
        raise cherrypy.HTTPRedirect('/unlock')
    return st


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


def _scope(scope, scope_id):
    """Validated (scope, int scope_id) from request params."""
    if scope not in db.SCOPES:
        raise cherrypy.HTTPError(400, f'unknown scope {scope!r}')
    try:
        return scope, int(scope_id or 0)
    except ValueError:
        raise cherrypy.HTTPError(400, 'scope_id must be a number')


def _deploy_key(project_id):
    """The ssh key this project would actually deploy with, and where it comes
    from. Never the private half: cred_resolve selects the row whole."""
    cred = store().cred_resolve('ssh_key', int(project_id))
    if not cred:
        return None
    own = cred['scope'] == 'project' and cred['scope_id'] == int(project_id)
    public = cred['public'] or ''
    return {'name': cred['name'], 'public': public, 'own': own,
            'scope': cred['scope'], 'updated_at': cred['updated_at'],
            'updated_by': cred['updated_by'],
            'fingerprint': db.fingerprint(public) if public.count(' ') >= 1 else None}


def require_admin():
    if not cherrypy.session.get('is_admin'):
        raise cherrypy.HTTPError(403, 'admin only')


# --- request guard --------------------------------------------------------

def guard():
    path = cherrypy.request.path_info.rstrip('/') or '/'
    s = cherrypy.session

    if cherrypy.request.method == 'POST':
        # A browser sends the literal "null" rather than an origin whenever the
        # referrer policy is no-referrer (Fetch, "append a request Origin
        # header"), and for sandboxed documents. It carries no information about
        # who sent this, so it cannot be compared; the CSRF token below and
        # SameSite=Strict are what actually stand between us and another site.
        # Rejecting it made every real browser unable to log in at all.
        origin = cherrypy.request.headers.get('Origin')
        if origin and origin != 'null':
            if origin.split('//')[-1] != cherrypy.request.headers.get('Host'):
                raise cherrypy.HTTPError(403, 'cross-origin POST rejected')
        if path not in PUBLIC:
            sent = cherrypy.request.params.get('csrf')
            if not sent or not pysecrets.compare_digest(str(sent), s.get('csrf') or ''):
                raise cherrypy.HTTPError(403, 'invalid CSRF token')

    if path in PUBLIC:
        return
    _sweep()

    started = s.get('login_at')
    if started and time.time() - started > HARD_SECONDS:
        _end_session()
        raise cherrypy.HTTPRedirect('/login?expired=1')

    if s.get('pending_user') and not s.get('user_id'):
        if path not in PRE_2FA:
            raise cherrypy.HTTPRedirect('/totp')
        return
    if not s.get('user_id'):
        raise cherrypy.HTTPRedirect('/login')
    # re-read the row so disable, delete and demote bite mid-session
    user = _rows('SELECT disabled, is_admin FROM user WHERE id=?', (s['user_id'],))
    if not user or user[0]['disabled']:
        _end_session()
        raise cherrypy.HTTPRedirect('/login')
    s['is_admin'] = bool(user[0]['is_admin'])

    last_seen = s.get('last_seen', 0)
    if time.time() - last_seen > SOFT_SECONDS:
        if path not in ('/relock', '/logout'):
            raise cherrypy.HTTPRedirect('/relock')
    elif path != '/relock':
        s['last_seen'] = time.time()

    if path not in PRE_UNLOCK and _store_for(s.id) is None:
        raise cherrypy.HTTPRedirect('/unlock')


def harden():
    cookie = cherrypy.response.cookie.get('session_id')
    if cookie is not None:
        cookie['samesite'] = 'Strict'  # CherryPy 18 has no samesite option itself
    # pages carry secrets and 2FA seeds: keep them out of browser caches and frames.
    # Scripts and styles run only with this response's nonce, so markup that slips
    # past autoescaping cannot execute or exfiltrate.
    nonce = getattr(cherrypy.request, 'csp_nonce', None)
    src = f"'nonce-{nonce}'" if nonce else "'none'"
    cherrypy.response.headers.update({
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        # same-origin, not no-referrer: the latter makes a browser send
        # "Origin: null" on every POST, which the guard cannot check against
        # anything. Nothing here links out and no URL carries a secret, so this
        # gives up nothing.
        'Referrer-Policy': 'same-origin',
        'Content-Security-Policy': (
            f"default-src 'none'; script-src {src}; style-src {src}; img-src 'self'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'none'")})
    if cherrypy.request.scheme == 'https':
        cherrypy.response.headers['Strict-Transport-Security'] = 'max-age=63072000'


cherrypy.tools.guard = cherrypy.Tool('before_handler', guard, priority=60)
cherrypy.tools.harden = cherrypy.Tool('before_finalize', harden)


class Root:

    # --- auth -------------------------------------------------------------
    @cherrypy.expose
    def login(self, username=None, password=None, expired=None):
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='login', expired=expired, error=None)
        if _locked('login'):
            return render('auth.html', stage='login', expired=None,
                          error=f"Too many failed attempts, retry in {_locked('login')}s")
        rows = _rows('SELECT * FROM user WHERE username=? AND disabled=0', (username,))
        user = rows[0] if rows else _NO_USER
        wrap = db.check_password(password or '', user['pw_hash'], user['pw_salt'])
        if not rows or not wrap:
            _failed('login')
            audit(username, 'login-failed')
            return render('auth.html', stage='login', expired=None,
                          error='Invalid credentials')
        _passed('login')
        totp_secret = db.unwrap_totp(user['totp_secret'], wrap)
        if user['totp_secret'] and not user['totp_secret'].startswith(db.TOTP_WRAPPED):
            _write('UPDATE user SET totp_secret=? WHERE id=?',
                   (db.wrap_totp(totp_secret, wrap), user['id']))
        _drop(cherrypy.session.id)
        cherrypy.session.regenerate()
        # the wrap key and the unwrapped seed exist only here, in RAM, for this session
        cherrypy.session.update({
            'pending_user': user['id'], 'username': user['username'],
            'is_admin': bool(user['is_admin']), 'login_at': time.time(),
            'csrf': pysecrets.token_urlsafe(32), 'wrap': wrap,
            'totp_secret': totp_secret if user['totp_confirmed'] else None})
        raise cherrypy.HTTPRedirect('/totp_setup' if not user['totp_confirmed']
                                    else '/totp')

    @cherrypy.expose
    def totp_setup(self, code=None, csrf=None):
        """First login: every user must register 2FA before going further."""
        user_id = cherrypy.session.get('pending_user') or cherrypy.session.get('user_id')
        user = _row('SELECT * FROM user WHERE id=?', (user_id,))
        if user['totp_confirmed']:
            raise cherrypy.HTTPRedirect('/totp')
        if 'wrap' not in cherrypy.session:
            # 2FA was reset mid-session; only a fresh login holds the key to seal a seed
            raise cherrypy.HTTPRedirect('/logout')
        secret = cherrypy.session.get('totp_pending')
        if not secret:
            secret = db.new_totp_secret()
            cherrypy.session['totp_pending'] = secret
        if cherrypy.request.method == 'POST':
            if db.totp_verify(secret, code):
                _write('UPDATE user SET totp_secret=?, totp_confirmed=1 WHERE id=?',
                       (db.wrap_totp(secret, cherrypy.session['wrap']), user_id))
                cherrypy.session.pop('totp_pending', None)
                cherrypy.session['totp_secret'] = secret
                audit(user['username'], '2fa-registered')
                return self._complete_login(user_id)
            return self._totp_setup_page(secret, user,
                                         'That code did not match, try the next one')
        return self._totp_setup_page(secret, user, None)

    def _totp_setup_page(self, secret, user, error):
        uri = db.totp_uri(secret, user['username'])
        return render('auth.html', stage='totp_setup', expired=None, error=error,
                      secret=secret, uri=uri)

    @cherrypy.expose
    def totp(self, code=None, csrf=None):
        user_id = cherrypy.session.get('pending_user')
        if not user_id:
            raise cherrypy.HTTPRedirect('/')
        user = _row('SELECT * FROM user WHERE id=?', (user_id,))
        if not user['totp_confirmed']:
            raise cherrypy.HTTPRedirect('/totp_setup')
        if cherrypy.request.method == 'POST':
            ok, error = self._check_totp(user, code)
            if ok:
                return self._complete_login(user_id)
            return render('auth.html', stage='totp', expired=None, error=error)
        return render('auth.html', stage='totp', expired=None, error=None)

    def _check_totp(self, user, code, detail=None):
        """(ok, error). One shared lockout for every TOTP prompt."""
        if _locked('totp'):
            return False, f"Too many failed attempts, retry in {_locked('totp')}s"
        if db.totp_verify(cherrypy.session.get('totp_secret'), code):
            _passed('totp')
            return True, None
        _failed('totp')
        audit(user['username'], '2fa-failed', detail)
        return False, 'Incorrect code'

    def _complete_login(self, user_id):
        cherrypy.session.pop('pending_user', None)
        cherrypy.session.pop('wrap', None)
        cherrypy.session.update({'user_id': user_id, 'last_seen': time.time()})
        audit(cherrypy.session.get('username'), 'login')
        raise cherrypy.HTTPRedirect('/unlock')

    @cherrypy.expose
    def unlock(self, passphrase=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='unlock', expired=None, error=None)
        if _locked('unlock'):
            return render('auth.html', stage='unlock', expired=None,
                          error=f"Too many failed attempts, retry in {_locked('unlock')}s")
        try:
            unlocked = SecretStore.unlock(passphrase or '')
        except Exception as exc:
            if not isinstance(exc, Locked):
                logger.exception('unlock failed unexpectedly')
            _failed('unlock')
            audit(actor(), 'unlock-failed')
            return render('auth.html', stage='unlock', expired=None,
                          error='Incorrect global password')
        _passed('unlock')
        _drop(cherrypy.session.id)
        with _stores_lock:
            _stores[cherrypy.session.id] = unlocked
        audit(actor(), 'unlock')
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def relock(self, code=None, ajax=None, csrf=None):
        """Soft lock: 10 minutes idle, reopened with a 2FA code only."""
        if cherrypy.request.method != 'POST':
            return render('auth.html', stage='relock', expired=None, error=None)
        user = _row('SELECT * FROM user WHERE id=?', (cherrypy.session['user_id'],))
        ok, error = self._check_totp(user, code, 'soft unlock')
        if ok:
            cherrypy.session['last_seen'] = time.time()
        if ajax:
            cherrypy.response.headers['Content-Type'] = 'application/json'
            return json.dumps({'ok': ok, 'error': error}).encode()
        if not ok:
            return render('auth.html', stage='relock', expired=None, error=error)
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def logout(self):
        audit(actor(), 'logout')
        _end_session()
        raise cherrypy.HTTPRedirect('/login')

    # --- dashboard --------------------------------------------------------
    @cherrypy.expose
    def index(self):
        return render('index.html',
                      projects=db.projects(),
                      environments=db.environments(),
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
                          if id else None, hosts=db.hosts(id) if id else [],
                          deploy_key=_deploy_key(id) if id else None)
        require_admin()
        if not delete:
            try:
                working_dir = runner.check_working_dir(working_dir)
                git_remote = runner.check_remote(git_remote)
            except ValueError as exc:
                raise cherrypy.HTTPError(400, str(exc))
        if delete:
            _write('DELETE FROM project WHERE id=?', (id,))
            store().orphan_sweep()
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

    # --- hosts ------------------------------------------------------------
    @cherrypy.expose
    def host(self, project_id=None, name=None, address=None, groups=None,
             ssh_host_key=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        project = _row('SELECT id FROM project WHERE id=?', (project_id,))
        if delete:
            if not db.host_delete(project['id'], name):
                raise cherrypy.HTTPError(404, f'no such host: {name}')
            audit(actor(), 'host-delete', f"project={project['id']} name={name}")
        else:
            try:
                name, key = db.host_set(project['id'], name, address, groups, ssh_host_key)
            except ValueError as exc:
                raise cherrypy.HTTPError(400, str(exc))
            audit(actor(), 'host-set', f"project={project['id']} name={name} "
                                       f"pinned={bool(key)}")
        raise cherrypy.HTTPRedirect(f"/project?id={project['id']}")

    # --- environments -----------------------------------------------------
    @cherrypy.expose
    def environment(self, id=None, project_id=None, name=None, inventory=None,
                    playbook=None, tags=None, skip_tags=None, limit_hosts=None,
                    become=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('environment.html',
                          env=_row('SELECT * FROM environment WHERE id=?', (id,))
                          if id else None,
                          projects=db.projects())
        require_admin()
        if delete:
            _write('DELETE FROM environment WHERE id=?', (id,))
            store().orphan_sweep()
            audit(actor(), 'environment-delete', f'id={id}')
            raise cherrypy.HTTPRedirect('/')
        for field, value in (('inventory', inventory), ('playbook', playbook),
                             ('tags', tags), ('skip_tags', skip_tags),
                             ('limit_hosts', limit_hosts)):
            if value and value.startswith('-'):
                raise cherrypy.HTTPError(400, f'{field} may not start with "-"')
        args = (project_id, name, inventory or None, playbook, tags or None,
                skip_tags or None, limit_hosts or None, 1 if become else 0)
        if id:
            _write('UPDATE environment SET project_id=?, name=?, inventory=?, '
                   'playbook=?, tags=?, skip_tags=?, limit_hosts=?, become=? '
                   'WHERE id=?', args + (id,))
            audit(actor(), 'environment-update', f'id={id}')
        else:
            new_id = _write('INSERT INTO environment (project_id, name, inventory, '
                            'playbook, tags, skip_tags, limit_hosts, become) '
                            'VALUES (?,?,?,?,?,?,?,?)', args)
            audit(actor(), 'environment-create', f'id={new_id}')
        raise cherrypy.HTTPRedirect('/')

    # --- deploys ----------------------------------------------------------
    @cherrypy.expose
    def deploy(self, environment_id=None, tags=None, skip_tags=None, csrf=None):
        """tags/skip_tags left blank mean the environment's own; runner validates
        both, so a hand-made POST cannot get anything else onto the argv."""
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        env_row = _row('SELECT e.*, p.name AS project_name FROM environment e '
                       'JOIN project p ON p.id=e.project_id WHERE e.id=?',
                       (environment_id,))
        project = _row('SELECT * FROM project WHERE id=?', (env_row['project_id'],))
        chosen = {'tags': tags, 'skip_tags': skip_tags}
        try:
            runner.playbook_argv(project, runner.with_tags(env_row, **chosen),
                                 inventory_path='validate-only')
        except ValueError as exc:
            raise cherrypy.HTTPError(400, str(exc))
        st, who = store().clone(), actor()
        runner.spawn(_then_close, st,
                     lambda: runner.deploy(project, env_row, st, who, **chosen))
        audit(actor(), 'deploy-start',
              f"env={environment_id} tags={tags or '-'} skip={skip_tags or '-'}")
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def sync(self, project_id=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        project = _row('SELECT * FROM project WHERE id=?', (project_id,))
        st, who = store().clone(), actor()
        runner.spawn(_then_close, st, lambda: runner.git_sync(project, st, who))
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def credentials(self, scope='global', scope_id=0, kind='ssh_key', name=None,
                    secret=None, generate=None, delete=None, back=None, csrf=None):
        """back= returns to that project's page, for the deploy key shown there.
        It is an id, not a URL, so it can only ever point back into this app."""
        scope, scope_id = _scope(scope, scope_id)
        st = store()
        if cherrypy.request.method == 'POST':
            require_admin()
            if delete:
                st.cred_delete(scope, scope_id, kind)
                audit(actor(), 'cred-delete', f'{scope}/{scope_id}/{kind}')
            elif generate:
                private, public = db.generate_ssh_key(name or 'hoisty')
                st.cred_set(scope, scope_id, 'ssh_key', name or 'hoisty',
                            private, public, actor())
                audit(actor(), 'cred-generate', f'{scope}/{scope_id}/ssh_key')
            else:
                st.cred_set(scope, scope_id, kind, name, secret, None, actor())
                audit(actor(), 'cred-set', f'{scope}/{scope_id}/{kind}')
            if back:
                raise cherrypy.HTTPRedirect(f'/project?id={int(back)}')
            raise cherrypy.HTTPRedirect('/credentials')
        return render('credentials.html', creds=st.cred_list(),
                      projects=db.projects(),
                      environments=db.environments())

    @cherrypy.expose
    def job(self, id):
        return render('job.html', job=_row('SELECT * FROM job WHERE id=?', (id,)))

    # --- secrets ----------------------------------------------------------
    @cherrypy.expose
    def secrets(self, scope='global', scope_id=0, name=None, value=None, note=None,
                vartype='string', note_only=None, delete=None, reveal=None,
                export=None, csrf=None):
        scope, scope_id = _scope(scope, scope_id)
        st = store()
        error = shown = exported = None
        if cherrypy.request.method == 'POST' and reveal:
            require_admin()
            shown = yaml.safe_dump(st.get(scope, scope_id, name))
            audit(actor(), 'secret-reveal', f'{scope}/{scope_id}/{name}')
        elif cherrypy.request.method == 'POST' and export:
            # the same plaintext /vars_export downloads, on screen instead, for
            # a scope small enough to copy by hand
            require_admin()
            exported = db.vars_export_text(st, scope, scope_id)
            audit(actor(), 'vars-export-inline', f'{scope}/{scope_id}')
        elif cherrypy.request.method == 'POST':
            require_admin()
            if delete:
                st.delete(scope, scope_id, name)
                audit(actor(), 'secret-delete', f'{scope}/{scope_id}/{name}')
            elif note_only:
                st.set_note(scope, scope_id, name, note)
                audit(actor(), 'secret-note', f'{scope}/{scope_id}/{name}')
            else:
                try:
                    typed = db.coerce_value(value, vartype)
                except ValueError as exc:
                    error = f'{name}: {exc}'
                if error is None:
                    st.set(scope, scope_id, name, typed, actor(), note)
                    audit(actor(), 'secret-set',
                          f'{scope}/{scope_id}/{name} type={vartype}')
            if error is None:
                raise cherrypy.HTTPRedirect(
                    f'/secrets?scope={scope}&scope_id={scope_id}')
        return render('secrets.html', scope=scope, scope_id=scope_id,
                      secrets=st.names(scope, scope_id),
                      revealed=name if shown else None, shown=shown, error=error,
                      exported=exported,
                      var_types=db.VAR_TYPES,
                      projects=db.projects(),
                      environments=db.environments())

    @cherrypy.expose
    def vars_import(self, scope=None, scope_id=None, varsfile=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        scope, scope_id = _scope(scope, scope_id)
        try:
            doc = db.load_yaml(varsfile.file.read().decode())
        except (yaml.YAMLError, UnicodeDecodeError, AttributeError) as exc:
            raise cherrypy.HTTPError(400, f'not a vars file: {exc}')
        if not isinstance(doc, dict):
            raise cherrypy.HTTPError(400, 'vars file must be a YAML mapping')
        st = store()
        for key, val in doc.items():
            st.set(scope, scope_id, str(key), val, actor())
        audit(actor(), 'vars-import', f'{scope}/{scope_id} names={sorted(doc)}')
        raise cherrypy.HTTPRedirect(f'/secrets?scope={scope}&scope_id={scope_id}')

    @cherrypy.expose
    def vars_export(self, scope=None, scope_id=None, csrf=None):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        scope, scope_id = _scope(scope, scope_id)
        body = db.vars_export_text(store(), scope, scope_id)
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
        if password:
            try:
                db.check_password_strength(password)
            except ValueError as exc:
                raise cherrypy.HTTPError(400, str(exc))
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
                # the seed is sealed under the old password, so it goes with it
                pw_hash, salt = db.hash_password(password)
                _write('UPDATE user SET pw_hash=?, pw_salt=?, totp_secret=NULL, '
                       'totp_confirmed=0 WHERE id=?', (pw_hash, salt, id))
                audit(actor(), 'password-reset', f'id={id}')
        else:
            if not username or not password:
                raise cherrypy.HTTPError(400, 'username and password are required')
            pw_hash, salt = db.hash_password(password)
            _write('INSERT INTO user (username, pw_hash, pw_salt, slack_user_id, '
                   'is_admin) VALUES (?,?,?,?,?)',
                   (username, pw_hash, salt, slack_user_id or None,
                    1 if is_admin else 0))
        audit(actor(), 'user-change', f'id={id} username={username}')
        raise cherrypy.HTTPRedirect('/users')

    # --- backups ----------------------------------------------------------
    @cherrypy.expose
    def backup(self, csrf=None):
        """A fresh zip for an off-box copy or a local run; restore with manage.py."""
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)
        require_admin()
        path, _ = scheduler.backup(store(), day=time.strftime('%Y-%m-%d-%H%M%S'))
        audit(actor(), 'backup-download', path.name)
        return static.serve_file(str(path), 'application/zip', 'attachment',
                                 f'hoisty-{path.name}')

    # --- schedules --------------------------------------------------------
    @cherrypy.expose
    def schedules(self, id=None, kind=None, target_id=None, at_time=None,
                  weekdays='*', enabled=None, delete=None, csrf=None):
        if cherrypy.request.method != 'POST':
            return render('schedules.html',
                          schedules=_rows('SELECT * FROM schedule ORDER BY at_time'),
                          projects=db.projects())
        require_admin()
        if not delete:
            if kind not in scheduler.KINDS:
                raise cherrypy.HTTPError(400, f'unknown schedule kind {kind!r}')
            try:
                scheduler.validate(at_time or '', weekdays or '*')
            except ValueError as exc:
                raise cherrypy.HTTPError(400, str(exc))
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


def _then_close(st, fn):
    """Worker thread body: the session's store clone is closed however fn ends."""
    try:
        fn()
    finally:
        st.close()


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == 'localhost'


def app(host='127.0.0.1', port=8080, tls=None):
    """Configure and mount; run() starts it, tests start the engine themselves.

    tls=(certfile, keyfile) serves HTTPS. Without it only a loopback bind is
    allowed: passwords, codes and the global password would otherwise cross the
    network in the clear. Reach a loopback bind over an SSH forward or a VPN."""
    if not tls and not _loopback(host):
        raise ValueError(f'refusing to serve plain HTTP on {host}: pass --tls-cert '
                         'and --tls-key, or bind to 127.0.0.1 and use an SSH forward')
    cherrypy.config.update({
        'environment': 'production',    # no tracebacks in responses, no autoreload,
        'server.socket_host': host,     # no access log on stdout
        'server.socket_port': port,
        'server.max_request_body_size': MAX_BODY,
        'tools.sessions.on': True,      # RamSession default; never FileSession
        'tools.sessions.timeout': HARD_SECONDS // 60,
        'tools.sessions.persistent': False,   # session cookie, nothing on disk
        'tools.sessions.secure': bool(tls),
        'tools.sessions.httponly': True,
        'tools.guard.on': True,
        'tools.harden.on': True,
    })
    if tls:
        cherrypy.config.update({'server.ssl_module': 'builtin',
                                'server.ssl_certificate': tls[0],
                                'server.ssl_private_key': tls[1]})
    return cherrypy.tree.mount(Root(), '/', {
        '/static': {'tools.staticdir.on': True,
                    'tools.staticdir.dir': str(HERE / 'static'),
                    'tools.guard.on': False,
                    'tools.harden.on': False,
                    'tools.sessions.on': False}})


def run(host='127.0.0.1', port=8080, tls=None):
    """No global password at startup: the key only ever lives in a user session,
    which is also why the scheduler runs in the bot and not here."""
    runner.reap_running()
    app(host, port, tls)
    cherrypy.engine.signals.subscribe()
    cherrypy.engine.start()
    cherrypy.engine.block()
