"""Single job runner shared by the Slack daemon, the web UI and the scheduler."""
import atexit
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from datetime import date, datetime
from pathlib import Path

import ansible_runner

from db import RUN_DIR, audit, deploy_conn

logger = logging.getLogger(__name__)

LOG_TAIL = 2000
_running = set()
_running_lock = threading.Lock()
_live_files = set()
_live_dirs = set()

VENV_BIN = str(Path(sys.executable).parent)   # do not resolve(): venv/bin/python is a symlink
ANSIBLE_PLAYBOOK = str(Path(VENV_BIN) / 'ansible-playbook')
GIT = '/usr/bin/git'
SAFE_TAGS = re.compile(r'^[A-Za-z0-9_,.:-]+$')
ASKPASS = Path(__file__).resolve().parent / 'git-askpass.sh'


def _cleanup_live_files(*_):
    for path in list(_live_files):
        try:
            os.unlink(path)
        except OSError:
            pass
    _live_files.clear()
    for path in list(_live_dirs):
        shutil.rmtree(path, ignore_errors=True)
    _live_dirs.clear()


atexit.register(_cleanup_live_files)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, lambda s, f: (_cleanup_live_files(), sys.exit(128 + s)))
    except ValueError:
        pass  # not the main thread


def redact(text, values):
    """Ansible prints task results verbatim; strip known secret values first."""
    for value in sorted((str(v) for v in values), key=len, reverse=True):
        if len(value) >= 4:
            text = text.replace(value, '***')
    return text


def _claim(keys):
    with _running_lock:
        if _running & keys:
            return False
        _running.update(keys)
        return True


def _release(keys):
    with _running_lock:
        _running.difference_update(keys)


def json_safe(value):
    """ansible-runner ships extravars as JSON, which has no date type."""
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def under(root, candidate):
    """Resolve candidate inside root, refusing anything that escapes it."""
    root = Path(root).resolve()
    path = (root / candidate).resolve()
    if root != path and root not in path.parents:
        raise ValueError(f'{candidate} escapes the project checkout')
    return str(path)


def runner_kwargs(project, env):
    """Structured ansible-runner arguments. Nothing stored becomes raw argv."""
    for field in ('inventory', 'playbook', 'limit_hosts'):
        value = env[field]
        if value and str(value).startswith('-'):
            raise ValueError(f'{field} may not start with "-": {value}')
    tags = env['tags']
    if tags and not SAFE_TAGS.match(tags):
        raise ValueError(f'tags may only contain letters, digits, _.:,- : {tags}')
    kwargs = {
        'project_dir': str(Path(project['working_dir']).resolve()),
        'playbook': under(project['working_dir'], env['playbook']),
        'inventory': under(project['working_dir'], env['inventory']),
        'limit': env['limit_hosts'] or None,
        'quiet': True,
        'rotate_artifacts': 0,
    }
    if tags:
        kwargs['cmdline'] = f'--tags {tags}'
    # ansible-runner spawns through sh, so the venv must be on PATH explicitly -
    # a systemd unit or cron job will not have it either
    envvars = {'PATH': VENV_BIN + os.pathsep + os.environ.get('PATH', '')}
    if env['become']:
        envvars['ANSIBLE_BECOME'] = 'True'
    kwargs['envvars'] = envvars
    return kwargs


def _start_job(kind, project_id, environment_id, actor):
    with deploy_conn() as conn:
        cur = conn.execute(
            'INSERT INTO job (kind, status, project_id, environment_id, triggered_by) '
            "VALUES (?, 'running', ?, ?, ?)", (kind, project_id, environment_id, actor))
        return cur.lastrowid


def _finish_job(job_id, status, exit_code, log):
    with deploy_conn() as conn:
        conn.execute("UPDATE job SET status=?, exit_code=?, finished_at=datetime('now'), "
                     'log=? WHERE id=?', (status, exit_code, log, job_id))


def write_secret_file(text, suffix=''):
    """0600 file in data/run/ (itself 0700), tracked so a signal still cleans it."""
    fd, path = tempfile.mkstemp(dir=str(RUN_DIR), suffix=suffix)
    _live_files.add(path)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
        if not text.endswith('\n'):
            fh.write('\n')      # ssh rejects a private key with no trailing newline
    return path


def drop_secret_file(path):
    _live_files.discard(path)
    try:
        os.unlink(path)
    except OSError:
        pass


def _run(argv, cwd, secret_values=(), env=None):
    ps = subprocess.run(argv, cwd=cwd, capture_output=True, env=env)
    out = (ps.stdout + ps.stderr).decode('utf-8', 'replace')
    return ps.returncode, redact(out, secret_values)


def _git_env(pat):
    """PAT reaches git through GIT_ASKPASS, so it never appears in argv."""
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'      # never hang a daemon on a prompt
    if pat:
        env['SLACK_DEPLOY_GIT_PAT'] = pat
        env['GIT_ASKPASS'] = str(ASKPASS)
    return env


def _authed_url(remote):
    """Put only the username in the URL; the PAT comes from GIT_ASKPASS."""
    if remote.startswith('https://') and '@' not in remote.split('//', 1)[1]:
        return remote.replace('https://', 'https://x-access-token@', 1)
    return remote


def deploy(project, env, store, actor, notify=None):
    """Run the playbook via ansible-runner, with the encrypted vars as extra-vars."""
    keys = {f"env:{env['id']}", f"dir:{project['working_dir']}"}
    if not _claim(keys):
        if notify:
            notify(f"Already running for {project['name']}/{env['name']}")
        return None
    job_id = _start_job('deploy', project['id'], env['id'], actor)
    extra = store.extra_vars(project['id'], env['id'])
    ssh = store.cred_resolve('ssh_key', project['id'], env['id'])
    secrets = list(extra.values()) + ([ssh['secret']] if ssh else [])
    # ansible-runner writes extravars and the ssh key under here at 0600; keep it
    # inside data/run/ (0700) and remove the lot afterwards
    workdir = tempfile.mkdtemp(dir=str(RUN_DIR))
    _live_dirs.add(workdir)
    key_path = None
    try:
        kwargs = runner_kwargs(project, env)
        if ssh:
            # deliberately not ansible-runner's ssh_key=: that wraps the run in an
            # ssh-agent which outlives it, leaving the decrypted key resident
            key_path = write_secret_file(ssh['secret'], '.key')
            kwargs['cmdline'] = ' '.join(
                filter(None, [kwargs.get('cmdline'), f'--private-key {key_path}']))
        result = ansible_runner.run(private_data_dir=workdir,
                                    extravars=json_safe(extra), **kwargs)
        code = result.rc
        out = redact(result.stdout.read() if result.stdout else '', secrets)
    except Exception as exc:
        _finish_job(job_id, 'error', None, redact(str(exc), secrets))
        if notify:
            notify(f"Deployment failed to start: {exc}")
        return job_id
    finally:
        if key_path:
            drop_secret_file(key_path)
        _live_dirs.discard(workdir)
        shutil.rmtree(workdir, ignore_errors=True)
        _release(keys)
    _finish_job(job_id, 'ok' if code == 0 else 'failed', code, out)
    audit(actor, 'deploy', f"{project['name']}/{env['name']} job={job_id} rc={code}")
    if notify:
        notify('Deployment done' if code == 0 else 'Deployment failed', out)
    return job_id


def git_sync(project, store=None, actor=None, notify=None):
    """Clone the ansible repo if it is not there yet, otherwise fast-forward it."""
    keys = {f"dir:{project['working_dir']}"}
    if not _claim(keys):
        if notify:
            notify(f"Busy, skipping refresh of {project['name']}")
        return None
    working_dir = Path(project['working_dir'])
    remote = project.get('git_remote')
    cred = store.cred_resolve('github_pat', project['id']) if store else None
    pat = cred['secret'] if cred else None
    branch = project['branch']
    try:
        if (working_dir / '.git').is_dir():
            argv = [GIT, 'pull', '--ff-only', 'origin', branch]
            cwd, kind = str(working_dir), 'git-pull'
        elif remote:
            argv = [GIT, 'clone', '--branch', branch, _authed_url(remote),
                    str(working_dir)]
            working_dir.parent.mkdir(parents=True, exist_ok=True)
            cwd, kind = str(working_dir.parent), 'git-clone'
        else:
            if notify:
                notify(f"{project['name']}: {working_dir} is not a checkout and the "
                       'project has no git remote set')
            return None
        job_id = _start_job(kind, project['id'], None, actor)
        if remote and remote.startswith('https://') and not pat:
            logger.warning('%s: https remote but no github_pat available',
                           project['name'])
        code, out = _run(argv, cwd, [pat] if pat else (), env=_git_env(pat))
    finally:
        _release(keys)
    _finish_job(job_id, 'ok' if code == 0 else 'failed', code, out)
    if notify:
        verb = f'{kind} done' if code == 0 else f'{kind} failed'
        notify(f"[{project['name']}] {verb}", out)
    return job_id


def spawn(fn, *args, **kwargs):
    thread = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    thread.start()
    return thread
