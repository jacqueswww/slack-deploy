"""Single job runner shared by the Slack daemon, the web UI and the scheduler."""
import atexit
import contextlib
import json
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

from db import BACKUP_DIR, DATA, ROOT, RUN_DIR, audit, deploy_conn, hosts as project_hosts

logger = logging.getLogger(__name__)

LOG_TAIL = 2000
_running = set()
_running_lock = threading.Lock()
_live = set()      # secret files and dirs to remove however the process ends

VENV_BIN = str(Path(sys.executable).parent)   # do not resolve(): venv/bin/python is a symlink
ANSIBLE_PLAYBOOK = str(Path(VENV_BIN) / 'ansible-playbook')
GIT = '/usr/bin/git'
DEPLOY_TIMEOUT = 6 * 3600
# fullmatch everywhere: `$` also matches before a trailing newline
SAFE_TAGS = re.compile(r'[A-Za-z0-9_,.:-]+')
# https, ssh:// or scp-style only: no file paths, no ext::/fd:: helpers, no
# cleartext git://. GIT_ALLOW_PROTOCOL in _git_env is the second lock on that door.
SAFE_REMOTE = re.compile(r'(https://[A-Za-z0-9._-]+(:\d+)?/|ssh://[A-Za-z0-9._@-]+(:\d+)?/'
                         r'|[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:)[A-Za-z0-9._/~-]+')
GIT_TIMEOUT = 600
ASKPASS = Path(__file__).resolve().parent / 'git-askpass.sh'


def check_remote(url):
    if url and not SAFE_REMOTE.fullmatch(url):
        raise ValueError('clone URL must be https://host/path, ssh://user@host/path '
                         'or user@host:path')
    return url or None


def check_working_dir(path):
    """Absolute, and not this checkout or the data or backup dirs: a project pointed
    at them would git-pull the code that reads the passphrase, or be backed up."""
    path = Path(path or '')
    if not path.is_absolute():
        raise ValueError('checkout directory must be an absolute path')
    resolved = path.resolve()
    for forbidden in (ROOT, DATA, BACKUP_DIR):
        if resolved == forbidden or forbidden in resolved.parents:
            raise ValueError(f'checkout directory may not be inside {forbidden}')
    return str(resolved)


def _remove(path):
    _live.discard(path)
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _cleanup_live(*_):
    for path in list(_live):
        _remove(path)


atexit.register(_cleanup_live)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, lambda s, f: (_cleanup_live(), sys.exit(128 + s)))
    except ValueError:
        pass  # not the main thread


def _leaves(values):
    """Every scalar inside nested values, in plain and JSON-escaped spelling."""
    out, stack = set(), list(values)
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple, set)):
            stack.extend(v)
        elif v is not None and not isinstance(v, bool):
            text = str(v)
            out.update((text, json.dumps(text)[1:-1]))
    return out


def redact(text, values):
    """Ansible prints task results as JSON; strip known secret values first."""
    for value in sorted(_leaves(values), key=len, reverse=True):
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
    """Extra-vars travel as JSON, which has no date type."""
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


def with_tags(env, tags=None, skip_tags=None):
    """The environment, with this run's own tag choices laid over it.

    None means "whatever the environment stores"; the empty string means
    deliberately none, which is how a run drops a stored tag and plays the whole
    playbook. Nothing is validated here - playbook_argv is the one gate every
    path goes through, so an override cannot slip past it.
    """
    out = dict(env)          # always a dict: a sqlite3.Row has no .get()
    if tags is not None:
        out['tags'] = tags or None
    if skip_tags is not None:
        out['skip_tags'] = skip_tags or None
    return out


def playbook_argv(project, env, extravars_path=None, key_path=None, inventory_path=None):
    """ansible-playbook argv from the typed columns. Nothing stored is raw argv:
    every value is one positional or the operand of a fixed flag, and none may
    begin with a dash. inventory_path is the one generated from the project's
    hosts; the environment's own inventory file, if any, is passed as well."""
    for field in ('inventory', 'playbook', 'limit_hosts'):
        value = env[field]
        if value and str(value).startswith('-'):
            raise ValueError(f'{field} may not start with "-": {value}')
    tags = env['tags']
    skip_tags = env['skip_tags'] if 'skip_tags' in env.keys() else None
    for field, value in (('tags', tags), ('skip_tags', skip_tags)):
        if value and not SAFE_TAGS.fullmatch(value):
            raise ValueError(
                f'{field} may only contain letters, digits, _.:,- : {value}')
    if not env['inventory'] and not inventory_path:
        raise ValueError('no inventory: set one on the environment or add hosts to the project')
    argv = [ANSIBLE_PLAYBOOK, under(project['working_dir'], env['playbook'])]
    if env['inventory']:
        argv += ['-i', under(project['working_dir'], env['inventory'])]
    if inventory_path:
        argv += ['-i', inventory_path]
    if env['limit_hosts']:
        argv += ['--limit', env['limit_hosts']]
    if tags:
        argv += ['--tags', tags]
    if skip_tags:
        argv += ['--skip-tags', skip_tags]
    if extravars_path:
        argv += ['-e', '@' + extravars_path]     # a file, never the values themselves
    if key_path:
        argv += ['--private-key', key_path]
    return argv


def _ansible_env(env, known_hosts=None):
    out = os.environ.copy()
    # ansible-playbook finds ansible-connection on PATH; a unit or cron has no venv there
    out['PATH'] = VENV_BIN + os.pathsep + out.get('PATH', '')
    # a repo ansible.cfg may not turn host key checking off: an unknown host key
    # is how a man in the middle gets the deploy key used against them
    out['ANSIBLE_HOST_KEY_CHECKING'] = 'True'
    out['ANSIBLE_NOCOLOR'] = '1'
    # Always set, pinned or not: an environment variable beats the checkout's own
    # ansible.cfg, so a repo cannot hand itself StrictHostKeyChecking=no, and the
    # behaviour does not flip with unrelated pinning state. A repo that needs its
    # own ssh options must set them per host in the inventory, not here.
    files = ' '.join(filter(None, (known_hosts, '~/.ssh/known_hosts')))
    out['ANSIBLE_SSH_EXTRA_ARGS'] = (f"-o 'UserKnownHostsFile={files}' "
                                     '-o StrictHostKeyChecking=yes')
    if env['become']:
        out['ANSIBLE_BECOME'] = 'True'
    return out


def write_inventory(workdir, hosts):
    """INI inventory from validated host rows: a line per host, a section per group."""
    lines = [h['name'] + (f" ansible_host={h['address']}" if h['address'] else '')
             for h in hosts]
    groups = {}
    for h in hosts:
        for g in filter(None, (h['groups'] or '').split(',')):
            groups.setdefault(g, []).append(h['name'])
    for g, names in sorted(groups.items()):
        lines += [f'[{g}]', *names]
    path = os.path.join(workdir, 'inventory.ini')
    Path(path).write_text('\n'.join(lines) + '\n')
    return path


def write_known_hosts(workdir, hosts):
    """One line per pinned host key; None when nothing is pinned."""
    lines = [f"{h['address'] or h['name']} {h['ssh_host_key']}" for h in hosts
             if h['ssh_host_key']]
    if not lines:
        return None
    path = os.path.join(workdir, 'known_hosts')
    Path(path).write_text('\n'.join(lines) + '\n')
    return path


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


def reap_running():
    """Jobs a previous process left 'running' can never finish; call at startup."""
    # ponytail: no graceful drain on SIGTERM, an in-flight deploy is simply marked lost
    with deploy_conn() as conn:
        return conn.execute("UPDATE job SET status='lost', finished_at=datetime('now') "
                            "WHERE status='running'").rowcount


def write_extravars(workdir, extra):
    """-e '{json}' on the command line is readable by every local user in
    /proc/*/cmdline; a 0600 file passed as -e @file is not."""
    path = os.path.join(workdir, 'extravars.json')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as fh:
        json.dump(json_safe(extra), fh)
    return path


def write_secret_file(text, suffix=''):
    """0600 file in data/run/ (itself 0700), tracked so a signal still cleans it."""
    fd, path = tempfile.mkstemp(dir=str(RUN_DIR), suffix=suffix)
    _live.add(path)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
        if not text.endswith('\n'):
            fh.write('\n')      # ssh rejects a private key with no trailing newline
    return path


def _run(argv, cwd, secret_values=(), env=None, timeout=GIT_TIMEOUT):
    """Its own process group, so a timeout kills the whole tree. ansible forks a
    worker per host and each forks ssh; killing only the parent would leave them
    touching production after the caller has deleted their key file and released
    the claim that stops a second deploy starting."""
    ps = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env, start_new_session=True)
    try:
        out, _ = ps.communicate(timeout=timeout)
        code = ps.returncode
    except subprocess.TimeoutExpired:
        # start_new_session makes the child its own group leader, so the group id
        # is its pid: never look it up, that fails once the child itself has gone
        # and would leave the forks it started running unsupervised.
        with contextlib.suppress(OSError):
            os.killpg(ps.pid, signal.SIGKILL)
        out, _ = ps.communicate()
        code, out = 124, (out or b'') + f'\nkilled after {timeout}s'.encode()
    return code, redact(out.decode('utf-8', 'replace'), secret_values)


def _git_env(pat):
    """PAT reaches git through GIT_ASKPASS, so it never appears in argv."""
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'      # never hang a daemon on a prompt
    env['GIT_ALLOW_PROTOCOL'] = 'https:ssh'   # no ext::, fd::, file or git://
    if pat:
        env['HOISTY_GIT_PAT'] = pat
        env['GIT_ASKPASS'] = str(ASKPASS)
    return env


def _authed_url(remote):
    """Put only the username in the URL; the PAT comes from GIT_ASKPASS."""
    if remote.startswith('https://') and '@' not in remote.split('//', 1)[1]:
        return remote.replace('https://', 'https://x-access-token@', 1)
    return remote


def deploy(project, env, store, actor, notify=None, tags=None, skip_tags=None):
    """Run ansible-playbook with the encrypted vars as an extra-vars file.

    tags/skip_tags override what the environment stores, for this run only."""
    env = with_tags(env, tags, skip_tags)
    keys = {f"env:{env['id']}", f"dir:{project['working_dir']}"}
    if not _claim(keys):
        if notify:
            notify(f"Already running for {project['name']}/{env['name']}")
        return None
    job_id = key_path = workdir = None
    secrets = ()
    try:
        job_id = _start_job('deploy', project['id'], env['id'], actor)
        extra = store.extra_vars(project['id'], env['id'])
        ssh = store.cred_resolve('ssh_key', project['id'], env['id'])
        secrets = list(extra.values()) + ([ssh['secret']] if ssh else [])
        # the extravars file and the ssh key live under data/run/ (0700) at 0600
        # for the life of the run and are removed however it ends
        workdir = tempfile.mkdtemp(dir=str(RUN_DIR))
        _live.add(workdir)
        vars_path = write_extravars(workdir, extra)
        if ssh:
            # a file, never ssh-agent: an agent outlives the run holding the key
            key_path = write_secret_file(ssh['secret'], '.key')
        hosts = project_hosts(project['id'])
        inventory = write_inventory(workdir, hosts) if hosts else None
        known = write_known_hosts(workdir, hosts) if hosts else None
        argv = playbook_argv(project, env, vars_path, key_path, inventory)
        code, out = _run(argv, project['working_dir'], secrets,
                         env=_ansible_env(env, known), timeout=DEPLOY_TIMEOUT)
    except Exception as exc:
        msg = redact(str(exc), secrets)
        if job_id:
            _finish_job(job_id, 'error', None, msg)
        if notify:
            notify(f"Deployment failed to start: {msg}")
        return job_id
    finally:
        for path in (key_path, workdir):
            if path:
                _remove(path)
        _release(keys)
    _finish_job(job_id, 'ok' if code == 0 else 'failed', code, out)
    audit(actor, 'deploy', f"{project['name']}/{env['name']} job={job_id} rc={code} "
                           f"tags={env['tags'] or '-'} skip={env.get('skip_tags') or '-'}")
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
    branch = project['branch']
    job_id = pat = None
    try:
        for value in (branch, remote, str(working_dir)):
            if value and value.startswith('-'):
                raise ValueError(f'git argument may not start with "-": {value}')
        check_remote(remote)
        check_working_dir(working_dir)
        cred = store.cred_resolve('github_pat', project['id']) if store else None
        pat = cred['secret'] if cred else None
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
    except Exception as exc:
        msg = redact(str(exc), [pat] if pat else ())
        if job_id:
            _finish_job(job_id, 'error', None, msg)
        if notify:
            notify(f"[{project['name']}] git failed to start: {msg}")
        return job_id
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
