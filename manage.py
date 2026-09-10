#!/usr/bin/env python3
"""slack-deploy admin CLI. Run from the checkout: python manage.py <command>."""
import argparse
import configparser
import getpass
import logging
import os
import shlex
import stat
import sys
import termios
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))

import db          # noqa: E402
import runner      # noqa: E402
import scheduler   # noqa: E402


def read_secret(prompt):
    """Like getpass, but into a bytearray the caller can wipe. The bot lives for
    weeks holding the derived key; the passphrase itself must not sit beside it
    in the heap that whole time. Piped stdin (CI) falls back to getpass."""
    try:
        fd = os.open('/dev/tty', os.O_RDWR)
    except OSError:
        return bytearray(getpass.getpass(prompt).encode())
    old = termios.tcgetattr(fd)
    new = old[:]
    new[3] &= ~termios.ECHO
    buf = bytearray()
    try:
        os.write(fd, prompt.encode())
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        while True:
            ch = os.read(fd, 1)
            if not ch or ch in (b'\n', b'\r'):
                break
            buf += ch
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        os.write(fd, b'\n')
        os.close(fd)
    return buf


def ask_passphrase(prompt='Global password: ', confirm=False, minimum=None):
    value = read_secret(prompt)
    if minimum and len(value) < minimum:
        db.wipe(value)
        raise SystemExit(f'must be at least {minimum} characters')
    if confirm:
        again = read_secret('Repeat: ')
        same = again == value
        db.wipe(again)
        if not same:
            db.wipe(value)
            raise SystemExit('passwords did not match')
    return value


def ask_password(*args, **kwargs):
    """A user password: hashed at once, then wiped."""
    value = ask_passphrase(*args, **kwargs)
    try:
        return db.hash_password(bytes(value).decode())
    finally:
        db.wipe(value)


def unlock():
    db.harden_process()
    if not db.KDF_FILE.exists():
        raise SystemExit('not initialised - run: python manage.py init')
    passphrase = ask_passphrase()
    try:
        return db.SecretStore.unlock(passphrase)
    except db.Locked:
        raise SystemExit('incorrect global password')
    finally:
        db.wipe(passphrase)


def require_migrated(conn, kind):
    """Refuse to start on an old schema: a missing column is a 500 at 3am otherwise."""
    if db.pending(conn, kind):
        raise SystemExit(f'{kind}.db has pending migrations - run: make migrate')


def scope_of(args):
    """--project/--env select the scope; neither means global."""
    if not getattr(args, 'project', None):
        return db.GLOBAL_SCOPE, 0
    with db.deploy_conn() as conn:
        project = conn.execute('SELECT id FROM project WHERE name=?',
                               (args.project,)).fetchone()
        if not project:
            raise SystemExit(f'no such project: {args.project}')
        if not getattr(args, 'env', None):
            return 'project', project['id']
        env = conn.execute('SELECT id FROM environment WHERE project_id=? AND name=?',
                           (project['id'], args.env)).fetchone()
        if not env:
            raise SystemExit(f'no such environment: {args.project}/{args.env}')
        return 'environment', env['id']


# --- commands -------------------------------------------------------------

def cmd_init(args):
    found = db.initialised()          # check before prompting for anything
    if found:
        print('Refusing to overwrite:', file=sys.stderr)
        for path in found:
            print(f'  {path}', file=sys.stderr)
        raise SystemExit(db.REFUSE_INIT)
    passphrase = ask_passphrase('New global password: ', confirm=True)
    try:
        store = db.init(passphrase)
    finally:
        db.wipe(passphrase)
    print(f'initialised {db.DATA}')
    with db.deploy_conn() as conn:
        existing = conn.execute('SELECT count(*) c FROM user').fetchone()['c']
    if not existing:
        username = input('First admin username: ').strip()
        pw_hash, salt = ask_password(f'Password for {username}: ', confirm=True,
                                     minimum=db.MIN_PASSWORD)
        with db.deploy_conn() as conn:
            conn.execute('INSERT INTO user (username, pw_hash, pw_salt, is_admin) '
                         'VALUES (?,?,?,1)', (username, pw_hash, salt))
        print(f'created admin {username} (registers 2FA on first web login)')
    store.close()


def cmd_migrate(args):
    with db.deploy_conn() as conn:
        applied = db.migrate(conn, 'deploy')
    print('deploy.db: ' + (', '.join(applied) if applied else 'up to date'))
    if args.all:
        store = unlock()
        applied = db.migrate(store._conn, 'secrets')
        store.close()
        print('secrets.db: ' + (', '.join(applied) if applied else 'up to date'))


def cmd_doctor(args):
    problems = []
    uid = os.getuid()

    def check(path, want_mode, label):
        if not path.exists():
            problems.append(f'missing: {path}')
            return
        st = path.stat()
        if st.st_uid != uid:
            problems.append(f'{label} not owned by uid {uid}: {path}')
        if st.st_mode & 0o077 & ~want_mode:
            problems.append(f'{label} readable by others ({oct(stat.S_IMODE(st.st_mode))}): {path}')

    check(db.DATA, 0, 'data dir')
    check(db.BACKUP_DIR, 0, 'backup dir')
    for f in (db.DEPLOY_DB, db.SECRETS_DB, db.KDF_FILE):
        check(f, 0, 'file')
    if ROOT.stat().st_mode & 0o022:
        problems.append(f'checkout is group/other writable: {ROOT}')
    # a playbook runs as this uid; if this uid can rewrite the code or the venv, one
    # bad deploy trojans the process that is next handed the global password
    for path in (ROOT / 'manage.py', ROOT / 'src', ROOT / 'venv'):
        if path.exists() and os.access(path, os.W_OK):
            problems.append(f'code writable by the uid that runs it (a compromised '
                            f'playbook can trojan it): {path}')
    if not Path(runner.ANSIBLE_PLAYBOOK).exists():
        problems.append(f'ansible-playbook not found at {runner.ANSIBLE_PLAYBOOK}')
    if not Path(runner.GIT).exists():
        problems.append(f'git not found at {runner.GIT}')
    if db.DEPLOY_DB.exists():
        with db.deploy_conn() as conn:
            for row in conn.execute('SELECT name, working_dir FROM project'):
                wd = Path(row['working_dir'])
                if not wd.exists():
                    problems.append(f"project {row['name']}: missing {wd}")
                elif wd.stat().st_mode & 0o022:
                    problems.append(f"project {row['name']}: checkout writable by "
                                    f'others, anyone who can edit it receives that '
                                    f"project's secrets: {wd}")
    problems += host_posture()
    print(f'running as uid {uid} ({getpass.getuser()}), data dir {db.DATA}')
    print('NOTE: encryption only protects a stolen database file unless this uid is '
          'separate from the accounts people log in as.')
    for p in problems:
        print('  ! ' + p)
    print('no problems found' if not problems else f'{len(problems)} problem(s)')
    return 1 if problems else 0


def _read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def host_posture():
    """Kernel and hardware settings the key's safety leans on. See THREAT-MODEL.md."""
    out = []
    vulns = Path('/sys/devices/system/cpu/vulnerabilities')
    exposed = [f.name for f in sorted(vulns.glob('*')) if (_read(f) or '').startswith('Vulnerable')]
    if exposed:
        out.append('CPU side channels unmitigated by the kernel (key material in cache '
                   f'is readable by any local process): {", ".join(exposed)}')
    scope = _read('/proc/sys/kernel/yama/ptrace_scope')
    if scope is not None and scope == '0':
        out.append('kernel.yama.ptrace_scope=0: any same-uid process may ptrace another '
                   '(PR_SET_DUMPABLE=0 covers this process, but set it to 1 or higher)')
    if _read('/proc/sys/kernel/randomize_va_space') not in (None, '2'):
        out.append('kernel.randomize_va_space is not 2: ASLR weakened')
    swaps = [line.split()[0] for line in (_read('/proc/swaps') or '').splitlines()[1:]
             if not line.startswith('/dev/zram')]     # zram is RAM, not a disk
    if swaps:
        out.append('swap on disk: pages holding the derived key or plaintext vars can '
                   'reach it unless it is encrypted (or use zram / no swap): '
                   + ', '.join(swaps))
    if Path('/sys/kernel/iommu_groups').exists() and not any(Path('/sys/kernel/iommu_groups').iterdir()):
        out.append('no IOMMU groups: DMA from a hostile PCIe/Thunderbolt device can read '
                   'RAM (enable intel_iommu=on / amd_iommu=on)')
    if _read('/proc/sys/kernel/dmesg_restrict') == '0':
        out.append('kernel.dmesg_restrict=0: kernel addresses and device state readable by '
                   'every user')
    if not list(Path('/etc/systemd/system').glob('slack-deploy*.service')):
        out.append('no slack-deploy unit installed: the units in deploy/ make src/, venv/ '
                   'and the rest of the filesystem read-only to the daemon')
    return out


def cmd_bot(args):
    import bot
    with db.deploy_conn() as conn:
        require_migrated(conn, 'deploy')
    store = unlock()
    require_migrated(store._conn, 'secrets')
    bot.run(store)


def cmd_web(args):
    db.harden_process()
    if not db.KDF_FILE.exists():
        raise SystemExit('not initialised - run: python manage.py init')
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit('--tls-cert and --tls-key go together')
    with db.deploy_conn() as conn:
        require_migrated(conn, 'deploy')
    import web
    try:
        web.run(host=args.host, port=args.port,
                tls=(args.tls_cert, args.tls_key) if args.tls_cert else None)
    except ValueError as exc:
        raise SystemExit(str(exc))


def cmd_user_add(args):
    pw_hash, salt = ask_password(f'Password for {args.username}: ', confirm=True,
                                 minimum=db.MIN_PASSWORD)
    with db.deploy_conn() as conn:
        conn.execute('INSERT INTO user (username, pw_hash, pw_salt, slack_user_id, '
                     'is_admin) VALUES (?,?,?,?,?)',
                     (args.username, pw_hash, salt, args.slack_id,
                      1 if args.admin else 0))
    print(f'created {args.username}; 2FA is registered on first web login')


def cmd_user_list(args):
    with db.deploy_conn() as conn:
        for r in conn.execute('SELECT * FROM user ORDER BY username'):
            flags = ','.join(f for f, on in (('admin', r['is_admin']),
                                             ('disabled', r['disabled']),
                                             ('2fa', r['totp_confirmed'])) if on)
            print(f"{r['username']:20} slack={r['slack_user_id'] or '-':12} {flags}")


def cmd_user_reset_2fa(args):
    with db.deploy_conn() as conn:
        changed = conn.execute('UPDATE user SET totp_secret=NULL, totp_confirmed=0 '
                               'WHERE username=?', (args.username,)).rowcount
    print(f'2FA reset for {args.username}' if changed else 'no such user')


def cmd_secret_set(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    value = db.coerce_value(getpass.getpass(f'Value for {args.name}: '), args.type)
    store.set(scope, scope_id, args.name, value, actor=getpass.getuser(),
              note=args.note)
    db.audit(getpass.getuser(), 'secret-set', f'{scope}/{scope_id}/{args.name}')
    print(f'set {args.name} on {scope} {scope_id}')
    store.close()


def cmd_secret_list(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    for s in store.names(scope, scope_id):
        print(f"{s['name']:30} {s['type']:8} {s['updated_at']}  "
              f"{s['updated_by'] or '-'}")
        if s['note']:
            print(f"{'':30} note: {s['note']}")
    store.close()


def cmd_vars_import(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    names = db.vars_import(store, scope, scope_id, args.path, getpass.getuser())
    db.audit(getpass.getuser(), 'vars-import', f'{scope}/{scope_id} names={names}')
    print(f'imported {len(names)} variables into {scope} {scope_id}: '
          + ', '.join(names))
    store.close()


def cmd_vars_export(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    text = db.vars_export_text(store, scope, scope_id)
    store.close()
    if not args.out:
        sys.stdout.write(text)
        return
    out = Path(args.out).resolve()
    if ROOT in out.parents or out.parent == ROOT:
        raise SystemExit('refusing to write plaintext secrets inside the checkout')
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
    db.audit(getpass.getuser(), 'vars-export', f'{scope}/{scope_id} -> {out}')
    print(f'wrote {out} (0600, plaintext - delete it when done)')


def cmd_project_add(args):
    try:
        working_dir = runner.check_working_dir(Path(args.dir).resolve())
        remote = runner.check_remote(args.remote)
    except ValueError as exc:
        raise SystemExit(str(exc))
    with db.deploy_conn() as conn:
        pid = conn.execute('INSERT INTO project (name, working_dir, branch, '
                           'git_remote) VALUES (?,?,?,?)',
                           (args.name, working_dir, args.branch, remote)).lastrowid
    print(f'project {args.name} (id {pid})'
          + (f' <- {args.remote}' if args.remote else ''))
    if args.remote:
        print(f'Next: make sync    # or: python manage.py sync {args.name}')


def cmd_project_list(args):
    for p in _projects():
        print(f"{p['name']:20} {p['branch']:10} {p['working_dir']}")
        if p['git_remote']:
            print(f"{'':20} remote: {p['git_remote']}")


def cmd_cred_set(args):
    """Read an ssh key from a file, or a token from a prompt."""
    store = unlock()
    scope, scope_id = scope_of(args)
    public = None
    if args.path:
        secret = Path(args.path).read_text()
        if args.kind == 'ssh_key' and 'PRIVATE KEY' not in secret:
            raise SystemExit(f'{args.path} does not look like a private key')
    else:
        secret = getpass.getpass(f'{args.kind} value: ')
    if args.kind == 'ssh_key' and args.public:
        public = Path(args.public).read_text().strip()
    store.cred_set(scope, scope_id, args.kind, args.name, secret, public,
                   getpass.getuser())
    db.audit(getpass.getuser(), 'cred-set', f'{scope}/{scope_id}/{args.kind}')
    print(f'stored {args.kind} "{args.name}" on {scope} {scope_id}')
    store.close()


def cmd_cred_gen(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    private, public = db.generate_ssh_key(args.name)
    store.cred_set(scope, scope_id, 'ssh_key', args.name, private, public,
                   getpass.getuser())
    db.audit(getpass.getuser(), 'cred-generate', f'{scope}/{scope_id}/ssh_key')
    store.close()
    print(f'generated ed25519 key "{args.name}" on {scope} {scope_id}.')
    print('Add this public key to the target hosts\' authorized_keys:\n')
    print(public)


def cmd_cred_list(args):
    store = unlock()
    scope = scope_id = None
    if args.project:
        scope, scope_id = scope_of(args)
    rows = store.cred_list(scope, scope_id)
    store.close()
    for r in rows:
        where = r['scope'] if r['scope'] == db.GLOBAL_SCOPE \
            else f"{r['scope']} {r['scope_id']}"
        print(f"{r['kind']:12} {r['name']:24} {where:16} {r['updated_at']}")
        if r['public']:
            print(f"             {r['public']}")
    if not rows:
        print('no credentials set')


def cmd_cred_rm(args):
    store = unlock()
    scope, scope_id = scope_of(args)
    store.cred_delete(scope, scope_id, args.kind)
    db.audit(getpass.getuser(), 'cred-delete', f'{scope}/{scope_id}/{args.kind}')
    store.close()
    print(f'removed {args.kind} from {scope} {scope_id}')


def cmd_sync(args):
    """Clone the project's ansible repo, or fast-forward it if already there."""
    store = unlock()
    projects = _projects(args.project)
    if not projects:
        raise SystemExit(f'no such project: {args.project}' if args.project
                         else 'no projects configured')
    for project in projects:
        job = runner.git_sync(project, store, actor=getpass.getuser(),
                              notify=lambda msg, log=None: print(msg))
        if job:
            with db.deploy_conn() as conn:
                row = conn.execute('SELECT status, log FROM job WHERE id=?',
                                   (job,)).fetchone()
            if row['status'] != 'ok':
                print(row['log'], file=sys.stderr)
    store.close()


def _projects(name=None):
    with db.deploy_conn() as conn:
        sql, params = 'SELECT * FROM project', ()
        if name:
            sql += ' WHERE name=?'
            params = (name,)
        return [dict(r) for r in conn.execute(sql, params)]


def cmd_rekey(args):
    db.harden_process()
    old = ask_passphrase('Current global password: ')
    new = ask_passphrase('New global password: ', confirm=True)
    try:
        db.rekey(old, new)
    finally:
        db.wipe(old)
        db.wipe(new)
    print('rekeyed. Restart the slack daemon and the web app.')


def cmd_backup(args):
    store = unlock()
    path, pruned = scheduler.backup(store)
    store.close()
    print(f'wrote {path}' + (f', pruned {len(pruned)}' if pruned else ''))


def cmd_restore(args):
    """Replace data/ with a backup zip; the current directory is kept beside it."""
    db.harden_process()
    if scheduler.scheduler_alive():
        raise SystemExit('the bot is running - stop it and the web app first')
    if not args.yes:
        answer = input(f'Replace {db.DATA} with {args.zip}? The current directory is '
                       'kept beside it. [y/N] ')
        if answer.strip().lower() != 'y':
            raise SystemExit('aborted')
    passphrase = ask_passphrase('Global password of the backup: ')
    try:
        old = scheduler.restore(args.zip, passphrase)
    except db.Locked:
        raise SystemExit('wrong global password, or the backup has been tampered with')
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc))
    finally:
        db.wipe(passphrase)
    print(f'restored {args.zip} into {db.DATA}')
    if old:
        print(f'previous state kept as {old}')
    print('Next: make migrate, then start the bot and the web app')


def cmd_schedule_add(args):
    try:
        scheduler.validate(args.at, args.weekdays)
    except ValueError as exc:
        raise SystemExit(str(exc))
    target = None
    if args.project:
        with db.deploy_conn() as conn:
            row = conn.execute('SELECT id FROM project WHERE name=?',
                               (args.project,)).fetchone()
            if not row:
                raise SystemExit(f'no such project: {args.project}')
            target = row['id']
    with db.deploy_conn() as conn:
        conn.execute('INSERT INTO schedule (kind, target_id, at_time, weekdays, '
                     'created_by) VALUES (?,?,?,?,?)',
                     (args.kind, target, args.at, args.weekdays, getpass.getuser()))
    print(f'scheduled {args.kind} at {args.at} ({args.weekdays})')


def cmd_schedule_list(args):
    with db.deploy_conn() as conn:
        for r in conn.execute('SELECT * FROM schedule ORDER BY at_time'):
            print(f"{r['id']:3} {r['kind']:10} at {r['at_time']} days={r['weekdays']:8} "
                  f"target={r['target_id'] or 'all':5} "
                  f"{'on' if r['enabled'] else 'off':4} last={r['last_run_on'] or '-'}")


def cmd_import_config(args):
    """Move an old config.ini into the project layout."""
    store = unlock()
    cfg = configparser.ConfigParser()
    if not cfg.read(args.path):
        raise SystemExit(f'cannot read {args.path}')
    glob = dict(cfg['global_settings']) if cfg.has_section('global_settings') else {}
    for key in ('slack_app_token', 'slack_bot_token'):
        if glob.get(key):
            store.set(db.GLOBAL_SCOPE, 0, key, glob[key], actor=getpass.getuser())
            print(f'stored {key} in the encrypted store')
    for slack_id in filter(None, (s.strip() for s in
                                  glob.get('user_whitelist', '').split(','))):
        with db.deploy_conn() as conn:
            conn.execute('UPDATE user SET slack_user_id=? WHERE slack_user_id IS NULL '
                         'AND id=(SELECT min(id) FROM user WHERE slack_user_id IS NULL)',
                         (slack_id,))
        print(f'whitelisted slack id {slack_id} (check with: manage.py user-list)')

    projects, skipped = {}, []
    for section in cfg.sections():
        if not section.startswith('env:'):
            continue
        env_name = section.split('env:', 1)[1]
        info = dict(cfg[section])
        working_dir = info['working_dir']
        if working_dir not in projects:
            name = Path(working_dir).name
            with db.deploy_conn() as conn:
                row = conn.execute('SELECT id FROM project WHERE name=?',
                                   (name,)).fetchone()
                projects[working_dir] = row['id'] if row else conn.execute(
                    'INSERT INTO project (name, working_dir, branch) VALUES (?,?,?)',
                    (name, working_dir, info.get('branch', 'master'))).lastrowid
            print(f'project {name} -> {working_dir}')
        parsed = parse_playbook_params(info.get('playbook_params', ''))
        if parsed is None:
            skipped.append((env_name, info.get('playbook_params')))
            continue
        with db.deploy_conn() as conn:
            conn.execute('INSERT OR REPLACE INTO environment (project_id, name, '
                         'inventory, playbook, tags, limit_hosts, become) '
                         'VALUES (?,?,?,?,?,?,?)',
                         (projects[working_dir], env_name, parsed['inventory'],
                          parsed['playbook'], parsed['tags'], parsed['limit_hosts'],
                          parsed['become']))
        print(f'  environment {env_name}: {parsed}')
    store.close()
    for name, raw in skipped:
        print(f'SKIPPED {name}: could not map "{raw}" - add it by hand', file=sys.stderr)
    return 1 if skipped else 0


def parse_playbook_params(raw):
    """Map an old params string onto structured columns, or None if unrecognised."""
    out = {'inventory': None, 'playbook': None, 'tags': None, 'limit_hosts': None,
           'become': 0}
    tokens = shlex.split(raw)
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in ('-i', '--inventory', '--inventory-file'):
            out['inventory'] = tokens[i + 1]; i += 2
        elif token in ('--tags', '-t'):
            out['tags'] = tokens[i + 1]; i += 2
        elif token in ('--limit', '-l'):
            out['limit_hosts'] = tokens[i + 1]; i += 2
        elif token in ('-b', '--become'):
            out['become'] = 1; i += 1
        elif not token.startswith('-') and out['playbook'] is None:
            out['playbook'] = token; i += 1
        else:
            return None  # anything else is arbitrary argv, refuse to guess
        continue
    return out if out['inventory'] and out['playbook'] else None


# --- argparse -------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(prog='manage.py', description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name, **kw)
        sp.set_defaults(fn=fn)
        return sp

    def scoped(sp):
        sp.add_argument('--project')
        sp.add_argument('--env')
        return sp

    add('init', cmd_init, help='create data dir, both databases and the first admin')
    m = add('migrate', cmd_migrate, help='apply pending migrations/')
    m.add_argument('--all', action='store_true',
                   help='also migrate secrets.db (prompts for the global password)')
    add('doctor', cmd_doctor, help='check ownership, permissions and dependencies')
    add('bot', cmd_bot, help='run the slack daemon')
    w = add('web', cmd_web, help='run the web interface')
    w.add_argument('--host', default='127.0.0.1')
    w.add_argument('--port', type=int, default=8080)
    w.add_argument('--tls-cert', help='PEM certificate; required for a non-loopback host')
    w.add_argument('--tls-key', help='PEM private key for --tls-cert')

    u = add('user-add', cmd_user_add, help='add a web user')
    u.add_argument('username')
    u.add_argument('--slack-id')
    u.add_argument('--admin', action='store_true')
    add('user-list', cmd_user_list, help='list users')
    r = add('user-reset-2fa', cmd_user_reset_2fa, help='force 2FA re-registration')
    r.add_argument('username')

    s = scoped(add('secret-set', cmd_secret_set, help='set one secret variable'))
    s.add_argument('name')
    s.add_argument('--note', help='what this variable is for')
    s.add_argument('--type', default='string', choices=db.VAR_TYPES,
                   help='how to interpret the value (default: string)')
    scoped(add('secret-list', cmd_secret_list, help='list secret names in a scope'))
    vi = scoped(add('vars-import', cmd_vars_import, help='import a vars YAML file'))
    vi.add_argument('path')
    ve = scoped(add('vars-export', cmd_vars_export, help='export a scope to YAML'))
    ve.add_argument('--out', help='file to write (0600, outside the checkout)')

    pa = add('project-add', cmd_project_add, help='register an ansible repo')
    pa.add_argument('name')
    pa.add_argument('--dir', required=True, help='checkout directory')
    pa.add_argument('--remote', help='https or ssh clone url')
    pa.add_argument('--branch', default='master')
    add('project-list', cmd_project_list, help='list projects')

    cs = scoped(add('cred-set', cmd_cred_set,
                    help='store an ssh key or github pat'))
    cs.add_argument('kind', choices=['ssh_key', 'github_pat'])
    cs.add_argument('name', help='label, e.g. deploy-key-prod')
    cs.add_argument('--path', help='file to read the key from (else prompt)')
    cs.add_argument('--public', help='matching .pub file, for reference')
    cg = scoped(add('cred-gen', cmd_cred_gen,
                    help='generate an ed25519 ssh key and print the public half'))
    cg.add_argument('name')
    scoped(add('cred-list', cmd_cred_list, help='list credentials'))
    cr = scoped(add('cred-rm', cmd_cred_rm, help='remove a credential'))
    cr.add_argument('kind', choices=['ssh_key', 'github_pat'])
    sy = add('sync', cmd_sync, help='clone or fast-forward project checkouts')
    sy.add_argument('project', nargs='?')

    add('rekey', cmd_rekey, help='change the global password')
    add('backup', cmd_backup, help='write todays sealed backup zip and prune old ones')
    rs = add('restore', cmd_restore, help='replace data/ with a backup zip (keeps the old dir)')
    rs.add_argument('zip')
    rs.add_argument('--yes', action='store_true', help='skip the confirmation prompt')
    sa = add('schedule-add', cmd_schedule_add, help='add a scheduled job')
    sa.add_argument('kind', choices=['backup', 'git-pull'])
    sa.add_argument('--at', required=True, help='HH:MM')
    sa.add_argument('--weekdays', default='*', help='* or 0-6 comma separated')
    sa.add_argument('--project', help='git-pull only; omit for all projects')
    add('schedule-list', cmd_schedule_list, help='list schedules')
    ic = add('import-config', cmd_import_config, help='migrate an old config.ini')
    ic.add_argument('path', nargs='?', default='config.ini')

    args = p.parse_args()
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(args.fn(args) or 0)


if __name__ == '__main__':
    main()
