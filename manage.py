#!/usr/bin/env python3
"""hoisty admin CLI. Run from the checkout: python manage.py <command>."""
import argparse
import getpass
import logging
import os
import shutil
import stat
import subprocess
import sys
import termios
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))

import db          # noqa: E402
import runner      # noqa: E402
import scheduler   # noqa: E402
import unlock      # noqa: E402


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


def unlock_store():
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
        store = unlock_store()
        applied = db.migrate(store._conn, 'secrets')
        store.close()
        print('secrets.db: ' + (', '.join(applied) if applied else 'up to date'))


def cmd_doctor(args):
    problems = []
    uid = os.getuid()

    def check(path, label):
        if not path.exists():
            problems.append(f'missing: {path}')
            return
        st = path.stat()
        if st.st_uid != uid:
            problems.append(f'{label} not owned by uid {uid}: {path}')
        if st.st_mode & 0o077:
            problems.append(f'{label} readable by others ({oct(stat.S_IMODE(st.st_mode))}): {path}')

    check(db.DATA, 'data dir')
    check(db.BACKUP_DIR, 'backup dir')
    for f in (db.DEPLOY_DB, db.SECRETS_DB, db.KDF_FILE):
        check(f, 'file')
    if ROOT.stat().st_mode & 0o022:
        problems.append(f'checkout is group/other writable: {ROOT}')
    # a playbook runs as this uid; if this uid can rewrite the code or the venv, one
    # bad deploy trojans the process that is next handed the global password.
    # Do not resolve() the venv: bin/python is a symlink to the system one.
    venv = Path(sys.executable).parent.parent
    for path in (ROOT / 'manage.py', ROOT / 'src', venv):
        if path.exists() and os.access(path, os.W_OK):
            problems.append(f'code writable by the uid that runs it (a compromised '
                            f'playbook can trojan it): {path}')
    if not Path(runner.ANSIBLE_PLAYBOOK).exists():
        problems.append(f'ansible-playbook not found at {runner.ANSIBLE_PLAYBOOK}')
    if not Path(runner.GIT).exists():
        problems.append(f'git not found at {runner.GIT}')
    if db.DEPLOY_DB.exists():
        for row in db.projects():
            wd = Path(row['working_dir'])
            if not wd.exists():
                problems.append(f"project {row['name']}: missing {wd}")
            elif wd.stat().st_mode & 0o022:
                problems.append(f"project {row['name']}: checkout writable by others, "
                                f"anyone who can edit it receives that project's secrets: {wd}")
    problems += host_posture()
    problems += package_integrity()
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


def package_integrity():
    """On a packaged install, ask dpkg whether anything it shipped has changed.
    It already records a checksum per file, so this needs no manifest of our own."""
    if not shutil.which('dpkg') or not Path('/var/lib/dpkg/info/hoisty.md5sums').exists():
        return []
    try:
        out = subprocess.run(['dpkg', '-V', 'hoisty'], capture_output=True, text=True,
                             timeout=120).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return [f'could not verify the installed package: {exc}']
    return [f'changed since it was installed: {line.split()[-1]}'
            for line in out.splitlines() if line.strip()]


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
    units = [u for d in ('/lib/systemd/system', '/usr/lib/systemd/system',
                         '/etc/systemd/system')
             for u in Path(d).glob('hoisty*.service') if Path(d).is_dir()]
    if not units:
        out.append('no hoisty unit installed: the unit in deploy/ (or the .deb) is '
                   'what makes app/ and venv/ read-only to the daemon')
    return out


def cmd_bot(args):
    """Starts locked; `hoisty unlock` on the same machine hands it the password."""
    import bot
    db.harden_process()
    if not db.KDF_FILE.exists():
        raise SystemExit('not initialised - run: hoisty init')
    with db.deploy_conn() as conn:
        require_migrated(conn, 'deploy')
    bot.run()


def cmd_unlock(args):
    """Hand the running daemon the global password. Root only, by its socket."""
    passphrase = ask_passphrase()
    try:
        reply = unlock.ask('unlock', passphrase)
    except OSError as exc:
        raise SystemExit(f'cannot reach the daemon on {unlock.SOCKET}: {exc}')
    finally:
        db.wipe(passphrase)
    print(reply)
    return 0 if reply == 'ok' else 1


def cmd_status(args):
    try:
        reply = unlock.ask('status')
    except OSError as exc:
        raise SystemExit(f'cannot reach the daemon on {unlock.SOCKET}: {exc}')
    print(reply)
    return 1 if reply.startswith('error:') else 0


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
    store = unlock_store()
    scope, scope_id = scope_of(args)
    value = db.coerce_value(getpass.getpass(f'Value for {args.name}: '), args.type)
    store.set(scope, scope_id, args.name, value, actor=getpass.getuser(),
              note=args.note)
    db.audit(getpass.getuser(), 'secret-set', f'{scope}/{scope_id}/{args.name}')
    print(f'set {args.name} on {scope} {scope_id}')
    store.close()


def cmd_secret_list(args):
    store = unlock_store()
    scope, scope_id = scope_of(args)
    for s in store.names(scope, scope_id):
        print(f"{s['name']:30} {s['type']:8} {s['updated_at']}  "
              f"{s['updated_by'] or '-'}")
        if s['note']:
            print(f"{'':30} note: {s['note']}")
    store.close()


def cmd_vars_import(args):
    store = unlock_store()
    scope, scope_id = scope_of(args)
    names = db.vars_import(store, scope, scope_id, args.path, getpass.getuser())
    db.audit(getpass.getuser(), 'vars-import', f'{scope}/{scope_id} names={names}')
    print(f'imported {len(names)} variables into {scope} {scope_id}: '
          + ', '.join(names))
    store.close()


def cmd_vars_export(args):
    store = unlock_store()
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
        print(f'Next: python manage.py sync {args.name}')


def _project(name):
    rows = db.projects(name)
    if not rows:
        raise SystemExit(f'no such project: {name}')
    return rows[0]


def cmd_host_add(args):
    project = _project(args.project)
    try:
        name, key = db.host_set(project['id'], args.name, args.address, args.groups, args.key)
    except ValueError as exc:
        raise SystemExit(str(exc))
    db.audit(getpass.getuser(), 'host-set', f"project={project['id']} name={name} "
                                            f'pinned={bool(key)}')
    print(f"{args.project}/{name}" + (f' pinned {db.fingerprint(key)}' if key
                                       else ' (no host key pinned)'))


def cmd_host_list(args):
    for project in ([_project(args.project)] if args.project else db.projects()):
        for h in db.hosts(project['id']):
            print(f"{project['name']:16} {h['name']:24} {h['address'] or '-':20} "
                  f"{h['groups'] or '-':16} {h['fingerprint'] or 'not pinned'}")


def cmd_host_rm(args):
    project = _project(args.project)
    if not db.host_delete(project['id'], args.name):
        raise SystemExit(f'no such host: {args.project}/{args.name}')
    db.audit(getpass.getuser(), 'host-delete', f"project={project['id']} name={args.name}")
    print(f'removed {args.project}/{args.name}')


def cmd_project_list(args):
    for p in db.projects():
        print(f"{p['name']:20} {p['branch']:10} {p['working_dir']}")
        if p['git_remote']:
            print(f"{'':20} remote: {p['git_remote']}")


def cmd_cred_set(args):
    """Read an ssh key from a file, or a token from a prompt."""
    store = unlock_store()
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
    store = unlock_store()
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
    store = unlock_store()
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
    store = unlock_store()
    scope, scope_id = scope_of(args)
    store.cred_delete(scope, scope_id, args.kind)
    db.audit(getpass.getuser(), 'cred-delete', f'{scope}/{scope_id}/{args.kind}')
    store.close()
    print(f'removed {args.kind} from {scope} {scope_id}')


def cmd_sync(args):
    """Clone the project's ansible repo, or fast-forward it if already there."""
    store = unlock_store()
    projects = db.projects(args.project)
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
    store = unlock_store()
    path, pruned = scheduler.backup(store)
    store.close()
    print(f'wrote {path}' + (f', pruned {len(pruned)}' if pruned else ''))


def safety_backup(passphrase):
    """Back up the current data dir before it is replaced. Never fatal: restore
    keeps the old directory beside the new one anyway, and the states this command
    exists to recover from - a half-finished rekey, a deleted secrets.db, a machine
    whose own password nobody remembers - are exactly the ones that cannot be
    backed up. Blocking on them would leave the operator with no way forward."""
    if not db.KDF_FILE.exists():
        print('no store here yet, nothing to back up first')
        return
    store = None
    try:
        store = db.SecretStore.unlock(passphrase)
        path, _ = scheduler.backup(store, day=f'{datetime.now():%Y-%m-%d-%H%M%S}-pre-import')
        print(f'backed up the current state to {path}')
    except Exception as exc:
        why = ('that is not this machine\'s global password' if isinstance(exc, db.Locked)
               else exc)
        print(f'WARNING: could not back up the current state ({why}). The current '
              'directory is still kept beside the new one.', file=sys.stderr)
    finally:
        if store:
            store.close()


def cmd_import(args):
    """Replace data/ with a backup zip from anywhere. A full sealed backup of the
    current state is written to backups/ first, and the old directory is kept."""
    db.harden_process()
    zip_path = Path(args.zip).resolve()
    if not zip_path.is_file():
        raise SystemExit(f'no such file: {zip_path}')
    if scheduler.scheduler_alive():
        raise SystemExit('the bot is running - stop it and the web app first')
    if not args.yes:
        answer = input(f'Replace {db.DATA} with {zip_path}? The current state is backed '
                       'up first. [y/N] ')
        if answer.strip().lower() != 'y':
            raise SystemExit('aborted')
    passphrase = ask_passphrase()
    other = None
    try:
        safety_backup(passphrase)
        try:
            old = scheduler.restore(zip_path, passphrase)
        except db.Locked:
            # the zip predates a rekey, or came from another install
            other = ask_passphrase('That is not the password of this backup. Its global password: ')
            try:
                old = scheduler.restore(zip_path, other)
            except db.Locked:
                raise SystemExit('wrong global password, or the backup has been tampered with')
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc))
    finally:
        db.wipe(passphrase)
        if other is not None:
            db.wipe(other)
    print(f'imported {zip_path} into {db.DATA}')
    if old:
        print(f'previous directory kept as {old}')
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
    add('bot', cmd_bot, help='run the slack daemon (starts locked)')
    add('unlock', cmd_unlock, help='give the running daemon the global password')
    add('status', cmd_status, help='ask the daemon whether it is locked')
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
    ha = add('host-add', cmd_host_add, help="add or update one of a project's hosts")
    ha.add_argument('project')
    ha.add_argument('name', help='inventory name')
    ha.add_argument('--address', help='ansible_host, when it differs from the name')
    ha.add_argument('--groups', help='comma separated inventory groups')
    ha.add_argument('--key', help='"<type> <base64>" from ssh-keyscan; pins the host key')
    hl = add('host-list', cmd_host_list, help='list hosts')
    hl.add_argument('project', nargs='?')
    hr = add('host-rm', cmd_host_rm, help='remove a host')
    hr.add_argument('project')
    hr.add_argument('name')

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
    im = add('import', cmd_import,
             help='replace data/ with a backup zip, after a full backup of the current state')
    im.add_argument('zip')
    im.add_argument('--yes', action='store_true', help='skip the confirmation prompt')
    sa = add('schedule-add', cmd_schedule_add, help='add a scheduled job')
    sa.add_argument('kind', choices=['backup', 'git-pull'])
    sa.add_argument('--at', required=True, help='HH:MM')
    sa.add_argument('--weekdays', default='*', help='* or 0-6 comma separated')
    sa.add_argument('--project', help='git-pull only; omit for all projects')
    add('schedule-list', cmd_schedule_list, help='list schedules')

    args = p.parse_args()
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(args.fn(args) or 0)


if __name__ == '__main__':
    main()
