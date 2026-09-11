#!/usr/bin/env python3
"""A real ansible run: argv construction, extravars delivery, redaction, cleanup."""
import sys
import tempfile
import threading
import time
from datetime import date
from pathlib import Path

import harness
from harness import WORK

import db
import runner

STORE = None
CTX = {}
SECRET = 'super-secret-value'


def stray_agents():
    """An ssh-agent started for a run outlives it holding the decrypted key.
    We must never leave one."""
    found = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            argv = (proc / 'cmdline').read_bytes().decode('utf-8', 'replace')
        except OSError:
            continue
        if 'ssh-agent' in argv and str(WORK) in argv:
            found.append(proc.name)
    return found


def _setup():
    global STORE
    STORE = harness.new_store()
    checkout = WORK / 'checkout'
    checkout.mkdir(exist_ok=True)
    (checkout / 'hosts').write_text('[local]\nlocalhost ansible_connection=local\n')
    (checkout / 'site.yml').write_text(
        '- hosts: local\n'
        '  gather_facts: false\n'
        '  tasks:\n'
        '    - name: the encrypted variable must arrive\n'
        '      assert:\n'
        '        that: db_password == "%s"\n'
        '      tags: [deploy]\n'
        '    - name: a date valued variable must survive the trip\n'
        '      assert:\n'
        '        that: cert_expiry == "2026-01-01"\n'
        '      tags: [deploy]\n' % SECRET)
    with db.deploy_conn() as conn:
        pid = conn.execute('INSERT INTO project (name, working_dir, branch) '
                           "VALUES ('proj',?,'main')", (str(checkout),)).lastrowid
        eid = conn.execute(
            'INSERT INTO environment (project_id, name, inventory, playbook, tags) '
            "VALUES (?,'live','hosts','site.yml','deploy')", (pid,)).lastrowid
        CTX['project'] = dict(conn.execute('SELECT * FROM project WHERE id=?',
                                           (pid,)).fetchone())
        CTX['env'] = dict(conn.execute('SELECT * FROM environment WHERE id=?',
                                       (eid,)).fetchone())
    CTX['eid'] = eid
    STORE.set('environment', eid, 'db_password', SECRET)
    STORE.set('environment', eid, 'cert_expiry', date(2026, 1, 1))
    STORE.cred_set('environment', eid, 'ssh_key', 'test-key',
                   *db.generate_ssh_key('test'))


def argv_is_built_from_structured_fields():
    _setup()
    argv = runner.playbook_argv(CTX['project'], CTX['env'], '/run/vars.json', '/run/k')
    checkout = Path(CTX['project']['working_dir'])
    assert argv == [runner.ANSIBLE_PLAYBOOK, str(checkout / 'site.yml'),
                    '-i', str(checkout / 'hosts'), '--tags', 'deploy',
                    '-e', '@/run/vars.json', '--private-key', '/run/k'], argv
    env = runner._ansible_env(CTX['env'])
    assert env['PATH'].startswith(runner.VENV_BIN), 'ansible-connection is found on PATH'
    assert env['ANSIBLE_HOST_KEY_CHECKING'] == 'True', \
        'a repo ansible.cfg must not be able to turn host key checking off'
    assert 'ANSIBLE_BECOME' not in env
    assert runner._ansible_env(dict(CTX['env'], become=1))['ANSIBLE_BECOME'] == 'True'


def a_run_may_choose_its_own_tags():
    """A deploy picks tags for that run; blank means the environment's own, and
    an empty string deliberately drops a stored one."""
    stored = dict(CTX['env'], tags='deploy', skip_tags='migrations')
    argv = runner.playbook_argv(CTX['project'], stored)
    assert argv[argv.index('--tags') + 1] == 'deploy'
    assert argv[argv.index('--skip-tags') + 1] == 'migrations'

    override = runner.with_tags(stored, tags='config,web', skip_tags='slow')
    argv = runner.playbook_argv(CTX['project'], override)
    assert argv[argv.index('--tags') + 1] == 'config,web'
    assert argv[argv.index('--skip-tags') + 1] == 'slow'

    assert runner.with_tags(stored)['tags'] == 'deploy', 'None keeps the stored one'
    cleared = runner.playbook_argv(CTX['project'],
                                   runner.with_tags(stored, tags='', skip_tags=''))
    assert '--tags' not in cleared and '--skip-tags' not in cleared, cleared

    # an override is validated by the same gate the stored value goes through
    for field in ('tags', 'skip_tags'):
        for bad in ('deploy; rm -rf /', '$(whoami)', 'a b', 'ok\n'):
            try:
                runner.playbook_argv(CTX['project'],
                                     runner.with_tags(stored, **{field: bad}))
                raise AssertionError(f'{field}={bad!r} must be rejected')
            except ValueError:
                pass


def git_remotes_are_https_or_ssh_only():
    """ext:: runs a shell, file: and bare paths clone from anywhere on the box."""
    for ok in ('https://github.com/org/repo.git', 'ssh://git@host/org/repo',
               'git@github.com:org/repo.git', 'https://gh.example:8443/o/r', None, ''):
        runner.check_remote(ok)
    for bad in ('ext::sh -c id', 'file:///tmp/x', '/tmp/x', 'git://h/r',
                'https://user:pw@h/r', 'https://h/r;id', '-oProxyCommand=id'):
        try:
            runner.check_remote(bad)
            raise AssertionError(f'{bad!r} must be refused')
        except ValueError:
            pass
    assert runner._git_env(None)['GIT_ALLOW_PROTOCOL'] == 'https:ssh'
    for bad in ('relative/dir', str(runner.ROOT), str(runner.ROOT / 'src'),
                str(db.DATA), str(db.RUN_DIR / 'x'), str(db.BACKUP_DIR)):
        try:
            runner.check_working_dir(bad)
            raise AssertionError(f'{bad!r} must be refused as a checkout dir')
        except ValueError:
            pass
    assert runner.check_working_dir(CTX['project']['working_dir'])
    hostile = dict(CTX['project'], git_remote='ext::sh -c id',
                   working_dir=str(WORK / 'nowhere'))
    said = []
    assert runner.git_sync(hostile, STORE, 'tester',
                           notify=lambda msg, log=None: said.append(msg)) is None
    assert said and 'clone URL' in said[0], said
    assert not (WORK / 'nowhere').exists(), 'nothing may be created before the check'


def stored_fields_cannot_become_raw_argv():
    for field, value, why in (
            ('playbook', '--become-user=root', 'a leading dash'),
            ('inventory', '-i/etc/shadow', 'a leading dash'),
            ('tags', 'deploy; rm -rf /', 'shell metacharacters'),
            ('tags', '$(whoami)', 'command substitution'),
            ('playbook', '../../../etc/passwd', 'path traversal')):
        try:
            runner.playbook_argv(CTX['project'], dict(CTX['env'], **{field: value}))
            raise AssertionError(f'{field}={value!r} must be rejected ({why})')
        except ValueError:
            pass


def dates_survive_json_extravars():
    """Extra-vars travel as JSON, which has no date type."""
    out = runner.json_safe({'d': date(2026, 1, 1), 'nested': {'l': [date(2027, 2, 3)]},
                            'plain': 'x', 'n': 7})
    assert out == {'d': '2026-01-01', 'nested': {'l': ['2027-02-03']},
                   'plain': 'x', 'n': 7}, out


def a_real_playbook_runs():
    before = set(db.RUN_DIR.iterdir())
    job_id = runner.deploy(CTX['project'], CTX['env'], STORE, 'tester')
    with db.deploy_conn() as conn:
        job = dict(conn.execute('SELECT * FROM job WHERE id=?', (job_id,)).fetchone())
    CTX['log'] = job['log']
    assert job['status'] == 'ok', job['log']
    assert job['exit_code'] == 0 and job['triggered_by'] == 'tester', job
    assert 'ok=2' in job['log'], job['log']
    assert set(db.RUN_DIR.iterdir()) == before, \
        'the private data dir and the key file must both be removed'


def secrets_are_redacted_from_the_log():
    assert SECRET not in CTX['log'], 'the secret leaked into the stored log'
    assert 'PRIVATE KEY' not in CTX['log'], 'the ssh key leaked into the stored log'
    text = 'password: sesame-open-up and short: ab'
    out = runner.redact(text, ['sesame-open-up', 'ab'])
    assert 'sesame-open-up' not in out and '***' in out
    assert 'ab' in out, 'values under 4 characters are too noisy to redact'


def nested_and_escaped_values_are_redacted_too():
    """Ansible prints mappings as JSON, so inner values and escaped spellings must match."""
    values = [{'db': {'pw': 'in-a-mapping'}, 'hosts': ['listed-secret']},
              'line\nbreak', 'quo"ted', 7, True]
    text = ('{"pw": "in-a-mapping", "h": ["listed-secret"], '
            '"m": "line\\nbreak", "q": "quo\\"ted", "n": 7, "b": true}')
    out = runner.redact(text, values)
    for leaked in ('in-a-mapping', 'listed-secret', 'line\\nbreak', 'quo\\"ted'):
        assert leaked not in out, f'{leaked!r} survived: {out}'
    assert '"n": 7' in out and 'true' in out, 'short numbers and booleans stay'


def extravars_never_touch_argv():
    """-e '{json}' on the command line is readable by every local user in
    /proc/*/cmdline. Ours must go through a 0600 file."""
    workdir = tempfile.mkdtemp(dir=str(db.RUN_DIR))
    try:
        path = runner.write_extravars(workdir, {'db_password': SECRET})
        argv = runner.playbook_argv(CTX['project'], CTX['env'], path)
        assert SECRET not in ' '.join(argv), argv
        assert '@' + path in argv and path.startswith(workdir), argv
        assert Path(path).stat().st_mode & 0o777 == 0o600
    finally:
        import shutil
        shutil.rmtree(workdir)


def no_process_ever_carries_the_secret():
    """Run a playbook slow enough to be caught mid-flight and scan /proc while it lives."""
    checkout = Path(CTX['project']['working_dir'])
    (checkout / 'slow.yml').write_text(
        '- hosts: local\n  gather_facts: false\n  tasks:\n'
        '    - wait_for: {timeout: 3}\n')
    with db.deploy_conn() as conn:
        eid = conn.execute('INSERT INTO environment (project_id, name, inventory, playbook) '
                           "VALUES (?,'slow','hosts','slow.yml')",
                           (CTX['project']['id'],)).lastrowid
        env = dict(conn.execute('SELECT * FROM environment WHERE id=?', (eid,)).fetchone())
    STORE.set('environment', eid, 'db_password', SECRET)
    seen, leaked, done = set(), [], threading.Event()

    def scan():
        while not done.is_set():
            for proc in Path('/proc').glob('[0-9]*'):
                try:
                    argv = (proc / 'cmdline').read_bytes().decode('utf-8', 'replace')
                except OSError:
                    continue
                if 'ansible-playbook' in argv and str(checkout) in argv:
                    seen.add(proc.name)
                    if SECRET in argv:
                        leaked.append(argv)
            time.sleep(0.05)

    watcher = threading.Thread(target=scan, daemon=True)
    watcher.start()
    try:
        job_id = runner.deploy(CTX['project'], env, STORE, 'tester')
    finally:
        done.set()
        watcher.join()
    with db.deploy_conn() as conn:
        job = dict(conn.execute('SELECT * FROM job WHERE id=?', (job_id,)).fetchone())
    assert job['status'] == 'ok', job['log']
    assert seen, 'the watcher never saw ansible-playbook, so the check proved nothing'
    assert not leaked, f'secret visible in /proc cmdline: {leaked[0][:200]}'


def project_hosts_become_the_inventory():
    """Hosts on the project are written out as an inventory and, where a key is
    pinned, a known_hosts file; an environment with no inventory file uses them alone."""
    checkout = Path(CTX['project']['working_dir'])
    (checkout / 'managed.yml').write_text(
        '- hosts: local\n  connection: local\n  gather_facts: false\n  tasks:\n'
        '    - assert:\n        that: db_password == "%s"\n' % SECRET)
    with db.deploy_conn() as conn:
        pid = conn.execute("INSERT INTO project (name, working_dir, branch) "
                           "VALUES ('managed',?,'main')", (str(checkout),)).lastrowid
        eid = conn.execute('INSERT INTO environment (project_id, name, inventory, playbook) '
                           "VALUES (?,'live',NULL,'managed.yml')", (pid,)).lastrowid
        project = dict(conn.execute('SELECT * FROM project WHERE id=?', (pid,)).fetchone())
        env = dict(conn.execute('SELECT * FROM environment WHERE id=?', (eid,)).fetchone())
    try:
        runner.playbook_argv(project, env)
        raise AssertionError('no inventory file and no hosts must be refused')
    except ValueError:
        pass
    _, public = db.generate_ssh_key('host')
    pinned = public.rsplit(' ', 1)[0]
    db.host_set(pid, 'box', '127.0.0.1', 'local')
    db.host_set(pid, 'db1.example', None, 'db, web', pinned + ' a comment')
    for bad in (('a b',), ('ok', 'x\n[evil]'), ('ok', None, 'g;h'), ('ok', None, None, 'rubbish'),
                ('ok', None, None, 'ssh-ed25519 !!!'), ('ok', None, None, 'ssh-dss AAAA')):
        try:
            db.check_host(*bad)
            raise AssertionError(f'{bad!r} must be refused')
        except ValueError:
            pass
    rows = db.hosts(pid)
    assert [h['name'] for h in rows] == ['box', 'db1.example'], rows
    assert rows[1]['groups'] == 'db,web' and rows[1]['ssh_host_key'] == pinned
    assert rows[1]['fingerprint'].startswith('SHA256:') and rows[0]['fingerprint'] is None
    workdir = tempfile.mkdtemp(dir=str(db.RUN_DIR))
    try:
        inv = Path(runner.write_inventory(workdir, rows)).read_text()
        assert inv == ('box ansible_host=127.0.0.1\ndb1.example\n'
                       '[db]\ndb1.example\n[local]\nbox\n[web]\ndb1.example\n'), inv
        known = runner.write_known_hosts(workdir, rows)
        assert Path(known).read_text() == f'db1.example {pinned}\n'
        extra = runner._ansible_env(env, known)['ANSIBLE_SSH_EXTRA_ARGS']
        assert known in extra and 'UserKnownHostsFile' in extra, extra
        assert runner.write_known_hosts(workdir, rows[:1]) is None, 'nothing pinned, no file'
        argv = runner.playbook_argv(project, env, inventory_path=known)
        assert '-i' in argv and argv.count('-i') == 1, argv
    finally:
        import shutil
        shutil.rmtree(workdir)
    STORE.set('environment', eid, 'db_password', SECRET)
    job_id = runner.deploy(project, env, STORE, 'tester')
    with db.deploy_conn() as conn:
        job = dict(conn.execute('SELECT * FROM job WHERE id=?', (job_id,)).fetchone())
    assert job['status'] == 'ok' and 'ok=1' in job['log'], job['log']
    with db.deploy_conn() as conn:
        conn.execute('DELETE FROM project WHERE id=?', (pid,))
        assert conn.execute('SELECT count(*) FROM host WHERE project_id=?',
                            (pid,)).fetchone()[0] == 0, 'hosts go with their project'


def a_host_update_never_silently_unpins_the_key():
    """The web form's key box is always empty, so an edit that omits the key must
    keep the pin: losing it downgrades the host to the unpinned fallback."""
    pid = CTX['project']['id']
    _, public = db.generate_ssh_key('host')
    pinned = public.rsplit(' ', 1)[0]
    db.host_set(pid, 'keeper', '10.0.0.9', 'web', pinned)
    name, key = db.host_set(pid, 'keeper', '10.0.0.10', 'web')      # address only
    assert key == pinned, 'omitting the key must not unpin the host'
    row = [h for h in db.hosts(pid) if h['name'] == 'keeper'][0]
    assert row['ssh_host_key'] == pinned and row['address'] == '10.0.0.10', row
    db.host_delete(pid, 'keeper')


def host_fields_cannot_reach_ssh_as_options_or_extra_lines():
    """Both become the ssh destination and a known_hosts line, so a leading dash
    is an option and a trailing newline is a second line. `$` matches before a
    trailing newline, which is why every pattern here uses fullmatch."""
    for bad in ('web1\n', '-E', '-oProxyCommand'):
        try:
            db.check_host(bad)
            raise AssertionError(f'name {bad!r} must be refused')
        except ValueError:
            pass
    try:
        db.check_host('h', '-E')
        raise AssertionError('an address may not start with "-"')
    except ValueError:
        pass
    try:
        db.check_host('h', None, 'web\n')
        raise AssertionError('a group may not carry a newline')
    except ValueError:
        pass
    assert runner.SAFE_REMOTE.fullmatch('https://h/r\n') is None
    assert runner.SAFE_TAGS.fullmatch('deploy\n') is None
    try:
        runner.check_remote('https://github.com/o/r\n')
        raise AssertionError('a remote may not carry a newline')
    except ValueError:
        pass


def host_key_checking_does_not_depend_on_pinning_state():
    """Set only when something was pinned, a repo's own ssh_extra_args became
    authoritative exactly when no key was pinned."""
    for known in (None, '/run/known_hosts'):
        extra = runner._ansible_env(CTX['env'], known)['ANSIBLE_SSH_EXTRA_ARGS']
        assert 'StrictHostKeyChecking=yes' in extra, extra
        assert '~/.ssh/known_hosts' in extra, extra
        assert (known or 'nothing') in extra or known is None, extra


def a_timed_out_run_kills_the_whole_tree():
    """ansible forks a worker per host; killing only the parent leaves them
    touching production after the key file has been deleted under them."""
    def sleepers():
        """Only real sleep processes: a shell quoting this file would match a grep."""
        out = []
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                argv = (proc / 'cmdline').read_bytes().decode('utf-8', 'replace')
            except OSError:
                continue
            if argv.startswith('sleep\x004077'):
                out.append(proc.name)
        return out

    # the background sleep holds the stdout pipe, so a parent that exits first
    # used to leave communicate() blocked on forks nothing was going to kill
    for script in ('sleep 4077 & sleep 4077', 'sleep 4077 & exit 0'):
        code, out = runner._run(['sh', '-c', script], '/tmp', timeout=2)
        assert code == 124 and 'killed after 2s' in out, (script, code, out)
        time.sleep(0.2)
        assert not sleepers(), f'orphans survived the timeout ({script}): {sleepers()}'


def a_failure_before_the_run_releases_the_claim():
    """A store error used to leave the environment "already running" until restart."""
    class Broken:
        def extra_vars(self, *a):
            raise RuntimeError('store went away')
    job_id = runner.deploy(CTX['project'], CTX['env'], Broken(), 'tester')
    with db.deploy_conn() as conn:
        job = dict(conn.execute('SELECT * FROM job WHERE id=?', (job_id,)).fetchone())
    assert job['status'] == 'error' and 'store went away' in job['log'], job
    assert runner._claim({f"env:{CTX['eid']}"}), 'the claim must be released on failure'
    runner._release({f"env:{CTX['eid']}"})


def a_restart_marks_running_jobs_lost():
    with db.deploy_conn() as conn:
        jid = conn.execute("INSERT INTO job (kind, status) VALUES ('deploy','running')").lastrowid
    assert runner.reap_running() == 1
    with db.deploy_conn() as conn:
        row = conn.execute('SELECT status, finished_at FROM job WHERE id=?', (jid,)).fetchone()
    assert row['status'] == 'lost' and row['finished_at'], dict(row)


def no_ssh_agent_is_left_behind():
    left = stray_agents()
    assert not left, f'{len(left)} ssh-agent(s) left holding the deploy key: {left}'


def a_second_deploy_is_refused_while_one_runs():
    runner._claim({f"env:{CTX['eid']}"})
    try:
        assert runner.deploy(CTX['project'], CTX['env'], STORE, 'tester') is None, \
            'a concurrent deploy of the same environment must be refused'
    finally:
        runner._release({f"env:{CTX['eid']}"})


if __name__ == '__main__':
    sys.exit(harness.run(
        argv_is_built_from_structured_fields, stored_fields_cannot_become_raw_argv,
        git_remotes_are_https_or_ssh_only, a_run_may_choose_its_own_tags,
        dates_survive_json_extravars, a_real_playbook_runs,
        secrets_are_redacted_from_the_log, nested_and_escaped_values_are_redacted_too,
        extravars_never_touch_argv, no_process_ever_carries_the_secret,
        no_ssh_agent_is_left_behind, a_second_deploy_is_refused_while_one_runs,
        project_hosts_become_the_inventory, a_host_update_never_silently_unpins_the_key,
        host_fields_cannot_reach_ssh_as_options_or_extra_lines,
        host_key_checking_does_not_depend_on_pinning_state,
        a_timed_out_run_kills_the_whole_tree,
        a_failure_before_the_run_releases_the_claim, a_restart_marks_running_jobs_lost))
