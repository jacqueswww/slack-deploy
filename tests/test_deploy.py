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
    """ansible-runner's ssh_key= wraps the run in an ssh-agent that outlives it,
    leaving the decrypted key resident in memory. We must never leave one."""
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
    kwargs = runner.runner_kwargs(CTX['project'], CTX['env'])
    checkout = Path(CTX['project']['working_dir'])
    assert kwargs['playbook'] == str(checkout / 'site.yml'), kwargs
    assert kwargs['inventory'] == str(checkout / 'hosts'), kwargs
    assert kwargs['cmdline'] == '--tags deploy', kwargs
    assert runner.VENV_BIN in kwargs['envvars']['PATH'], \
        'ansible-runner spawns through sh, so the venv must be on PATH'
    assert kwargs['envvars']['ANSIBLE_HOST_KEY_CHECKING'] == 'True', \
        'a repo ansible.cfg must not be able to turn host key checking off'
    with_become = runner.runner_kwargs(CTX['project'], dict(CTX['env'], become=1))
    assert with_become['envvars']['ANSIBLE_BECOME'] == 'True'


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
            runner.runner_kwargs(CTX['project'], dict(CTX['env'], **{field: value}))
            raise AssertionError(f'{field}={value!r} must be rejected ({why})')
        except ValueError:
            pass


def dates_survive_json_extravars():
    """ansible-runner ships extravars as JSON, which has no date type."""
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
    """ansible-runner turns extravars= into -e '{json}' on the command line, which
    every local user can read in /proc/*/cmdline. Ours must go through a file."""
    import ansible_runner
    workdir = tempfile.mkdtemp(dir=str(db.RUN_DIR))
    try:
        runner.write_extravars(workdir, {'db_password': SECRET})
        rc = ansible_runner.RunnerConfig(private_data_dir=workdir,
                                         **runner.runner_kwargs(CTX['project'], CTX['env']))
        rc.prepare()
        cmd = ' '.join(rc.command)
        assert SECRET not in cmd, cmd
        assert '-e @' in cmd and cmd.split('-e @', 1)[1].startswith(workdir), cmd
        assert (Path(workdir) / 'env' / 'extravars').stat().st_mode & 0o777 == 0o600
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
        git_remotes_are_https_or_ssh_only,
        dates_survive_json_extravars, a_real_playbook_runs,
        secrets_are_redacted_from_the_log, nested_and_escaped_values_are_redacted_too,
        extravars_never_touch_argv, no_process_ever_carries_the_secret,
        no_ssh_agent_is_left_behind, a_second_deploy_is_refused_while_one_runs,
        a_failure_before_the_run_releases_the_claim, a_restart_marks_running_jobs_lost))
