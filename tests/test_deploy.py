#!/usr/bin/env python3
"""A real ansible run: argv construction, extravars delivery, redaction, cleanup."""
import sys
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
    with_become = runner.runner_kwargs(CTX['project'], dict(CTX['env'], become=1))
    assert with_become['envvars']['ANSIBLE_BECOME'] == 'True'


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
        dates_survive_json_extravars, a_real_playbook_runs,
        secrets_are_redacted_from_the_log, no_ssh_agent_is_left_behind,
        a_second_deploy_is_refused_while_one_runs))
