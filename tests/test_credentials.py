#!/usr/bin/env python3
"""SSH keys and the GitHub PAT: generation, scope precedence, encryption."""
import sys

import harness

import db

STORE = None
IDS = {}


def generated_keys_are_openssh():
    global STORE
    STORE = harness.new_store()
    private, public = db.generate_ssh_key('a-comment')
    assert private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'), private[:40]
    assert private.endswith('\n'), 'ssh rejects a key with no trailing newline'
    assert public.startswith('ssh-ed25519 ') and public.endswith(' a-comment'), public
    other, _ = db.generate_ssh_key()
    assert other != private, 'each call must generate a fresh key'


def credentials_are_encrypted_at_rest():
    private, public = db.generate_ssh_key('deploy-key')
    STORE.cred_set(db.GLOBAL_SCOPE, 0, 'ssh_key', 'deploy-key', private, public)
    STORE.cred_set(db.GLOBAL_SCOPE, 0, 'github_pat', 'gh-ro', 'ghp_readonly_example')
    raw = db.SECRETS_DB.read_bytes()
    assert b'PRIVATE KEY' not in raw, 'the private key must not be readable on disk'
    assert b'ghp_readonly_example' not in raw, 'the PAT must not be readable on disk'
    listed = {c['kind']: c for c in STORE.cred_list()}
    assert listed['ssh_key']['public'] == public, 'the public half is kept for reference'
    assert 'secret' not in listed['ssh_key'], 'cred_list must not return secrets'


def resolution_prefers_the_narrowest_scope():
    with db.deploy_conn() as conn:
        IDS['project'] = conn.execute(
            "INSERT INTO project (name, working_dir) VALUES ('p','/tmp')").lastrowid
        IDS['env'] = conn.execute(
            'INSERT INTO environment (project_id, name, inventory, playbook) '
            "VALUES (?,'e','h','p.yml')", (IDS['project'],)).lastrowid

    assert STORE.cred_resolve('ssh_key', IDS['project'], IDS['env'])['name'] == \
        'deploy-key', 'should fall back to global'
    STORE.cred_set('project', IDS['project'], 'ssh_key', 'project-key', 'PK')
    assert STORE.cred_resolve('ssh_key', IDS['project'], IDS['env'])['name'] == \
        'project-key', 'project beats global'
    STORE.cred_set('environment', IDS['env'], 'ssh_key', 'env-key', 'EK')
    assert STORE.cred_resolve('ssh_key', IDS['project'], IDS['env'])['name'] == \
        'env-key', 'environment beats project'
    assert STORE.cred_resolve('ssh_key', IDS['project'])['name'] == 'project-key', \
        'with no environment the project credential applies'
    assert STORE.cred_resolve('nosuchkind', IDS['project'], IDS['env']) is None


def one_credential_per_kind_and_scope():
    STORE.cred_set('project', IDS['project'], 'ssh_key', 'replacement', 'RK')
    rows = [c for c in STORE.cred_list('project', IDS['project'])
            if c['kind'] == 'ssh_key']
    assert len(rows) == 1 and rows[0]['name'] == 'replacement', rows


def credentials_are_not_ansible_variables():
    merged = STORE.extra_vars(IDS['project'], IDS['env'])
    assert merged == {}, f'credentials must never appear as extra vars: {merged}'


def deleting_and_sweeping():
    STORE.cred_delete('environment', IDS['env'], 'ssh_key')
    assert STORE.cred_resolve('ssh_key', IDS['project'], IDS['env'])['name'] == \
        'replacement'
    with db.deploy_conn() as conn:
        conn.execute('DELETE FROM environment WHERE id=?', (IDS['env'],))
        recreated = conn.execute(
            'INSERT INTO environment (project_id, name, inventory, playbook) '
            "VALUES (?,'again','h','p.yml')", (IDS['project'],)).lastrowid
    STORE.cred_set('environment', IDS['env'], 'ssh_key', 'stale', 'SK')
    STORE.orphan_sweep()
    assert STORE.cred_resolve('ssh_key', None, recreated)['name'] != 'stale', \
        'a recreated environment must not inherit a deleted one\'s credential'


if __name__ == '__main__':
    sys.exit(harness.run(
        generated_keys_are_openssh, credentials_are_encrypted_at_rest,
        resolution_prefers_the_narrowest_scope, one_credential_per_kind_and_scope,
        credentials_are_not_ansible_variables, deleting_and_sweeping))
