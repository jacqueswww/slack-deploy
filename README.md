# slack-deploy

Runs Ansible playbooks from Slack or a web UI, with every variable, SSH key and
token held in an encrypted store that only a human-typed passphrase can open.

## What it does

- **Deploy from Slack.** `@bot deploy <project>/<env>` runs the environment's
  playbook and posts the redacted log in the thread. `list` and `refresh-repos`
  are the other two commands. Only Slack users linked to an account may use it.
- **Deploy from the web.** Dashboard of projects, environments and recent jobs
  with a Deploy button, job logs, and admin pages for configuration.
- **Encrypted store.** Variables per environment, project or global scope, typed
  (string, int, float, bool, date, yaml). Environment values override project
  values; global values never reach Ansible. SSH deploy keys and GitHub PATs are
  stored alongside and resolved narrowest scope first.
- **Structured environments.** Inventory, playbook, tags, limit and become are
  separate fields. No free-text argument string ever reaches `ansible-playbook`.
- **Git sync.** Clone or fast-forward each project's repo on demand or on a
  schedule, over HTTPS with a stored PAT or over SSH.
- **Backups.** Daily sealed zip of the whole data directory, 90-day retention,
  one-command restore.
- **Audit.** Every login, failure, unlock, reveal, export, config change and
  deploy is recorded in the database and in the process log.

## Security in brief

- Two databases: `secrets.db` is SQLCipher (AES-256, HMAC-SHA512) under a key
  derived by scrypt N=2^18 from a 20+ character passphrase; `deploy.db` holds
  configuration, scrypt password hashes and TOTP seeds sealed under each user's
  password.
- The passphrase is typed at bot start and at each web login. It is never on
  disk, in argv or in a log. The web process holds a key only inside a session:
  2 hour hard limit, 5 minute idle relock on a 2FA code.
- Web login is password, then TOTP, then the passphrase. Lockouts per factor
  escalate from 5 minutes to 1 hour. Plain HTTP is refused off loopback.
  CSP with per-request nonce, no third-party script.
- Secrets reach Ansible as a 0600 extra-vars file, never on the command line.
  Job output is redacted against every value the run was given.
- Backups are AES-GCM sealed under the store key: useless without the
  passphrase, and a tampered file refuses to restore.
- Dependencies are pinned with sha256 hashes; crypto primitives are checked
  against known answers at every start.

Full analysis, residual risks and deployment requirements: [THREAT-MODEL.md](THREAT-MODEL.md).

## Requirements

- Linux, Python 3.12, git 2.x, a Slack app with Socket Mode.
- Target hosts reachable over SSH from the deploy box.

## Setup

```
make setup                     # ./venv from the hash-pinned requirements.txt
make init                      # data/, both databases, the first admin
python manage.py project-add myproj --dir /srv/ansible/myproj \
    --remote https://github.com/org/myproj.git --branch main
python manage.py cred-gen deploy-key --project myproj    # prints the public key
python manage.py secret-set db_password --project myproj --env prod
make sync                      # clone the repo
make bot                       # prompts for the passphrase, stays up
make web                       # 127.0.0.1:8080, reach over an SSH forward
make doctor                    # permissions, ownership, host posture
```

Environments are created in the web UI (admin) or by `import-config` from an
old `config.ini`. Every user registers 2FA on first web login.

Production: install `deploy/slack-deploy-bot.service` and
`deploy/slack-deploy-web.service`, apply `deploy/sysctl-slack-deploy.conf`, run
`make doctor` until it reports no problems.

## Slack app

Socket Mode on. Bot token scopes: `chat:write`, `app_mentions:read`,
`groups:write`. Event subscription: `app_mention`. Store the tokens:

```
python manage.py secret-set slack_app_token      # xapp-...
python manage.py secret-set slack_bot_token      # xoxb-...
python manage.py user-add alice --slack-id U0123456 --admin
```

## CLI

| Command | Purpose |
|---|---|
| `init`, `migrate`, `doctor` | Create the store, apply migrations, check the host |
| `bot`, `web [--tls-cert --tls-key]` | Run the daemons |
| `user-add`, `user-list`, `user-reset-2fa` | Web and Slack users |
| `secret-set`, `secret-list`, `vars-import`, `vars-export` | Variables per scope (`--project`, `--env`) |
| `cred-set`, `cred-gen`, `cred-list`, `cred-rm` | SSH keys and GitHub PATs |
| `project-add`, `project-list`, `sync` | Repos and checkouts |
| `backup`, `restore <zip>`, `rekey` | Sealed backups, passphrase change |
| `schedule-add`, `schedule-list` | Daily backup or git pull at HH:MM |
| `import-config [path]` | Migrate a pre-store `config.ini` |

## Tests

```
make test              # every file, one process each
make test T=web        # one file: auth, backup, credentials, crypto, deploy, migrate, variables, web
```

`test_deploy.py` runs a real playbook against localhost and scans `/proc` for
leaked secrets and stray ssh-agents. Layout and invariants for contributors:
`AGENTS.md`.
