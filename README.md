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
- **Hosts per project.** Name, address, groups and an optional pinned SSH host
  key. Written out as the inventory for each run, alone or beside the
  environment's inventory file, and as a known_hosts file, so a changed host key
  fails the deploy instead of being accepted.
- **Git sync.** Clone or fast-forward each project's repo on demand or on a
  schedule, over HTTPS with a stored PAT or over SSH.
- **Backups.** Daily sealed zip of the whole data directory, 90-day retention.
  `import <zip>` brings one back from any path, after taking a full backup of the
  current state.
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

- Linux, Python 3.12, git 2.x, a Slack app with Socket Mode. Ansible is installed
  into the venv.
- Target hosts reachable over SSH from the deploy box.

## Setup

```
make setup                     # ./venv from the hash-pinned requirements.txt
make init                      # data/, both databases, the first admin
python manage.py project-add myproj --dir /srv/ansible/myproj \
    --remote https://github.com/org/myproj.git --branch main
python manage.py cred-gen deploy-key --project myproj    # prints the public key
python manage.py host-add myproj web1 --address 10.0.0.5 --groups web \
    --key "$(ssh-keyscan -t ed25519 10.0.0.5 2>/dev/null | cut -d' ' -f2-)"
python manage.py secret-set db_password --project myproj --env prod
python manage.py sync          # clone the repo
make bot                       # prompts for the passphrase, stays up
make web                       # 127.0.0.1:8080, reach over an SSH forward
make doctor                    # permissions, ownership, host posture
```

Environments are created in the web UI (admin). Every user registers 2FA on
first web login by typing the shown secret into their authenticator.

## Production

`doctor` only reports, it changes nothing. It passes when the daemon's uid owns
`data/` and `backups/` (0700) and nothing else: the checkout and `venv/` belong
to root, so a playbook that goes bad cannot rewrite the program that is next
handed the passphrase. The unit adds `ProtectSystem=strict`, which mounts
everything except the data paths read-only for the running daemon. As root:

```
# 1. service account; data, backups and checkouts are the only paths it owns
useradd --system --home-dir /var/lib/slack-deploy --create-home \
    --shell /usr/sbin/nologin slack-deploy
install -d -o slack-deploy -g slack-deploy -m 700 \
    /var/lib/slack-deploy/data /var/lib/slack-deploy/backups /srv/ansible

# 2. code and venv: root-owned, world-readable, writable by nobody else
git clone https://github.com/jacqueswww/slack-deploy /opt/slack-deploy
cd /opt/slack-deploy && make setup && chmod -R go-w /opt/slack-deploy

# 3. every manage.py command runs as the daemon uid against its data dir
SD="sudo -u slack-deploy -H env SLACK_DEPLOY_DATA=/var/lib/slack-deploy/data \
    /opt/slack-deploy/venv/bin/python /opt/slack-deploy/manage.py"
$SD init

# 4. kernel settings and units (doctor checks for both)
install -m 644 deploy/sysctl-slack-deploy.conf /etc/sysctl.d/60-slack-deploy.conf
sysctl --system
cp deploy/slack-deploy@.service /etc/systemd/system/
cp -r deploy/slack-deploy@bot.service.d /etc/systemd/system/
systemctl daemon-reload

# 5. must print "no problems found" before anything is enabled
$SD doctor

# 6. start. The bot waits for the passphrase on tty12, after every (re)start;
#    change TTYPath in the drop-in for a serial console
systemctl enable --now slack-deploy@web slack-deploy@bot
```

Use `$SD` for all later admin commands (`project-add`, `secret-set`, `sync`,
`backup`, ...). Reach the web UI over `ssh -L 8080:127.0.0.1:8080 deploybox`.
Findings doctor still lists after this are host posture (swap on disk, IOMMU
off, unmitigated CPU bugs) and need a kernel or BIOS change, not a chmod.

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
| `host-add <project> <name> [--address --groups --key]`, `host-list`, `host-rm` | A project's target hosts |
| `backup`, `import <zip>`, `rekey` | Sealed backup; replace data/ with a zip (backs up first); passphrase change |
| `schedule-add`, `schedule-list` | Daily backup or git pull at HH:MM |

## Tests

```
make test              # every file, one process each
make test T=web        # one file: auth, backup, credentials, crypto, deploy, migrate, variables, web
```

`test_deploy.py` runs a real playbook against localhost and scans `/proc` for
leaked secrets and stray ssh-agents. Layout and invariants for contributors:
`AGENTS.md`.
