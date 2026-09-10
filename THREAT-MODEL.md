# Threat model

What this tool protects, who is assumed to attack it, where each attack lands,
and what stands in the way. The adversary is assumed to have nation-state means:
zero-days, supply-chain reach, patience, and physical access to hardware they can
get near. Each item says whether the defence is in the code, in the deployment
this repository ships (`deploy/`, `manage.py doctor`), or out of reach.

## Assets, most to least valuable

1. **The global passphrase and the key derived from it.** Opens `secrets.db`.
   Exists as a bytearray in the bot process for its lifetime and in the web
   process per unlocked session. Never on disk, never in argv, never logged.
2. **`secrets.db` contents.** Ansible extra-vars (database passwords, API keys),
   SSH deploy keys, GitHub PATs, Slack tokens. SQLCipher, AES-256-CBC + HMAC-SHA512,
   key from scrypt N=2^18 over a 20+ character passphrase.
3. **Deploy capability.** Running a playbook is running code on every target host
   as the deploy user, usually with `become`.
4. **Deploy configuration** (`deploy.db`, plaintext): which repo, branch, playbook
   and inventory run. Changing it turns the next legitimate deploy into a hostile one.
5. **Web credentials**: scrypt password hashes and TOTP seeds sealed under those
   passwords. Slack user IDs that grant deploy rights through the bot.
6. **Job logs and audit trail.** Redacted, but hostnames, paths and timing leak.

## Actors

| Actor | Has | Wants |
|---|---|---|
| Network adversary | Position on the path to the web UI, to Slack, to GitHub, to the target hosts | Credentials in transit, session cookies, MITM of SSH or git |
| Compromised web user | A user's password, or their browser | Secrets, deploy rights, config changes |
| Compromised Slack account | A linked user's Slack session | Trigger deploys |
| Compromised ansible repo | Push access, the PAT, or GitHub itself | Code execution as the daemon, cross-project secrets |
| Local same-uid process | A shell as the daemon user (via a hostile playbook, most likely) | The key in memory, plaintext vars in flight, the code tree |
| Local other-uid process | Any account on the host | The same, via /proc, ptrace, world-readable files |
| Root or the hypervisor | Everything on the box | Everything |
| Backup thief | A copy of `backups/` or `data/` | Secrets offline, or a tampered restore |
| Supply chain | PyPI, the mirror, a maintainer account, the OS packages, the CPU | Trojaned code that sees the passphrase |
| Physical | The powered box, its RAM, its bus, its disks | Cold-boot, DMA, disk imaging |

## Surfaces and defences

### Web interface (`src/web.py`)

- **Transport.** Refuses plain HTTP off loopback; serves TLS itself with HSTS, or
  is reached over an SSH forward. Cookie: HttpOnly, SameSite=Strict, Secure under TLS.
- **Authentication.** Password (scrypt) then TOTP then the global passphrase.
  Unknown usernames cost a scrypt too. Lockouts per factor double from 5 minutes
  to an hour until a success; every lockout is a WARNING in the log. Sessions: 2 h
  hard cap, 5 min idle relock on a TOTP code, RAM only, regenerated at login.
- **Authorisation.** Every request re-reads the user row: disable, delete and
  demote bite on the next request. Admin-only: config, users, secrets, reveal,
  export, backup. Reveal is POST-only and audited.
- **CSRF.** Per-session token on every POST plus Origin/Host check plus SameSite.
- **Injection.** Parameterised SQL throughout. Jinja autoescape. CSP with a
  per-request nonce, `default-src 'none'`, no inline handlers, no third-party
  script, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`. Bodies capped
  at 1 MB; user YAML may not use aliases.
- **Denial of service.** The lockout counter is global per factor by design (all
  clients arrive as 127.0.0.1 over a forward). An attacker with network reach can
  therefore keep legitimate users locked out. Accepted: reaching the port at all
  requires a foothold, and the audit log shows it.
- **Residual.** A compromised admin *browser* with a live unlocked session has the
  admin's powers for up to 5 minutes idle / 2 hours total. A zero-day in CherryPy,
  Jinja or Python is not mitigated by anything but the CSP, the pinned versions
  and the systemd sandbox.

### Slack bot (`src/bot.py`)

- Socket Mode over Slack's authenticated websocket: no inbound port, no signing
  secret to leak. Commands are `list`, `deploy <project>/<env>`, `refresh-repos`;
  arguments match database rows exactly, nothing is interpolated.
- Authorisation is by Slack user ID against the user table. **A compromised Slack
  account of a linked user can trigger any configured deploy.** It cannot change
  what gets deployed. Accepted, that is the bot's purpose; Slack's own 2FA is the
  control, and every denied and executed command is audited.
- Logs posted to the channel are redacted against every secret value the run was
  given (nested and JSON-escaped spellings). Redaction is best-effort: a secret
  that ansible transforms before printing is not caught. Prefer `no_log: true` in
  playbooks that touch secrets.

### Job execution (`src/runner.py`)

- `ansible-playbook` argv is built from typed columns; no field may start with `-`,
  tags are an allow-listed alphabet, playbook and inventory must resolve inside the
  checkout. A free-text params field would be arbitrary argv, which is code
  execution as the daemon.
- Extra-vars go to a 0600 file in a 0700 dir and are passed as `-e @file`, never on
  the command line (`/proc/*/cmdline` is world-readable). The SSH key is a 0600
  file for the life of the run; never `ssh_key=`, which leaves an `ssh-agent`
  holding the decrypted key forever. Both are removed on exit, on SIGTERM and at
  interpreter exit.
- `ANSIBLE_HOST_KEY_CHECKING=True` is forced; a repo's `ansible.cfg` cannot turn
  it off. Under the shipped unit `~/.ssh/known_hosts` is read-only, so a host key
  must be provisioned before the first deploy, and a changed one fails the run.
- Git: remotes must be https, ssh:// or scp-style and `GIT_ALLOW_PROTOCOL=https:ssh`
  is set, so `ext::` cannot run a shell and `file:` cannot clone from elsewhere on
  the box. The PAT reaches git through `GIT_ASKPASS`, never argv or the remote URL.
  Pulls are `--ff-only` on a fixed branch and time out.
- **Residual, and the largest one.** A playbook runs as the daemon's uid. Anyone
  who controls what is checked out (push access, the PAT, a GitHub compromise,
  write access to the checkout) runs code as that uid. What that uid can do is
  the deployment's problem, see below. What the code guarantees is only that it
  cannot read the key from the daemon's memory (`PR_SET_DUMPABLE=0`) and that it
  gets only the variables of the environment being deployed. Commit signature
  verification is not implemented: it would need a keyring and a policy per
  project, and a signed hostile commit is still hostile. Review the repo.

### Local host

- **Same uid.** `PR_SET_DUMPABLE=0` blocks ptrace and `/proc/<pid>/mem` from the
  same uid; `RLIMIT_CORE=0` blocks core files; the key page is `mlock`ed and the
  SQLCipher copy is under `cipher_memory_security` (mlock + wipe). The passphrase
  is read into a bytearray and wiped after derivation in the CLI and bot; in the
  web process it arrives as a request parameter and is an immutable str until the
  allocator reuses it. What a same-uid process *can* do: read `deploy.db`, write
  to `data/run/` while another deploy is in flight, and, unless the filesystem
  says otherwise, rewrite `src/`, `venv/` and other projects' checkouts. That is
  why `deploy/slack-deploy-*.service` set `ProtectSystem=strict` with only `data/`,
  `backups/` and the checkouts writable, drop every capability, forbid new
  privileges and namespaces, and filter syscalls; and why `doctor` flags a code
  tree writable by the uid that runs it.
- **Other uid.** Every file under `data/` and `backups/` is 0600 in a 0700
  directory; `doctor` checks. `deploy.db` is plaintext but holds nothing that is a
  factor on its own: scrypt hashes, TOTP seeds sealed under those passwords, config.
  Yama `ptrace_scope>=1` (`deploy/sysctl-slack-deploy.conf`) stops cross-process
  inspection that `PR_SET_DUMPABLE` does not cover.
- **Root, the hypervisor, the kernel.** Out of reach. Root reads process memory,
  a hypervisor reads guest RAM, a kernel zero-day is root. The design limits the
  *time* the key exists in the web process (per session, 2 h max) and puts it in
  exactly one long-lived process (the bot). The bot's unit is the sandbox; keep
  the kernel patched.
- **Side channels.** Timing: constant-time comparison for passwords, TOTP codes
  and CSRF tokens; scrypt is memory-hard, so the KDF is not the leak. Cache and
  speculative-execution attacks from a co-resident process against AES or scrypt
  are a kernel and CPU matter: `doctor` reports any entry under
  `/sys/devices/system/cpu/vulnerabilities` the kernel calls `Vulnerable`, and the
  unit forbids the daemon from being that co-resident process for anyone else.
  AES is OpenSSL's, AES-NI where the CPU has it (constant time); without AES-NI a
  same-core attacker with a cache side channel is in reach of the key. Power and
  EM analysis need physical access and are not mitigated.

### Data at rest

- `secrets.db`: SQLCipher 4, HMAC-SHA512, key from scrypt N=2^18 r=8 (256 MiB)
  over a 20+ character passphrase with a random 16-byte salt held in `kdf.json`.
  Brute force is ~0.7 s and 256 MiB per guess per core; a 20-character
  passphrase from a decent process is out of reach of any budget. The KDF params
  are stored with the salt, so raising them never bricks a store; `rekey` upgrades.
- `deploy.db`: plaintext by design (the web process must start without a
  passphrase). Contents rated above. Backups seal it.
- **Backups**: `kdf.json` in the clear plus one AES-256-GCM blob under
  HMAC-SHA256(store key, "slack-deploy backup"), `kdf.json` as associated data.
  A stolen backup is noise without the passphrase; a tampered one refuses to
  restore, which closes the path "doctor a backup, get it restored, own a project
  row, wait for the next Slack deploy". There is no unauthenticated backup.
- **Key storage: why no TPM, HSM or enclave.** Sealing the key to the machine would
  let the machine open the store unattended, so any code execution on it (the
  hostile playbook above) is every secret. The design instead requires a human to
  type the passphrase at daemon start and keeps nothing on disk that can become
  the key. The cost is a restart needs a person. A TPM would add "and this
  hardware" to "this passphrase", useful against a stolen disk image, which
  scrypt over a 20-character passphrase already defeats. Not implemented.
- **Swap and hibernation.** Key pages are mlocked, but Python's own copies (the
  passphrase str in the web process, the `bytes` scrypt returns before it is
  copied into the bytearray) are not. `doctor` flags active swap. Use encrypted
  swap, zram, or none; never hibernate the host.
- **Disk theft.** `secrets.db` is as above; `deploy.db` and `kdf.json` are not
  secret on their own. Full-disk encryption is still recommended for the logs.

### Physical

- **Cold boot.** DRAM remanence recovers whatever was in RAM at power-off: the
  bot's key, the web sessions' keys, plaintext vars mid-deploy. Not mitigated by
  software beyond minimising copies and wiping on close. Mitigation is physical
  and platform: memory encryption (AMD SME/SEV, Intel TME) where available, and
  a machine no one can walk up to.
- **DMA.** A hostile PCIe or Thunderbolt device reads RAM unless the IOMMU is on;
  `doctor` flags a host without IOMMU groups.
- **Chip decapping, firmware implants, evil-maid on the boot chain.** Out of scope
  for a Python service. Measured boot and a locked BIOS are the platform's answer.

### Supply chain

- **Python packages.** `requirements.txt` pins every package, transitive included,
  with the sha256 of every published wheel; `make setup` installs with
  `--require-hashes`, so a package that does not match what was recorded at lock
  time is refused. This defeats a poisoned mirror, a hijacked later release and a
  MITM of PyPI. It does not defeat a release that was already hostile when
  locked: review upgrades, run `make lock` deliberately.
- **The crypto library.** At every start, before any passphrase is read, scrypt,
  AES-GCM and SHA-256 are checked against published known answers (RFC 7914,
  NIST GCM test vectors). A swapped libcrypto that gives different answers stops
  the process. One that gives the right answers and also copies the key elsewhere
  is not detectable this way; OpenSSL comes from the OS, keep it patched and
  verify the package signature.
- **Ansible collections and the playbooks.** Code from the repo, executed as the
  daemon. See Job execution.
- **The OS, the kernel, the CPU microcode.** Out of scope; `doctor` reports what
  the kernel says about the CPU.
- **This repository.** Reviewed changes, CI runs the full suite on every push,
  and the suite includes the negative checks (a leaked secret in a log, a stray
  ssh-agent, a tampered backup, a swapped crypto answer) that would fail loudly.

## Detection

Every login, failure, lockout, unlock, reveal, export, config change and deploy
is a row in `audit` and a line on the `audit` logger. The table is in `deploy.db`
and editable by the uid; the log line goes to journald and from there wherever
the host forwards logs, which is the copy that counts. Lockouts are WARNINGs. A
sustained TOTP brute force at the capped rate is 120 rows a day under one name.

## Deployment requirements, in order of consequence

1. The daemon runs as its own uid that owns `data/`, `backups/` and the checkouts
   and nothing else; `src/`, `venv/` and `manage.py` are root-owned. Use the units
   in `deploy/`. `doctor` fails until this holds.
2. The web UI is reached over an SSH forward or with `--tls-cert`; never a plain
   port on a network.
3. `deploy/sysctl-slack-deploy.conf` applied; swap encrypted or absent; IOMMU on.
4. Every ansible repo is treated as code that runs on the deploy box, because it
   does: protected branches, review, no untrusted collections.
5. Passphrase 20+ characters, given at start by a person, held by as few people
   as possible; `rekey` when one of them leaves.
6. Logs forwarded off the box.

## Not defended, stated plainly

- Root, the hypervisor, or a kernel zero-day on the deploy host.
- A hostile change to an ansible repo by someone with legitimate push access.
- A compromised admin browser during a live session.
- A compromised Slack account triggering configured deploys.
- Cold-boot, bus and firmware attacks by someone at the machine.
- A cryptographic library that gives correct answers and also leaks.
- Denial of service against the web login by anyone who can reach the port.
