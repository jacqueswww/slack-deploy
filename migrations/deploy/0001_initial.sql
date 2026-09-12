CREATE TABLE IF NOT EXISTS project (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  working_dir TEXT NOT NULL,
  branch TEXT NOT NULL DEFAULT 'master',
  -- clone URL; https remotes authenticate with the github_pat credential,
  -- ssh remotes with the daemon user's own key
  git_remote TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS environment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  -- inventory file in the checkout; NULL means the project's host table alone
  inventory TEXT,
  playbook TEXT NOT NULL,
  tags TEXT,
  limit_hosts TEXT,
  become INTEGER NOT NULL DEFAULT 0,
  UNIQUE(project_id, name)
);
-- Target hosts a project deploys to. Written out as an inventory at run time
-- (name, ansible_host=address, one [group] section per group) and, where a host
-- key is pinned, as a known_hosts file, so a first connection is never trust on
-- first use and a changed key fails the run.
CREATE TABLE IF NOT EXISTS host (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  address TEXT,
  groups TEXT,
  ssh_host_key TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(project_id, name)
);
CREATE TABLE IF NOT EXISTS user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pw_hash BLOB NOT NULL,
  pw_salt BLOB NOT NULL,
  slack_user_id TEXT,
  -- sealed under the user's password (db.wrap_totp), never a bare seed
  totp_secret TEXT,
  totp_confirmed INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS job (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER,
  environment_id INTEGER,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  exit_code INTEGER,
  triggered_by TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  log TEXT
);
CREATE TABLE IF NOT EXISTS schedule (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  target_id INTEGER,
  at_time TEXT NOT NULL,
  weekdays TEXT NOT NULL DEFAULT '*',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_on TEXT,
  created_by TEXT
);
CREATE TABLE IF NOT EXISTS scheduler_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  pid INTEGER,
  heartbeat_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  actor TEXT,
  action TEXT NOT NULL,
  detail TEXT
);
