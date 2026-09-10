CREATE TABLE IF NOT EXISTS project (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  working_dir TEXT NOT NULL,
  branch TEXT NOT NULL DEFAULT 'master',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS environment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  inventory TEXT NOT NULL,
  playbook TEXT NOT NULL,
  tags TEXT,
  limit_hosts TEXT,
  become INTEGER NOT NULL DEFAULT 0,
  UNIQUE(project_id, name)
);
CREATE TABLE IF NOT EXISTS user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pw_hash BLOB NOT NULL,
  pw_salt BLOB NOT NULL,
  slack_user_id TEXT,
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
