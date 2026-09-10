-- Credentials, as opposed to variables: these become files and command-line
-- flags at deploy time, never `-e` extra-vars. Linked by the same
-- (scope, scope_id) pair the secret table uses; environment beats project
-- beats global.
CREATE TABLE IF NOT EXISTS credential (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL CHECK (scope IN ('global','project','environment')),
  scope_id INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL CHECK (kind IN ('ssh_key','github_pat')),
  name TEXT NOT NULL,
  secret TEXT NOT NULL,
  public TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT,
  UNIQUE(scope, scope_id, kind)
);
