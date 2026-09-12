-- Variables, stored as YAML scalars so dates, lists and mappings round-trip.
-- scope_id points into deploy.db, which has no cross-file foreign key: deletes
-- there call SecretStore.orphan_sweep().
CREATE TABLE IF NOT EXISTS secret (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL CHECK (scope IN ('global','project','environment')),
  scope_id INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  -- what the variable is for; lives here because the note often hints at the value
  note TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT,
  UNIQUE(scope, scope_id, name)
);
-- Credentials, as opposed to variables: these become files and command-line
-- flags at deploy time, never `-e` extra-vars. Environment beats project beats
-- global.
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
