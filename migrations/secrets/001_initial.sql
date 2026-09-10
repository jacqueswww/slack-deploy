CREATE TABLE IF NOT EXISTS secret (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL CHECK (scope IN ('global','project','environment')),
  scope_id INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT,
  UNIQUE(scope, scope_id, name)
);
