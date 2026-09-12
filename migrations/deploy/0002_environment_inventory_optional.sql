-- environment.inventory became optional when projects gained their own host
-- table: an environment with no inventory file deploys to the project's hosts
-- alone. SQLite cannot drop a NOT NULL, and 0001 is all CREATE TABLE IF NOT
-- EXISTS, so on a store that predates the squash the old constraint is still
-- there and saving such an environment fails. Rebuilding is the only way; on a
-- store created by 0001 it is an identical table and a no-op in effect.
CREATE TABLE environment_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  inventory TEXT,
  playbook TEXT NOT NULL,
  tags TEXT,
  limit_hosts TEXT,
  become INTEGER NOT NULL DEFAULT 0,
  UNIQUE(project_id, name)
);
INSERT INTO environment_new (id, project_id, name, inventory, playbook, tags,
                             limit_hosts, become)
  SELECT id, project_id, name, inventory, playbook, tags, limit_hosts, become
  FROM environment;
DROP TABLE environment;
ALTER TABLE environment_new RENAME TO environment;
