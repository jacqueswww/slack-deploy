-- A stored default for --skip-tags, beside the one for --tags. A run may pick
-- its own for either; this is what it falls back to. Added here rather than in
-- 0001, which is all CREATE TABLE IF NOT EXISTS and so never changes a table an
-- existing store already has. See migrations/README.md.
ALTER TABLE environment ADD COLUMN skip_tags TEXT;
