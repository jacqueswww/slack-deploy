-- The tags the playbook actually defines, cached from `ansible-playbook
-- --list-tags` so the deploy form can offer them. A cache, never an input:
-- playbook_argv still validates whatever is typed.
ALTER TABLE environment ADD COLUMN known_tags TEXT;
