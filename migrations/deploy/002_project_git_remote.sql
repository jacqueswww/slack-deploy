-- Clone URL for the project's ansible repo. HTTPS remotes authenticate with the
-- read-only github_pat secret; SSH remotes use the daemon user's own key.
ALTER TABLE project ADD COLUMN git_remote TEXT;
