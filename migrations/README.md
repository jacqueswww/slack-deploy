Migrations are plain SQL, applied in filename order, once each, tracked in a
`schema_migrations` table inside each database.

- `deploy/` runs against the plaintext `deploy.db`
- `secrets/` runs against the SQLCipher `secrets.db` (needs the global password)

To add one: create `NNN_short_name.sql` with the next number. Never edit an
applied file, and never renumber - the filename stem is the version key.

    python manage.py migrate          # deploy.db only, no password needed
    python manage.py migrate --all    # both, prompts for the global password
