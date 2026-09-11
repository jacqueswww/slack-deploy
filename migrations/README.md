Migrations are plain SQL, applied in filename order, once each, tracked in a
`schema_migrations` table inside each database.

- `deploy/` runs against the plaintext `deploy.db`
- `secrets/` runs against the SQLCipher `secrets.db` (needs the global password)

To add one: create `NNNN_short_name.sql` with the next number. Never edit an
applied file, and never renumber - the filename stem is the version key.

`0001` is every table as `CREATE TABLE IF NOT EXISTS`, so it creates what a store
predating the squash is missing and leaves what it already has alone. The trap:
that also means **editing `0001` never changes an existing table**. A new column
or a relaxed constraint on a table already in `0001` needs its own numbered
migration, or it lands on fresh stores only and 500s on every older one.
`0002_environment_inventory_optional.sql` is that migration for the one case so
far, and shows the rebuild SQLite needs to drop a `NOT NULL`.

    python manage.py migrate          # deploy.db only, no password needed
    python manage.py migrate --all    # both, prompts for the global password
