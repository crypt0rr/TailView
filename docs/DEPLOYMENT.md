# Deployment

## Compose

Copy `.env.example`, replace all public example secrets, then run `docker compose up -d --build`. The default frontend listens on `TAILVIEW_PORT`; backend and database use internal Compose networks. Check `/health/live`, `/health/ready`, and authenticated application status separately.

For Caddy, set a resolvable `APP_DOMAIN`, use `COOKIE_SECURE=true`, and start the `caddy` profile. For Tailscale Serve or another reverse proxy, forward to the frontend only and configure the exact external `APP_URL`.

## Backup and restore

Create encrypted, access-controlled PostgreSQL custom-format dumps with `pg_dump -Fc`. Restore into a staging database regularly, run all migrations, and validate login, topology, policy, and flow queries. The credential-encryption key is not stored in the database and must be backed up separately.

## Upgrade and rollback

1. Back up PostgreSQL and `.env` secrets.
2. Pull/build the intended tagged version.
3. Run migrations and verify readiness.
4. Validate capability and synchronization pages.

Application rollback is safe only when its schema is compatible with the migrated database. Prefer restoring the pre-upgrade database into a new volume rather than running destructive down migrations.

## Resource guidance

Start with two backend CPUs, 1 GiB backend memory, and PostgreSQL sized for flow retention. Large tailnets should monitor database size, query duration, raw flow ingestion, and graph edge counts. Apply host-level limits appropriate for observed load.

