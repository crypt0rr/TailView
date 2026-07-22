# Deployment

## Compose

Copy `.env.example`, replace all public example secrets, then run `docker compose up -d --build`. The default frontend listens on `TAILVIEW_PORT`; backend and database use internal Compose networks. Check `/health/live`, `/health/ready`, and authenticated application status separately.

For Caddy, set a resolvable `APP_DOMAIN`, use `COOKIE_SECURE=true`, and start the `caddy` profile. For Tailscale Serve or another reverse proxy, forward to the frontend only and configure the exact external `APP_URL`.

## Backup and restore

Create encrypted, access-controlled PostgreSQL custom-format dumps with `make backup`. TailView writes SHA-256 and JSON sidecars beside the dump. Verify a dump with `make verify-backup FILE=tailview.dump`; the drill creates a uniquely named, isolated PostgreSQL container, restores the dump, applies current migrations, performs safe authentication/inventory/reporting table checks, records the result in **Operations**, and removes the temporary resources. It never targets the live database.

The credential-encryption key is not stored in PostgreSQL and must be backed up separately. A database dump without the matching key cannot decrypt stored integration, MFA, or notification secrets.

## Upgrade and rollback

1. Back up PostgreSQL and `.env` secrets.
2. Pull/build the intended tagged version.
3. Run migrations and verify readiness.
4. Validate capability and synchronization pages.

Application rollback is safe only when its schema is compatible with the migrated database. Prefer restoring the pre-upgrade database into a new volume rather than running destructive down migrations.

## Resource guidance

Start with two backend CPUs, 1 GiB backend memory, and PostgreSQL sized for flow retention. Large tailnets should monitor database size, query duration, raw flow ingestion, and graph edge counts. Apply host-level limits appropriate for observed load.

The Administrator-only **Operations** workspace reports PostgreSQL relation sizes, retained-record counts, scheduler heartbeats, job executions, queue delay, cleanup previews, aggregate coverage, and backup drill age. Host disk capacity is intentionally not inferred from PostgreSQL and must still be monitored at the container host or infrastructure layer. TailView emits corresponding Prometheus metrics from `/metrics`.

Reporting adds hourly and daily aggregate tables plus retained binary artifacts. Size PostgreSQL for `FLOW_DAILY_AGGREGATE_RETENTION_DAYS` and `REPORT_ARTIFACT_RETENTION_DAYS`, monitor failed or timeout-recovered report runs and aggregate coverage on the Reports page, and keep `REPORT_MAX_CONCURRENT_JOBS=1` unless the backend has sufficient CPU and memory for parallel PDF generation. Existing schema-v1 reports remain valid after the reporting-experience migration.
