# TailView

TailView is a self-hosted, read-only observability dashboard for a Tailscale tailnet. It keeps inventory, current policy, historical network-flow reports, configuration audit events, local metadata, and optional single-node telemetry visibly distinct.

> TailView never modifies Tailscale configuration. Network flow logs are historical client-reported windows, not active sessions, and may contain overlapping reports from both peers.

## Features

- One-time setup-token bootstrap, Argon2id passwords, optional TOTP MFA, recovery codes, revocable server-side sessions, administrator/viewer RBAC, progressive login throttling, and CSRF protection.
- Administrator-managed TailView accounts remain separate from tailnet users. Temporary passwords require replacement, users can inspect and revoke their own sessions, and Administrators can manage fleet sessions, MFA policy, and immutable local security history under **Settings → TailView access**.
- Device/user inventory with multi-role classification, routes, tags, local metadata, and provenance.
- Private or team-shared saved workspaces with authenticated links and personal page defaults.
- A Security posture workspace with typed device attributes, expiry/freshness coverage, current-policy evaluation, conservative findings, feature settings, and redacted integration inventory.
- Administrator-only access governance for credential metadata, device invites, tailnet contacts, log-stream status, expiry, and conservative review findings. TailView never requests usable secret values.
- A durable Findings workspace consolidates policy, posture, expiry, governance, and repeated synchronization signals with acknowledgement, suppression, assignment, recurrence, automatic resolution, and immutable lifecycle history.
- Optional signed JSON webhooks use an encrypted endpoint configuration and PostgreSQL outbox with idempotency, bounded retries, and SSRF-resistant destination validation.
- Capability-aware navigation keeps active data sources prominent and groups definitively unavailable licensed/scoped features or successfully synchronized empty configuration inventories under a collapsible **Not in use** section. Services, routes, exit nodes, subnet routers, groups, and tags return automatically when synchronized data appears; transient failures and unprobed capabilities stay visible.
- Interactive Cytoscape topology with observed and policy-permitted layers, layouts, filtering, selection, and a details drawer.
- Flow explorer, reported-volume charts, CSV/JSON export, unresolved destinations, and virtual/subnet/exit/physical categories.
- Real PostgreSQL-backed traffic time series, shared 1-hour/24-hour/7-day/30-day ranges, keyset pagination, and filter-matched exports.
- In-app network usage reports generated from saved Flow views, with 13 months of compact aggregate history and authenticated PDF, JSON, and CSV evidence downloads.
- Read-only HuJSON policy snapshots, normalized Grants/ACL sections, selector expansion, and explicit incomplete/unsupported results.
- Configuration audit events, synchronization history, independent capability states, Prometheus metrics, and structured logs.
- Administrator Operations center for scheduler health, queue delay, PostgreSQL growth, retention safety, aggregate coverage, and isolated backup verification.
- Administrator DNS inventory covering MagicDNS preferences, nameservers, search domains, split-DNS routing, freshness, and API provenance.
- Isolated demo mode and an explicitly opt-in local telemetry profile.

## Quick start

Requirements: Docker Engine 29+ with Compose v2.

```bash
cp .env.example .env
# Replace every REPLACE value. Generate values with the commands documented in .env.
docker compose up -d --build
docker compose ps
```

Open `http://localhost:8080`, then create the first administrator with `TAILVIEW_SETUP_TOKEN`. Setup becomes unavailable after the account is created.

The first Administrator can create additional local accounts from **Settings → TailView access**. New accounts receive an Administrator-assigned temporary password and must replace it at first login. Every user can open account security by selecting their identity at the bottom of the sidebar.

To preview the complete UI without a tailnet, set `DEMO_MODE=true` before first startup. Demo data is synthetic, displays demo provenance, and is never mixed with real synchronization.

## Tailscale credentials

OAuth client credentials are preferred. For complete inventory including Services, use the documented universal read-only scope:

```text
all:read
```

If Services synchronization is disabled, TailView can instead use the documented granular read scopes: `devices:core:read`, `users:read`, `devices:routes:read`, `devices:posture_attributes:read`, `policy_file:read`, `logs:network:read`, `logs:configuration:read`, `dns:read`, and `webhooks:read`. Tailscale does not currently document a granular Services scope.

Scope names and endpoints are checked against the current official API before each release; see [API capabilities](docs/API_CAPABILITIES.md). A full API access token is supported as a fallback but carries broader permissions and expires within the period selected in Tailscale.

Network Flow Logs must be enabled separately and require an eligible Tailscale plan. TailView does not enable logging or Destination Logging.

Set `TAILSCALE_TAILNET=-` to use the tailnet owned by the OAuth credential, or use the Tailnet ID shown in Tailscale Admin Console → General. A `*.ts.net` MagicDNS name is not the API Tailnet ID.

## Development and tests

```bash
make install
make lint
make test
make build
make compose-check
# Full browser suite against a running demo stack:
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build --abort-on-container-exit
```

The host can also run the frontend directly:

```bash
cd frontend && npm ci && npm run dev
```

Python 3.13 is required for local backend work. The Docker build supplies the correct runtime when the host does not.

`EXPORT_ROW_LIMIT` controls the maximum number of matching records in CSV and JSON exports and defaults to 10,000. Export responses include limit and truncation headers.

Network reporting retains hourly aggregates for 90 days and daily aggregates for 400 days by default. Completed report artifacts are retained for 180 days. Administrators create schedules under **Reports**, select the included evidence sections and comparison behavior, and can inspect immutable failed and retried runs. All authenticated TailView users can inspect and download completed reports. PDF, JSON v2, and CSV evidence share one canonical snapshot; older schema-v1 artifacts remain downloadable. Volumes remain client-reported and potentially overlapping.

Resolved findings and notification delivery history are retained for 180 days by default (`FINDINGS_RETENTION_DAYS`). Webhook destinations require public HTTPS in production. Private destinations must be explicitly constrained with `ALERT_WEBHOOK_HOST_ALLOWLIST`.

## Deployment

- Default: frontend on port 8080, backend and PostgreSQL on internal Compose networks.
- Caddy TLS: `docker compose --profile caddy up -d --build` with `APP_DOMAIN` configured.
- Tailscale Serve: proxy the local frontend port; keep `APP_URL`, `COOKIE_SECURE=true`, and trusted proxy settings aligned with the public origin.
- Optional telemetry: review the socket risk in [SECURITY.md](SECURITY.md), configure a unique telemetry secret, then use `--profile telemetry`.

See [architecture](docs/ARCHITECTURE.md), [deployment](docs/DEPLOYMENT.md), and [policy engine](docs/POLICY_ENGINE.md) for operational details.

## Important limitations

- Flow logs record successful traffic windows, not denied attempts, packet payloads, DNS queries, URLs, or direct user activity.
- User-flow views are attributed through device ownership only.
- Exit destinations and ports are absent unless Tailscale Destination Logging supplies them.
- “Offline” is shown only when an explicit API value exists; otherwise TailView displays timestamped last-seen information.
- Historic policy before TailView's first snapshot is available only when audit diffs contain sufficient data.
- Optional CLI telemetry is a point-in-time view from one collector node, never a tailnet-wide fact.

## Backup and upgrade

Back up PostgreSQL before upgrades:

```bash
docker compose exec -T database pg_dump -U tailview -Fc tailview > tailview.dump
docker compose pull
docker compose up -d --build
```

Use `make backup`, verify it safely with `make verify-backup FILE=tailview.dump`, or restore deliberately with `make restore FILE=tailview.dump`. The verification command never targets the live database; see [deployment details](docs/DEPLOYMENT.md).

Licensed under the [MIT License](LICENSE).
