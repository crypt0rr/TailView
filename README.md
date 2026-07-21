# TailView

TailView is a self-hosted, read-only observability dashboard for a Tailscale tailnet. It keeps inventory, current policy, historical network-flow reports, configuration audit events, local metadata, and optional single-node telemetry visibly distinct.

> TailView never modifies Tailscale configuration. Network flow logs are historical client-reported windows, not active sessions, and may contain overlapping reports from both peers.

## Features

- One-time setup-token bootstrap, Argon2id passwords, revocable server-side sessions, administrator/viewer RBAC, login throttling, and CSRF protection.
- Device/user inventory with multi-role classification, routes, tags, local metadata, saved-view schema, and provenance.
- Interactive Cytoscape topology with observed and policy-permitted layers, layouts, filtering, selection, and a details drawer.
- Flow explorer, reported-volume charts, CSV/JSON export, unresolved destinations, and virtual/subnet/exit/physical categories.
- Real PostgreSQL-backed traffic time series, shared 1-hour/24-hour/7-day/30-day ranges, keyset pagination, and filter-matched exports.
- Read-only HuJSON policy snapshots, normalized Grants/ACL sections, selector expansion, and explicit incomplete/unsupported results.
- Configuration audit events, synchronization history, independent capability states, Prometheus metrics, and structured logs.
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

Use `make backup` or `make restore FILE=tailview.dump`. Restore into an empty database when possible and test procedures regularly; see [deployment details](docs/DEPLOYMENT.md).

Licensed under the [MIT License](LICENSE).
