# Tailscale API capabilities

Validated against official documentation on **2026-07-20**. The official API/OpenAPI definition remains the source of truth; TailView records upstream HTTP failures without inventing plan or permission causes.

| Capability | Read endpoint | Preferred scope | Default poll | TailView behavior |
|---|---|---|---:|---|
| Devices | `GET /api/v2/tailnet/{tailnet}/devices` | `devices:core:read` | 5 min | Normalized inventory and raw redacted snapshot |
| Device details | `GET /api/v2/device/{deviceID}` | `devices:core:read` | On demand | Stable-ID enrichment |
| Users | `GET /api/v2/tailnet/{tailnet}/users` | `users:read` | 5 min | Identity and ownership inventory |
| Routes | `GET /api/v2/device/{deviceID}/routes` | `devices:routes:read` | 5 min | Advertised and enabled routes remain distinct |
| Posture attributes | `GET /api/v2/device/{deviceID}/attributes` | `devices:posture_attributes:read` | 5 min | Used only when accessible; missing data means incomplete evaluation |
| Policy | `GET /api/v2/tailnet/{tailnet}/acl` | `policy_file:read` plus documented device scopes | 5 min | HuJSON read-only snapshot and local explanation |
| Policy validation/preview | `POST .../acl/validate`, `POST .../acl/preview` | `policy_file:read` | Diagnostics | Optional cross-check, never policy mutation |
| Network logs | `GET .../logging/network?start=&end=` | `logs:network:read` | 1 min | Overlapping inclusive windows and deterministic dedupe |
| Configuration logs | `GET .../logging/configuration?start=&end=` | `logs:configuration:read` | 5 min | Separate audit-event storage |
| DNS preferences | `GET .../dns/preferences` | `dns:read` | Diagnostics | Capability and configuration summary |
| Services | Official Services list/get/host read methods | `services:read` where offered | 5 min | First-class inventory when the endpoint is available; policy-only state otherwise |
| Webhooks | `GET /api/v2/tailnet/{tailnet}/webhooks` | `webhooks:read` | Diagnostics | Capability only; TailView never creates or changes webhooks |

Network logs have no pagination or maximum page size. Requests therefore use bounded inclusive RFC3339 windows, overlap recent time to capture delays, and deduplicate exact records. They are available upstream for 30 days, require eligible plans, and are client-reported. Configuration logs similarly use inclusive time windows without pagination and are retained upstream for 90 days.

Capability status values are `available`, `permission_denied`, `feature_disabled`, `plan_unavailable`, `unsupported`, `upstream_error`, and `unknown`. TailView uses a precise value only when the upstream response supports it.

