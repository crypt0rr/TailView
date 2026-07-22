# Tailscale API capabilities

Validated against official documentation on **2026-07-21**. The official API/OpenAPI definition remains the source of truth; TailView records upstream HTTP failures without inventing plan or permission causes.

| Capability | Read endpoint | Preferred scope | Default poll | TailView behavior |
|---|---|---|---:|---|
| Devices | `GET /api/v2/tailnet/{tailnet}/devices?fields=all` | `devices:core:read` | 5 min | Complete documented inventory plus separately stored device-reported connectivity; detail reads are fallback-only |
| Device details | `GET /api/v2/device/{deviceID}` | `devices:core:read` | Fallback | Used only when required fields remain absent from the complete listing |
| Users | `GET /api/v2/tailnet/{tailnet}/users` | `users:read` | 5 min | Identity and ownership inventory |
| Routes | `GET /api/v2/device/{deviceID}/routes` | `devices:routes:read` | 5 min | Advertised and enabled routes remain distinct |
| Posture attributes | `GET /api/v2/device/{deviceID}/attributes` | `devices:posture_attributes:read` | 5 min | Independently synchronized typed values and expiries; per-device last-good preservation |
| Posture integrations | `GET /api/v2/tailnet/{tailnet}/posture/integrations`, `GET /api/v2/posture/integrations/{integrationID}` | `feature_settings:read` | 15 min | Redacted provider/status inventory; no configuration writes |
| Tailnet feature settings | `GET /api/v2/tailnet/{tailnet}/settings` | `feature_settings:read` | 15 min | Allowlisted documented security/feature values; no settings writes |
| Policy | `GET /api/v2/tailnet/{tailnet}/acl` | `policy_file:read` plus documented device scopes | 5 min | HuJSON read-only snapshot and local explanation |
| Policy validation/preview | `POST .../acl/validate`, `POST .../acl/preview` | `policy_file:read` | Diagnostics | Optional cross-check, never policy mutation |
| Network logs | `GET .../logging/network?start=&end=` | `logs:network:read` | 1 min | Overlapping inclusive windows and deterministic dedupe |
| Configuration logs | `GET .../logging/configuration?start=&end=` | `logs:configuration:read` | 5 min | Separate audit-event storage |
| DNS configuration | `GET .../dns/preferences`, `/nameservers`, `/searchpaths`, `/split-dns` | `dns:read` | 5 min | Administrator-only DNS page with preferences, resolvers, search domains, split-DNS routing, freshness, and provenance |
| Services | Official Services list/get/host/approval-status read methods | `all:read` (no granular Services scope is documented) | 5 min | First-class inventory when the endpoint is available; policy-only state otherwise |
| Webhooks | `GET /api/v2/tailnet/{tailnet}/webhooks` | `webhooks:read` | 5 min | Administrator-only inventory with credentials and query values removed |
| Credential inventory | `GET /api/v2/tailnet/{tailnet}/keys` | `all:read` or applicable granular key read scopes | 15 min | Administrator-only metadata with masked identifiers; no usable secrets |
| Device invites | `GET /api/v2/device/{deviceID}/device-invites` | `devices_invites:read` | 15 min | Bounded per-device synchronization with last-good preservation |
| Tailnet contacts | `GET /api/v2/tailnet/{tailnet}/contacts` | `account_settings:read` | 15 min | Administrator-only contact and explicit verification metadata |
| Log streaming | `GET .../logging/{logType}/stream`, `GET .../logging/{logType}/status` | `log_streaming:read` | 15 min | Sanitized destination and status inventory; no configuration writes |

Network logs have no pagination or maximum page size. Requests therefore use bounded inclusive RFC3339 windows, overlap recent time to capture delays, and deduplicate exact records. They are available upstream for 30 days, require eligible plans, and are client-reported. Configuration logs similarly use inclusive time windows without pagination and are retained upstream for 90 days.

Capability status values are `available`, `permission_denied`, `feature_disabled`, `plan_unavailable`, `unsupported`, `upstream_error`, and `unknown`. TailView uses a precise value only when the upstream response supports it.

The DNS endpoints expose tailnet configuration, not DNS activity. TailView cannot obtain DNS queries, answers, URLs, or per-device resolver state from this management API and does not infer them from flow records.

Posture attributes are evaluated locally against the current synchronized policy. Fresh, successfully retrieved evidence may produce pass or fail. Failed or stale retrieval produces `incomplete_data`; unknown syntax produces `unsupported_condition`; ambiguous shared or routed source applicability produces `not_applicable`. Current posture is never attributed to the time of a historical flow.

`clientConnectivity` is delayed, device-reported information returned by `fields=all`. TailView stores it separately with retrieval time and never presents endpoints, DERP selection, mapping behavior, or latency as live or tailnet-wide facts.

## Device address provenance

The device API supplies Tailnet IPv4 and IPv6 addresses but does not supply authoritative LAN-interface or public-WAN addresses. TailView displays those API values separately as **Tailnet addresses**.

For device troubleshooting, TailView can also summarize physical endpoint candidates from retained network flow logs. A candidate is attributed only when the physical-flow source resolves to the selected device's synchronized Tailnet address. Candidates are grouped by IP and classified locally; no reverse DNS, geolocation, active probing, or external enrichment is performed.

Physical endpoint values remain client-reported and unverified. They may represent NAT mappings, relay infrastructure, temporary ports, or spoofed data, so TailView never labels them as authoritative device interface addresses. The verified reporting-node ID, observation window, ports, volume, and provenance remain attached to the summary.
