# Security policy

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Send a private report to the repository owner with the affected version, impact, reproduction steps, and any suggested mitigation. Avoid including real Tailscale credentials, flow logs, or policy files.

## Threat model and boundaries

TailView treats the browser, upstream API responses, optional telemetry agent, reverse-proxy headers, and network-flow client fields as untrusted. PostgreSQL contains sensitive inventory, policy, audit, flow, session, and encrypted credential data. A database dump plus the deployment master key is sufficient to recover stored Tailscale credentials, so they must be stored and backed up separately.

The integration is read-only. Administrators can configure credentials, metadata, schedules, and users; viewers cannot mutate application state. Tailscale secrets stay in the backend and are redacted from logs and raw diagnostic payloads.

Access-governance synchronization stores only upstream credential metadata. Usable key and token values are never requested. Identifiers are masked in API responses and the UI; secret-bearing raw fields, authorization headers, URL credentials, and query values are removed before diagnostic persistence.

Finding webhooks are outbound TailView actions and do not modify the tailnet. Full endpoint URLs and HMAC signing secrets are encrypted with the deployment master key; only sanitized URLs are displayed. Payloads contain safe summaries and public references, not raw evidence or upstream secret-bearing identifiers. Production destinations must use HTTPS, redirects are not followed, and DNS results are rejected when they resolve to loopback, private, link-local, multicast, or reserved addresses unless an exact hostname or CIDR is explicitly allowlisted. Keep `ALERT_WEBHOOK_HOST_ALLOWLIST` empty unless a reviewed private receiver is required.

Receivers should verify `X-TailView-Timestamp` and `X-TailView-Signature` against the exact request body, reject stale timestamps, and deduplicate by `X-TailView-Event-ID` or `Idempotency-Key`. The signing secret is shown only once at endpoint creation.

## Production requirements

- Replace the setup token, encryption key, database password, and telemetry secret with independent random values.
- Use HTTPS and `COOKIE_SECURE=true`; enable HSTS only after TLS is working.
- Restrict the published frontend port and PostgreSQL backups. Never expose PostgreSQL publicly.
- Configure trusted proxy addresses narrowly. Preserve the original scheme and host.
- Rotate Tailscale OAuth secrets/API tokens and the setup token after suspected disclosure. Revoke all application sessions.
- Keep images and dependencies patched; run `npm audit`, Python dependency auditing, and a container scanner such as Docker Scout or Trivy in CI.

## Optional telemetry risk

The telemetry profile mounts the local Tailscale socket read-only. Socket access can still expose sensitive tailnet state and may permit more operations than TailView needs if the CLI or daemon behavior changes. Enable it only on a dedicated trusted host, use a unique HMAC secret, and restrict the agent/backend network. Its results describe only that collector node at that observation time.

## Supported versions

Security fixes are applied to the latest tagged release. Until the first stable tag, only the current default branch is supported.
