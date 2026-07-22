# Architecture

## Durable findings and delivery

The evaluator runs after relevant manual synchronization and every five minutes under a PostgreSQL advisory lock. It converts conservative normalized signals into stable fingerprints, occurrences, and immutable lifecycle transitions. A source can resolve its previous findings only after a complete successful evaluation; incomplete or failed source data preserves the last state as stale.

Outbound notifications use a transactional PostgreSQL outbox. A separate locked worker signs the exact JSON body with HMAC-SHA256 and retries bounded transient failures. Endpoint URLs and secrets are encrypted with the application master key, response bodies are discarded, and destination validation is repeated before every attempt to reduce DNS-rebinding risk.

```text
Browser ──same-origin──> Frontend/nginx ──internal HTTP──> FastAPI
                                                        │
                  Tailscale API <──read-only HTTPX──────┤
                                                        │
                  Optional CLI agent ──signed JSON──────┤
                                                        ▼
                                                  PostgreSQL 17
```

The frontend never receives upstream credentials. FastAPI owns authentication, authorization, API integration, policy analysis, scheduled ingestion, aggregation/query APIs, metrics, and redaction. PostgreSQL stores normalized current state, history, raw redacted diagnostics, checkpoints, sessions, throttling state, and encrypted credentials.

Saved workspaces contain only strictly validated filtering and presentation state. They are private
by default, can be shared with authenticated TailView users, and exclude cursors, selected drawers,
secrets, and unsaved forms. Personal defaults are separate records so each account can choose its
own starting workspace without modifying a shared view.

Local identity uses hashed opaque session cookies and PostgreSQL-backed revocation. A password-only login creates a full session unless the account must replace a temporary password or enroll mandatory MFA; those cases receive a restricted onboarding session. Existing MFA accounts receive a short-lived hashed challenge and no session until TOTP or a single-use recovery code succeeds. TOTP secrets are AES-GCM encrypted with the application master key, and local security events are stored separately from upstream configuration audit logs.

Scheduled jobs use a single-process APScheduler plus PostgreSQL advisory locks, so additional backend instances skip work already held elsewhere. Each source records its own job result and capability state; optional failures do not affect readiness.

Every scheduled surface also writes a generic operational execution and heartbeat record. These records complement rather than replace synchronization, report, finding, and notification histories. The Operations evaluator creates Administrator-only findings after persistent failures and uses the existing signed-webhook outbox.

Network reporting incrementally rebuilds overlapping hourly and daily flow buckets so delayed upstream records are incorporated before raw-flow cleanup. Scheduled and manual report runs copy their saved-view revision and versioned presentation options into an immutable canonical snapshot, then render PDF, JSON, and a ZIP of CSV evidence from that same snapshot. Generation stages are persisted, abandoned running jobs are failed after the configured timeout, and retries create linked runs instead of rewriting history. Report generation and schedule claiming use a PostgreSQL advisory lock, and raw rows are removed only after both aggregate granularities cover the retention boundary.

Demo mode uses synthetic records and disables real scheduling. The optional agent is a separate profile with explicit socket access and single-node provenance.
