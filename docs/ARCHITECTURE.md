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

Scheduled jobs use a single-process APScheduler plus PostgreSQL advisory locks, so additional backend instances skip work already held elsewhere. Each source records its own job result and capability state; optional failures do not affect readiness.

Demo mode uses synthetic records and disables real scheduling. The optional agent is a separate profile with explicit socket access and single-node provenance.
