# TailView v1.0 release checklist

Use this checklist for `v1.0.0-rc.1` and repeat it before promoting `v1.0.0`. Store the
completed copy with the release evidence. The release owner signs the final decision;
unchecked required items mean **no-go**.

## Candidate identity

- [ ] Protected default-branch commit: `____________________________`
- [ ] Working tree clean and all required changes committed
- [ ] Signed tag is SemVer (`v1.0.0-rc.1` for the first candidate)
- [ ] Packaged Alembic head: `0014_v1_completion`
- [ ] Backend image digest: `sha256:________________________________`
- [ ] Frontend image digest: `sha256:________________________________`
- [ ] Telemetry image digest: `sha256:________________________________`
- [ ] Compose bundle SHA-256: `________________________________________`
- [ ] Published manifests contain `linux/amd64` and `linux/arm64`
- [ ] Readiness reports the candidate version, commit, build time, and exact schema head

## Automated release gates

- [ ] Ruff and strict mypy
- [ ] Pytest and enforced coverage threshold
- [ ] Python dependency audit and npm production dependency audit
- [ ] ESLint, strict TypeScript, Vitest, and production frontend build
- [ ] Playwright Administrator/Viewer, onboarding, mutation, download, and accessibility suite
- [ ] Secret scan
- [ ] Fresh PostgreSQL migration from an empty database
- [ ] Representative `0013_operations_center` upgrade to `0014_v1_completion`
- [ ] Authentication, devices, flows, findings, reports, artifacts, saved views, and Operations history preserved
- [ ] Backup restore into an isolated PostgreSQL instance, migration, and smoke queries
- [ ] Production and release Compose validation
- [ ] Candidate images pass HIGH/CRITICAL fixable vulnerability scans
- [ ] Published-image Compose acceptance passes setup, login, API query, report download, restart, and persistence

Vulnerability exceptions are not implicit. Record any approved exception with the advisory,
affected component, compensating control, owner, reason, and an expiry date:

`______________________________________________________________________________`

## Pre-upgrade recovery rehearsal

- [ ] Current deployment backed up before the rehearsal
- [ ] Backup filename: `____________________________`
- [ ] Backup SHA-256: `_______________________________________________`
- [ ] Matching encryption key and deployment configuration secured separately
- [ ] Backup restored into a separate database volume or isolated PostgreSQL instance
- [ ] Restored copy migrated to the candidate schema
- [ ] Authentication, inventory, findings, reporting, and artifact smoke queries passed
- [ ] Live database was never used as a restore target

Rollback is the previous application plus the pre-upgrade database restored into a **new**
volume. Destructive Alembic downgrades are not a supported rollback procedure.

## 24-hour read-only tailnet soak

Start: `________________`  End: `________________`  Tailnet: `________________`

- [ ] No Tailscale mutation endpoint was called
- [ ] Users, devices, routes, Services, DNS, webhooks, posture, settings, policy, flows, and audit each produced an independently observable result
- [ ] Capability states matched license/scope behavior and did not oscillate on transient errors
- [ ] Scheduled executions stayed current; no abandoned or repeatedly failing jobs
- [ ] Flow overlap/checkpoint behavior produced no duplicate-growth regression
- [ ] Hourly/daily aggregates advanced and remained safe for retention cleanup
- [ ] Findings evaluated, resolved/reopened conservatively, and did not alert on intentionally unavailable optional capabilities
- [ ] Reports generated and all authenticated artifact downloads succeeded
- [ ] Retention preview did not delete raw flows without aggregate coverage
- [ ] Backend, frontend, and database restarts recovered without data loss
- [ ] Readiness remained accurate after restarts and reported the packaged schema head
- [ ] Logs contained no credentials, authorization headers, tokens, or unsafe upstream payloads

Record incidents, accepted limitations, and remediation links:

`______________________________________________________________________________`

## Go/no-go

- [ ] Every required gate above is complete
- [ ] Known limitations are published and acceptable for v1.0
- [ ] Rollback owner and maintenance window are confirmed
- [ ] Stable release is from the same tested, clean default-branch commit
- [ ] `latest` will move only for `v1.0.0`, never for the release candidate

Decision: `GO / NO-GO`

Release owner: `________________`  Date/time (UTC): `________________`

Signature or signed approval reference: `_______________________________________`
