# Releasing TailView

TailView releases are created from immutable semantic-version tags. The release workflow runs the backend and frontend quality gates, migration and backup rehearsals, validates both Compose modes, publishes temporary commit-addressed candidate images, scans and exercises those exact images, and only then promotes their manifests to release tags. It attaches provenance and SBOM attestations and creates a GitHub Release after acceptance succeeds.

## Create a release

1. Complete [the release checklist](RELEASE_CHECKLIST.md), including the isolated restore rehearsal and 24-hour read-only tailnet soak.
2. Confirm the intended commit is on the protected default branch, the tree is clean, and CI is green.
3. Use `v1.0.0-rc.1` for the first v1 candidate. Use a `vMAJOR.MINOR.PATCH` tag for a stable release and append a SemVer prerelease suffix for later candidates. Do not reuse the historical non-SemVer `v1.0` tag.
4. Create and push a signed tag:

   ```bash
   git tag -s v1.2.0 -m "TailView v1.2.0"
   git push origin v1.2.0
   ```

The workflow uses the repository `GITHUB_TOKEN`; no registry password is required. The repository workflow must be allowed `packages: write`, `contents: write`, `attestations: write`, and `id-token: write`, as declared per job in the workflow.

## Published packages

- `ghcr.io/crypt0rr/tailview-backend`
- `ghcr.io/crypt0rr/tailview-frontend`
- `ghcr.io/crypt0rr/tailview-telemetry-agent`

Every build is first published only as `candidate-$GITHUB_SHA`. After release-image acceptance, the tested manifest is promoted without rebuilding. Stable releases receive the exact version, major/minor, major, and `latest` tags. Prereleases receive only their exact version and never move `latest`. The generated GitHub Release includes candidate image digests and a checksummed Compose bundle.

GHCR initially creates packages as private. An owner must make each package public once if TailView should support anonymous pulls. Package visibility is not safely changeable from the release workflow.

Container scanning blocks every HIGH or CRITICAL result. A temporary exception must be recorded in `.trivyignore.yaml` with a constrained path, operational justification, and expiry date; expired exceptions fail the release gate and must never be renewed without review.

## Rollback

Set `TAILVIEW_VERSION` to the previous version, pull the images, and recreate the services against a restored copy of the pre-upgrade database in a separate volume. Never overwrite the upgraded live volume and do not use destructive Alembic downgrades.
