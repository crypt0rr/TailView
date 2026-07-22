# Releasing TailView

TailView releases are created from immutable semantic-version tags. The candidate workflow accepts only `vMAJOR.MINOR.PATCH-rc.N`, runs the complete release gate, and promotes accepted commit-addressed manifests to that RC tag. The image metadata contains the core application version (for example `1.0.0`), while the registry and GitHub Release retain the RC identity. A stable release is a separate, protected manual promotion and never rebuilds an image.

## Create a release

1. Complete [the release checklist](RELEASE_CHECKLIST.md), including the isolated restore rehearsal and 24-hour read-only tailnet soak.
2. Confirm the intended commit is on the protected default branch, the tree is clean, and CI is green.
3. Use `v1.0.0-rc.1` for the first v1 candidate and increment only the RC number for a new commit. Do not reuse the historical non-SemVer `v1.0` tag.
4. Create and push a signed tag:

   ```bash
   git tag -s v1.0.0-rc.1 -m "TailView v1.0.0-rc.1"
   git push origin v1.0.0-rc.1
   ```

The workflow uses the repository `GITHUB_TOKEN`; no registry password is required. The repository workflow must be allowed `packages: write`, `contents: write`, `attestations: write`, and `id-token: write`, as declared per job in the workflow.

## Published packages

- `ghcr.io/crypt0rr/tailview-backend`
- `ghcr.io/crypt0rr/tailview-frontend`
- `ghcr.io/crypt0rr/tailview-telemetry-agent`

Every build is first published only as `candidate-$GITHUB_SHA`. After release-image acceptance, the tested manifest is promoted without rebuilding to the exact RC version only. The generated prerelease contains the digest manifest and checksummed Compose/soak bundle. It never moves `latest`.

## Isolated soak

Create `.env.soak` from the protected production configuration, set `APP_URL=http://localhost:18080`, set `TAILVIEW_VERSION` to the RC without the leading `v`, keep `DEMO_MODE=false`, and retain the matching encryption key/read-only Tailscale credential. Never commit this file. The backup must have the `.sha256` sidecar produced by `deploy/backup.sh`.

```bash
make soak-start CANDIDATE=v1.0.0-rc.1 BACKUP=/secure/tailview.dump ENV_FILE=.env.soak
make soak-login CANDIDATE=v1.0.0-rc.1 USERNAME=release-owner ENV_FILE=.env.soak
make soak-check CANDIDATE=v1.0.0-rc.1 ENV_FILE=.env.soak
# Repeat checks during the 24-hour window.
make soak-restart CANDIDATE=v1.0.0-rc.1 ENV_FILE=.env.soak
make soak-finish CANDIDATE=v1.0.0-rc.1 ENV_FILE=.env.soak \
  GPG_FINGERPRINT=0123456789ABCDEF0123456789ABCDEF01234567 UPLOAD=true
```

The scripts always use a separate `tailview-soak` Compose project, port `18080`, network, and named PostgreSQL volume. They reject `.env` and the live `tailview` project name. Telemetry is not started. `soak-finish` requires at least 24 hours, three successful captures, a controlled restart, an authenticated report download, and a release-owner signature. Failed evidence is retained; fix the issue on a new commit and publish the next RC.

## Stable promotion

Configure a protected GitHub environment named `stable-release` and the repository variables `RELEASE_GPG_PUBLIC_KEY` and `RELEASE_GPG_FINGERPRINT`. After the signed soak evidence is attached to the RC release, create the stable tag on the identical commit. The tag message must bind the candidate and SHA-256 of the signed evidence manifest:

```bash
evidence_sha=$(sha256sum tailview-1.0.0-rc.1-SHA256SUMS | awk '{print $1}')
git tag -s v1.0.0 -m "TailView v1.0.0" \
  -m "Candidate: v1.0.0-rc.1" -m "Evidence-SHA256: ${evidence_sha}"
git push origin v1.0.0
```

Manually run **Promote accepted release candidate** with `candidate_tag=v1.0.0-rc.1` and `stable_tag=v1.0.0`. The workflow verifies the signed tag and evidence, default-branch commit, provenance attestations, architectures, and all three recorded digests. It then moves `1.0.0`, `1.0`, `1`, and `latest` to those exact manifests without invoking an image build.

GHCR initially creates packages as private. An owner must make each package public once if TailView should support anonymous pulls. Package visibility is not safely changeable from the release workflow.

Container scanning blocks every HIGH or CRITICAL result. A temporary exception must be recorded in `.trivyignore.yaml` with a constrained path, operational justification, and expiry date; expired exceptions fail the release gate and must never be renewed without review.

## Rollback

Set `TAILVIEW_VERSION` to the previous version, pull the images, and recreate the services against a restored copy of the pre-upgrade database in a separate volume. Never overwrite the upgraded live volume and do not use destructive Alembic downgrades.
