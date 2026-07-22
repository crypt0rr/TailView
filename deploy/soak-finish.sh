#!/bin/sh
set -eu
# shellcheck source=deploy/soak-common.sh
. "$(dirname "$0")/soak-common.sh"
require_candidate
: "${RELEASE_GPG_FINGERPRINT:?Set RELEASE_GPG_FINGERPRINT to the release-owner signing key}"
minimum_seconds=${SOAK_MINIMUM_SECONDS:-86400}
python3 deploy/soak_evidence.py finalize \
  --state "$SOAK_EVIDENCE_DIR/state.json" --checks "$SOAK_EVIDENCE_DIR/checks" \
  --restart-marker "$SOAK_EVIDENCE_DIR/restart.json" --output-dir "$SOAK_EVIDENCE_DIR" \
  --minimum-seconds "$minimum_seconds"
version=${CANDIDATE_TAG#v}
manifest="$SOAK_EVIDENCE_DIR/tailview-${version}-SHA256SUMS"
gpg --batch --yes --local-user "$RELEASE_GPG_FINGERPRINT" --armor --detach-sign --output "$manifest.asc" "$manifest"
gpg --verify "$manifest.asc" "$manifest"
if test "${SOAK_UPLOAD:-false}" = true; then
  gh release upload "$CANDIDATE_TAG" --clobber \
    "$SOAK_EVIDENCE_DIR/tailview-${version}-soak.json" \
    "$SOAK_EVIDENCE_DIR/tailview-${version}-go-no-go.md" "$manifest" "$manifest.asc"
fi
echo "Signed release evidence is ready in $SOAK_EVIDENCE_DIR. The isolated stack remains running for inspection."
