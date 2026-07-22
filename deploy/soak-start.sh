#!/bin/sh
set -eu
# shellcheck source=deploy/soak-common.sh
. "$(dirname "$0")/soak-common.sh"
require_candidate
: "${BACKUP_FILE:?Set BACKUP_FILE=/absolute/path/to/tailview.dump}"
test -f "$BACKUP_FILE" || { echo "Backup not found: $BACKUP_FILE" >&2; exit 2; }
test -f "$BACKUP_FILE.sha256" || { echo "Backup checksum not found: $BACKUP_FILE.sha256" >&2; exit 2; }
test ! -e "$SOAK_EVIDENCE_DIR/state.json" || {
  echo "Soak state already exists; finish or explicitly remove the isolated project first" >&2
  exit 2
}
if docker volume inspect "${SOAK_PROJECT}-postgres-data" >/dev/null 2>&1; then
  echo "Refusing to restore over an existing soak database volume: ${SOAK_PROJECT}-postgres-data" >&2
  exit 2
fi
mkdir -p "$SOAK_EVIDENCE_DIR/checks" "$SOAK_EVIDENCE_DIR/runtime"

expected_name=$(basename "$BACKUP_FILE")
(cd "$(dirname "$BACKUP_FILE")" && sha256sum -c "${expected_name}.sha256")
backup_sha=$(sha256sum "$BACKUP_FILE" | awk '{print $1}')

compose config --quiet
compose pull database backend frontend
compose up -d database
# The variables intentionally expand inside the database container.
# shellcheck disable=SC2016
compose exec -T database sh -c 'until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do sleep 1; done'
# shellcheck disable=SC2016
compose exec -T database sh -c 'pg_restore --clean --if-exists --no-owner --no-privileges -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "$BACKUP_FILE"
compose up -d backend frontend
wait_ready "$SOAK_EVIDENCE_DIR/runtime/readiness-start.json"

owner=$(env_value TAILVIEW_IMAGE_NAMESPACE)
version=${CANDIDATE_TAG#v}
commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"]["revision"])' "$SOAK_EVIDENCE_DIR/runtime/readiness-start.json")
digest_file="$SOAK_EVIDENCE_DIR/tailview-${version}-image-digests.json"
python3 - "$digest_file" "$CANDIDATE_TAG" "$commit" "$owner" <<'PY'
import json, subprocess, sys
path, candidate, commit, owner = sys.argv[1:]
images = {}
for name in ("tailview-backend", "tailview-frontend", "tailview-telemetry-agent"):
    ref = f"{owner}/{name}:{candidate[1:]}"
    output = subprocess.check_output(["docker", "buildx", "imagetools", "inspect", ref], text=True)
    digest = next(line.split()[1] for line in output.splitlines() if line.startswith("Digest:"))
    images[name] = digest
with open(path, "w", encoding="utf-8") as target:
    json.dump({"schema_version": 1, "candidate_tag": candidate, "core_version": ".".join(candidate[1:].split("-")[0].split(".")), "source_commit": commit, "images": images}, target, indent=2, sort_keys=True)
    target.write("\n")
PY
python3 deploy/soak_evidence.py init \
  --candidate "$CANDIDATE_TAG" --source-commit "$commit" --backup-sha256 "$backup_sha" \
  --project "$SOAK_PROJECT" --readiness "$SOAK_EVIDENCE_DIR/runtime/readiness-start.json" \
  --digests "$digest_file" --output "$SOAK_EVIDENCE_DIR/state.json"
echo "Isolated soak started at $SOAK_URL. Run 'make soak-login' and then 'make soak-check'."
