#!/bin/sh
set -eu
# shellcheck source=deploy/soak-common.sh
. "$(dirname "$0")/soak-common.sh"
require_candidate
test -f "$SOAK_EVIDENCE_DIR/state.json" || { echo "Run soak-start first" >&2; exit 2; }
compose restart database backend frontend
wait_ready "$SOAK_EVIDENCE_DIR/runtime/readiness-restart.json"
curl --fail --silent --show-error --cookie "$SOAK_COOKIE_JAR" "$SOAK_URL/api/v1/auth/me" >/dev/null
python3 - "$SOAK_EVIDENCE_DIR/restart.json" <<'PY'
import json, sys
from datetime import datetime, timezone
with open(sys.argv[1], "w", encoding="utf-8") as target:
    json.dump({"completed": True, "completed_at": datetime.now(timezone.utc).isoformat()}, target, indent=2, sort_keys=True)
    target.write("\n")
PY
sh deploy/soak-check.sh
