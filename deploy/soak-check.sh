#!/bin/sh
set -eu
# shellcheck source=deploy/soak-common.sh
. "$(dirname "$0")/soak-common.sh"
require_candidate
test -f "$SOAK_EVIDENCE_DIR/state.json" || { echo "Run soak-start first" >&2; exit 2; }
test -f "$SOAK_COOKIE_JAR" || { echo "Run soak-login first" >&2; exit 2; }
runtime="$SOAK_EVIDENCE_DIR/runtime"
mkdir -p "$runtime" "$SOAK_EVIDENCE_DIR/checks"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
wait_ready "$runtime/readiness-${stamp}.json"

get() {
  curl --fail --silent --show-error --cookie "$SOAK_COOKIE_JAR" "$SOAK_URL$1" > "$2"
}
get /api/v1/operations/summary "$runtime/operations-${stamp}.json"
get /api/v1/operations/storage "$runtime/storage-${stamp}.json"
get /api/v1/operations/retention "$runtime/retention-${stamp}.json"
get /api/v1/capabilities "$runtime/capabilities-${stamp}.json"
get /api/v1/sync "$runtime/sync-${stamp}.json"
get /api/v1/reports/summary "$runtime/reports-${stamp}.json"
get /api/v1/findings/summary "$runtime/findings-${stamp}.json"
get '/api/v1/reports?status=completed&limit=1' "$runtime/report-list-${stamp}.json"

report_id=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("items", [{}])[0].get("id", "") if d.get("items") else "")' "$runtime/report-list-${stamp}.json")
report_args=
if test -n "$report_id"; then
  report_tmp="$runtime/report-${stamp}.json"
  get "/api/v1/reports/${report_id}/download?format=json" "$report_tmp"
  report_sha=$(sha256sum "$report_tmp" | awk '{print $1}')
  report_size=$(wc -c < "$report_tmp" | tr -d ' ')
  report_args="--report-sha256 $report_sha --report-size $report_size"
fi
# shellcheck disable=SC2086
python3 deploy/soak_evidence.py snapshot \
  --state "$SOAK_EVIDENCE_DIR/state.json" --readiness "$runtime/readiness-${stamp}.json" \
  --operations "$runtime/operations-${stamp}.json" --storage "$runtime/storage-${stamp}.json" \
  --retention "$runtime/retention-${stamp}.json" --capabilities "$runtime/capabilities-${stamp}.json" \
  --sync "$runtime/sync-${stamp}.json" --reports "$runtime/reports-${stamp}.json" \
  --findings "$runtime/findings-${stamp}.json" \
  $report_args --output "$SOAK_EVIDENCE_DIR/checks/${stamp}.json"
test ! -f "$runtime/report-${stamp}.json" || rm -f "$runtime/report-${stamp}.json"
echo "Soak evidence captured: $stamp"
