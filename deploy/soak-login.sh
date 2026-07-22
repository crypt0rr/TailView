#!/bin/sh
set -eu
# shellcheck source=deploy/soak-common.sh
. "$(dirname "$0")/soak-common.sh"
require_candidate
: "${SOAK_USERNAME:?Set SOAK_USERNAME to an Administrator in the restored copy}"
test -t 0 || { echo "soak-login requires an interactive terminal" >&2; exit 2; }
printf 'Password for %s: ' "$SOAK_USERNAME" >&2
stty -echo
IFS= read -r password
stty echo
printf '\n' >&2
trap 'stty echo 2>/dev/null || true' EXIT INT TERM
payload=$(python3 -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.argv[2]}))' "$SOAK_USERNAME" "$password")
password=
mkdir -p "$SOAK_EVIDENCE_DIR"
response=$(mktemp)
trap 'stty echo 2>/dev/null || true; rm -f "$response"' EXIT INT TERM
curl --fail --silent --show-error --cookie-jar "$SOAK_COOKIE_JAR" \
  -H "Origin: $SOAK_URL" -H 'Content-Type: application/json' --data "$payload" \
  "$SOAK_URL/api/v1/auth/login" > "$response"
payload=
status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$response")
if test "$status" = mfa_required; then
  challenge=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["challenge"])' "$response")
  printf 'TOTP or recovery code: ' >&2
  stty -echo
  IFS= read -r code
  stty echo
  printf '\n' >&2
  payload=$(python3 -c 'import json,sys; print(json.dumps({"challenge":sys.argv[1],"code":sys.argv[2]}))' "$challenge" "$code")
  code=
  curl --fail --silent --show-error --cookie-jar "$SOAK_COOKIE_JAR" \
    -H "Origin: $SOAK_URL" -H 'Content-Type: application/json' --data "$payload" \
    "$SOAK_URL/api/v1/auth/mfa/verify" > "$response"
  payload=
  status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$response")
fi
test "$status" = authenticated || {
  echo "The soak account must have completed password and MFA enrollment onboarding" >&2
  exit 1
}
chmod 600 "$SOAK_COOKIE_JAR"
curl --fail --silent --show-error --cookie "$SOAK_COOKIE_JAR" "$SOAK_URL/api/v1/auth/me" >/dev/null
echo "Authenticated soak session created. The cookie jar is excluded from evidence and source control."
