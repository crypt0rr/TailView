#!/bin/sh
set -eu

SOAK_PROJECT=${SOAK_PROJECT:-tailview-soak}
SOAK_ENV_FILE=${SOAK_ENV_FILE:-.env.soak}
SOAK_PORT=${SOAK_PORT:-18080}
SOAK_URL=${SOAK_URL:-http://localhost:${SOAK_PORT}}
SOAK_EVIDENCE_DIR=${SOAK_EVIDENCE_DIR:-release-evidence/${CANDIDATE_TAG:-candidate}}
SOAK_COOKIE_JAR=${SOAK_COOKIE_JAR:-${SOAK_EVIDENCE_DIR}/.session.cookies}

case "$SOAK_PROJECT" in
  tailview-soak|tailview-soak-*) ;;
  *) echo "Soak project names must be tailview-soak or start with tailview-soak-" >&2; exit 2 ;;
esac
test "$SOAK_PORT" != 8080 || { echo "The live default port 8080 cannot be used for a soak" >&2; exit 2; }
case "$SOAK_ENV_FILE" in
  .env|*/.env) echo "The soak must use a dedicated environment file, never .env" >&2; exit 2 ;;
esac
test -f "$SOAK_ENV_FILE" || { echo "Missing soak environment file: $SOAK_ENV_FILE" >&2; exit 2; }

compose() {
  TAILVIEW_SOAK_PROJECT="$SOAK_PROJECT" TAILVIEW_SOAK_PORT="$SOAK_PORT" \
    docker compose --project-name "$SOAK_PROJECT" --env-file "$SOAK_ENV_FILE" \
      -f docker-compose.yml -f docker-compose.release.yml -f docker-compose.soak.yml "$@"
}

env_value() {
  key=$1
  sed -n "s/^${key}=//p" "$SOAK_ENV_FILE" | tail -n 1
}

require_candidate() {
  : "${CANDIDATE_TAG:?Set CANDIDATE_TAG=v1.0.0-rc.1}"
  python3 deploy/release_validate.py core-version "$CANDIDATE_TAG" >/dev/null
  version=${CANDIDATE_TAG#v}
  configured=$(env_value TAILVIEW_VERSION)
  test "$configured" = "$version" || {
    echo "TAILVIEW_VERSION in $SOAK_ENV_FILE must be $version" >&2
    exit 2
  }
  test "$(env_value DEMO_MODE)" = "false" || {
    echo "DEMO_MODE must be false for the real-tailnet soak" >&2
    exit 2
  }
  test "$(env_value APP_URL)" = "$SOAK_URL" || {
    echo "APP_URL in $SOAK_ENV_FILE must exactly match SOAK_URL ($SOAK_URL)" >&2
    exit 2
  }
}

wait_ready() {
  attempts=0
  until curl --fail --silent --show-error "$SOAK_URL/health/ready" > "$1"; do
    attempts=$((attempts + 1))
    test "$attempts" -lt 90 || { echo "Soak stack did not become ready" >&2; return 1; }
    sleep 2
  done
}
