#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "Usage: sh deploy/verify-backup.sh BACKUP.dump" >&2
  exit 2
fi

backup_path="$1"
case "$backup_path" in
  /*) ;;
  *) backup_path="$(pwd)/$backup_path" ;;
esac
work_dir="$(mktemp -d)"
suffix="$(date +%s)-$$"
container="tailview-backup-verify-$suffix"
network="tailview-backup-verify-$suffix"
password="verify-$suffix"
result_file="$work_dir/result.json"
status="failed"
error_class="VerificationFailed"
recorded=0

cleanup() {
  if [ "$recorded" -eq 0 ] && [ -n "${backup_hash:-}" ]; then
    FILENAME="$(basename "$backup_path")" BACKUP_HASH="$backup_hash" BACKUP_SIZE="${backup_size:-0}" \
    STATUS="failed" ERROR_CLASS="$error_class" \
    python3 -c 'import json,os; print(json.dumps({"filename":os.environ["FILENAME"],"content_hash":os.environ["BACKUP_HASH"],"size":int(os.environ["BACKUP_SIZE"]),"status":"failed","checks":{},"error_class":os.environ["ERROR_CLASS"]}))' > "$result_file" 2>/dev/null || true
    docker compose exec -T backend python -m app.ops_cli record-backup-verification < "$result_file" >/dev/null 2>&1 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

if command -v sha256sum >/dev/null 2>&1; then
  backup_hash="$(sha256sum "$backup_path" | awk '{print $1}')"
else
  backup_hash="$(shasum -a 256 "$backup_path" | awk '{print $1}')"
fi
backup_size="$(wc -c < "$backup_path" | tr -d ' ')"
if [ -f "${backup_path}.sha256" ]; then
  expected_hash="$(awk '{print $1}' "${backup_path}.sha256")"
  [ "$backup_hash" = "$expected_hash" ] || { echo "Backup hash does not match sidecar" >&2; exit 1; }
fi

docker network create "$network" >/dev/null
docker run -d --name "$container" --network "$network" \
  -e POSTGRES_DB=tailview_verify -e POSTGRES_USER=tailview_verify -e POSTGRES_PASSWORD="$password" \
  postgres:17.5-alpine >/dev/null

attempt=0
until docker exec "$container" pg_isready -U tailview_verify -d tailview_verify >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 30 ] || { echo "Temporary PostgreSQL did not become ready" >&2; exit 1; }
  sleep 1
done

docker exec -i "$container" pg_restore -U tailview_verify -d tailview_verify \
  --clean --if-exists --no-owner --no-privileges < "$backup_path"
docker compose build backend >/dev/null
docker run --rm --network "$network" \
  -e ENVIRONMENT=development \
  -e DATABASE_URL="postgresql+psycopg://tailview_verify:$password@$container:5432/tailview_verify" \
  tailview-backend sh -c "alembic upgrade head"

migration_revision="$(docker exec "$container" psql -At -U tailview_verify -d tailview_verify -c 'SELECT version_num FROM alembic_version')"
postgres_version="$(docker exec "$container" psql -At -U tailview_verify -d tailview_verify -c 'SHOW server_version')"
docker exec "$container" psql -v ON_ERROR_STOP=1 -U tailview_verify -d tailview_verify \
  -c 'SELECT count(*) FROM app_users' \
  -c 'SELECT count(*) FROM devices' \
  -c 'SELECT count(*) FROM report_runs' >/dev/null
status="success"
error_class=""

FILENAME="$(basename "$backup_path")" BACKUP_HASH="$backup_hash" BACKUP_SIZE="$backup_size" \
POSTGRES_VERSION="$postgres_version" MIGRATION_REVISION="$migration_revision" STATUS="$status" ERROR_CLASS="$error_class" \
python3 -c 'import json,os; print(json.dumps({"filename":os.environ["FILENAME"],"content_hash":os.environ["BACKUP_HASH"],"size":int(os.environ["BACKUP_SIZE"]),"status":os.environ["STATUS"],"postgres_version":os.environ["POSTGRES_VERSION"],"migration_revision":os.environ["MIGRATION_REVISION"],"checks":{"restore":True,"migrations":True,"authentication_table":True,"inventory_table":True,"reporting_table":True},"error_class":os.environ["ERROR_CLASS"]}))' > "$result_file"
docker compose exec -T backend python -m app.ops_cli record-backup-verification < "$result_file"
recorded=1
echo "Backup verified in an isolated PostgreSQL instance (SHA-256: $backup_hash)"
