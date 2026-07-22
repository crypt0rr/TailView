#!/bin/sh
set -eu

backup_path="${1:-tailview-$(date -u +%Y%m%dT%H%M%SZ).dump}"
docker compose exec -T database pg_dump \
  --username "${POSTGRES_USER:-tailview}" \
  --format custom \
  "${POSTGRES_DB:-tailview}" > "$backup_path"
if command -v sha256sum >/dev/null 2>&1; then
  backup_hash="$(sha256sum "$backup_path" | awk '{print $1}')"
else
  backup_hash="$(shasum -a 256 "$backup_path" | awk '{print $1}')"
fi
printf '%s  %s\n' "$backup_hash" "$(basename "$backup_path")" > "${backup_path}.sha256"
BACKUP_FILENAME="$(basename "$backup_path")" BACKUP_HASH="$backup_hash" \
BACKUP_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
python3 -c 'import json,os; print(json.dumps({"schema_version":1,"filename":os.environ["BACKUP_FILENAME"],"sha256":os.environ["BACKUP_HASH"],"created_at":os.environ["BACKUP_CREATED_AT"]}))' > "${backup_path}.json"
echo "Backup written to $backup_path (SHA-256: $backup_hash)"
