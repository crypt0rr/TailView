#!/bin/sh
set -eu

backup_path="${1:-tailview-$(date -u +%Y%m%dT%H%M%SZ).dump}"
docker compose exec -T database pg_dump \
  --username "${POSTGRES_USER:-tailview}" \
  --format custom \
  "${POSTGRES_DB:-tailview}" > "$backup_path"
echo "Backup written to $backup_path"
