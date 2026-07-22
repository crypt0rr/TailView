#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "Usage: sh deploy/restore.sh BACKUP.dump" >&2
  exit 2
fi

docker compose exec -T database pg_restore \
  --username "${POSTGRES_USER:-tailview}" \
  --dbname "${POSTGRES_DB:-tailview}" \
  --clean --if-exists < "$1"
echo "Restore completed from $1"
