#!/usr/bin/env bash
# PostgreSQL snapshot (pg_dump) + rotation.
# Run ON the server. Suggested cron: 0 4 * * *  /opt/vulnradar/deploy/backup-db.sh
set -euo pipefail

APP=/opt/vulnradar
KEEP=3
TS=$(date +%Y%m%d-%H%M%S)

mkdir -p "$APP/data/backups"

set -a
# shellcheck disable=SC1091
source "$APP/deploy/.env.prod"
set +a

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is empty in deploy/.env.prod" >&2
  exit 1
fi

docker run --rm postgres:16-alpine pg_dump --no-owner --no-acl "$DATABASE_URL" \
  | gzip > "$APP/data/backups/humo-$TS.sql.gz"

ls -1t "$APP/data/backups"/humo-*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backups retained: $(ls -1 "$APP/data/backups" 2>/dev/null | wc -l)"
du -sh "$APP/data/backups" 2>/dev/null || true
