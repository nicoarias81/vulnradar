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

# The DB host (`postgres`) only resolves on the `db` network: without it pg_dump
# fails to connect and the pipe leaves an empty 20-byte gzip that looks like a backup.
# The client major must match the server (17.x in prod): a 16 client aborts with
# "server version mismatch" and, with pipefail, leaves the empty file behind.
docker run --rm --network db postgres:17-alpine pg_dump --no-owner --no-acl "$DATABASE_URL" \
  | gzip > "$APP/data/backups/humo-$TS.sql.gz"

# A dump that decompresses to nothing is not a backup: fail loudly instead of rotating it in.
if [ "$(gzip -dc "$APP/data/backups/humo-$TS.sql.gz" | head -c 64 | wc -c)" -lt 64 ]; then
  echo "backup is empty, aborting: $APP/data/backups/humo-$TS.sql.gz" >&2
  rm -f "$APP/data/backups/humo-$TS.sql.gz"
  exit 1
fi

ls -1t "$APP/data/backups"/humo-*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backups retained: $(ls -1 "$APP/data/backups" 2>/dev/null | wc -l)"
du -sh "$APP/data/backups" 2>/dev/null || true
