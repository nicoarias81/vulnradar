#!/usr/bin/env bash
# Snapshot consistente de SQLite (API .backup, sin parar el dashboard) + rotación.
# Correr EN el server. Cron sugerido: 0 4 * * *  /opt/vulnradar/deploy/backup-db.sh
set -euo pipefail

APP=/opt/vulnradar
KEEP=3
TS=$(date +%Y%m%d-%H%M%S)

mkdir -p "$APP/data/backups"

docker compose -f "$APP/deploy/docker-compose.server.yml" --env-file "$APP/deploy/.env.prod" \
  exec -T dashboard python - "$TS" <<'PY'
import sqlite3, sys
from pathlib import Path

ts = sys.argv[1]
dst_path = Path(f"/app/data/backups/humo-{ts}.db")
src = sqlite3.connect("/app/data/humo.db")
dst = sqlite3.connect(dst_path)
try:
    src.backup(dst)
finally:
    dst.close()
    src.close()
print(f"backup: humo-{ts}.db {dst_path.stat().st_size // (1024*1024)} MB")
PY

# Comprimir y rotar (los .db crudos son ~2 GB).
gzip -f "$APP/data/backups/humo-$TS.db"
ls -1t "$APP/data/backups"/humo-*.db.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backups retenidos: $(ls -1 "$APP/data/backups" 2>/dev/null | wc -l)"
du -sh "$APP/data/backups" 2>/dev/null || true
