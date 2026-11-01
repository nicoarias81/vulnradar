"""Creates the search indexes with CONCURRENTLY (it does not block the worker).

`init_db` cannot: it runs inside a transaction and with a lock_timeout, so
in production the large indexes are created with this script once.

    docker exec -i vulnradar-dashboard-1 python - < scripts/create_indexes.py
"""
import sys
import time

sys.path.insert(0, "/app")

from core.db import get_db

INDEXES = [
    (
        "idx_cves_fts",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cves_fts ON cves "
        "USING gin (to_tsvector('english', coalesce(description, '')))",
    ),
    (
        "idx_enrich_brand_trgm",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enrich_brand_trgm ON enrichments "
        "USING gin (brand_name gin_trgm_ops)",
    ),
    (
        "idx_cves_id_trgm",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cves_id_trgm ON cves "
        "USING gin (cve_id gin_trgm_ops)",
    ),
]


def main() -> None:
    conn = get_db()
    conn._raw.autocommit = True  # CONCURRENTLY cannot run inside a transaction
    try:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        for name, sql in INDEXES:
            start = time.time()
            print(f"creando {name} ...", flush=True)
            conn.execute(sql)
            print(f"ok {name} en {time.time() - start:.1f}s", flush=True)
        rows = conn.execute(
            "SELECT indexname FROM pg_indexes WHERE indexname LIKE '%trgm%' OR indexname LIKE '%_fts'"
        ).fetchall()
        print("indices:", [tuple(r)[0] for r in rows], flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
