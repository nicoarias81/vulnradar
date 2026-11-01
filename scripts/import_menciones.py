"""Imports the mentions produced by backfill_local.py into the server DB.

It reads the NDJSON, inserts into media_mentions without duplicating and adds media_count only
for the new URLs (the PK (cve_id, url) is the lock, same as in the normal
path). Then it marks the CVEs in attention_backfill and rescores.

    python scripts/import_menciones.py .local/menciones-0de1.jsonl --batch 5000
"""

import argparse
import json
import sys
from pathlib import Path

from core.db import get_db

STAGING = "CREATE TEMP TABLE stg_menciones (" \
          "cve_id text, url text, title text, source text, published text) ON COMMIT DROP"

NUEVAS_POR_CVE = """
    SELECT s.cve_id, count(*) FILTER (WHERE m.url IS NULL) AS nuevas
    FROM stg_menciones s
    LEFT JOIN media_mentions m ON m.cve_id = s.cve_id AND m.url = s.url
    GROUP BY s.cve_id
"""


def importar(conn, rows):
    """rows: list of dicts with cve_id/url/title/source/published."""
    cur = conn.cursor()
    cur.execute(STAGING)
    cur.executemany(
        "INSERT INTO stg_menciones (cve_id, url, title, source, published) "
        "VALUES (?, ?, ?, ?, ?)",
        [(f["cve_id"], f["url"], f.get("title"), f.get("source"),
          f.get("published")) for f in rows],
    )
    cur.execute(NUEVAS_POR_CVE)
    nuevas = {r[0]: r[1] for r in cur.fetchall()}

    cur.execute("""
        INSERT INTO media_mentions (cve_id, url, title, source, published)
        SELECT DISTINCT ON (cve_id, url) cve_id, url, title, source, published
        FROM stg_menciones
        ON CONFLICT (cve_id, url) DO NOTHING
    """)
    insertadas = cur.rowcount

    for cve_id, delta in nuevas.items():
        if not delta:
            continue
        cur.execute("""
            INSERT INTO enrichments (cve_id, media_count) VALUES (?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET
                media_count = COALESCE(enrichments.media_count, 0) + excluded.media_count,
                updated_at = CURRENT_TIMESTAMP
        """, (cve_id, delta))
    conn.commit()
    cur.close()
    return insertadas, nuevas


def main():
    p = argparse.ArgumentParser()
    p.add_argument("archivo", help="NDJSON with mentions")
    p.add_argument("--batch", type=int, default=5000)
    p.add_argument("--no-score", action="store_true")
    p.add_argument("--no-marcar", action="store_true",
                   help="do not touch attention_backfill: leaves the Google queue intact "
                        "when the mentions come from another source (HN)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    ruta = Path(args.archivo)
    if not ruta.exists():
        sys.exit(f"no existe {ruta}")

    conn = get_db()
    total_leidas = total_insert = 0
    cves_tocados = set()
    batch = []

    with open(ruta, encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea:
                continue
            try:
                batch.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
            total_leidas += 1
            if len(batch) >= args.batch:
                if not args.dry_run:
                    ins, nuevas = importar(conn, batch)
                    total_insert += ins
                    cves_tocados.update(nuevas)
                print(f"{total_leidas} read, {total_insert} inserted", flush=True)
                batch = []

    if batch and not args.dry_run:
        ins, nuevas = importar(conn, batch)
        total_insert += ins
        cves_tocados.update(nuevas)
        print(f"{total_leidas} read, {total_insert} inserted", flush=True)

    if cves_tocados:
        cur = conn.cursor()
        if not args.no_marcar:
            cur.executemany(
                "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                "ON CONFLICT (cve_id) DO NOTHING",
                [(c,) for c in cves_tocados],
            )
            conn.commit()
        if not args.no_score:
            from agents.scoring_agent import score_cves
            for i in range(0, len(cves_tocados), 500):
                chunk = sorted(cves_tocados)[i:i + 500]
                score_cves(conn, chunk)
                conn.commit()
        cur.close()

    print(f"done: {total_leidas} mentions read, {total_insert} new, "
          f"{len(cves_tocados)} CVEs marked", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
