"""Importa las menciones producidas por backfill_local.py a la base del servidor.

Lee el NDJSON, inserta en media_mentions sin duplicar y suma media_count sólo
por las URLs nuevas (la PK (cve_id, url) es el candado, igual que en el camino
normal). Después marca los CVEs en attention_backfill y repuntúa.

    python scripts/import_menciones.py .local/menciones-0de1.jsonl --lote 5000
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


def importar(conn, filas):
    """filas: lista de dicts con cve_id/url/title/source/published."""
    cur = conn.cursor()
    cur.execute(STAGING)
    cur.executemany(
        "INSERT INTO stg_menciones (cve_id, url, title, source, published) "
        "VALUES (?, ?, ?, ?, ?)",
        [(f["cve_id"], f["url"], f.get("title"), f.get("source"),
          f.get("published")) for f in filas],
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
    p.add_argument("archivo", help="NDJSON con menciones")
    p.add_argument("--lote", type=int, default=5000)
    p.add_argument("--no-score", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    ruta = Path(args.archivo)
    if not ruta.exists():
        sys.exit(f"no existe {ruta}")

    conn = get_db()
    total_leidas = total_insert = 0
    cves_tocados = set()
    lote = []

    with open(ruta, encoding="utf-8") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea:
                continue
            try:
                lote.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
            total_leidas += 1
            if len(lote) >= args.lote:
                if not args.dry_run:
                    ins, nuevas = importar(conn, lote)
                    total_insert += ins
                    cves_tocados.update(nuevas)
                print(f"{total_leidas} leídas, {total_insert} insertadas", flush=True)
                lote = []

    if lote and not args.dry_run:
        ins, nuevas = importar(conn, lote)
        total_insert += ins
        cves_tocados.update(nuevas)
        print(f"{total_leidas} leídas, {total_insert} insertadas", flush=True)

    if cves_tocados:
        cur = conn.cursor()
        cur.executemany(
            "INSERT INTO attention_backfill (cve_id) VALUES (?) "
            "ON CONFLICT (cve_id) DO NOTHING",
            [(c,) for c in cves_tocados],
        )
        conn.commit()
        if not args.no_score:
            from agents.scoring_agent import score_cves
            for i in range(0, len(cves_tocados), 500):
                trozo = sorted(cves_tocados)[i:i + 500]
                score_cves(conn, trozo)
                conn.commit()
        cur.close()

    print(f"listo: {total_leidas} menciones leídas, {total_insert} nuevas, "
          f"{len(cves_tocados)} CVEs marcados", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
