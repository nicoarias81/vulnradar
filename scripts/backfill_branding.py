"""Backfill de brand_name (apodo) para los CVEs que tienen menciones en prensa.

Hasta ahora el paso de branding corría 50 CVEs por ciclo y sólo por LLM, así que
`enrichments.brand_name` quedaba vacío en toda la base y el buscador no podía
resolver "Log4Shell". Este script aplica el heurístico (nombres conocidos,
CamelCase y "dubbed X") sobre los titulares ya guardados: sin red, sin LLM y
sin tocar tone_score/KEV/EPSS.

    python scripts/backfill_branding.py --dry-run
    python scripts/backfill_branding.py

Idempotente: sólo escribe cuando encuentra un apodo que la fila no tiene.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.enrichment_agent import heuristic_branding
from core.db import get_db, init_db


def latest_titles(conn) -> dict:
    """Titular más reciente por CVE (el que tiene más chance de traer el apodo)."""
    rows = conn.execute("""
        SELECT cve_id, title
        FROM media_mentions
        WHERE title IS NOT NULL AND btrim(title) <> ''
        ORDER BY id DESC
    """).fetchall()
    titles: dict = {}
    for row in rows:
        cve_id = (row["cve_id"] or "").strip().upper()
        if cve_id and cve_id not in titles:
            titles[cve_id] = row["title"]
    return titles


def main(dry_run: bool = False) -> dict:
    init_db()
    conn = get_db()
    try:
        titles = latest_titles(conn)
        existing = {
            row["cve_id"]: row["brand_name"]
            for row in conn.execute(
                "SELECT cve_id, brand_name FROM enrichments "
                "WHERE brand_name IS NOT NULL AND btrim(brand_name) <> ''"
            ).fetchall()
        }
        found: list[tuple] = []
        for cve_id, title in titles.items():
            branding, brand = heuristic_branding(title)
            if not branding or not brand:
                continue
            if existing.get(cve_id) == brand:
                continue
            found.append((brand, cve_id))

        print(f"titulares: {len(titles)} | apodos detectados: {len(found)} | "
              f"ya tenían: {len(existing)}")
        if dry_run:
            for brand, cve_id in found[:20]:
                print(f"  {cve_id} -> {brand}")
            return {"candidates": len(found), "written": 0}

        written = 0
        for brand, cve_id in found:
            conn.execute("""
                INSERT INTO enrichments (cve_id, branding, brand_name)
                VALUES (?, 1, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    branding = 1,
                    brand_name = excluded.brand_name
            """, (cve_id, brand))
            written += 1
            if written % 500 == 0:
                conn.commit()
                print(f"  ... {written}/{len(found)}")
        conn.commit()
        print(f"escritos: {written}")
        return {"candidates": len(found), "written": written}
    finally:
        conn.close()


if __name__ == "__main__":
    main(dry_run="--dry-run" in sys.argv)
