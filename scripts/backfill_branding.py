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

from agents.enrichment_agent import (
    KNOWN_BRANDS,
    analyze_tone_batch,
    heuristic_branding,
    upsert_tone,
)
from core.db import get_db, init_db

LLM_BATCH = 8


def top_without_brand(conn, limit: int) -> list:
    """CVEs con más hype que todavía no tienen apodo (para preguntarle al LLM)."""
    rows = conn.execute("""
        SELECT s.cve_id AS cve_id, c.description AS description
        FROM scores s
        JOIN cves c ON c.cve_id = s.cve_id
        LEFT JOIN enrichments e ON e.cve_id = s.cve_id
        WHERE e.brand_name IS NULL OR btrim(e.brand_name) = ''
        ORDER BY s.hype DESC NULLS LAST
        LIMIT ?
    """, (max(0, int(limit)),)).fetchall()
    return [
        {"cve_id": row["cve_id"], "title": (row["description"] or "")[:280]}
        for row in rows
    ]


def llm_backfill(conn, limit: int, batch_size: int = LLM_BATCH) -> dict:
    """Pide al LLM el apodo de marketing de los CVEs más visibles.

    Sólo escribe brand_name cuando la respuesta viene del LLM: el heurístico
    sobre una descripción NVD levanta CamelCase de productos (Chrome, Windows).
    """
    targets = top_without_brand(conn, limit)
    named = written = 0
    for start in range(0, len(targets), batch_size):
        chunk = targets[start:start + batch_size]
        results = analyze_tone_batch(chunk)
        for item in results:
            if item.get("source") != "llm":
                item.pop("brand_name", None)
                item["branding"] = False
            elif item.get("brand_name"):
                named += 1
        written += upsert_tone(conn, results)
        conn.commit()
        print(f"  {min(start + batch_size, len(targets))}/{len(targets)} "
              f"apodos={named}", flush=True)
    return {"targets": len(targets), "written": written, "named": named}


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


def main(dry_run: bool = False, llm_limit: int = 0) -> dict:
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
            # El heurístico también levanta CamelCase de productos y grupos
            # (TeamViewer, GitLab, ShinyHunters): para el buscador sólo sirven
            # apodos de marketing, así que se aceptan los de la lista curada.
            if brand not in KNOWN_BRANDS:
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
        if llm_limit and not dry_run:
            print(f"LLM: apodos para los {llm_limit} CVEs con mas hype ...", flush=True)
            print("llm:", llm_backfill(conn, llm_limit), flush=True)
        return {"candidates": len(found), "written": written}
    finally:
        conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    limit = 0
    for i, arg in enumerate(args):
        if arg.startswith("--llm="):
            limit = int(arg.split("=", 1)[1])
        elif arg == "--llm" and i + 1 < len(args):
            limit = int(args[i + 1])
    main(dry_run="--dry-run" in args, llm_limit=limit)
