"""Backfill of brand_name (nickname) for the CVEs that have press mentions.

Until now the branding step ran 50 CVEs per cycle and only through the LLM, so
`enrichments.brand_name` stayed empty across the whole DB and the search box could not
resolve "Log4Shell". This script applies the heuristic (known names,
CamelCase and "dubbed X") over the headlines already stored: no network, no LLM and
no touching tone_score/KEV/EPSS.

    python scripts/backfill_branding.py --dry-run
    python scripts/backfill_branding.py

Idempotent: it only writes when it finds a nickname the row does not have.
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
    """CVEs with the most hype that still have no nickname (to ask the LLM)."""
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
    """Asks the LLM for the marketing nickname of the most visible CVEs.

    It only writes brand_name when the answer comes from the LLM: the heuristic
    over an NVD description picks up product CamelCase (Chrome, Windows).
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
    """Most recent headline per CVE (the one most likely to carry the nickname)."""
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
            # The heuristic also picks up product and group CamelCase
            # (TeamViewer, GitLab, ShinyHunters): the search box only takes
            # marketing nicknames, so only the ones in the curated list are accepted.
            if brand not in KNOWN_BRANDS:
                continue
            if existing.get(cve_id) == brand:
                continue
            found.append((brand, cve_id))

        print(f"headlines: {len(titles)} | brand names detected: {len(found)} | "
              f"already had one: {len(existing)}")
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
            print(f"LLM: brand names for the {llm_limit} most hyped CVEs ...", flush=True)
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
