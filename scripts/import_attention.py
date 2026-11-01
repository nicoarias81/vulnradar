#!/usr/bin/env python
"""Imports into the production DB the JSONL produced by collect_attention_local.py.

Idempotent: mentions have PK (cve_id, url), so reimporting the same
file duplicates nothing. It marks attention_backfill and recalculates only what was touched.

    python scripts/import_attention.py attention.jsonl
    python scripts/import_attention.py attention.jsonl --score-only
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.enrichment_agent import upsert_media_mentions
from agents.scoring_agent import score_cves
from core.db import get_db, init_db


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="JSONL produced by collect_attention_local.py")
    ap.add_argument("--score-only", action="store_true",
                    help="do not insert, only recompute the score of the CVEs in the file")
    ap.add_argument("--limit", type=int, default=0, help="truncate to N lines")
    args = ap.parse_args()

    init_db()
    conn = get_db()

    pending, touched, new_total, errors = [], [], 0, 0
    with open(args.jsonl, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if args.limit and i >= args.limit:
                break
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue
            cve_id = (row.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            touched.append(cve_id)
            if args.score_only:
                continue
            mentions = [dict(m, cve_id=cve_id) for m in row.get("menciones") or []]
            if mentions:
                new_total += upsert_media_mentions(conn, mentions).get(cve_id, 0)
                # Refreshes title/outlet/date of what is already loaded without touching the counts.
                for m in mentions:
                    conn.execute(
                        "UPDATE media_mentions SET title = ?, source = ?, published = ? "
                        "WHERE cve_id = ? AND url = ?",
                        (m.get("title"), m.get("source"), m.get("published"),
                         cve_id, m.get("url")),
                    )
            pending.append(cve_id)
            if len(pending) >= 500:
                for cve in pending:
                    conn.execute(
                        "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                        "ON CONFLICT (cve_id) DO NOTHING", (cve,)
                    )
                conn.commit()
                pending = []
                print(f"  imported {i + 1} records, {new_total} new mentions", flush=True)

    for cve in pending:
        conn.execute(
            "INSERT INTO attention_backfill (cve_id) VALUES (?) ON CONFLICT (cve_id) DO NOTHING",
            (cve,),
        )
    conn.commit()

    scored = score_cves(conn, touched)
    conn.commit()
    print(f"done: {len(touched)} CVEs, {new_total} new mentions, "
          f"{scored} scored, {errors} unreadable lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
