#!/usr/bin/env python
"""Resumable attention backfill (press + PoCs + tone) over every CVE.

Meant to run "a little at a time": each invocation processes a bounded batch, marks
it in attention_backfill and the next one resumes where it stopped. It never repeats a CVE.

    python scripts/backfill_all_attention.py --batch 40          # one batch
    python scripts/backfill_all_attention.py --batch 40 --tone   # with the LLM
    python scripts/backfill_all_attention.py --state             # how much is left
"""
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests

from agents.enrichment_agent import (
    load_pocs,
    load_tone,
    search_mentions,
    upsert_media_mentions,
)
from agents.scoring_agent import score_cves
from core.db import get_db, init_db

# Priority: first what can have attention today (KEV, with PoCs, recent).
NEXT_BATCH = """
    SELECT e.cve_id AS cve_id,
           e.brand_name AS brand_name,
           COALESCE(e.poc_count, 0) AS poc_count,
           COALESCE(e.media_count, 0) AS media_count
    FROM enrichments e
    LEFT JOIN cves c ON c.cve_id = e.cve_id
    LEFT JOIN attention_backfill b ON b.cve_id = e.cve_id
    WHERE b.cve_id IS NULL
    ORDER BY COALESCE(e.in_kev, 0) DESC,
             COALESCE(e.poc_count, 0) DESC,
             c.published DESC NULLS LAST
    LIMIT ?
"""

PENDING = """
    SELECT count(*) AS pending
    FROM enrichments e
    LEFT JOIN attention_backfill b ON b.cve_id = e.cve_id
    WHERE b.cve_id IS NULL
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=int, default=40, help="CVEs per run")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between CVEs")
    parser.add_argument("--tone", action="store_true", help="analyze tone with the LLM")
    parser.add_argument("--skip-pocs", action="store_true", help="do not query GitHub")
    parser.add_argument("--state", action="store_true", help="only report progress")
    parser.add_argument(
        "--workers", type=int, default=1,
        help="threads in parallel (1 = sequential). Each one opens its own "
             "connection; use a bigger batch.",
    )
    parser.add_argument(
        "--poc-interval", type=float, default=6.0,
        help="seconds between GitHub searches when there are several workers "
             "(without a token it is 10 req/min: 6 s avoids the 429s)",
    )
    parser.add_argument(
        "--rate", type=float, default=15.0,
        help="press queries per second, all threads combined (0 = no cap). "
             "20 threads are faster, but Google News cuts you off if abused",
    )
    args = parser.parse_args()

    init_db()
    conn = get_db()

    pending = conn.execute(PENDING).fetchone()["pending"]
    if args.state:
        done_count = conn.execute("SELECT count(*) AS c FROM attention_backfill").fetchone()["c"]
        print(f"processed: {done_count} | pending: {pending}")
        return 0

    if not pending:
        print("backfill complete: no CVEs pending")
        return 0

    batch_rows = conn.execute(NEXT_BATCH, (max(1, args.batch),)).fetchall()
    print(f"pending: {pending} | batch: {len(batch_rows)}")

    http = requests.Session()
    processed, with_press = [], 0

    if args.workers > 1:
        # Each thread opens its own connection: psycopg does not share one across threads.
        # Press parallelizes well; GitHub does not, because without a token it is 10
        # searches per minute and in parallel you only harvest 429s.
        poc_lock = threading.Lock()
        # Global press query ceiling: 8 threads do 37 req/s and Google
        # News starts returning empty. A shared turn keeps it even.
        rate_lock = threading.Lock()
        interval = (1.0 / args.rate) if args.rate > 0 else 0.0
        last = [0.0]

        def throttle():
            if not interval:
                return
            with rate_lock:
                wait = interval - (time.monotonic() - last[0])
                if wait > 0:
                    time.sleep(wait)
                last[0] = time.monotonic()

        def process(row):
            cve_id = row["cve_id"]
            own_conn = get_db()
            try:
                if not args.skip_pocs and not row["poc_count"]:
                    with poc_lock:
                        load_pocs(own_conn, [cve_id])
                        time.sleep(max(0.0, args.poc_interval))
                throttle()
                session = requests.Session()
                mentions = search_mentions(cve_id, row["brand_name"], session=session)
                new_count = upsert_media_mentions(own_conn, mentions).get(cve_id, 0)
                own_conn.execute(
                    "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                    "ON CONFLICT (cve_id) DO NOTHING", (cve_id,)
                )
                own_conn.commit()
                return cve_id, new_count, None
            except Exception as exc:
                try:
                    own_conn.rollback()
                except Exception:
                    pass
                return cve_id, 0, f"{type(exc).__name__}: {str(exc)[:90]}"
            finally:
                try:
                    own_conn.close()
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(process, r) for r in batch_rows]
            for fut in as_completed(futures):
                cve_id, new_count, err = fut.result()
                if err:
                    print(f"  {cve_id}: {err}")
                    continue
                if new_count:
                    with_press += 1
                processed.append(cve_id)
    else:
        for row in batch_rows:
            cve_id = row["cve_id"]
            try:
                if not args.skip_pocs and not row["poc_count"]:
                    load_pocs(conn, [cve_id])
                mentions = search_mentions(cve_id, row["brand_name"], session=http)
                new_count = upsert_media_mentions(conn, mentions).get(cve_id, 0)
                if new_count:
                    with_press += 1
                conn.execute(
                    "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                    "ON CONFLICT (cve_id) DO NOTHING", (cve_id,)
                )
                conn.commit()
                processed.append(cve_id)
            except Exception as exc:
                conn.rollback()
                print(f"  {cve_id}: {type(exc).__name__}: {str(exc)[:90]}")
            time.sleep(max(0.0, args.delay))

    if args.tone and processed:
        try:
            updated = load_tone(conn, limit=max(10, len(processed)))
            conn.commit()
            print(f"tone updated: {updated}")
        except Exception as exc:
            conn.rollback()
            print(f"  tone: {type(exc).__name__}: {str(exc)[:90]}")

    scored = 0
    for i in range(0, len(sorted(processed)), 250):
        chunk = sorted(processed)[i:i + 250]
        scored += score_cves(conn, chunk)
        conn.commit()

    remaining = conn.execute(PENDING).fetchone()["pending"]
    print(f"batch done: {len(processed)} CVEs ({with_press} with new press) "
          f"| scored: {scored} | pending: {remaining}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
