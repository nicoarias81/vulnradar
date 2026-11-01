#!/usr/bin/env python
"""Collects attention (press) locally, without touching the production DB.

It writes a JSONL that is later imported with scripts/import_attention.py.
Resumable: CVEs already done stay in the .done file and are not repeated.

    python scripts/collect_attention_local.py --input targets.csv --limit 500
    python scripts/collect_attention_local.py --input targets.csv --workers 5
"""
import argparse
import csv
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote_plus

import feedparser
import requests

UA = "vulnradar/0.3 (+https://github.com/nicoarias81/vulnradar)"
NEWS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"

_lock = threading.Lock()


def fetch_mentions(cve_id, brand, session, limit=25, timeout=20):
    queries = [cve_id]
    if brand and brand.strip():
        queries.append(brand.strip())
    seen, results = set(), []
    for query in queries:
        try:
            r = session.get(NEWS_URL.format(query=quote_plus(query)),
                            timeout=timeout, headers={"User-Agent": UA})
            r.raise_for_status()
        except Exception:
            continue
        parsed = feedparser.parse(r.content)
        for entry in parsed.entries[:limit]:
            url = (entry.get("link") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            outlet = entry.get("source")
            if isinstance(outlet, dict):
                outlet = outlet.get("title") or ""
            results.append({
                "url": url,
                "title": (entry.get("title") or "").strip(),
                # Google News: the real outlet is in <source>, not in the feed title.
                "source": (outlet or "").strip() or "Google News",
                "published": entry.get("published") or entry.get("updated"),
            })
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="CSV of CVEs (cve_id, brand_name, ...)")
    ap.add_argument("--out", default="attention.jsonl")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="0 = all pending")
    ap.add_argument("--delay", type=float, default=0.25, help="pause per CVE in each worker")
    args = ap.parse_args()

    out = Path(args.out)
    done_path = out.with_suffix(".done")
    done_ids = set(done_path.read_text(encoding="utf-8").split()) if done_path.exists() else set()

    rows = []
    with open(args.input, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["cve_id"] in done_ids:
                continue
            rows.append(row)
            if args.limit and len(rows) >= args.limit:
                break

    if not rows:
        print("nothing pending in this CSV")
        return 0

    print(f"to process: {len(rows)} (already done: {len(done_ids)})", flush=True)
    local_session = threading.local()

    def task(row):
        session = getattr(local_session, "s", None)
        if session is None:
            session = local_session.s = requests.Session()
        try:
            mentions = fetch_mentions(row["cve_id"], row.get("brand_name"), session)
        except Exception as exc:
            return {"cve_id": row["cve_id"], "error": f"{type(exc).__name__}: {exc}"[:120]}
        time.sleep(max(0.0, args.delay))
        return {"cve_id": row["cve_id"], "menciones": mentions}

    processed = 0
    with_press = 0
    with out.open("a", encoding="utf-8") as fh, done_path.open("a", encoding="utf-8") as dfh:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for result in pool.map(task, rows):
                with _lock:
                    fh.write(json.dumps(result, ensure_ascii=False) + "\n")
                    fh.flush()
                    dfh.write(result["cve_id"] + "\n")
                    dfh.flush()
                    processed += 1
                    if result.get("menciones"):
                        with_press += 1
                    if processed % 50 == 0:
                        print(f"  {processed}/{len(rows)} (with press: {with_press})", flush=True)

    print(f"done: {processed} CVEs, {with_press} with press -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
