"""Technical attention via Hacker News (Algolia API), no key or registration.

Google News blocked our IP with 503 after a few thousand queries and its
sustained rate was ~1.2 CVE/s. HN answers in ~0.6 s and holds 12 req/s
measured, with 55% coverage on 2021-2024 CVEs: it works as a massive sweep
where Google no longer keeps up.

    python scripts/backfill_hn.py --entrada .cache/pendientes.csv \
        --salida .cache/hn --shard 0/1 --hilos 8 --rate 10

It writes the same NDJSON as backfill_local.py, so it goes in through
import_menciones.py. Its state is its own (hechos-hn-<shard>.txt): HN and Google
do not share what is done, because a CVE can be in one and not the other.
"""

import argparse
import csv
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

API = "https://hn.algolia.com/api/v1/search"
UA = "vulnradar-research/0.1 (+https://nan.builders)"
PER_PAGE = 100


def search(cve_id, session, timeout=20):
    """(mentions, state). Stories only: comments are noise for this."""
    try:
        r = session.get(API, params={"query": cve_id, "hitsPerPage": PER_PAGE},
                       timeout=timeout, headers={"User-Agent": UA})
    except Exception as exc:
        return [], f"error:{type(exc).__name__}"
    if r.status_code in (429, 503):
        return [], "throttled"
    if r.status_code != 200:
        return [], f"error:{r.status_code}"
    try:
        hits = r.json().get("hits", [])
    except ValueError:
        return [], "error:json"

    results, seen = [], set()
    for hit in hits:
        tags = hit.get("_tags") or []
        if "story" not in tags:
            continue
        title = (hit.get("title") or hit.get("story_title") or "").strip()
        if not title:
            continue
        url = (hit.get("url") or "").strip()
        if not url:
            url = f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        if url in seen:
            continue
        seen.add(url)
        results.append({
            "cve_id": cve_id,
            "url": url,
            "title": title,
            "source": "Hacker News",
            "published": hit.get("created_at"),
            "points": hit.get("points") or 0,
            "comments": hit.get("num_comments") or 0,
        })
    return results, "ok"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--entrada", required=True)
    p.add_argument("--salida", required=True)
    p.add_argument("--shard", default="0/1")
    p.add_argument("--hilos", type=int, default=8)
    p.add_argument("--rate", type=float, default=10.0)
    p.add_argument("--limite", type=int, default=0)
    args = p.parse_args()

    i, n = (int(x) for x in args.shard.split("/"))
    out_dir = Path(args.salida)
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson = out_dir / f"hn-{i}de{n}.jsonl"
    done_file = out_dir / f"hechos-hn-{i}de{n}.txt"

    already = set()
    if done_file.exists():
        already = {l.strip() for l in done_file.read_text(encoding="utf-8").splitlines() if l.strip()}

    pending = []
    with open(args.entrada, newline="", encoding="utf-8") as fh:
        for idx, row in enumerate(csv.reader(fh)):
            if not row:
                continue
            if idx % n != i or row[0] in already:
                continue
            pending.append(row[0])
            if args.limite and len(pending) >= args.limite:
                break

    print(f"shard {i}/{n}: {len(pending)} CVEs to query on HN "
          f"({len(already)} already done)", flush=True)
    if not pending:
        return

    interval = (1.0 / args.rate) if args.rate > 0 else 0.0
    rate_lock = threading.Lock()
    last = [0.0]
    thread_local = threading.local()

    def throttle():
        if not interval:
            return
        with rate_lock:
            wait = interval - (time.monotonic() - last[0])
            if wait > 0:
                time.sleep(wait)
            last[0] = time.monotonic()

    def session():
        if not hasattr(thread_local, "s"):
            thread_local.s = requests.Session()
        return thread_local.s

    def process(cve):
        throttle()
        return cve, search(cve, session())

    t0 = time.perf_counter()
    with_data = total = blocked_streak = 0
    with open(ndjson, "a", encoding="utf-8") as out, \
            open(done_file, "a", encoding="utf-8") as done, \
            ThreadPoolExecutor(max_workers=args.hilos) as pool:
        futures = {pool.submit(process, c): c for c in pending}
        try:
            for k, fut in enumerate(as_completed(futures), 1):
                try:
                    cve, (mentions, state) = fut.result()
                except Exception as exc:
                    print(f"  {futures[fut]}: {type(exc).__name__}", flush=True)
                    continue
                if state != "ok":
                    blocked_streak += 1
                    if blocked_streak >= 25:
                        for pend in futures:
                            pend.cancel()
                        print(f"\nABORTED: {blocked_streak} queries without a useful response "
                              f"({state}). CVEs with an error stay pending.",
                              flush=True)
                        return
                    continue
                blocked_streak = 0
                for m in mentions:
                    out.write(json.dumps(m, ensure_ascii=False) + "\n")
                total += len(mentions)
                if mentions:
                    with_data += 1
                done.write(cve + "\n")
                if k % 250 == 0:
                    out.flush()
                    done.flush()
                    dt = time.perf_counter() - t0
                    print(f"{k}/{len(pending)}  {k/dt:5.1f} CVE/s  "
                          f"with_mentions={with_data}  mentions={total}", flush=True)
        finally:
            out.flush()
            done.flush()

    dt = time.perf_counter() - t0
    print(f"done: {len(pending)} CVEs in {dt:.0f}s ({len(pending)/dt:.1f} CVE/s), "
          f"{with_data} with mentions, {total} mentions -> {ndjson}", flush=True)


if __name__ == "__main__":
    main()
