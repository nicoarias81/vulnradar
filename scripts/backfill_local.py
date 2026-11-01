"""Press backfill from a local machine, without a database.

The server sits behind a datacenter IP and Google News throttles it to
~1 CVE/s with sustained 5-10 s latencies. From a home connection the
same request takes ~0.5 s and holds ~13 req/s. This runner does only the
network part: it reads the pending list exported from the server and writes the
mentions as NDJSON. The import into Postgres happens later, over there.

    python scripts/backfill_local.py --entrada .cache/pendientes.csv \
        --salida .cache/menciones --shard 0/2 --hilos 8 --rate 12

It is resumable: every finished CVE goes into hechos-<shard>.txt and on the next
run it is skipped. Two different shards can run in parallel without clashing.
"""

import argparse
import csv
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote_plus

import feedparser
import requests

URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
LIMIT_PER_QUERY = 25


def iso_date(entry):
    for field in ("published_parsed", "updated_parsed"):
        value = entry.get(field)
        if value:
            try:
                return time.strftime("%Y-%m-%dT%H:%M:%S", value)
            except Exception:
                pass
    return (entry.get("published") or entry.get("updated") or "").strip() or None


def search(cve_id, brand_name, session, timeout=20):
    """Press mentions for a CVE. Two queries: the id and the nickname.

    Returns (mentions, state). The state matters: Google answers 503 when it
    throttles us, and that is NOT "this CVE had no press". Treating it the same made
    the runner mark thousands of CVEs as done with zero mentions.
    """
    queries = [cve_id]
    if brand_name and brand_name.strip():
        queries.append(brand_name.strip())
    seen, results = set(), []
    blocked = False
    complete = False
    for query in queries:
        try:
            r = session.get(URL.format(query=quote_plus(query)), timeout=timeout,
                           headers={"User-Agent": UA})
        except Exception:
            continue
        if r.status_code in (429, 503):
            blocked = True
            continue
        if r.status_code != 200:
            continue
        complete = True
        for entry in feedparser.parse(r.content).entries[:LIMIT_PER_QUERY]:
            url = (entry.get("link") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            medium = entry.get("source")
            if isinstance(medium, dict):
                medium = medium.get("title") or ""
            results.append({
                "cve_id": cve_id,
                "url": url,
                "title": (entry.get("title") or "").strip(),
                "source": (medium or "").strip(),
                "published": iso_date(entry),
            })
    if blocked and not complete:
        return results, "blocked"
    if not complete:
        return results, "error"
    return results, "ok"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--entrada", required=True, help="CSV cve_id,brand_name")
    p.add_argument("--salida", required=True, help="results folder")
    p.add_argument("--shard", default="0/1", help="i/n: which slice to process")
    p.add_argument("--hilos", type=int, default=8)
    p.add_argument("--rate", type=float, default=12.0,
                   help="queries per second, all threads combined")
    p.add_argument("--limite", type=int, default=0, help="stop after N CVEs")
    args = p.parse_args()

    i, n = (int(x) for x in args.shard.split("/"))
    out_dir = Path(args.salida)
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson = out_dir / f"menciones-{i}de{n}.jsonl"
    done_file = out_dir / f"hechos-{i}de{n}.txt"

    already = set()
    if done_file.exists():
        already = {l.strip() for l in done_file.read_text(encoding="utf-8").splitlines() if l.strip()}

    pending = []
    with open(args.entrada, newline="", encoding="utf-8") as fh:
        for idx, row in enumerate(csv.reader(fh)):
            if not row:
                continue
            if idx % n != i:
                continue
            if row[0] in already:
                continue
            pending.append((row[0], row[1] if len(row) > 1 else ""))
            if args.limite and len(pending) >= args.limite:
                break

    print(f"shard {i}/{n}: {len(pending)} CVEs to process "
          f"({len(already)} already done)", flush=True)
    if not pending:
        return

    interval = (1.0 / args.rate) if args.rate > 0 else 0.0
    rate_lock = threading.Lock()
    last = [0.0]

    def throttle():
        if not interval:
            return
        with rate_lock:
            wait = interval - (time.monotonic() - last[0])
            if wait > 0:
                time.sleep(wait)
            last[0] = time.monotonic()

    thread_local = threading.local()

    def session():
        if not hasattr(thread_local, "s"):
            thread_local.s = requests.Session()
        return thread_local.s

    def process(pair):
        cve, brand = pair
        throttle()
        return cve, search(cve, brand, session())

    t0 = time.perf_counter()
    with_data = total = blocked_streak = 0

    def abort(reason):
        print(f"\nABORTED: {reason}\n"
              f"CVEs that failed were not marked as done: they are "
              f"retried on the next run.", flush=True)

    with open(ndjson, "a", encoding="utf-8") as out, \
            open(done_file, "a", encoding="utf-8") as done, \
            ThreadPoolExecutor(max_workers=args.hilos) as pool:
        futures = {pool.submit(process, pair): pair[0] for pair in pending}
        try:
            for k, fut in enumerate(as_completed(futures), 1):
                try:
                    cve, (mentions, state) = fut.result()
                except Exception as exc:
                    print(f"  {futures[fut]}: {type(exc).__name__}: {str(exc)[:80]}",
                          flush=True)
                    continue
                if state != "ok":
                    # No data means we know nothing about the CVE: leave it pending.
                    blocked_streak += 1
                    if blocked_streak >= 25:
                        for pend in futures:
                            pend.cancel()
                        abort(f"{blocked_streak} consecutive queries without a useful response "
                                f"({state}) — they are throttling us")
                        return
                    continue
                blocked_streak = 0
                for m in mentions:
                    out.write(json.dumps(m, ensure_ascii=False) + "\n")
                total += len(mentions)
                if mentions:
                    with_data += 1
                done.write(cve + "\n")
                if k % 200 == 0:
                    out.flush()
                    done.flush()
                    dt = time.perf_counter() - t0
                    print(f"{k}/{len(pending)}  {k/dt:5.1f} CVE/s  "
                          f"mentions={total}", flush=True)
        finally:
            out.flush()
            done.flush()

    dt = time.perf_counter() - t0
    print(f"done: {len(pending)} CVEs in {dt:.0f}s "
          f"({len(pending)/dt:.1f} CVE/s), {with_data} with press, "
          f"{total} mentions -> {ndjson}", flush=True)


if __name__ == "__main__":
    main()
