#!/usr/bin/env python
"""Recolecta atención (prensa) en local, sin tocar la base productiva.

Escribe un JSONL que después se importa con scripts/import_attention.py.
Reanudable: los CVEs ya hechos quedan en el .done y no se repiten.

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

UA = "humo-vs-miedo/0.3 (+https://github.com/humo-vs-miedo)"
NEWS_URL = "https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"

_lock = threading.Lock()


def fetch_mentions(cve_id, brand, session, limit=25, timeout=20):
    queries = [cve_id]
    if brand and brand.strip():
        queries.append(brand.strip())
    vistas, salida = set(), []
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
            if not url or url in vistas:
                continue
            vistas.add(url)
            medio = entry.get("source")
            if isinstance(medio, dict):
                medio = medio.get("title") or ""
            salida.append({
                "url": url,
                "title": (entry.get("title") or "").strip(),
                # Google News: el medio real está en <source>, no en el título del feed.
                "source": (medio or "").strip() or "Google News",
                "published": entry.get("published") or entry.get("updated"),
            })
    return salida


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="CSV de CVEs (cve_id, brand_name, ...)")
    ap.add_argument("--out", default="attention.jsonl")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="0 = todos los pendientes")
    ap.add_argument("--delay", type=float, default=0.25, help="pausa por CVE en cada worker")
    args = ap.parse_args()

    out = Path(args.out)
    done_path = out.with_suffix(".done")
    hechos = set(done_path.read_text(encoding="utf-8").split()) if done_path.exists() else set()

    filas = []
    with open(args.input, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["cve_id"] in hechos:
                continue
            filas.append(row)
            if args.limit and len(filas) >= args.limit:
                break

    if not filas:
        print("nada pendiente en este CSV")
        return 0

    print(f"a procesar: {len(filas)} (ya hechos: {len(hechos)})", flush=True)
    sesion_local = threading.local()

    def trabajo(row):
        session = getattr(sesion_local, "s", None)
        if session is None:
            session = sesion_local.s = requests.Session()
        try:
            menciones = fetch_mentions(row["cve_id"], row.get("brand_name"), session)
        except Exception as exc:
            return {"cve_id": row["cve_id"], "error": f"{type(exc).__name__}: {exc}"[:120]}
        time.sleep(max(0.0, args.delay))
        return {"cve_id": row["cve_id"], "menciones": menciones}

    procesados = 0
    con_prensa = 0
    with out.open("a", encoding="utf-8") as fh, done_path.open("a", encoding="utf-8") as dfh:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for resultado in pool.map(trabajo, filas):
                with _lock:
                    fh.write(json.dumps(resultado, ensure_ascii=False) + "\n")
                    fh.flush()
                    dfh.write(resultado["cve_id"] + "\n")
                    dfh.flush()
                    procesados += 1
                    if resultado.get("menciones"):
                        con_prensa += 1
                    if procesados % 50 == 0:
                        print(f"  {procesados}/{len(filas)} (con prensa: {con_prensa})", flush=True)

    print(f"listo: {procesados} CVEs, {con_prensa} con prensa -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
