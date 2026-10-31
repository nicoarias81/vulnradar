"""Corre sólo la etapa RSS con rerank LLM (CVE + apodo de prensa).

Imprime progreso por feed: el rerank es lo caro (una llamada al LLM cada
RERANK_BATCH entradas), así que sin líneas intermedias un log vacío no dice si
está trabajando o si se colgó.

    python scripts/rerank_feeds.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents import enrichment_agent as agent
from core.db import get_db, init_db


def main() -> None:
    init_db()
    conn = get_db()
    try:
        feeds = agent.load_sources_config().get("rss") or []
        print(f"feeds a procesar: {len(feeds)}", flush=True)
        total_mentions = 0
        total_cves = 0
        for item in feeds:
            # sources.yaml mezcla strings y {name, url}: load_rss espera la URL.
            if isinstance(item, dict):
                url, name = item.get("url"), item.get("name") or item.get("url")
            else:
                url, name = str(item), str(item)
            if not url:
                continue
            start = time.time()
            try:
                res = agent.load_rss(conn, [url], rerank=True)
                conn.commit()
                cves = len(res)
                mentions = sum(res.values())
                total_cves += cves
                total_mentions += mentions
                print(
                    f"  {name}: {cves} CVEs con mención nueva, {mentions} menciones "
                    f"({time.time() - start:.0f}s)",
                    flush=True,
                )
            except Exception as exc:  # un feed roto no frena al resto
                # Sin rollback la conexión queda en "transaction aborted" y
                # todos los feeds siguientes fallan en cascada.
                conn.rollback()
                print(f"  {name}: ERROR {type(exc).__name__}: {exc}", flush=True)

        print(f"total: {total_cves} CVEs, {total_mentions} menciones", flush=True)
        rows = conn.execute(
            """SELECT cve_id, brand_name FROM enrichments
               WHERE brand_name IS NOT NULL AND btrim(brand_name) <> ''
               ORDER BY cve_id DESC LIMIT 15"""
        ).fetchall()
        print(f"apodos guardados (muestra): {len(rows)}", flush=True)
        for row in rows:
            print(f"   {row['cve_id']} -> {row['brand_name']}", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
