"""Atención técnica vía Hacker News (Algolia API), sin key ni registro.

Google News nos bloqueó la IP con 503 después de unos miles de consultas y su
ritmo sostenido era ~1,2 CVE/s. HN responde en ~0,6 s y aguanta 12 req/s
medidos, con cobertura del 55% en CVEs de 2021-2024: sirve como barrido masivo
donde Google ya no da abasto.

    python scripts/backfill_hn.py --entrada .cache/pendientes.csv \
        --salida .cache/hn --shard 0/1 --hilos 8 --rate 10

Escribe el mismo NDJSON que backfill_local.py, así entra por
import_menciones.py. El estado es propio (hechos-hn-<shard>.txt): HN y Google
no comparten qué está hecho, porque un CVE puede estar en una y no en la otra.
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
POR_PAGINA = 100


def buscar(cve_id, sesion, timeout=20):
    """(menciones, estado). Sólo stories: los comentarios son ruido para esto."""
    try:
        r = sesion.get(API, params={"query": cve_id, "hitsPerPage": POR_PAGINA},
                       timeout=timeout, headers={"User-Agent": UA})
    except Exception as exc:
        return [], f"error:{type(exc).__name__}"
    if r.status_code in (429, 503):
        return [], "bloqueado"
    if r.status_code != 200:
        return [], f"error:{r.status_code}"
    try:
        hits = r.json().get("hits", [])
    except ValueError:
        return [], "error:json"

    salida, vistas = [], set()
    for hit in hits:
        etiquetas = hit.get("_tags") or []
        if "story" not in etiquetas:
            continue
        titulo = (hit.get("title") or hit.get("story_title") or "").strip()
        if not titulo:
            continue
        url = (hit.get("url") or "").strip()
        if not url:
            url = f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        if url in vistas:
            continue
        vistas.add(url)
        salida.append({
            "cve_id": cve_id,
            "url": url,
            "title": titulo,
            "source": "Hacker News",
            "published": hit.get("created_at"),
            "points": hit.get("points") or 0,
            "comments": hit.get("num_comments") or 0,
        })
    return salida, "ok"


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
    salida = Path(args.salida)
    salida.mkdir(parents=True, exist_ok=True)
    ndjson = salida / f"hn-{i}de{n}.jsonl"
    hechos = salida / f"hechos-hn-{i}de{n}.txt"

    ya = set()
    if hechos.exists():
        ya = {l.strip() for l in hechos.read_text(encoding="utf-8").splitlines() if l.strip()}

    pendientes = []
    with open(args.entrada, newline="", encoding="utf-8") as fh:
        for idx, fila in enumerate(csv.reader(fh)):
            if not fila:
                continue
            if idx % n != i or fila[0] in ya:
                continue
            pendientes.append(fila[0])
            if args.limite and len(pendientes) >= args.limite:
                break

    print(f"shard {i}/{n}: {len(pendientes)} CVEs por consultar en HN "
          f"({len(ya)} ya hechos)", flush=True)
    if not pendientes:
        return

    intervalo = (1.0 / args.rate) if args.rate > 0 else 0.0
    turno_lock = threading.Lock()
    ultimo = [0.0]
    hilo_local = threading.local()

    def turno():
        if not intervalo:
            return
        with turno_lock:
            espera = intervalo - (time.monotonic() - ultimo[0])
            if espera > 0:
                time.sleep(espera)
            ultimo[0] = time.monotonic()

    def sesion():
        if not hasattr(hilo_local, "s"):
            hilo_local.s = requests.Session()
        return hilo_local.s

    def procesar(cve):
        turno()
        return cve, buscar(cve, sesion())

    t0 = time.perf_counter()
    con_datos = total = bloqueos = 0
    with open(ndjson, "a", encoding="utf-8") as out, \
            open(hechos, "a", encoding="utf-8") as done, \
            ThreadPoolExecutor(max_workers=args.hilos) as pool:
        futuros = {pool.submit(procesar, c): c for c in pendientes}
        try:
            for k, fut in enumerate(as_completed(futuros), 1):
                try:
                    cve, (menciones, estado) = fut.result()
                except Exception as exc:
                    print(f"  {futuros[fut]}: {type(exc).__name__}", flush=True)
                    continue
                if estado != "ok":
                    bloqueos += 1
                    if bloqueos >= 25:
                        for pend in futuros:
                            pend.cancel()
                        print(f"\nABORTADO: {bloqueos} consultas sin respuesta útil "
                              f"({estado}). Los CVEs con error quedan pendientes.",
                              flush=True)
                        return
                    continue
                bloqueos = 0
                for m in menciones:
                    out.write(json.dumps(m, ensure_ascii=False) + "\n")
                total += len(menciones)
                if menciones:
                    con_datos += 1
                done.write(cve + "\n")
                if k % 250 == 0:
                    out.flush()
                    done.flush()
                    dt = time.perf_counter() - t0
                    print(f"{k}/{len(pendientes)}  {k/dt:5.1f} CVE/s  "
                          f"con_menciones={con_datos}  menciones={total}", flush=True)
        finally:
            out.flush()
            done.flush()

    dt = time.perf_counter() - t0
    print(f"fin: {len(pendientes)} CVEs en {dt:.0f}s ({len(pendientes)/dt:.1f} CVE/s), "
          f"{con_datos} con menciones, {total} menciones -> {ndjson}", flush=True)


if __name__ == "__main__":
    main()
