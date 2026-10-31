"""Backfill de prensa desde una máquina local, sin base de datos.

El servidor está detrás de la IP de un datacenter y Google News lo frena a
~1 CVE/s con latencias de 5-10 s sostenidas. Desde una conexión doméstica el
mismo pedido tarda ~0.5 s y aguanta ~13 req/s. Este runner hace sólo la parte
de red: lee la lista de pendientes exportada del servidor y escribe las
menciones en NDJSON. El import a Postgres se hace después, allá.

    python scripts/backfill_local.py --entrada .cache/pendientes.csv \
        --salida .cache/menciones --shard 0/2 --hilos 8 --rate 12

Es reanudable: cada CVE terminado queda en hechos-<shard>.txt y al volver a
correr se saltea. Dos shards distintos pueden correr en paralelo sin pisarse.
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
LIMITE_POR_CONSULTA = 25


def iso_date(entry):
    for campo in ("published_parsed", "updated_parsed"):
        valor = entry.get(campo)
        if valor:
            try:
                return time.strftime("%Y-%m-%dT%H:%M:%S", valor)
            except Exception:
                pass
    return (entry.get("published") or entry.get("updated") or "").strip() or None


def buscar(cve_id, brand_name, sesion, timeout=20):
    """Menciones de prensa para un CVE. Dos consultas: el id y el apodo."""
    consultas = [cve_id]
    if brand_name and brand_name.strip():
        consultas.append(brand_name.strip())
    vistas, salida = set(), []
    for query in consultas:
        try:
            r = sesion.get(URL.format(query=quote_plus(query)), timeout=timeout,
                           headers={"User-Agent": UA})
            r.raise_for_status()
        except Exception:
            continue
        for entry in feedparser.parse(r.content).entries[:LIMITE_POR_CONSULTA]:
            url = (entry.get("link") or "").strip()
            if not url or url in vistas:
                continue
            vistas.add(url)
            medio = entry.get("source")
            if isinstance(medio, dict):
                medio = medio.get("title") or ""
            salida.append({
                "cve_id": cve_id,
                "url": url,
                "title": (entry.get("title") or "").strip(),
                "source": (medio or "").strip(),
                "published": iso_date(entry),
            })
    return salida


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--entrada", required=True, help="CSV cve_id,brand_name")
    p.add_argument("--salida", required=True, help="carpeta de resultados")
    p.add_argument("--shard", default="0/1", help="i/n: qué porción procesar")
    p.add_argument("--hilos", type=int, default=8)
    p.add_argument("--rate", type=float, default=12.0,
                   help="consultas por segundo, todas las sumadas")
    p.add_argument("--limite", type=int, default=0, help="cortar después de N CVEs")
    args = p.parse_args()

    i, n = (int(x) for x in args.shard.split("/"))
    salida = Path(args.salida)
    salida.mkdir(parents=True, exist_ok=True)
    ndjson = salida / f"menciones-{i}de{n}.jsonl"
    hechos = salida / f"hechos-{i}de{n}.txt"

    ya = set()
    if hechos.exists():
        ya = {l.strip() for l in hechos.read_text(encoding="utf-8").splitlines() if l.strip()}

    pendientes = []
    with open(args.entrada, newline="", encoding="utf-8") as fh:
        for idx, fila in enumerate(csv.reader(fh)):
            if not fila:
                continue
            if idx % n != i:
                continue
            if fila[0] in ya:
                continue
            pendientes.append((fila[0], fila[1] if len(fila) > 1 else ""))
            if args.limite and len(pendientes) >= args.limite:
                break

    print(f"shard {i}/{n}: {len(pendientes)} CVEs por procesar "
          f"({len(ya)} ya hechos)", flush=True)
    if not pendientes:
        return

    intervalo = (1.0 / args.rate) if args.rate > 0 else 0.0
    turno_lock = threading.Lock()
    ultimo = [0.0]

    def turno():
        if not intervalo:
            return
        with turno_lock:
            espera = intervalo - (time.monotonic() - ultimo[0])
            if espera > 0:
                time.sleep(espera)
            ultimo[0] = time.monotonic()

    hilo_local = threading.local()

    def sesion():
        if not hasattr(hilo_local, "s"):
            hilo_local.s = requests.Session()
        return hilo_local.s

    def procesar(par):
        cve, marca = par
        turno()
        return cve, buscar(cve, marca, sesion())

    t0 = time.perf_counter()
    con_datos = total = 0
    with open(ndjson, "a", encoding="utf-8") as out, \
            open(hechos, "a", encoding="utf-8") as done, \
            ThreadPoolExecutor(max_workers=args.hilos) as pool:
        futuros = {pool.submit(procesar, par): par[0] for par in pendientes}
        for k, fut in enumerate(as_completed(futuros), 1):
            try:
                cve, menciones = fut.result()
            except Exception as exc:
                print(f"  {futuros[fut]}: {type(exc).__name__}: {str(exc)[:80]}", flush=True)
                continue
            for m in menciones:
                out.write(json.dumps(m, ensure_ascii=False) + "\n")
            total += len(menciones)
            if menciones:
                con_datos += 1
            done.write(cve + "\n")
            if k % 200 == 0:
                out.flush()
                done.flush()
                dt = time.perf_counter() - t0
                print(f"{k}/{len(pendientes)}  {k/dt:5.1f} CVE/s  "
                      f"menciones={total}", flush=True)

    dt = time.perf_counter() - t0
    print(f"fin: {len(pendientes)} CVEs en {dt:.0f}s "
          f"({len(pendientes)/dt:.1f} CVE/s), {con_datos} con prensa, "
          f"{total} menciones -> {ndjson}", flush=True)


if __name__ == "__main__":
    main()
