#!/usr/bin/env python
"""Backfill reanudable de atención (prensa + PoCs + tono) sobre todos los CVEs.

Pensado para correr "de a poco": cada invocación procesa un lote acotado, lo
marca en attention_backfill y la próxima sigue donde quedó. Nunca repite un CVE.

    python scripts/backfill_all_attention.py --batch 40          # un lote
    python scripts/backfill_all_attention.py --batch 40 --tone   # con LLM
    python scripts/backfill_all_attention.py --state             # cuánto falta
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

# Prioridad: primero lo que puede tener atención hoy (KEV, con PoCs, reciente).
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
    SELECT count(*) AS pendientes
    FROM enrichments e
    LEFT JOIN attention_backfill b ON b.cve_id = e.cve_id
    WHERE b.cve_id IS NULL
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=int, default=40, help="CVEs por corrida")
    parser.add_argument("--delay", type=float, default=1.0, help="segundos entre CVEs")
    parser.add_argument("--tone", action="store_true", help="analizar tono con el LLM")
    parser.add_argument("--skip-pocs", action="store_true", help="no consultar GitHub")
    parser.add_argument("--state", action="store_true", help="sólo informar el avance")
    parser.add_argument(
        "--workers", type=int, default=1,
        help="hilos en paralelo (1 = secuencial). Cada uno abre su conexión; "
             "pone un lote más grande.",
    )
    parser.add_argument(
        "--poc-interval", type=float, default=6.0,
        help="segundos entre búsquedas en GitHub cuando hay varios workers "
             "(sin token son 10 req/min: 6 s evita los 429)",
    )
    parser.add_argument(
        "--rate", type=float, default=15.0,
        help="consultas de prensa por segundo, todas las sumadas (0 = sin tope). "
             "20 hilos van más rápido, pero Google News corta si se abusa",
    )
    args = parser.parse_args()

    init_db()
    conn = get_db()

    pendientes = conn.execute(PENDING).fetchone()["pendientes"]
    if args.state:
        hechos = conn.execute("SELECT count(*) AS c FROM attention_backfill").fetchone()["c"]
        print(f"procesados: {hechos} | pendientes: {pendientes}")
        return 0

    if not pendientes:
        print("backfill completo: no quedan CVEs pendientes")
        return 0

    lote = conn.execute(NEXT_BATCH, (max(1, args.batch),)).fetchall()
    print(f"pendientes: {pendientes} | lote: {len(lote)}")

    http = requests.Session()
    procesados, con_prensa = [], 0

    if args.workers > 1:
        # Cada hilo abre su propia conexión: psycopg no comparte una entre hilos.
        # La prensa se paraleliza bien; GitHub no, porque sin token son 10
        # búsquedas por minuto y en paralelo sólo se cosechan 429.
        poc_lock = threading.Lock()
        # Techo global de consultas a prensa: 8 hilos hacen 37 req/s y Google
        # News empieza a devolver vacío. Un turno compartido lo deja parejo.
        turno_lock = threading.Lock()
        intervalo = (1.0 / args.rate) if args.rate > 0 else 0.0
        ultimo = [0.0]

        def turno():
            if not intervalo:
                return
            with turno_lock:
                espera = intervalo - (time.monotonic() - ultimo[0])
                if espera > 0:
                    time.sleep(espera)
                ultimo[0] = time.monotonic()

        def procesar(row):
            cve_id = row["cve_id"]
            propio = get_db()
            try:
                if not args.skip_pocs and not row["poc_count"]:
                    with poc_lock:
                        load_pocs(propio, [cve_id])
                        time.sleep(max(0.0, args.poc_interval))
                turno()
                sesion = requests.Session()
                menciones = search_mentions(cve_id, row["brand_name"], session=sesion)
                nuevas = upsert_media_mentions(propio, menciones).get(cve_id, 0)
                propio.execute(
                    "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                    "ON CONFLICT (cve_id) DO NOTHING", (cve_id,)
                )
                propio.commit()
                return cve_id, nuevas, None
            except Exception as exc:
                try:
                    propio.rollback()
                except Exception:
                    pass
                return cve_id, 0, f"{type(exc).__name__}: {str(exc)[:90]}"
            finally:
                try:
                    propio.close()
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futuros = [pool.submit(procesar, r) for r in lote]
            for fut in as_completed(futuros):
                cve_id, nuevas, err = fut.result()
                if err:
                    print(f"  {cve_id}: {err}")
                    continue
                if nuevas:
                    con_prensa += 1
                procesados.append(cve_id)
    else:
        for row in lote:
            cve_id = row["cve_id"]
            try:
                if not args.skip_pocs and not row["poc_count"]:
                    load_pocs(conn, [cve_id])
                menciones = search_mentions(cve_id, row["brand_name"], session=http)
                nuevas = upsert_media_mentions(conn, menciones).get(cve_id, 0)
                if nuevas:
                    con_prensa += 1
                conn.execute(
                    "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                    "ON CONFLICT (cve_id) DO NOTHING", (cve_id,)
                )
                conn.commit()
                procesados.append(cve_id)
            except Exception as exc:
                conn.rollback()
                print(f"  {cve_id}: {type(exc).__name__}: {str(exc)[:90]}")
            time.sleep(max(0.0, args.delay))

    if args.tone and procesados:
        try:
            actualizados = load_tone(conn, limit=max(10, len(procesados)))
            conn.commit()
            print(f"tono actualizado: {actualizados}")
        except Exception as exc:
            conn.rollback()
            print(f"  tono: {type(exc).__name__}: {str(exc)[:90]}")

    puntuados = 0
    for i in range(0, len(sorted(procesados)), 250):
        trozo = sorted(procesados)[i:i + 250]
        puntuados += score_cves(conn, trozo)
        conn.commit()

    resto = conn.execute(PENDING).fetchone()["pendientes"]
    print(f"lote listo: {len(procesados)} CVEs ({con_prensa} con prensa nueva) "
          f"| puntuados: {puntuados} | pendientes: {resto}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
