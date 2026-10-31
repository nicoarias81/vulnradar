#!/usr/bin/env python
"""Rellena la atención pública (prensa y PoCs) de los CVEs que importan.

Los feeds del ciclo sólo traen lo último publicado, así que un CVE con 700 PoCs
y en KEV puede quedarse con media_count=0 y hype 1.8. Esto busca cada CVE en
Google News, guarda las menciones y recalcula el scoring.

    python scripts/backfill_attention.py --limit 20
    python scripts/backfill_attention.py --cve CVE-2026-109619 --skip-pocs
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests

from agents.enrichment_agent import (
    load_pocs,
    load_tone,
    search_mentions,
    select_attention_targets,
    upsert_media_mentions,
)
from agents.scoring_agent import score_all
from core.db import get_db, init_db


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=20, help="cuántos CVEs procesar")
    parser.add_argument("--cve", action="append", default=None, help="CVE puntual")
    parser.add_argument("--skip-pocs", action="store_true", help="no consultar GitHub")
    parser.add_argument("--skip-score", action="store_true", help="no recalcular score")
    parser.add_argument("--tone", action="store_true",
                        help="analizar tono y apodo de las menciones (usa el LLM)")
    args = parser.parse_args()

    init_db()
    conn = get_db()
    http = requests.Session()

    if args.cve:
        objetivos = []
        for cve_id in args.cve:
            row = conn.execute(
                "SELECT brand_name FROM enrichments WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            objetivos.append((cve_id, row["brand_name"] if row else None))
    else:
        objetivos = select_attention_targets(conn, limit=args.limit)

    print(f"CVEs a revisar: {len(objetivos)}")
    total_menciones = 0
    for cve_id, brand in objetivos:
        if not args.skip_pocs:
            try:
                load_pocs(conn, [cve_id])
            except Exception as exc:
                print(f"  {cve_id}: pocs falló ({type(exc).__name__})")
        try:
            menciones = search_mentions(cve_id, brand, session=http)
            nuevas = upsert_media_mentions(conn, menciones)
        except Exception as exc:
            print(f"  {cve_id}: prensa falló ({type(exc).__name__})")
            nuevas = {}
        conn.commit()
        agregadas = nuevas.get(cve_id, 0)
        total_menciones += agregadas
        fila = conn.execute(
            "SELECT poc_count, media_count FROM enrichments WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        print(f"  {cve_id}: +{agregadas} menciones "
              f"(pocs={fila['poc_count']}, media={fila['media_count']})")
        time.sleep(1)  # no gatillar el rate limit de la búsqueda

    if args.tone:
        print("analizando tono y apodo...")
        print(f"CVEs con tono nuevo: {load_tone(conn, limit=max(10, len(objetivos) * 2))}")
        conn.commit()

    if not args.skip_score:
        print(f"recalculando scores ({total_menciones} menciones nuevas)...")
        puntuados = score_all(conn)
        conn.commit()  # sin esto el trabajo se descarta al cerrar la conexión
        print(f"CVEs puntuados: {puntuados}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
