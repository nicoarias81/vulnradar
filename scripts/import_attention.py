#!/usr/bin/env python
"""Importa a la base productiva el JSONL que produce collect_attention_local.py.

Idempotente: las menciones tienen PK (cve_id, url), así que reimportar el mismo
archivo no duplica nada. Marca attention_backfill y recalcula sólo lo tocado.

    python scripts/import_attention.py attention.jsonl
    python scripts/import_attention.py attention.jsonl --score-only
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.enrichment_agent import upsert_media_mentions
from agents.scoring_agent import score_cves
from core.db import get_db, init_db


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("archivo", help="JSONL de collect_attention_local.py")
    ap.add_argument("--score-only", action="store_true",
                    help="no insertar, sólo recalcular el score de los CVEs del archivo")
    ap.add_argument("--limit", type=int, default=0, help="cortar a N líneas")
    args = ap.parse_args()

    init_db()
    conn = get_db()

    pendientes, tocados, nuevas_total, errores = [], [], 0, 0
    with open(args.archivo, encoding="utf-8") as fh:
        for i, linea in enumerate(fh):
            if args.limit and i >= args.limit:
                break
            try:
                fila = json.loads(linea)
            except json.JSONDecodeError:
                errores += 1
                continue
            cve_id = (fila.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            tocados.append(cve_id)
            if args.score_only:
                continue
            menciones = [dict(m, cve_id=cve_id) for m in fila.get("menciones") or []]
            if menciones:
                nuevas_total += upsert_media_mentions(conn, menciones).get(cve_id, 0)
                # Refresca título/medio/fecha de lo ya cargado sin tocar los conteos.
                for m in menciones:
                    conn.execute(
                        "UPDATE media_mentions SET title = ?, source = ?, published = ? "
                        "WHERE cve_id = ? AND url = ?",
                        (m.get("title"), m.get("source"), m.get("published"),
                         cve_id, m.get("url")),
                    )
            pendientes.append(cve_id)
            if len(pendientes) >= 500:
                for cid in pendientes:
                    conn.execute(
                        "INSERT INTO attention_backfill (cve_id) VALUES (?) "
                        "ON CONFLICT (cve_id) DO NOTHING", (cid,)
                    )
                conn.commit()
                pendientes = []
                print(f"  importados {i + 1} registros, {nuevas_total} menciones nuevas", flush=True)

    for cid in pendientes:
        conn.execute(
            "INSERT INTO attention_backfill (cve_id) VALUES (?) ON CONFLICT (cve_id) DO NOTHING",
            (cid,),
        )
    conn.commit()

    puntuados = score_cves(conn, tocados)
    conn.commit()
    print(f"listo: {len(tocados)} CVEs, {nuevas_total} menciones nuevas, "
          f"{puntuados} puntuados, {errores} líneas ilegibles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
