"""Agrega `vendor`/`product` a `cves` y los puebla desde el CPE de NVD.

El CPE vive en `raw_json -> configurations[].nodes[].cpeMatch[].criteria`
(`cpe:2.3:a:google:chrome:...`). Se toma el primer CPE de aplicación; si el CVE
sólo tiene CPE de sistema operativo/hardware, se usa ese igual para que el
filtro de producto no quede vacío en la mitad del catálogo.

    python scripts/backfill_products.py --dry-run
    python scripts/backfill_products.py

Idempotente y por lotes: `raw_json` pesa KBs por fila y traer las 417k de una
sola vez se come la RAM del contenedor (el proceso muere sin mensaje). Las filas
sin CPE quedan con product = '' para no volver a leerlas.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db

ALTERS = [
    "ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor TEXT",
    "ALTER TABLE cves ADD COLUMN IF NOT EXISTS product TEXT",
]
BATCH = 400
PLACEHOLDERS = {"", "*", "-", "n/a", "unknown"}


def product_from_raw(raw: str | None) -> tuple[str | None, str | None]:
    """(vendor, product) del primer `affected` que declare producto.

    `raw_json` es un CVE_RECORD 5.0, no la respuesta NVD 2.0: el producto está en
    `containers.cna.affected[].product` y, si el CNA no lo declaró, en los bloques
    ADP. Ahí los nombres vienen legibles ("Apache Log4j2"), sin resolver CPEs.
    """
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None, None
    containers = data.get("containers") or {}
    blocks = [containers.get("cna") or {}]
    blocks.extend(containers.get("adp") or [])
    for block in blocks:
        for item in block.get("affected") or []:
            product = str(item.get("product") or "").strip()
            if product.lower() in PLACEHOLDERS:
                continue
            vendor = str(item.get("vendor") or "").strip() or None
            if vendor and vendor.lower() in PLACEHOLDERS:
                vendor = None
            return vendor, product
    return None, None


def main(dry_run: bool = False) -> dict:
    conn = get_db()
    try:
        for stmt in ALTERS:
            conn.execute(stmt)
        conn.commit()

        seen = filled = empty = 0
        last = ""
        while True:
            rows = conn.execute(
                "SELECT cve_id, raw_json FROM cves "
                "WHERE product IS NULL AND cve_id > ? ORDER BY cve_id LIMIT ?",
                (last, BATCH),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                last = row["cve_id"]
                seen += 1
                vendor, product = product_from_raw(row["raw_json"])
                if product:
                    filled += 1
                    if not dry_run:
                        conn.execute(
                            "UPDATE cves SET vendor = ?, product = ? WHERE cve_id = ?",
                            (vendor, product, last),
                        )
                else:
                    empty += 1
                    if not dry_run:
                        conn.execute("UPDATE cves SET product = '' WHERE cve_id = ?", (last,))
                if dry_run and seen >= 200:
                    break
            if not dry_run:
                conn.commit()
            if seen % 10000 < BATCH:
                print(f"  {seen} leidos | con producto {filled} | sin producto {empty}", flush=True)
            if dry_run and seen >= 200:
                break

        stats = conn.execute(
            "SELECT count(*) AS total, "
            "count(*) FILTER (WHERE product <> '') AS con_producto FROM cves"
        ).fetchone()
        print(f"resultado: {stats['con_producto']}/{stats['total']} con producto")
        return {"seen": seen, "filled": filled, "empty": empty, "total": stats["total"]}
    finally:
        conn.close()


if __name__ == "__main__":
    main(dry_run="--dry-run" in sys.argv)
