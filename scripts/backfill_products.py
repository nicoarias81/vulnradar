"""Adds `vendor`/`product` to `cves` and populates them from the NVD CPE.

The CPE lives in `raw_json -> configurations[].nodes[].cpeMatch[].criteria`
(`cpe:2.3:a:google:chrome:...`). The first application CPE is taken; if the CVE
only has an OS/hardware CPE, that one is used anyway so the product
filter is not empty for half the catalog.

    python scripts/backfill_products.py --dry-run
    python scripts/backfill_products.py

Idempotent and batched: `raw_json` weighs KBs per row and pulling the 417k in one
go eats the container RAM (the process dies without a message). Rows
without a CPE keep product = '' so they are not read again.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db
from core.normalizer import extract_vendor_product

ALTERS = [
    "ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor TEXT",
    "ALTER TABLE cves ADD COLUMN IF NOT EXISTS product TEXT",
]
BATCH = 400


def product_from_raw(raw):
    """(vendor, product) from the CVE 5.0 record already stored."""
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None, None
    return extract_vendor_product(data)


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
                print(f"  {seen} read | with product {filled} | without product {empty}", flush=True)
            if dry_run and seen >= 200:
                break

        stats = conn.execute(
            "SELECT count(*) AS total, "
            "count(*) FILTER (WHERE product <> '') AS con_producto FROM cves"
        ).fetchone()
        print(f"result: {stats['con_producto']}/{stats['total']} with product")
        return {"seen": seen, "filled": filled, "empty": empty, "total": stats["total"]}
    finally:
        conn.close()


if __name__ == "__main__":
    main(dry_run="--dry-run" in sys.argv)
