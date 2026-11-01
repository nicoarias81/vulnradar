"""Normalizes the `product` column of `cves` (strips the version glued to the name).

The CNAs write "Google Chrome prior to 55.0.2883.75 for Mac, Windows and Linux"
and that way every version becomes a different product: 60k options in the filter.
`clean_product` cuts the version suffix.

    python scripts/normalize_products.py --dry-run
    python scripts/normalize_products.py

A single UPDATE against a temp table: 61k row-by-row UPDATEs rebuild
the trigram index many times and take minutes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db
from core.normalizer import clean_product

BATCH = 5000


def build_mapping(conn) -> dict:
    rows = conn.execute(
        "SELECT DISTINCT product FROM cves WHERE product IS NOT NULL AND btrim(product) <> ''"
    ).fetchall()
    mapping = {}
    for row in rows:
        old = row["product"]
        new = clean_product(old)
        if new and new != old and new.lower() not in ("", "*", "-", "n/a", "unknown"):
            mapping[old] = new
    return mapping


def main(dry_run: bool = False) -> dict:
    conn = get_db()
    try:
        mapping = build_mapping(conn)
        print(f"distinct products with a version glued on: {len(mapping)}")
        if dry_run:
            for old, new in list(mapping.items())[:10]:
                print(f"  {old!r} -> {new!r}")
            return {"mapped": len(mapping), "updated": 0}

        conn.execute("DROP TABLE IF EXISTS product_map")
        conn.execute("CREATE TEMP TABLE product_map (old_product TEXT, new_product TEXT)")
        items = list(mapping.items())
        for start in range(0, len(items), BATCH):
            conn.executemany(
                "INSERT INTO product_map (old_product, new_product) VALUES (?, ?)",
                items[start:start + BATCH],
            )
        conn.execute("""
            UPDATE cves c SET product = m.new_product
            FROM product_map m WHERE c.product = m.old_product
        """)
        conn.commit()

        stats = conn.execute("""
            SELECT count(DISTINCT product) AS distintos,
                   count(*) FILTER (WHERE product <> '') AS con_producto
            FROM cves
        """).fetchone()
        print(f"distinct products now: {stats['distintos']} | with product: {stats['con_producto']}")
        return {"mapped": len(mapping), "distintos": stats["distintos"]}
    finally:
        conn.close()


if __name__ == "__main__":
    main(dry_run="--dry-run" in sys.argv)
