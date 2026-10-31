"""
Enrichment Agent — Rellena señales de KEV, EPSS, media, PoCs
Versión base: implementa las fuentes abiertas.
"""
import csv
import gzip
import io
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import ensure_cve_stub, get_db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def upsert_kev(conn, vulnerabilities) -> int:
    """
    Escribe SÓLO las columnas de KEV: un INSERT OR REPLACE borraría el EPSS
    ya cargado de la misma fila de enrichments.
    """
    count = 0
    for vuln in vulnerabilities:
        cve_id = (vuln.get("cveID") or "").strip()
        if not cve_id:
            continue
        # El FK exige el CVE padre; un stub mínimo evita perder la señal.
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, in_kev, kev_date, ransomware_use)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                in_kev = 1,
                kev_date = excluded.kev_date,
                ransomware_use = excluded.ransomware_use,
                updated_at = CURRENT_TIMESTAMP
        """, (
            cve_id,
            vuln.get("dateAdded"),
            1 if vuln.get("knownRansomwareCampaignUse") == "Known" else 0,
        ))
        count += 1
    return count


def upsert_epss(conn, rows) -> int:
    """Escribe SÓLO las columnas de EPSS, preservando KEV y el resto."""
    count = 0
    for row in rows:
        cve_id = (row.get("cve") or "").strip()
        if not cve_id:
            continue
        ensure_cve_stub(conn, cve_id)
        conn.execute("""
            INSERT INTO enrichments (cve_id, epss, epss_percentile)
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss = excluded.epss,
                epss_percentile = excluded.epss_percentile,
                updated_at = CURRENT_TIMESTAMP
        """, (cve_id, _to_float(row.get("epss")), _to_float(row.get("percentile"))))
        count += 1
    return count


def load_kev(conn):
    print("Descargando CISA KEV...")
    data = requests.get(KEV_URL, timeout=30).json()
    count = upsert_kev(conn, data.get("vulnerabilities", []))
    conn.commit()
    print(f"KEV cargado: {count} CVEs.")


def load_epss(conn):
    print("Descargando EPSS...")
    response = requests.get(EPSS_URL, timeout=60)
    with gzip.open(io.BytesIO(response.content), "rt", encoding="utf-8") as stream:
        count = upsert_epss(conn, csv.DictReader(stream))
    conn.commit()
    print(f"EPSS cargado: {count} CVEs.")


def run():
    conn = get_db()
    try:
        load_kev(conn)
        load_epss(conn)
        # TODO(Fase 2): RSS + GitHub PoCs
    finally:
        conn.close()
    print("Enriquecimiento base completado.")


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    run()
