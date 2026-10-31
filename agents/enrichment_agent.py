"""
Enrichment Agent — Rellena señales de KEV, EPSS, media, PoCs
Versión base: implementa las fuentes abiertas.
"""
import requests
import gzip
import csv
import io
from core.db import get_db

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

def load_kev(conn):
    print("Descargando CISA KEV...")
    data = requests.get(KEV_URL, timeout=30).json()
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        conn.execute("""
            INSERT OR REPLACE INTO enrichments (cve_id, in_kev, kev_date, ransomware_use)
            VALUES (?, 1, ?, ?)
        """, (cve_id, vuln.get("dateAdded"), vuln.get("knownRansomwareCampaignUse") == "Known"))
    conn.commit()
    print("KEV cargado.")

def load_epss(conn):
    print("Descargando EPSS...")
    r = requests.get(EPSS_URL, timeout=60)
    with gzip.open(io.BytesIO(r.content), "rt") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("cve")
            epss = float(row.get("epss", 0))
            conn.execute("""
                INSERT INTO enrichments (cve_id, epss) VALUES (?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET epss = excluded.epss
            """, (cve_id, epss))
    conn.commit()
    print("EPSS cargado.")

def run():
    conn = get_db()
    load_kev(conn)
    load_epss(conn)
    # TODO: añadir RSS + GitHub PoCs
    conn.close()
    print("Enriquecimiento base completado.")

if __name__ == "__main__":
    run()
