"""
Sync Agent — Sincroniza CVE List V5
Uso: python agents/sync_agent.py [--full]
"""
import subprocess
import json
from pathlib import Path
from datetime import datetime
from core.db import get_db

CVE_LIST_PATH = Path("data/cvelistV5")
REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

def clone_or_pull():
    if not CVE_LIST_PATH.exists():
        print("Clonando CVE List V5 por primera vez...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(CVE_LIST_PATH)], check=True)
    else:
        print("Actualizando CVE List V5...")
        subprocess.run(["git", "-C", str(CVE_LIST_PATH), "pull"], check=True)

def process_cve_file(path: Path, conn):
    try:
        data = json.loads(path.read_text())
        cve_id = data.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            return
        # Extraer campos básicos (simplificado)
        published = data.get("cveMetadata", {}).get("datePublished")
        description = ""
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        # CVSS (buscar en metrics)
        cvss = None
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                cvss = metric["cvssV3_1"].get("baseScore")
                break

        conn.execute("""
            INSERT OR REPLACE INTO cves (cve_id, published, description, cvss_score, raw_json, synced_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cve_id, published, description, cvss, json.dumps(data), datetime.utcnow().isoformat()))
    except Exception as e:
        print(f"Error procesando {path}: {e}")

def sync(full=False):
    clone_or_pull()
    conn = get_db()
    cves_dir = CVE_LIST_PATH / "cves"
    count = 0
    for year_dir in cves_dir.iterdir():
        if not year_dir.is_dir():
            continue
        for json_file in year_dir.rglob("*.json"):
            process_cve_file(json_file, conn)
            count += 1
            if count % 1000 == 0:
                conn.commit()
                print(f"Procesados {count} CVEs...")
    conn.commit()
    conn.close()
    print(f"Sync completado. Total: {count} CVEs.")

if __name__ == "__main__":
    import sys
    full = "--full" in sys.argv
    sync(full=full)
