"""
Sync Agent — Sincroniza CVE List V5
Uso: python agents/sync_agent.py [--full]
"""
import json
import os
import subprocess
from pathlib import Path

from core.db import get_db, resolve_path
from core.normalizer import normalize_cve_list_v5

CVE_LIST_PATH = resolve_path(os.getenv("CVE_LIST_PATH", ""), "data/cvelistV5")
REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

# UPSERT en lugar de INSERT OR REPLACE: con PRAGMA foreign_keys=ON, REPLACE
# borraría la fila de cves y rompería el FK de enrichments/scores.
UPSERT_SQL = """
    INSERT INTO cves (cve_id, published, last_modified, description,
                      cvss_score, cvss_vector, cvss_severity, raw_json)
    VALUES (:cve_id, :published, :last_modified, :description,
            :cvss_score, :cvss_vector, :cvss_severity, :raw_json)
    ON CONFLICT(cve_id) DO UPDATE SET
        published = excluded.published,
        last_modified = excluded.last_modified,
        description = excluded.description,
        cvss_score = excluded.cvss_score,
        cvss_vector = excluded.cvss_vector,
        cvss_severity = excluded.cvss_severity,
        raw_json = excluded.raw_json,
        synced_at = CURRENT_TIMESTAMP
"""


def clone_or_pull():
    if not CVE_LIST_PATH.exists():
        print("Clonando CVE List V5 por primera vez...")
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, str(CVE_LIST_PATH)],
            check=True,
        )
    else:
        print("Actualizando CVE List V5...")
        subprocess.run(["git", "-C", str(CVE_LIST_PATH), "pull"], check=True)


def process_cve_file(path: Path, conn) -> bool:
    """Normaliza un JSON de CVE List V5 y lo upsertea. False si se descarta."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error procesando {path}: {exc}")
        return False

    record = normalize_cve_list_v5(data)
    if record is None:
        return False

    conn.execute(UPSERT_SQL, record)
    return True


def sync(full: bool = True):
    """Recorre el mirror completo y upsertea cada CVE."""
    if not full:
        print("Aviso: el sync incremental todavía no existe (Fase 2); se sincroniza todo.")
    clone_or_pull()

    conn = get_db()
    cves_dir = CVE_LIST_PATH / "cves"
    count = 0
    try:
        for year_dir in cves_dir.iterdir():
            if not year_dir.is_dir():
                continue
            for json_file in year_dir.rglob("*.json"):
                if process_cve_file(json_file, conn):
                    count += 1
                if count % 1000 == 0:
                    conn.commit()
                    print(f"Procesados {count} CVEs...")
        conn.commit()
    finally:
        conn.close()
    print(f"Sync completado. Total: {count} CVEs.")


if __name__ == "__main__":
    import sys

    sync(full="--full" in sys.argv)
