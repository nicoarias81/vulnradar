"""
Scoring Agent — Calcula Hype y Reality para CVEs enriquecidos
"""
from core.db import get_db
from core.scoring import score_cve

def run():
    conn = get_db()
    rows = conn.execute("""
        SELECT c.*, e.*
        FROM cves c
        LEFT JOIN enrichments e ON c.cve_id = e.cve_id
        WHERE e.cve_id IS NOT NULL
    """).fetchall()

    for row in rows:
        signals = {
            "cvss": row["cvss_score"] or 0,
            "in_kev": bool(row["in_kev"]),
            "epss": row["epss"] or 0,
            "wild_confirmation": bool(row["wild_confirmation"]),
            "ransomware_use": bool(row["ransomware_use"]),
            "media_score": min((row["media_count"] or 0) / 2, 10),  # escala simple
            "tone_score": row["tone_score"] or 0,
            "branding": bool(row["branding"]),
            "poc_score": min((row["poc_count"] or 0) * 2, 10),
        }
        result = score_cve(signals)
        conn.execute("""
            INSERT INTO scores (cve_id, hype, reality, category)
            VALUES (?, ?, ?, ?)
        """, (row["cve_id"], result["hype"], result["reality"], result["category"]))

    conn.commit()
    conn.close()
    print("Scoring completado.")

if __name__ == "__main__":
    run()
