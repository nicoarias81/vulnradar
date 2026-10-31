"""
Carga un set chico de CVEs de demostración (todas las categorías).

No clona CVE List V5. Idempotente: reescribe sólo los CVE-2026-9xxx de demo.
Uso: python scripts/seed_demo.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.db import get_db, init_db
from core.normalizer import build_signals
from core.scoring import score_cve

DEMO_PREFIX = "CVE-2026-9"

# media_score = min(media_count/2, 10); poc_score = min(poc_count*2, 10)
DEMOS = [
    {
        "cve_id": "CVE-2026-9001",
        "description": "RCE en un CMS popular. La prensa lo bautizó GhostShell y lo comparó con Log4Shell.",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "in_kev": 0,
        "epss": 0.02,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 20,
        "poc_count": 5,
        "tone_score": 9.5,
        "branding": 1,
        "brand_name": "GhostShell",
        "days_ago": 3,
        "alert": True,
        "mentions": [
            ("The Hacker News", "GhostShell: CMS RCE compared to Log4Shell", "https://example.test/thn/ghostshell"),
            ("BleepingComputer", "Critical CMS flaw exploited in the wild?", "https://example.test/bc/ghostshell"),
        ],
    },
    {
        "cve_id": "CVE-2026-9002",
        "description": "Auth bypass en un VPN corporativo. CISA lo metió al KEV; hay explotación en la calle y ransomware.",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "in_kev": 1,
        "epss": 0.87,
        "wild_confirmation": 1,
        "ransomware_use": 1,
        "media_count": 16,
        "poc_count": 3,
        "tone_score": 7.0,
        "branding": 0,
        "brand_name": None,
        "days_ago": 6,
        "alert": True,
        "mentions": [
            ("SecurityWeek", "CISA adds VPN auth bypass to KEV", "https://example.test/sw/vpn"),
        ],
    },
    {
        "cve_id": "CVE-2026-9003",
        "description": "RCE en un servicio de archivos usado en interná. En KEV, casi sin cobertura mediática.",
        "cvss_score": 9.1,
        "cvss_severity": "CRITICAL",
        "in_kev": 1,
        "epss": 0.91,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 1,
        "poc_count": 0,
        "tone_score": 2.0,
        "branding": 0,
        "brand_name": None,
        "days_ago": 9,
        "alert": False,
    },
    {
        "cve_id": "CVE-2026-9004",
        "description": "XSS reflejado en un plugin de blog. Advisory rutinario, parche el mismo día.",
        "cvss_score": 6.1,
        "cvss_severity": "MEDIUM",
        "in_kev": 0,
        "epss": 0.01,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 1,
        "poc_count": 0,
        "tone_score": 1.0,
        "branding": 0,
        "brand_name": None,
        "days_ago": 12,
        "alert": False,
    },
    {
        "cve_id": "CVE-2026-9005",
        "description": "Deserialización en una librería Java de logging. Titulares de apocalipsis, KEV todavía no.",
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "in_kev": 0,
        "epss": 0.15,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 18,
        "poc_count": 4,
        "tone_score": 8.5,
        "branding": 1,
        "brand_name": "Log4Boom",
        "days_ago": 15,
        "alert": False,
    },
    {
        "cve_id": "CVE-2026-9006",
        "description": "Escape de sandbox en un hipervisor. KEV + wild + mucha prensa técnica.",
        "cvss_score": 8.8,
        "cvss_severity": "HIGH",
        "in_kev": 1,
        "epss": 0.64,
        "wild_confirmation": 1,
        "ransomware_use": 0,
        "media_count": 12,
        "poc_count": 2,
        "tone_score": 6.0,
        "branding": 0,
        "brand_name": None,
        "days_ago": 18,
        "alert": False,
    },
    {
        "cve_id": "CVE-2026-9007",
        "description": "Heap overflow en un parser de imágenes de cámaras IP. En KEV, un solo post técnico.",
        "cvss_score": 8.1,
        "cvss_severity": "HIGH",
        "in_kev": 1,
        "epss": 0.55,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 2,
        "poc_count": 1,
        "tone_score": 3.0,
        "branding": 0,
        "brand_name": None,
        "days_ago": 21,
        "alert": False,
    },
    {
        "cve_id": "CVE-2026-9008",
        "description": "Open redirect en un IdP interno. CVSS bajo, sin PoC público.",
        "cvss_score": 4.3,
        "cvss_severity": "MEDIUM",
        "in_kev": 0,
        "epss": 0.0,
        "wild_confirmation": 0,
        "ransomware_use": 0,
        "media_count": 0,
        "poc_count": 0,
        "tone_score": 0.5,
        "branding": 0,
        "brand_name": None,
        "days_ago": 25,
        "alert": False,
    },
]


UPSERT_CVE = """
    INSERT INTO cves (cve_id, description, cvss_score, cvss_severity, published)
    VALUES (:cve_id, :description, :cvss_score, :cvss_severity, :published)
    ON CONFLICT(cve_id) DO UPDATE SET
        description = excluded.description,
        cvss_score = excluded.cvss_score,
        cvss_severity = excluded.cvss_severity,
        published = excluded.published
"""

UPSERT_ENRICHMENT = """
    INSERT INTO enrichments (
        cve_id, in_kev, epss, wild_confirmation, ransomware_use,
        media_count, poc_count, tone_score, branding, brand_name
    ) VALUES (
        :cve_id, :in_kev, :epss, :wild_confirmation, :ransomware_use,
        :media_count, :poc_count, :tone_score, :branding, :brand_name
    )
    ON CONFLICT(cve_id) DO UPDATE SET
        in_kev = excluded.in_kev,
        epss = excluded.epss,
        wild_confirmation = excluded.wild_confirmation,
        ransomware_use = excluded.ransomware_use,
        media_count = excluded.media_count,
        poc_count = excluded.poc_count,
        tone_score = excluded.tone_score,
        branding = excluded.branding,
        brand_name = excluded.brand_name
"""

UPSERT_SCORE = """
    INSERT INTO scores (cve_id, hype, reality, category)
    VALUES (:cve_id, :hype, :reality, :category)
    ON CONFLICT(cve_id) DO UPDATE SET
        hype = excluded.hype,
        reality = excluded.reality,
        category = excluded.category,
        calculated_at = CURRENT_TIMESTAMP
"""


def _published(item: dict) -> str:
    """Fecha de publicación relativa a hoy.

    Las fechas fijas dejaban la demo fuera del rango por defecto del dashboard
    (mes en curso) y la página aparecía vacía aunque hubiera datos.
    """
    if "days_ago" in item:
        return (datetime.now() - timedelta(days=item["days_ago"])).strftime("%Y-%m-%dT%H:%M:%S")
    return item["published"]


def seed(db_path=None) -> int:
    init_db(db_path)
    conn = get_db(db_path)
    n = 0
    try:
        for item in DEMOS:
            cve_params = {k: item[k] for k in ("cve_id", "description", "cvss_score", "cvss_severity")}
            cve_params["published"] = _published(item)
            conn.execute(
                UPSERT_CVE,
                cve_params,
            )
            conn.execute(
                UPSERT_ENRICHMENT,
                {k: item[k] for k in (
                    "cve_id", "in_kev", "epss", "wild_confirmation", "ransomware_use",
                    "media_count", "poc_count", "tone_score", "branding", "brand_name",
                )},
            )
            cve_row = conn.execute(
                "SELECT cve_id, cvss_score FROM cves WHERE cve_id = ?",
                (item["cve_id"],),
            ).fetchone()
            enrich_row = conn.execute(
                "SELECT * FROM enrichments WHERE cve_id = ?",
                (item["cve_id"],),
            ).fetchone()
            result = score_cve(build_signals(cve_row, enrich_row))
            conn.execute(
                UPSERT_SCORE,
                {
                    "cve_id": item["cve_id"],
                    "hype": result["hype"],
                    "reality": result["reality"],
                    "category": result["category"],
                },
            )
            for source, title, url in item.get("mentions") or []:
                conn.execute(
                    """
                    INSERT INTO media_mentions (cve_id, url, title, source, published)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (item["cve_id"], url, title, source, _published(item)),
                )
            if item["alert"]:
                conn.execute(
                    """
                    INSERT INTO alerts_sent (cve_id, channel, rule)
                    VALUES (?, 'slack', ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        item["cve_id"],
                        "overhyped" if result["category"] == "Overhyped" else "earned_the_hype",
                    ),
                )
            n += 1
            print(f"  {item['cve_id']}  hype={result['hype']:.2f}  "
                  f"reality={result['reality']:.2f}  {result['category']}")
        conn.commit()
    finally:
        conn.close()
    return n


if __name__ == "__main__":
    print(f"Seed demo ({len(DEMOS)} CVEs)")
    seed()
