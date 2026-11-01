"""
Loads a small set of demo CVEs (every category).

It does not clone CVE List V5. Idempotent: it only rewrites the CVE-2026-9xxx demo rows.
Usage: python scripts/seed_demo.py
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
        "description": "RCE in a popular CMS. The press dubbed it GhostShell and compared it to Log4Shell.",
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
        "description": "Auth bypass in a corporate VPN. CISA added it to KEV; it is exploited in the wild and used by ransomware.",
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
        "description": "RCE in an internally used file-sharing service. In KEV, with almost no media coverage.",
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
        "description": "Reflected XSS in a blog plugin. Routine advisory, patched the same day.",
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
        "description": "Deserialization in a Java logging library. Apocalyptic headlines, not in KEV yet.",
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
        "description": "Sandbox escape in a hypervisor. KEV + wild + plenty of technical press.",
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
        "description": "Heap overflow in an IP camera image parser. In KEV, a single technical post.",
        "cvss_score": 8.1,
        "cvss_severity": "HIGH",
        "in_kev": 1,
        "epss": 0.55,
        "wild_confirmation": 1,
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
        "description": "Open redirect in an internal IdP. Low CVSS, no public PoC.",
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
    """Publication date relative to today.

    Fixed dates left the demo outside the dashboard default range
    (current month) and the page came out empty even though there was data.
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
