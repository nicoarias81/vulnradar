"""Intel Agent: Exploit-DB parsing and signal writes, no network."""
from datetime import datetime, timezone

from agents.intel_agent import (parse_exploitdb, run_daily, sync_exploitdb,
                                sync_ghsa, sync_sightings)
from agents.sync_agent import set_state
from core.db import get_db, init_db

CSV = """id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
50592,exploits/multiple/webapps/50592.py,"Log4Shell",2021-12-10,x,webapps,multiple,,2021-12-10,2021-12-10,1,CVE-2021-44228;OSVDB-1234,,,,
50000,exploits/linux/local/50000.c,"Otro",2020-01-01,y,local,linux,,2020-01-01,2020-01-01,0,CVE-2021-44228;cve-2020-0001,,,,
"""


class _Resp:
    def __init__(self, payload=None, text=""):
        self._payload = payload
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _Sesion:
    """Stores the requests made and returns fixed responses."""

    def __init__(self, respuestas):
        self.respuestas = list(respuestas)
        self.llamadas = []

    def get(self, url, params=None, timeout=None, headers=None):
        self.llamadas.append({"url": url, "params": params or {}})
        return self.respuestas.pop(0) if len(self.respuestas) > 1 else self.respuestas[0]


def _db(tmp_path):
    path = tmp_path / "intel.db"
    init_db(path)
    return get_db(path)


def test_parse_exploitdb_normalizes_and_drops_non_cve():
    mapa = parse_exploitdb(CSV)
    assert mapa["CVE-2021-44228"] == [50592, 50000]
    assert mapa["CVE-2020-0001"] == [50000]
    assert "OSVDB-1234" not in mapa


def test_sync_exploitdb_does_not_lower_a_higher_poc_count(tmp_path):
    conn = _db(tmp_path)
    try:
        sync_exploitdb(conn, csv_text=CSV)
        assert conn.execute(
            "SELECT poc_count FROM enrichments WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()[0] == 2

        # The GitHub search had already seen 5: the catalog must not go backwards.
        conn.execute("UPDATE enrichments SET poc_count = 5 WHERE cve_id = 'CVE-2021-44228'")
        sync_exploitdb(conn, csv_text=CSV)
        assert conn.execute(
            "SELECT poc_count FROM enrichments WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()[0] == 5
    finally:
        conn.close()


def test_sync_sightings_only_marks_exploited(tmp_path):
    conn = _db(tmp_path)
    datos = {"metadata": {"count": 3}, "data": [
        {"type": "exploited", "vulnerability": "CVE-2024-3400"},
        {"type": "seen", "vulnerability": "CVE-2024-1111"},
        {"type": "seen", "vulnerability": "CVE-2024-2222"},
    ]}
    fake_session = _Sesion([_Resp(payload=datos)])
    try:
        res = sync_sightings(conn, days=3, session=fake_session)
        assert res["cves_explotados"] == 1
        assert conn.execute(
            "SELECT wild_confirmation FROM enrichments WHERE cve_id = 'CVE-2024-3400'"
        ).fetchone()[0] == 1
        # A 'seen' is a mention, not observed exploitation.
        assert conn.execute(
            "SELECT COUNT(*) FROM enrichments WHERE cve_id = 'CVE-2024-1111'"
        ).fetchone()[0] == 0
        assert fake_session.llamadas[0]["params"]["date_from"]
    finally:
        conn.close()


def test_sync_ghsa_fills_cvss_only_when_missing(tmp_path):
    conn = _db(tmp_path)
    conn.execute("INSERT INTO cves (cve_id, cvss_score) VALUES ('CVE-2026-0001', NULL)")
    conn.execute("INSERT INTO cves (cve_id, cvss_score) VALUES ('CVE-2026-0002', 9.9)")
    avisos = [
        {"cve_id": "CVE-2026-0001", "cvss": {"score": 7.5}, "severity": "high"},
        {"cve_id": "CVE-2026-0002", "cvss": {"score": 3.1}, "severity": "low"},
    ]
    fake_session = _Sesion([_Resp(payload=avisos)])
    try:
        res = sync_ghsa(conn, pages=1, session=fake_session)
        assert res["cvss_rellenados"] == 1
        assert conn.execute(
            "SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2026-0001'"
        ).fetchone()[0] == 7.5
        assert conn.execute(
            "SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2026-0002'"
        ).fetchone()[0] == 9.9
    finally:
        conn.close()


def test_run_daily_does_not_repeat_inside_the_window(tmp_path):
    conn = _db(tmp_path)
    try:
        ahora = datetime.now(timezone.utc).isoformat(timespec="seconds")
        set_state(conn, "intel_last_run", ahora)
        # No network: if it ignored the window it would try to download the CSV and fail.
        assert run_daily(conn, hours=24)["skipped"] is True
    finally:
        conn.close()
