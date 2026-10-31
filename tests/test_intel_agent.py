"""Intel Agent: parseo de Exploit-DB y escritura de señales sin red."""
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
    """Guarda las requests hechas y devuelve respuestas fijas."""

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


def test_parse_exploitdb_normaliza_y_descarta_no_cve():
    mapa = parse_exploitdb(CSV)
    assert mapa["CVE-2021-44228"] == [50592, 50000]
    assert mapa["CVE-2020-0001"] == [50000]
    assert "OSVDB-1234" not in mapa


def test_sync_exploitdb_no_baja_un_poc_count_mayor(tmp_path):
    conn = _db(tmp_path)
    try:
        sync_exploitdb(conn, csv_text=CSV)
        assert conn.execute(
            "SELECT poc_count FROM enrichments WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()[0] == 2

        # El search de GitHub ya había visto 5: el catálogo no debe retroceder.
        conn.execute("UPDATE enrichments SET poc_count = 5 WHERE cve_id = 'CVE-2021-44228'")
        sync_exploitdb(conn, csv_text=CSV)
        assert conn.execute(
            "SELECT poc_count FROM enrichments WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()[0] == 5
    finally:
        conn.close()


def test_sync_sightings_solo_marca_explotados(tmp_path):
    conn = _db(tmp_path)
    datos = {"metadata": {"count": 3}, "data": [
        {"type": "exploited", "vulnerability": "CVE-2024-3400"},
        {"type": "seen", "vulnerability": "CVE-2024-1111"},
        {"type": "seen", "vulnerability": "CVE-2024-2222"},
    ]}
    sesion = _Sesion([_Resp(payload=datos)])
    try:
        res = sync_sightings(conn, days=3, session=sesion)
        assert res["cves_explotados"] == 1
        assert conn.execute(
            "SELECT wild_confirmation FROM enrichments WHERE cve_id = 'CVE-2024-3400'"
        ).fetchone()[0] == 1
        # Un 'seen' es una mención, no explotación observada.
        assert conn.execute(
            "SELECT COUNT(*) FROM enrichments WHERE cve_id = 'CVE-2024-1111'"
        ).fetchone()[0] == 0
        assert sesion.llamadas[0]["params"]["date_from"]
    finally:
        conn.close()


def test_sync_ghsa_rellena_cvss_solo_si_falta(tmp_path):
    conn = _db(tmp_path)
    conn.execute("INSERT INTO cves (cve_id, cvss_score) VALUES ('CVE-2026-0001', NULL)")
    conn.execute("INSERT INTO cves (cve_id, cvss_score) VALUES ('CVE-2026-0002', 9.9)")
    avisos = [
        {"cve_id": "CVE-2026-0001", "cvss": {"score": 7.5}, "severity": "high"},
        {"cve_id": "CVE-2026-0002", "cvss": {"score": 3.1}, "severity": "low"},
    ]
    sesion = _Sesion([_Resp(payload=avisos)])
    try:
        res = sync_ghsa(conn, pages=1, session=sesion)
        assert res["cvss_rellenados"] == 1
        assert conn.execute(
            "SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2026-0001'"
        ).fetchone()[0] == 7.5
        assert conn.execute(
            "SELECT cvss_score FROM cves WHERE cve_id = 'CVE-2026-0002'"
        ).fetchone()[0] == 9.9
    finally:
        conn.close()


def test_run_daily_no_repite_si_paso_menos_de_la_ventana(tmp_path):
    conn = _db(tmp_path)
    try:
        ahora = datetime.now(timezone.utc).isoformat(timespec="seconds")
        set_state(conn, "intel_last_run", ahora)
        # Sin red: si no respeta la ventana, intentaría bajar el CSV y fallaría.
        assert run_daily(conn, hours=24)["skipped"] is True
    finally:
        conn.close()
