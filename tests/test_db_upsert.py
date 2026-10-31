"""Tests de persistencia: init idempotente, KEV/EPSS que no se pisan,
score vigente único y sync normalizado. Sin red."""
from pathlib import Path

import pytest

from agents.enrichment_agent import upsert_epss, upsert_kev
from agents.scoring_agent import score_all
from agents.sync_agent import process_cve_file
from core.db import get_db, init_db, list_tables

CVE_ID = "CVE-2026-0001"
FIXTURES = Path(__file__).parent / "fixtures" / "cvelistV5"


@pytest.fixture
def db_file(tmp_path) -> Path:
    path = tmp_path / "humo.db"
    init_db(path)
    return path


@pytest.fixture
def conn(db_file):
    connection = get_db(db_file)
    yield connection
    connection.close()


def _insert_cve(conn, cve_id=CVE_ID, cvss=9.8):
    conn.execute(
        "INSERT INTO cves (cve_id, published, description, cvss_score) VALUES (?, ?, ?, ?)",
        (cve_id, "2026-01-06T12:30:00.000Z", "Descripción de prueba", cvss),
    )


def _enrichment_row(conn, cve_id=CVE_ID):
    return conn.execute("SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,)).fetchone()


def _count(conn, table, cve_id=CVE_ID):
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE cve_id = ?", (cve_id,)).fetchone()[0]


def test_init_db_aisla_por_clave_y_no_depende_del_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = init_db(tmp_path / "otro.db")

    conn = get_db(path)
    try:
        tables = list_tables(conn)
    finally:
        conn.close()

    assert {"cves", "enrichments", "scores", "assets", "cve_assets"} <= tables


def test_init_db_es_idempotente(db_file):
    init_db(db_file)
    init_db(db_file)

    conn = get_db(db_file)
    try:
        assert _count(conn, "scores") == 0
    finally:
        conn.close()


def test_no_se_puede_crear_enrichment_sin_cve(conn):
    with pytest.raises(Exception) as excinfo:
        conn.execute("INSERT INTO enrichments (cve_id, epss) VALUES (?, ?)", ("CVE-2026-9999", 0.1))

    assert "FOREIGN KEY" in str(excinfo.value).upper()


def test_kev_y_epss_se_conservan_en_ambos_ordenes(conn):
    _insert_cve(conn)
    kev = [{"cveID": CVE_ID, "dateAdded": "2026-01-10", "knownRansomwareCampaignUse": "Known"}]
    epss = [{"cve": CVE_ID, "epss": "0.42", "percentile": "0.97"}]

    upsert_kev(conn, kev)
    upsert_epss(conn, epss)
    row = _enrichment_row(conn)

    assert row["in_kev"] == 1
    assert row["kev_date"] == "2026-01-10"
    assert row["ransomware_use"] == 1
    assert row["epss"] == pytest.approx(0.42)
    assert row["epss_percentile"] == pytest.approx(0.97)

    # Orden inverso: EPSS primero y KEV después tampoco debe borrar señales.
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.5", "percentile": "0.99"}])
    upsert_kev(conn, kev)
    row = _enrichment_row(conn)

    assert row["in_kev"] == 1
    assert row["epss"] == pytest.approx(0.5)
    assert row["epss_percentile"] == pytest.approx(0.99)


def test_kev_crea_stub_de_cve_para_no_perder_la_senal(conn):
    upsert_kev(conn, [{"cveID": "CVE-2026-7777", "dateAdded": "2026-02-01"}])

    stub = conn.execute("SELECT * FROM cves WHERE cve_id = ?", ("CVE-2026-7777",)).fetchone()
    row = _enrichment_row(conn, "CVE-2026-7777")

    assert stub is not None
    assert stub["description"] is None
    assert row["in_kev"] == 1


def test_epss_sin_cve_previo_tambien_crea_stub(conn):
    upsert_epss(conn, [{"cve": "CVE-2026-8888", "epss": "0.11", "percentile": "0.8"}])

    assert _enrichment_row(conn, "CVE-2026-8888")["epss"] == pytest.approx(0.11)


def test_scoring_repetido_deja_un_solo_score_vigente(conn):
    _insert_cve(conn)
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.1", "percentile": "0.5"}])

    assert score_all(conn) == 1
    first = conn.execute("SELECT * FROM scores WHERE cve_id = ?", (CVE_ID,)).fetchone()

    assert score_all(conn) == 1

    assert _count(conn, "scores") == 1
    assert first["hype"] == pytest.approx(1.96)  # cvss 9.8 -> sólo hype por CVSS

    # Una nueva señal EPSS sube el reality y REEMPLAZA el score, no lo duplica.
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.9", "percentile": "0.99"}])
    assert score_all(conn) == 1

    second = conn.execute("SELECT * FROM scores WHERE cve_id = ?", (CVE_ID,)).fetchone()
    assert _count(conn, "scores") == 1
    assert second["reality"] > first["reality"]
    assert second["reality"] == pytest.approx(7.0)  # 0.45*10 (KEV) + 0.25*9 (EPSS) + 0.05*5
    assert second["category"] == "Sleeper"  # hype bajo (1.96) y reality alto (7.0)


def test_scoring_ignora_cves_sin_enrichment(conn):
    _insert_cve(conn, "CVE-2026-1111")

    assert score_all(conn) == 0
    assert _count(conn, "scores", "CVE-2026-1111") == 0


def test_scoring_ignora_stubs_sin_datos_de_sync(conn):
    """KEV/EPSS pueden crear stubs; no deben puntuar hasta que el sync llene el CVE."""
    upsert_kev(conn, [{"cveID": "CVE-2026-7777", "dateAdded": "2026-02-01"}])
    upsert_epss(conn, [{"cve": "CVE-2026-7777", "epss": "0.9", "percentile": "0.99"}])

    assert score_all(conn) == 0
    assert _count(conn, "scores", "CVE-2026-7777") == 0


def test_process_cve_file_normaliza_y_hace_upsert(conn):
    path = FIXTURES / "CVE-2026-0001.json"

    assert process_cve_file(path, conn) is True
    row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (CVE_ID,)).fetchone()

    assert row["published"] == "2026-01-06T12:30:00.000Z"
    assert row["last_modified"] == "2026-01-09T08:15:00.000Z"
    assert row["cvss_score"] == pytest.approx(9.8)
    assert row["cvss_severity"] == "CRITICAL"
    assert "remote code execution" in row["description"]

    # Re-sincronizar el mismo archivo no duplica ni rompe el FK de enrichments.
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    assert process_cve_file(path, conn) is True

    assert _count(conn, "cves") == 1
    assert _enrichment_row(conn)["in_kev"] == 1
