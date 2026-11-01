"""Persistence tests: idempotent init, KEV/EPSS that do not overwrite each other,
a single current score and normalized sync. No network."""
from pathlib import Path

import pytest

from agents.enrichment_agent import upsert_epss, upsert_kev
from agents.scoring_agent import score_all
from agents.sync_agent import process_cve_file
from core.db import get_db, init_db, list_tables
from dashboard.data import load_score_history

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
        (cve_id, "2026-01-06T12:30:00.000Z", "Test description", cvss),
    )


def _enrichment_row(conn, cve_id=CVE_ID):
    return conn.execute("SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,)).fetchone()


def _count(conn, table, cve_id=CVE_ID):
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE cve_id = ?", (cve_id,)).fetchone()[0]


def test_init_db_is_isolated_by_key_and_does_not_depend_on_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = init_db(tmp_path / "otro.db")

    conn = get_db(path)
    try:
        tables = list_tables(conn)
    finally:
        conn.close()

    assert {"cves", "enrichments", "scores", "assets", "cve_assets"} <= tables


def test_init_db_is_idempotent(db_file):
    init_db(db_file)
    init_db(db_file)

    conn = get_db(db_file)
    try:
        assert _count(conn, "scores") == 0
    finally:
        conn.close()


def test_cannot_create_enrichment_without_cve(conn):
    with pytest.raises(Exception) as excinfo:
        conn.execute("INSERT INTO enrichments (cve_id, epss) VALUES (?, ?)", ("CVE-2026-9999", 0.1))

    assert "FOREIGN KEY" in str(excinfo.value).upper()


def test_kev_and_epss_survive_in_both_orders(conn):
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

    # Reverse order: EPSS first and KEV afterwards must not erase signals either.
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.5", "percentile": "0.99"}])
    upsert_kev(conn, kev)
    row = _enrichment_row(conn)

    assert row["in_kev"] == 1
    assert row["epss"] == pytest.approx(0.5)
    assert row["epss_percentile"] == pytest.approx(0.99)


def test_kev_creates_cve_stub_to_keep_the_signal(conn):
    upsert_kev(conn, [{"cveID": "CVE-2026-7777", "dateAdded": "2026-02-01"}])

    stub = conn.execute("SELECT * FROM cves WHERE cve_id = ?", ("CVE-2026-7777",)).fetchone()
    row = _enrichment_row(conn, "CVE-2026-7777")

    assert stub is not None
    assert stub["description"] is None
    assert row["in_kev"] == 1


def test_epss_without_previous_cve_also_creates_stub(conn):
    upsert_epss(conn, [{"cve": "CVE-2026-8888", "epss": "0.11", "percentile": "0.8"}])

    assert _enrichment_row(conn, "CVE-2026-8888")["epss"] == pytest.approx(0.11)


def test_repeated_scoring_leaves_a_single_current_score(conn):
    _insert_cve(conn)
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.1", "percentile": "0.5"}])

    assert score_all(conn) == 1
    first = conn.execute("SELECT * FROM scores WHERE cve_id = ?", (CVE_ID,)).fetchone()

    assert score_all(conn) == 0  # unchanged fingerprints are skipped

    assert _count(conn, "scores") == 1
    assert first["hype"] == pytest.approx(0.0)  # cvss 9.8 -> hype from CVSS only

    # A new EPSS signal raises reality and REPLACES the score, it does not duplicate it.
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.9", "percentile": "0.99"}])
    assert score_all(conn) == 1

    second = conn.execute("SELECT * FROM scores WHERE cve_id = ?", (CVE_ID,)).fetchone()
    assert _count(conn, "scores") == 1
    assert second["reality"] > first["reality"]
    assert second["reality"] == pytest.approx(7.9)  # 0.40*10 (KEV) + 0.25*9 (EPSS)
    assert second["category"] == "Sleeper"  # low hype (1.96) and reality 6.25


def test_score_history_stores_each_change_and_not_repeats(conn):
    """Evolution lives in score_history: `scores` keeps only the current one."""
    _insert_cve(conn)
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.1", "percentile": "0.5"}])

    score_all(conn)
    assert _count(conn, "score_history") == 1  # first snapshot

    score_all(conn)  # same value: does not pollute the series
    assert _count(conn, "score_history") == 1

    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.9", "percentile": "0.99"}])
    score_all(conn)
    assert _count(conn, "score_history") == 2

    rows = conn.execute(
        "SELECT hype, reality FROM score_history WHERE cve_id = ? ORDER BY id", (CVE_ID,)
    ).fetchall()
    assert [round(float(f["reality"]), 2) for f in rows] == [7.1, 7.9]


def test_load_score_history_returns_series_old_to_new(conn):
    _insert_cve(conn)
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.1", "percentile": "0.5"}])
    score_all(conn)
    upsert_epss(conn, [{"cve": CVE_ID, "epss": "0.9", "percentile": "0.99"}])
    score_all(conn)

    serie = load_score_history(conn, CVE_ID)

    assert len(serie) == 2
    assert serie[0]["reality"] < serie[-1]["reality"]
    assert serie[0]["date"][:4].isdigit()  # date+time, not just the day


def test_scoring_ignores_cves_without_enrichment(conn):
    _insert_cve(conn, "CVE-2026-1111")

    assert score_all(conn) == 0
    assert _count(conn, "scores", "CVE-2026-1111") == 0


def test_scoring_ignores_stubs_without_sync_data(conn):
    """KEV/EPSS can create stubs; they must not score until sync fills the CVE in."""
    upsert_kev(conn, [{"cveID": "CVE-2026-7777", "dateAdded": "2026-02-01"}])
    upsert_epss(conn, [{"cve": "CVE-2026-7777", "epss": "0.9", "percentile": "0.99"}])

    assert score_all(conn) == 0
    assert _count(conn, "scores", "CVE-2026-7777") == 0


def test_process_cve_file_normalizes_and_upserts(conn):
    path = FIXTURES / "CVE-2026-0001.json"

    assert process_cve_file(path, conn) is True
    row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (CVE_ID,)).fetchone()

    assert row["published"] == "2026-01-06T12:30:00.000Z"
    assert row["last_modified"] == "2026-01-09T08:15:00.000Z"
    assert row["cvss_score"] == pytest.approx(9.8)
    assert row["cvss_severity"] == "CRITICAL"
    assert "remote code execution" in row["description"]

    # Re-syncing the same file neither duplicates nor breaks the enrichments FK.
    upsert_kev(conn, [{"cveID": CVE_ID, "dateAdded": "2026-01-10"}])
    assert process_cve_file(path, conn) is True

    assert _count(conn, "cves") == 1
    assert _enrichment_row(conn)["in_kev"] == 1
