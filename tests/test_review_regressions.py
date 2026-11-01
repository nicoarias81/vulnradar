"""Regression coverage for catalog completeness, refreshes and bounded scoring."""
import json
import uuid

import psycopg
import pytest
from psycopg import sql

from agents import enrichment_agent as enrichment
from agents import scoring_agent as scoring
from agents.sync_agent import process_cve_file
from core import db


@pytest.fixture
def conn(tmp_path):
    path = tmp_path / "regressions.db"
    db.init_db(path)
    connection = db.get_db(path)
    yield connection
    connection.close()


def add_cve(conn, cve="CVE-2026-1234"):
    conn.execute("INSERT INTO cves (cve_id, published) VALUES (?, ?)", (cve, "2026-10-01"))
    enrichment.upsert_poc_count(conn, cve, 7)
    enrichment.upsert_epss(conn,[{"cve":cve,"epss":0,"percentile":0}])
    return cve


@pytest.mark.parametrize("status", [0, 401, 403, 429, 500, 502])
def test_failed_github_checks_preserve_evidence(conn, monkeypatch, status):
    cve = add_cve(conn)
    enrichment.upsert_pocs(conn, cve, [{"repo": "a/b", "stars": 12}])
    monkeypatch.setattr(enrichment, "fetch_poc_repos", lambda *a, **k: (0, [], status))
    assert enrichment.load_pocs(conn, [cve], pause=0, sleep=lambda _: None) == 0
    assert conn.execute("SELECT poc_count FROM enrichments WHERE cve_id = ?", (cve,)).fetchone()[0] == 7
    assert conn.execute("SELECT stars FROM pocs WHERE cve_id = ?", (cve,)).fetchone()[0] == 12
    assert enrichment.select_poc_targets(conn) == []  # bounded retry cooldown


@pytest.mark.parametrize("total", [0, 1])
def test_positive_and_empty_results_refresh_after_deadline(conn, monkeypatch, total):
    cve = add_cve(conn)
    repos = [{"repo": "a/b", "stars": 1}] if total else []
    monkeypatch.setattr(enrichment, "fetch_poc_repos", lambda *a, **k: (total, repos, 200))
    assert enrichment.load_pocs(conn, [cve], pause=0) == 1
    assert enrichment.select_poc_targets(conn) == []
    conn.execute("UPDATE poc_checks SET next_check_at = CURRENT_TIMESTAMP - INTERVAL '1 second'")
    assert enrichment.select_poc_targets(conn) == [cve]
    monkeypatch.setattr(enrichment, "fetch_poc_repos", lambda *a, **k: (1, [{"repo": "a/b", "stars": 42}], 200))
    assert enrichment.load_pocs(conn, enrichment.select_poc_targets(conn), pause=0) == 1
    assert conn.execute("SELECT stars FROM pocs WHERE cve_id = ?", (cve,)).fetchone()[0] == 42


def test_successful_empty_result_clears_old_repos(conn, monkeypatch):
    cve = add_cve(conn)
    enrichment.upsert_pocs(conn, cve, [{"repo": "a/b"}])
    monkeypatch.setattr(enrichment, "fetch_poc_repos", lambda *a, **k: (0, [], 200))
    enrichment.load_pocs(conn, [cve], pause=0)
    assert conn.execute("SELECT count(*) FROM pocs WHERE cve_id = ?", (cve,)).fetchone()[0] == 0


def test_sync_updates_vendor_and_product(conn, tmp_path):
    raw = {"cveMetadata": {"cveId": "CVE-2026-1234"}, "containers": {"cna": {
        "affected": [{"vendor": "Example", "product": "Widget prior to 3.0"}]
    }}}
    path = tmp_path / "record.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert process_cve_file(path, conn)
    row = conn.execute("SELECT vendor, product FROM cves").fetchone()
    assert (row[0], row[1]) == ("Example", "Widget")
    raw["containers"]["cna"]["affected"][0]["product"] = "Other 2.0"
    path.write_text(json.dumps(raw), encoding="utf-8")
    process_cve_file(path, conn)
    assert conn.execute("SELECT product FROM cves").fetchone()[0] == "Other"


def test_scoring_batches_changed_inputs_and_skips_unchanged(conn, monkeypatch):
    for i in range(5):
        add_cve(conn, f"CVE-2026-{1000+i}")
    monkeypatch.setattr(scoring, "SCORE_BATCH_SIZE", 2)
    batches = []
    original = scoring._score_rows

    def bounded(connection, rows):
        batches.append(len(rows))
        original(connection, rows)

    monkeypatch.setattr(scoring, "_score_rows", bounded)
    assert scoring.score_all(conn) == 5
    assert batches == [2, 2, 1]
    assert scoring.score_all(conn) == 0
    assert scoring.score_cves(conn, ["CVE-2026-1000"]) == 0
    enrichment.upsert_epss(conn,[{"cve":"CVE-2026-1000","epss":0.9,"percentile":0.9}])
    assert scoring.score_all(conn) == 1
    assert conn.execute("SELECT count(*) FROM score_history").fetchone()[0] == 6
    # A version bump invalidates the old fingerprints, even with identical inputs.
    monkeypatch.setattr(scoring, "SELECT_ENRICHED", scoring.SELECT_ENRICHED.replace(
        scoring.SCORING_VERSION, "test-next-formula-version"))
    assert scoring.score_all(conn) == 5
    assert conn.execute("SELECT count(*) FROM score_history").fetchone()[0] == 6


def test_category_only_correction_is_recorded_in_history(conn):
    cve = add_cve(conn)
    scoring.score_all(conn)
    conn.execute("UPDATE scores SET category = 'Sleeper', input_hash = NULL WHERE cve_id = ?", (cve,))
    assert scoring.score_all(conn) == 1
    assert conn.execute("SELECT category FROM score_history ORDER BY id DESC LIMIT 1").fetchone()[0] == "Quiet"
    assert conn.execute("SELECT count(*) FROM score_history").fetchone()[0] == 2


def test_cleanup_preserves_unregistered_schemas(tmp_path, monkeypatch):
    key = tmp_path / "owned.db"
    db.init_db(key)
    owned = db.schema_name(key)
    protected = ["t_team_" + uuid.uuid4().hex, "t_" + uuid.uuid4().hex[:16]]
    monkeypatch.setattr(db, "_TEST_SCHEMAS", {owned})
    with psycopg.connect(db.database_url(), autocommit=True) as raw:
        created = []
        try:
            for name in protected:
                raw.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
                created.append(name)
            db.drop_test_schemas()
            for name in protected:
                assert raw.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (name,)).fetchone()
            assert raw.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (owned,)).fetchone() is None
        finally:
            for name in created:
                raw.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def test_upgrade_preserves_legacy_scores_and_installs_shared_indexes(tmp_path):
    path = tmp_path / "legacy.db"
    conn = db.get_db(path)
    try:
        conn.execute("""CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT,
            description TEXT, cvss_score DOUBLE PRECISION, cvss_vector TEXT,
            cvss_severity TEXT, raw_json TEXT,
            synced_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE scores (
            id INTEGER PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
            cve_id TEXT NOT NULL UNIQUE REFERENCES cves(cve_id),
            hype DOUBLE PRECISION, reality DOUBLE PRECISION, category TEXT,
            calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("INSERT INTO cves (cve_id, published) VALUES ('CVE-2026-1234', '2026-10-01')")
        conn.execute("INSERT INTO scores (cve_id, hype, reality, category) VALUES ('CVE-2026-1234', 5, 8, 'Quiet')")
        conn.commit()
    finally:
        conn.close()
    db.init_db(path)
    db.init_db(path)
    conn = db.get_db(path)
    try:
        assert {"vendor", "product"} <= db.table_columns(conn, "cves")
        assert "input_hash" in db.table_columns(conn, "scores")
        assert {"poc_checks", "soc_sessions"} <= db.list_tables(conn)
        assert {"idx_cves_fts", "idx_cves_id_trgm"} <= db.table_indexes(conn, "cves")
        assert conn.execute("SELECT category FROM scores").fetchone()[0] == "Quiet"
        assert conn.execute("""SELECT n.nspname FROM pg_extension e
            JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pg_trgm'""").fetchone()[0] == "public"
        conn.execute("INSERT INTO enrichments (cve_id, in_kev, epss) VALUES ('CVE-2026-1234', 1, 0.9)")
        assert scoring.score_all(conn) == 1
        assert conn.execute("SELECT category FROM scores").fetchone()[0] == "Sleeper"
    finally:
        conn.close()
