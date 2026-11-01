"""Dashboard tests without the Streamlit runtime: loading and filtering scores."""
from pathlib import Path

import pytest

from core.db import get_db, init_db
from dashboard.data import (
    count_scores,
    daily_averages,
    filter_scores,
    guess_vuln_type,
    hype_components,
    load_agent_stats,
    load_daily_averages,
    load_last_agent_status,
    load_recent_events,
    load_score,
    load_scores,
)

OVERHYPED = "CVE-2026-0101"
QUIET = "CVE-2026-0102"


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


def _score(conn, cve_id, hype, reality, category, *, description="Test description"):
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_score, cvss_severity) "
        "VALUES (?, ?, ?, ?)",
        (cve_id, description, 9.8, "CRITICAL"),
    )
    conn.execute(
        "INSERT INTO scores (cve_id, hype, reality, category) VALUES (?, ?, ?, ?)",
        (cve_id, hype, reality, category),
    )
    conn.commit()


def test_load_scores_with_empty_db_returns_zero_rows(conn):
    # With no scores the UI shows the empty state: loading must not blow up.
    assert load_scores(conn) == []


def test_load_scores_returns_both_scores_with_category(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")

    rows = load_scores(conn)

    assert len(rows) == 2
    por_cve = {row["cve_id"]: row for row in rows}
    assert por_cve[OVERHYPED]["category"] == "Overhyped"
    assert por_cve[QUIET]["category"] == "Quiet"
    # JOIN with cves: description and CVSS reach the dashboard.
    assert por_cve[OVERHYPED]["description"] == "Test description"
    assert por_cve[OVERHYPED]["cvss_score"] == 9.8
    # LEFT JOIN with enrichments: without enrichment signals are NULL, not fewer rows.
    assert por_cve[OVERHYPED]["tone_score"] is None
    assert por_cve[OVERHYPED]["alertado"] is False


def test_filter_scores_by_category_keeps_only_overhyped(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    rows = load_scores(conn)

    filtradas = filter_scores(rows, ["Overhyped"])

    assert [row["cve_id"] for row in filtradas] == [OVERHYPED]
    # With no categories selected nothing is filtered.
    assert len(filter_scores(rows, [])) == 2


def test_filter_scores_respects_hype_and_reality_minimums(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    rows = load_scores(conn)

    solo_hype = filter_scores(rows, None, min_hype=5.0)
    solo_reality = filter_scores(rows, None, min_reality=2.5)

    assert [row["cve_id"] for row in solo_hype] == [OVERHYPED]
    assert [row["cve_id"] for row in solo_reality] == [QUIET]
    # A minimum of 0 means "no filter" (slider default).
    assert len(filter_scores(rows, None, 0, 0)) == 2


def test_load_scores_without_alerts_sent_table_does_not_fail(conn):
    # DB created before Phase 4: without alerts_sent everything stays unalerted.
    conn.execute("DROP TABLE alerts_sent")
    conn.commit()
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")

    rows = load_scores(conn)

    assert len(rows) == 1
    assert rows[0]["alertado"] is False
    assert rows[0]["alertas"] == 0


def test_load_scores_marks_already_alerted_cves(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    # Two alerts for the same CVE: the flag is "count > 0", not the rule.
    for rule in ("overhyped", "humo"):
        conn.execute(
            "INSERT INTO alerts_sent (cve_id, channel, rule) VALUES (?, 'slack', ?)",
            (OVERHYPED, rule),
        )
    conn.commit()

    por_cve = {row["cve_id"]: row for row in load_scores(conn)}

    assert por_cve[OVERHYPED]["alertado"] is True
    assert por_cve[OVERHYPED]["alertas"] == 2
    assert por_cve[QUIET]["alertado"] is False


def test_guess_vuln_type_and_daily_averages(conn):
    assert guess_vuln_type("Remote code execution in foo") == "RCE"
    assert guess_vuln_type("reflected XSS") == "XSS"
    conn.execute(
        "INSERT INTO cves (cve_id, description, published, cvss_severity) "
        "VALUES ('CVE-2026-0101', 'RCE', '2026-05-12', 'CRITICAL')"
    )
    conn.execute(
        "INSERT INTO cves (cve_id, description, published, cvss_severity) "
        "VALUES ('CVE-2026-0102', 'XSS', '2026-05-12', 'MEDIUM')"
    )
    conn.execute(
        "INSERT INTO scores (cve_id, hype, reality, category) VALUES ('CVE-2026-0101', 9.2, 2.1, 'Overhyped')"
    )
    conn.execute(
        "INSERT INTO scores (cve_id, hype, reality, category) VALUES ('CVE-2026-0102', 1.5, 3.0, 'Quiet')"
    )
    conn.commit()
    rows = load_scores(conn)
    series = daily_averages(rows)
    assert len(series) == 1
    assert series[0]["n"] == 2
    crit = filter_scores(rows, severities=["CRITICAL"])
    assert [row["cve_id"] for row in crit] == [OVERHYPED]
    stats = load_agent_stats(conn)
    assert stats["scores"] == 2
    comps = hype_components(rows[0])
    assert {item["key"] for item in comps} == {"cvss", "media", "tone", "branding", "pocs"}


def test_count_and_limit_do_not_materialize_everything(conn):
    for i in range(5):
        _score(conn, f"CVE-2026-02{i:02d}", 9.0 - i, 1.0, "Overhyped",
               description="RCE")
    assert count_scores(conn) == 5
    capped = load_scores(conn, limit=2, order="hype")
    assert len(capped) == 2
    assert capped[0]["hype"] >= capped[1]["hype"]
    assert load_score(conn, "CVE-2026-0200")["cve_id"] == "CVE-2026-0200"
    assert load_score(conn, "CVE-2099-0000") is None
    series = load_daily_averages(conn)
    assert series and series[0]["n"] == 5
    assert count_scores(conn, category="Overhyped") == 5
    assert count_scores(conn, category="Quiet") == 0


def test_load_recent_events_and_last_status(conn):
    conn.execute(
        "INSERT INTO agent_events (agent, event_type, details, status) "
        "VALUES ('sync', 'SYNC', 'ok', 'SUCCESS')"
    )
    conn.execute(
        "INSERT INTO agent_events (agent, event_type, details, status) "
        "VALUES ('sync', 'SYNC', 'start', 'RUNNING')"
    )
    conn.commit()
    events = load_recent_events(conn, 10)
    assert events[0]["status"] == "RUNNING"
    last = load_last_agent_status(conn)
    assert last["sync"]["status"] == "RUNNING"
    stats = load_agent_stats(conn)
    assert stats["agents"]["sync"]["status"] == "RUNNING"


def test_category_does_not_judge_severity():
    """Low reality means missing evidence of use, not a harmless bug.

    "Overrated" read as "no need to patch": the label now says what was
    measured, and the note makes clear that a freshly published CVE has not
    accumulated evidence yet.
    """
    from dashboard.markup import detail_html

    html = detail_html(
        cve_id="CVE-2026-9999",
        description="d",
        badges="",
        bars="",
        hype=7.5,
        reality=2.0,
        category="Overhyped",
        events="",
        mentions="",
        pocs_html="",
        poc_count=0,
        now="2026-11-01",
        caveat="Published 3 days ago. Exploitation evidence takes weeks.",
    )

    assert "NO EVIDENCE OF USE" in html
    assert "overrated" not in html.lower()
    assert "does not mean" in html
    assert "Published 3 days ago" in html


def test_parse_dt_accepts_rfc822_from_feeds():
    """Mentions store the RSS date exactly as it arrives, not in ISO."""
    from dashboard import screens

    momento = screens.parse_dt("Fri, 16 Oct 2026 07:00:00 GMT")

    assert momento is not None
    assert momento.year == 2026 and momento.month == 10 and momento.day == 16
    assert momento.tzinfo is not None
    # ISO still works (NVD and Postgres) and invalid input does not break.
    assert screens.parse_dt("2026-10-16T07:00:00Z").day == 16
    assert screens.parse_dt("") is None
    assert screens.parse_dt("no es una fecha") is None
