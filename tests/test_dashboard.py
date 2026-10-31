"""Tests del dashboard sin runtime de Streamlit: carga y filtrado de scores."""
from pathlib import Path

import pytest

from core.db import get_db, init_db
from dashboard.data import (
    daily_averages,
    filter_scores,
    guess_vuln_type,
    hype_components,
    load_agent_stats,
    load_last_agent_status,
    load_recent_events,
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


def _score(conn, cve_id, hype, reality, category, *, description="Descripción de prueba"):
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


def test_load_scores_con_db_vacia_devuelve_cero_filas(conn):
    # Sin scores la UI muestra el empty state: la carga no puede explotar.
    assert load_scores(conn) == []


def test_load_scores_devuelve_los_dos_scores_con_su_categoria(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")

    rows = load_scores(conn)

    assert len(rows) == 2
    por_cve = {row["cve_id"]: row for row in rows}
    assert por_cve[OVERHYPED]["category"] == "Overhyped"
    assert por_cve[QUIET]["category"] == "Quiet"
    # JOIN con cves: la descripción y el CVSS llegan al dashboard.
    assert por_cve[OVERHYPED]["description"] == "Descripción de prueba"
    assert por_cve[OVERHYPED]["cvss_score"] == 9.8
    # LEFT JOIN con enrichments: sin enrichment las señales son NULL, no filas menos.
    assert por_cve[OVERHYPED]["tone_score"] is None
    assert por_cve[OVERHYPED]["alertado"] is False


def test_filter_scores_por_categoria_deja_solo_overhyped(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    rows = load_scores(conn)

    filtradas = filter_scores(rows, ["Overhyped"])

    assert [row["cve_id"] for row in filtradas] == [OVERHYPED]
    # Sin categorías elegidas no se filtra nada.
    assert len(filter_scores(rows, [])) == 2


def test_filter_scores_respeta_los_minimos_de_hype_y_reality(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    rows = load_scores(conn)

    solo_hype = filter_scores(rows, None, min_hype=5.0)
    solo_reality = filter_scores(rows, None, min_reality=2.5)

    assert [row["cve_id"] for row in solo_hype] == [OVERHYPED]
    assert [row["cve_id"] for row in solo_reality] == [QUIET]
    # Un mínimo en 0 es "sin filtro" (default de los sliders).
    assert len(filter_scores(rows, None, 0, 0)) == 2


def test_load_scores_sin_tabla_alerts_sent_no_falla(conn):
    # Base creada antes de la Fase 4: sin alerts_sent todo queda no alertado.
    conn.execute("DROP TABLE alerts_sent")
    conn.commit()
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")

    rows = load_scores(conn)

    assert len(rows) == 1
    assert rows[0]["alertado"] is False
    assert rows[0]["alertas"] == 0


def test_load_scores_marca_los_cves_ya_alertados(conn):
    _score(conn, OVERHYPED, 9.2, 2.1, "Overhyped")
    _score(conn, QUIET, 1.5, 3.0, "Quiet")
    # Dos alertas para el mismo CVE: el flag es "count > 0", no la regla.
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


def test_guess_vuln_type_y_daily_averages(conn):
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


def test_load_recent_events_y_ultimo_status(conn):
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
