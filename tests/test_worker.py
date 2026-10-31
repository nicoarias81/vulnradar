"""Worker autónomo: un ciclo loguea eventos sin red."""
from pathlib import Path

import pytest

from core.db import get_db, init_db
from dashboard.data import load_last_agent_status, load_recent_events
from scripts.run_worker import log_event, run_cycle


@pytest.fixture
def db(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "humo.db"
    init_db(path)
    monkeypatch.setattr("core.db.DB_PATH", path)
    monkeypatch.setattr("scripts.run_worker.get_db", lambda p=None: get_db(path))
    monkeypatch.setattr("scripts.run_worker.init_db", lambda p=None: init_db(path))
    return path


def test_log_event_queda_en_agent_events(db):
    log_event("sync", "SYNC", "hola", "SUCCESS")
    conn = get_db(db)
    try:
        events = load_recent_events(conn)
        last = load_last_agent_status(conn)
    finally:
        conn.close()
    assert events[0]["agent"] == "sync"
    assert last["sync"]["status"] == "SUCCESS"


def test_run_cycle_continúa_si_un_paso_falla(db, monkeypatch):
    def boom(**kw):
        raise RuntimeError("boom")

    monkeypatch.setattr("agents.sync_agent.sync", boom)
    monkeypatch.setattr("agents.enrichment_agent.run", lambda **kw: {"kev": 1})
    monkeypatch.setattr("agents.scoring_agent.run", lambda **kw: None)
    monkeypatch.setattr("agents.alert_agent.run", lambda **kw: {"sent": 0})

    summary = run_cycle()

    assert summary["sync"] is None
    assert summary["enrich"] == {"kev": 1}
    conn = get_db(db)
    try:
        events = load_recent_events(conn, 20)
        statuses = {(e["agent"], e["status"]) for e in events}
    finally:
        conn.close()
    assert ("sync", "ERROR") in statuses
    assert ("enrich", "SUCCESS") in statuses
    assert ("worker", "ERROR") in statuses
