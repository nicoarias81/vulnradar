"""Rerank must not send already processed entries to the LLM again.

Measured in production: the 7 feeds took ~5 min per cycle and returned 0 new
mentions, because RSS rotates slowly and every run re-analyzed the same items.
"""
import json
from pathlib import Path

import psycopg
import pytest

from agents import enrichment_agent as agent
from core.db import get_db, init_db

FEEDS = Path(__file__).parent / "fixtures" / "feeds"


class _Resp:
    def __init__(self, content=b""):
        self.content = content
        self.status_code = 200

    def raise_for_status(self):
        return None


class _Session:
    def __init__(self, content):
        self.content = content
        self.calls = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls += 1
        return _Resp(self.content)


@pytest.fixture
def db_file(tmp_path):
    path = tmp_path / "humo.db"
    init_db(path)
    return path


@pytest.fixture
def conn(db_file):
    connection = get_db(db_file)
    yield connection
    connection.close()


@pytest.fixture
def session():
    return _Session((FEEDS / "example_rss.xml").read_bytes())


class _Counter:
    """Fake completer: counts calls and answers a fixed CVE per entry."""

    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def __call__(self, prompt):
        self.calls += 1
        if self.fail:
            raise RuntimeError("LLM down")
        # Each entry in the prompt comes as 'N. title="..." summary="..."'.
        n = sum(1 for line in prompt.splitlines() if line.strip()[:2].rstrip(".").isdigit())
        return json.dumps([
            {"i": i + 1, "cve_id": "CVE-2026-9001", "brand_name": None, "relevant": True}
            for i in range(max(n, 1))
        ])


def _rerank(conn, session, counter):
    return agent.load_rss(
        conn, ["https://feeds.example.com/rss"],
        session=session, rerank=True, completer=counter,
    )


def test_first_run_uses_the_llm(conn, session):
    counter = _Counter()
    nuevas = _rerank(conn, session, counter)

    assert counter.calls > 0
    assert nuevas


def test_second_run_does_not_spend_llm(conn, session):
    first = _Counter()
    _rerank(conn, session, first)

    second = _Counter()
    nuevas = _rerank(conn, session, second)

    assert second.calls == 0, "las mismas notas se re-mandaron al LLM"
    assert nuevas == {}


def test_stores_processed_urls(conn, session):
    _rerank(conn, session, _Counter())

    guardadas = {row["url"] for row in conn.execute("SELECT url FROM reranked_urls").fetchall()}
    del_fixture = {e["url"] for e in agent.parse_feed(session.content, source="x") if e.get("url")}

    assert "https://example.com/story-1" in guardadas
    assert guardadas == del_fixture


def test_failed_batch_is_not_marked_and_is_retried(conn, session):
    _rerank(conn, session, _Counter(fail=True))

    assert conn.execute("SELECT count(*) c FROM reranked_urls").fetchone()["c"] == 0

    retry = _Counter()
    _rerank(conn, session, retry)
    assert retry.calls > 0, "una entrada sin veredicto no puede quedar como procesada"


def test_get_db_leaves_no_open_transaction(db_file):
    # Without committing the initial SET the session stays "idle in transaction" and any
    # later statement dies with InFailedSqlTransaction if something failed earlier.
    conn = get_db(db_file)
    try:
        assert conn._raw.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    finally:
        conn.close()
