"""El rerank no debe volver a mandar al LLM las entradas ya procesadas.

Medido en producción: los 7 feeds tardaban ~5 min por ciclo y devolvían 0 menciones
nuevas, porque los RSS rotan lento y cada corrida re-analizaba las mismas notas.
"""
import json
from pathlib import Path

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
    """Completer falso: cuenta llamadas y contesta un CVE fijo por entrada."""

    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def __call__(self, prompt):
        self.calls += 1
        if self.fail:
            raise RuntimeError("LLM caído")
        # Cada entrada del prompt viene como 'N. title="..." summary="..."'.
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


def test_primera_corrida_usa_el_llm(conn, session):
    counter = _Counter()
    nuevas = _rerank(conn, session, counter)

    assert counter.calls > 0
    assert nuevas


def test_segunda_corrida_no_gasta_llm(conn, session):
    first = _Counter()
    _rerank(conn, session, first)

    second = _Counter()
    nuevas = _rerank(conn, session, second)

    assert second.calls == 0, "las mismas notas se re-mandaron al LLM"
    assert nuevas == {}


def test_guarda_las_urls_procesadas(conn, session):
    _rerank(conn, session, _Counter())

    urls = {row["url"] for row in conn.execute("SELECT url FROM reranked_urls").fetchall()}
    assert "https://example.com/story-1" in urls
    assert len(urls) == 3  # las tres entradas del fixture


def test_lote_caido_no_se_marca_y_se_reintenta(conn, session):
    _rerank(conn, session, _Counter(fail=True))

    assert conn.execute("SELECT count(*) c FROM reranked_urls").fetchone()["c"] == 0

    retry = _Counter()
    _rerank(conn, session, retry)
    assert retry.calls > 0, "una entrada sin veredicto no puede quedar como procesada"


def test_get_db_no_deja_transaccion_abierta(conn):
    # Sin commit del SET inicial la sesión queda "idle in transaction" y cualquier
    # sentencia posterior muere con InFailedSqlTransaction si algo falló antes.
    state = conn.execute(
        "SELECT state FROM pg_stat_activity WHERE pid = pg_backend_pid()"
    ).fetchone()["state"]

    assert state == "idle", f"la conexión quedó {state}"
