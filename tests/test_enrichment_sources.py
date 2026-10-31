"""Fase 3: RSS, PoCs de GitHub y tone/branding vía LLM.

Sin red: los feeds y la búsqueda salen de fixtures, y el LLM se inyecta o se
mockea. Todo se persiste contra un schema PostgreSQL aislado (`tmp_path` como clave).
"""
import json
from pathlib import Path

import pytest

from agents import enrichment_agent as agent
from agents.enrichment_agent import (
    analyze_tone_batch,
    build_parser,
    build_poc_query,
    collect_mentions,
    fetch_poc_count,
    heuristic_branding,
    heuristic_tone,
    load_pocs,
    load_rss,
    load_tone,
    parse_feed,
    upsert_kev,
    upsert_epss,
    upsert_media_mentions,
    upsert_poc_count,
    upsert_tone,
)
from core.db import get_db, init_db

CVE_1 = "CVE-2026-9001"
CVE_2 = "CVE-2026-9002"
FEEDS = Path(__file__).parent / "fixtures" / "feeds"


# --------------------------------------------------------------------------
# Dobles de red
# --------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, payload=None, content=b"", status_code=200):
        self._payload = payload
        self.content = content
        self.text = content.decode("utf-8", "replace") if content else str(payload)
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class _FakeSession:
    """Registra cada GET y devuelve una respuesta fija por URL."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        response = self.responses.get(url) or next(iter(self.responses.values()))
        if isinstance(response, Exception):
            raise response
        return response


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


@pytest.fixture
def rss_session():
    content = (FEEDS / "example_rss.xml").read_bytes()
    return _FakeSession({
        "https://feeds.example.com/rss": _FakeResponse(content=content),
    })


def _enrichment_row(conn, cve_id=CVE_1):
    return conn.execute("SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,)).fetchone()


def _media_rows(conn, cve_id=None):
    if cve_id is None:
        return conn.execute("SELECT * FROM media_mentions").fetchall()
    return conn.execute("SELECT * FROM media_mentions WHERE cve_id = ?", (cve_id,)).fetchall()


def _feed_mentions(conn, cve_id=CVE_1):
    return upsert_media_mentions(conn, [
        {"cve_id": cve_id, "url": f"https://example.com/{cve_id}", "title": "Log4Shell apocalypse!!!",
         "source": "Example", "published": "2026-01-05"},
    ])


# --------------------------------------------------------------------------
# RSS
# --------------------------------------------------------------------------
def test_schema_crea_la_tabla_media_mentions(db_file):
    conn = get_db(db_file)
    try:
        from core.db import list_tables

        tables = list_tables(conn)
    finally:
        conn.close()

    assert "media_mentions" in tables


def test_rss_cuenta_menciones_por_cve_sin_repetir_url(conn, rss_session):
    nuevas = load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    # story-1 menciona los dos CVEs, story-3 sólo al segundo.
    assert nuevas == {CVE_1: 1, CVE_2: 2}
    assert _enrichment_row(conn, CVE_1)["media_count"] == 1
    assert _enrichment_row(conn, CVE_2)["media_count"] == 2

    urls_9001 = {row["url"] for row in _media_rows(conn, CVE_1)}
    urls_9002 = {row["url"] for row in _media_rows(conn, CVE_2)}
    assert urls_9001 == {"https://example.com/story-1"}
    assert urls_9002 == {"https://example.com/story-1", "https://example.com/story-3"}
    assert len(_media_rows(conn)) == 3  # la URL repetida no duplica la fila


def test_rss_guarda_titulo_y_medio(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    row = _media_rows(conn, CVE_1)[0]
    assert row["title"] == "Critical CVE-2026-9001 RCE is under attack"
    assert row["source"] == "Example Security Feed"
    assert row["published"].startswith("2026-01-05")


def test_rss_no_doble_cuenta_si_se_repite_la_corrida(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)
    nuevas = load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    assert nuevas == {}
    assert _enrichment_row(conn, CVE_1)["media_count"] == 1
    assert _enrichment_row(conn, CVE_2)["media_count"] == 2
    assert len(_media_rows(conn)) == 3


def test_rss_crea_stub_del_cve(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    stub = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (CVE_2,)).fetchone()
    assert stub is not None
    assert stub["description"] is None


def test_rss_ignora_feed_caido_y_sigue(conn):
    session = _FakeSession({
        "https://roto.example.com/rss": _FakeResponse(status_code=500),
        "https://feeds.example.com/rss": _FakeResponse(content=(FEEDS / "example_rss.xml").read_bytes()),
    })

    nuevas = load_rss(conn, ["https://roto.example.com/rss", "https://feeds.example.com/rss"],
                      session=session)

    assert nuevas == {CVE_1: 1, CVE_2: 2}


def test_atom_tambien_se_parsea(conn):
    session = _FakeSession({
        "https://atom.example.com/feed": _FakeResponse(content=(FEEDS / "example_atom.xml").read_bytes()),
    })

    nuevas = load_rss(conn, ["https://atom.example.com/feed"], session=session)

    assert nuevas == {"CVE-2026-9100": 1}
    assert _media_rows(conn, "CVE-2026-9100")[0]["source"] == "Example Atom Feed"


def test_parse_feed_sin_cves_no_genera_menciones():
    entries = parse_feed((FEEDS / "example_atom.xml").read_bytes())

    assert len(entries) == 2
    assert collect_mentions(entries[1:]) == []  # entrada sin CVE


# --------------------------------------------------------------------------
# GitHub PoCs
# --------------------------------------------------------------------------
def test_github_poc_count_se_reemplaza_no_se_suma(conn):
    upsert_poc_count(conn, CVE_1, 7)
    assert _enrichment_row(conn)["poc_count"] == 7

    upsert_poc_count(conn, CVE_1, 2)
    assert _enrichment_row(conn)["poc_count"] == 2  # reemplaza


def test_github_lee_total_count_del_search(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"total_count": 4}),
    })

    count = load_pocs(conn, [CVE_1], session=session, token="")

    assert count == 1
    assert _enrichment_row(conn)["poc_count"] == 4

    call = session.calls[0]
    assert call["params"]["q"] == f"{CVE_1} poc"
    assert "Authorization" not in call["headers"]  # sin token no se inventa header


def test_github_manda_token_si_existe(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"total_count": 1}),
    })

    load_pocs(conn, [CVE_1], session=session, token="ghp_test")

    assert session.calls[0]["headers"]["Authorization"] == "Bearer ghp_test"


def test_github_usa_items_cuando_no_hay_total_count(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"items": [{}, {}]}),
    })

    assert fetch_poc_count(CVE_1, session=session, token="") == 2


def test_github_403_por_rate_limit_no_rompe(conn):
    import requests

    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"message": "rate limit"}, status_code=403),
    })

    assert fetch_poc_count(CVE_1, session=session, token="") == 0

    session = _FakeSession({"https://api.github.com/search/repositories": requests.ConnectionError("sin red")})
    assert fetch_poc_count(CVE_1, session=session, token="") == 0


def test_build_poc_query_agrega_poc_si_falta():
    assert build_poc_query("{cve_id}", CVE_1) == f"{CVE_1} poc"
    assert build_poc_query("{cve_id} poc", CVE_1) == f"{CVE_1} poc"
    assert build_poc_query("", CVE_1) == f"{CVE_1} poc"  # default del módulo


def test_github_poc_count_preserva_kev_y_epss(conn):
    upsert_kev(conn, [{"cveID": CVE_1, "dateAdded": "2026-01-10"}])
    upsert_epss(conn, [{"cve": CVE_1, "epss": "0.42", "percentile": "0.5"}])

    upsert_poc_count(conn, CVE_1, 3)

    row = _enrichment_row(conn)
    assert row["poc_count"] == 3
    assert row["in_kev"] == 1
    assert row["epss"] == pytest.approx(0.42)


# --------------------------------------------------------------------------
# LLM: tone_score + branding
# --------------------------------------------------------------------------
def _fake_llm(payload, calls=None):
    def _complete(prompt, *, system=None, config=None, session=None):
        if calls is not None:
            calls.append({"prompt": prompt, "system": system, "config": config, "session": session})
        return payload

    return _complete


def test_llm_persiste_tone_y_branding(conn, rss_session, monkeypatch):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)
    payload = json.dumps([
        {"cve_id": CVE_1, "tone_score": 9, "branding": True, "brand_name": "ExampleShell"},
        {"cve_id": CVE_2, "tone_score": 2, "branding": False, "brand_name": None},
    ])
    calls = []
    monkeypatch.setattr("core.llm.complete", _fake_llm(payload, calls))

    assert load_tone(conn) == 2

    row_1, row_2 = _enrichment_row(conn, CVE_1), _enrichment_row(conn, CVE_2)
    assert row_1["tone_score"] == pytest.approx(9.0)
    assert row_1["branding"] == 1
    assert row_1["brand_name"] == "ExampleShell"
    assert row_2["tone_score"] == pytest.approx(2.0)
    assert row_2["branding"] == 0
    assert row_2["brand_name"] is None

    # Un lote -> una sola llamada, con las dos cabeceras en el prompt.
    assert len(calls) == 1
    assert CVE_1 in calls[0]["prompt"] and CVE_2 in calls[0]["prompt"]
    assert calls[0]["system"] == agent.TONE_SYSTEM


def test_llm_un_lote_por_cada_diez_titulares(conn, monkeypatch):
    for index in range(12):
        _feed_mentions(conn, f"CVE-2026-80{index:02d}")
    calls = []
    monkeypatch.setattr("core.llm.complete", _fake_llm("[]", calls))

    assert load_tone(conn, limit=12, batch_size=10) == 12

    assert len(calls) == 2  # 10 + 2, no una llamada por CVE


def test_llm_json_roto_cae_al_heurístico(conn, monkeypatch):
    upsert_media_mentions(conn, [
        {"cve_id": CVE_1, "url": "https://example.com/log4shell",
         "title": "Log4Shell apocalypse!!!", "source": "Example", "published": "2026-01-05"},
    ])
    monkeypatch.setattr("core.llm.complete", _fake_llm("Sorry, I cannot help with that."))

    assert load_tone(conn) == 1

    row = _enrichment_row(conn)
    assert row["branding"] == 1
    assert row["brand_name"] == "Log4Shell"
    assert row["tone_score"] >= 7.0


def test_llm_envuelto_en_markdown_y_fences(conn, monkeypatch):
    _feed_mentions(conn, CVE_1)
    payload = 'Claro:\n```json\n[{"cve_id": "%s", "tone_score": 5, "branding": true, "brand_name": "X"}]\n```' % CVE_1
    monkeypatch.setattr("core.llm.complete", _fake_llm(payload))

    assert load_tone(conn) == 1
    assert _enrichment_row(conn)["tone_score"] == pytest.approx(5.0)


def test_llm_sin_proxy_usa_heurística_y_no_rompe(conn):
    _feed_mentions(conn, CVE_1)

    def _explota(*args, **kwargs):
        raise agent.llm_client.LlmConfigError("Falta la API key")

    results = analyze_tone_batch([{"cve_id": CVE_1, "title": "Dry vendor advisory, patch available"}],
                                 completer=_explota)

    assert results[0]["source"] == "heuristic"
    assert results[0]["branding"] is False
    assert results[0]["tone_score"] <= 3.0


def test_llm_no_pisa_kev_ni_epss(conn, rss_session, monkeypatch):
    upsert_kev(conn, [{"cveID": CVE_1, "dateAdded": "2026-01-10",
                       "knownRansomwareCampaignUse": "Known"}])
    upsert_epss(conn, [{"cve": CVE_1, "epss": "0.42", "percentile": "0.97"}])
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)
    monkeypatch.setattr("core.llm.complete", _fake_llm(json.dumps(
        [{"cve_id": CVE_1, "tone_score": 8, "branding": True, "brand_name": "Z"}]
    )))

    upsert_tone(conn, analyze_tone_batch([{"cve_id": CVE_1, "title": "x"}]))

    row = _enrichment_row(conn)
    assert row["in_kev"] == 1
    assert row["kev_date"] == "2026-01-10"
    assert row["ransomware_use"] == 1
    assert row["epss"] == pytest.approx(0.42)
    assert row["epss_percentile"] == pytest.approx(0.97)
    assert row["media_count"] == 1
    assert row["tone_score"] == pytest.approx(8.0)
    assert row["brand_name"] == "Z"


def test_tone_fuera_de_rango_se_acota(conn):
    upsert_tone(conn, [{"cve_id": CVE_1, "tone_score": 42, "branding": False}])

    assert _enrichment_row(conn)["tone_score"] == pytest.approx(10.0)


def test_tone_sin_valor_numerico_no_escribe(conn):
    assert upsert_tone(conn, [{"cve_id": CVE_1, "tone_score": "panic"}]) == 0
    assert _enrichment_row(conn) is None


# --------------------------------------------------------------------------
# Heurístico
# --------------------------------------------------------------------------
def test_heuristica_de_tone_separa_panico_de_advisory():
    assert heuristic_tone("Log4Shell apocalypse!!!") >= 7.0
    assert heuristic_tone("Vendor advisory: patch available for CVE-2026-9001") <= 3.0
    assert 0.0 <= heuristic_tone("") <= 10.0


def test_heuristica_de_branding_por_nombre_conocido_y_camel_case():
    assert heuristic_branding("Log4Shell apocalypse!!!") == (True, "Log4Shell")
    assert heuristic_branding("New flaw dubbed GhostBreak hits routers") == (True, "GhostBreak")
    assert heuristic_branding("CVE-2026-9001 patched in HTTP/2 stack") == (False, None)


# --------------------------------------------------------------------------
# CLI y orquestación
# --------------------------------------------------------------------------
def test_parser_flags_de_skip():
    args = build_parser().parse_args(["--skip-kev", "--skip-epss", "--skip-rss",
                                      "--skip-github", "--skip-llm"])

    assert (args.skip_kev, args.skip_epss, args.skip_rss, args.skip_github, args.skip_llm) == (
        True, True, True, True, True)
    assert args.rss_only is False


def test_parser_rss_only_y_defaults():
    args = build_parser().parse_args(["--rss-only"])

    assert args.rss_only is True
    assert args.skip_rss is False
    assert args.llm_batch_size == 10


def test_rss_only_no_toca_red(tmp_path, monkeypatch):
    def _sin_red(*args, **kwargs):
        raise AssertionError("--rss-only no debe llamar a la red")

    monkeypatch.setattr("agents.enrichment_agent.requests.get", _sin_red)
    monkeypatch.setattr("core.llm.complete", _sin_red)
    sources = tmp_path / "sources.yaml"
    sources.write_text("sources:\n  rss: []\n  github_search:\n    enabled: false\n", encoding="utf-8")
    db_path = tmp_path / "humo.db"

    assert agent.main(["--rss-only", "--sources", str(sources), "--db-path", str(db_path)]) == 0
    conn = get_db(db_path)
    try:
        from core.db import list_tables

        assert "cves" in list_tables(conn)
    finally:
        conn.close()


def test_run_con_todo_skippeado_devuelve_ceros(tmp_path):
    summary = agent.run(skip_kev=True, skip_epss=True, skip_rss=True, skip_github=True,
                        skip_llm=True, db_path=tmp_path / "humo.db")

    # Por clave y no por dict exacto: cada fuente nueva que devuelve su propio
    # contador rompía este test sin que nada estuviera mal.
    assert summary["kev"] == 0
    assert summary["epss"] == 0
    assert summary["rss"] == {}
    assert summary["poc"] == 0
    assert summary["tone"] == 0
    assert summary["attention"]["nuevas"] == 0


def test_load_sources_config_lee_fuentes_del_repo():
    sources = agent.load_sources_config()

    assert isinstance(sources.get("rss"), list) and sources["rss"]
    assert sources["github_search"]["enabled"] is True


def test_select_poc_targets_prioriza_cves_con_prensa(conn, rss_session):
    conn.execute("INSERT INTO cves (cve_id, published) VALUES (?, ?)", ("CVE-2026-7000", "2026-06-01T00:00:00Z"))
    upsert_kev(conn, [{"cveID": "CVE-2026-7000", "dateAdded": "2026-06-02"}])
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    targets = agent.select_poc_targets(conn, limit=2)

    # Los CVEs con más menciones van primero; el lote está acotado por limit.
    assert targets == [CVE_2, CVE_1]
    assert agent.select_poc_targets(conn, limit=0) == []


def test_select_tone_targets_toma_un_titular_por_cve(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    targets = agent.select_tone_targets(conn, limit=10)

    assert [item["cve_id"] for item in targets] == [CVE_2, CVE_1]  # id DESC
    assert all(item["title"] for item in targets)


# --------------------------------------------------------------------------
# Rerank LLM de feeds: descarta no-vulns, resuelve CVE y captura apodos
# --------------------------------------------------------------------------
def test_parse_rerank_reply_acepta_fences_y_prosa():
    reply = (
        "Aca va:\n```json\n"
        '[{"i": 1, "cve_id": "CVE-2026-1111", "brand_name": "Log4Shell", "relevant": true}]\n'
        "```"
    )

    items = agent.parse_rerank_reply(reply)

    assert items[0]["cve_id"] == "CVE-2026-1111"
    assert items[0]["brand_name"] == "Log4Shell"


def test_parse_rerank_reply_sin_json_devuelve_vacio():
    assert agent.parse_rerank_reply("no pude procesar") == []
    assert agent.parse_rerank_reply(None) == []
    assert agent.parse_rerank_reply("[{roto}]") == []


def test_rerank_entries_mapea_por_indice_y_descarta_cve_invalido():
    entries = [
        {"title": "Uno", "summary": ""},
        {"title": "Dos", "summary": ""},
        {"title": "Tres", "summary": ""},
    ]
    reply = json.dumps([
        {"i": 1, "cve_id": "cve-2026-2222", "brand_name": "Heartbleed", "relevant": True},
        {"i": 2, "cve_id": "no-es-cve", "brand_name": "Inventado", "relevant": True},
        {"i": 3, "cve_id": None, "brand_name": "SinCve", "relevant": False},
    ])

    out = agent.rerank_entries(entries, completer=lambda prompt: reply)

    assert out[0]["cve_id"] == "CVE-2026-2222"  # se normaliza a mayúsculas
    assert out[0]["brand_name"] == "Heartbleed"
    assert out[1]["cve_id"] is None  # formato inválido no se propaga
    assert out[1]["brand_name"] is None
    assert out[2]["relevant"] is False
    assert out[2]["brand_name"] is None  # apodo sin CVE no sirve


def test_rerank_entries_llm_caido_no_pierde_entradas():
    entries = [{"title": "Uno"}, {"title": "Dos"}]

    def boom(prompt):
        raise RuntimeError("litellm timeout")

    out = agent.rerank_entries(entries, completer=boom)

    assert out == [{}, {}]


def test_mentions_from_rerank_solo_toma_vulns_con_cve():
    entries = [
        {"title": "Chrome RCE", "url": "https://x/1", "source": "x"},
        {"title": "Conferencia anual", "url": "https://x/2", "source": "x"},
        {"title": "Sin cve", "url": "https://x/3", "source": "x"},
    ]
    reranked = [
        {"cve_id": "CVE-2026-3333", "brand_name": "ShuffleShock", "relevant": True},
        {"cve_id": None, "brand_name": None, "relevant": False},
        {"cve_id": None, "brand_name": None, "relevant": True},
    ]

    mentions = agent.mentions_from_rerank(entries, reranked)

    assert len(mentions) == 1
    assert mentions[0]["cve_id"] == "CVE-2026-3333"
    assert mentions[0]["brand_name"] == "ShuffleShock"
    assert mentions[0]["url"] == "https://x/1"
