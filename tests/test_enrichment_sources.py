"""Phase 3: RSS, GitHub PoCs and tone/branding through the LLM.

No network: feeds and search come from fixtures, and the LLM is either injected
or mocked. Everything is persisted against an isolated PostgreSQL schema (`tmp_path` as key).
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
# Network doubles
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
    """Records every GET and returns a fixed response per URL."""

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
def test_schema_creates_media_mentions_table(db_file):
    conn = get_db(db_file)
    try:
        from core.db import list_tables

        tables = list_tables(conn)
    finally:
        conn.close()

    assert "media_mentions" in tables


def test_rss_counts_mentions_per_cve_without_repeating_url(conn, rss_session):
    nuevas = load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    # story-1 mentions both CVEs, story-3 only the second one.
    assert nuevas == {CVE_1: 1, CVE_2: 2}
    assert _enrichment_row(conn, CVE_1)["media_count"] == 1
    assert _enrichment_row(conn, CVE_2)["media_count"] == 2

    urls_9001 = {row["url"] for row in _media_rows(conn, CVE_1)}
    urls_9002 = {row["url"] for row in _media_rows(conn, CVE_2)}
    assert urls_9001 == {"https://example.com/story-1"}
    assert urls_9002 == {"https://example.com/story-1", "https://example.com/story-3"}
    assert len(_media_rows(conn)) == 3  # the repeated URL does not duplicate the row


def test_rss_stores_title_and_source(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    row = _media_rows(conn, CVE_1)[0]
    assert row["title"] == "Critical CVE-2026-9001 RCE is under attack"
    assert row["source"] == "Example Security Feed"
    assert row["published"].startswith("2026-01-05")


def test_rss_does_not_double_count_on_repeated_run(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)
    nuevas = load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    assert nuevas == {}
    assert _enrichment_row(conn, CVE_1)["media_count"] == 1
    assert _enrichment_row(conn, CVE_2)["media_count"] == 2
    assert len(_media_rows(conn)) == 3


def test_rss_creates_cve_stub(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    stub = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (CVE_2,)).fetchone()
    assert stub is not None
    assert stub["description"] is None


def test_rss_ignores_dead_feed_and_continues(conn):
    session = _FakeSession({
        "https://roto.example.com/rss": _FakeResponse(status_code=500),
        "https://feeds.example.com/rss": _FakeResponse(content=(FEEDS / "example_rss.xml").read_bytes()),
    })

    nuevas = load_rss(conn, ["https://roto.example.com/rss", "https://feeds.example.com/rss"],
                      session=session)

    assert nuevas == {CVE_1: 1, CVE_2: 2}


def test_atom_is_also_parsed(conn):
    session = _FakeSession({
        "https://atom.example.com/feed": _FakeResponse(content=(FEEDS / "example_atom.xml").read_bytes()),
    })

    nuevas = load_rss(conn, ["https://atom.example.com/feed"], session=session)

    assert nuevas == {"CVE-2026-9100": 1}
    assert _media_rows(conn, "CVE-2026-9100")[0]["source"] == "Example Atom Feed"


def test_parse_feed_without_cves_generates_no_mentions():
    entries = parse_feed((FEEDS / "example_atom.xml").read_bytes())

    assert len(entries) == 2
    assert collect_mentions(entries[1:]) == []  # entry without a CVE


# --------------------------------------------------------------------------
# GitHub PoCs
# --------------------------------------------------------------------------
def test_github_poc_count_is_replaced_not_added(conn):
    upsert_poc_count(conn, CVE_1, 7)
    assert _enrichment_row(conn)["poc_count"] == 7

    upsert_poc_count(conn, CVE_1, 2)
    assert _enrichment_row(conn)["poc_count"] == 2  # replaces


def test_github_reads_total_count_from_search(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"total_count": 4}),
    })

    count = load_pocs(conn, [CVE_1], session=session, token="")

    assert count == 1
    assert _enrichment_row(conn)["poc_count"] == 4

    call = session.calls[0]
    assert call["params"]["q"] == f"{CVE_1} poc"
    assert "Authorization" not in call["headers"]  # without a token no header is invented


def test_github_sends_token_when_present(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"total_count": 1}),
    })

    load_pocs(conn, [CVE_1], session=session, token="ghp_test")

    assert session.calls[0]["headers"]["Authorization"] == "Bearer ghp_test"


def test_github_uses_items_when_no_total_count(conn):
    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"items": [{}, {}]}),
    })

    assert fetch_poc_count(CVE_1, session=session, token="") == 2


def test_github_403_rate_limit_does_not_break(conn):
    import requests

    session = _FakeSession({
        "https://api.github.com/search/repositories": _FakeResponse(payload={"message": "rate limit"}, status_code=403),
    })

    assert fetch_poc_count(CVE_1, session=session, token="") == 0

    session = _FakeSession({"https://api.github.com/search/repositories": requests.ConnectionError("sin red")})
    assert fetch_poc_count(CVE_1, session=session, token="") == 0


def test_build_poc_query_adds_poc_when_missing():
    assert build_poc_query("{cve_id}", CVE_1) == f"{CVE_1} poc"
    assert build_poc_query("{cve_id} poc", CVE_1) == f"{CVE_1} poc"
    assert build_poc_query("", CVE_1) == f"{CVE_1} poc"  # module default


def test_github_poc_count_preserves_kev_and_epss(conn):
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


def test_llm_persists_tone_and_rejects_ungrounded_branding(conn, rss_session, monkeypatch):
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
    assert row_1["branding"] == 0
    assert row_1["brand_name"] is None  # absent from the actual headline
    assert row_2["tone_score"] == pytest.approx(2.0)
    assert row_2["branding"] == 0
    assert row_2["brand_name"] is None

    # One batch -> a single call, with both headlines in the prompt.
    assert len(calls) == 1
    assert CVE_1 in calls[0]["prompt"] and CVE_2 in calls[0]["prompt"]
    assert calls[0]["system"] == agent.TONE_SYSTEM


def test_llm_one_batch_per_ten_headlines(conn, monkeypatch):
    for index in range(12):
        _feed_mentions(conn, f"CVE-2026-80{index:02d}")
    calls = []
    monkeypatch.setattr("core.llm.complete", _fake_llm("[]", calls))

    assert load_tone(conn, limit=12, batch_size=10) == 12

    assert len(calls) == 2  # 10 + 2, not one call per CVE


def test_llm_broken_json_falls_back_to_the_heuristic(conn, monkeypatch):
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


def test_llm_wrapped_in_markdown_and_fences(conn, monkeypatch):
    _feed_mentions(conn, CVE_1)
    payload = 'Claro:\n```json\n[{"cve_id": "%s", "tone_score": 5, "branding": true, "brand_name": "X"}]\n```' % CVE_1
    monkeypatch.setattr("core.llm.complete", _fake_llm(payload))

    assert load_tone(conn) == 1
    assert _enrichment_row(conn)["tone_score"] == pytest.approx(5.0)


def test_llm_without_proxy_uses_heuristic_and_does_not_break(conn):
    _feed_mentions(conn, CVE_1)

    def _explota(*args, **kwargs):
        raise agent.llm_client.LlmConfigError("Missing API key")

    results = analyze_tone_batch([{"cve_id": CVE_1, "title": "Dry vendor advisory, patch available"}],
                                 completer=_explota)

    assert results[0]["source"] == "heuristic"
    assert results[0]["branding"] is False
    assert results[0]["tone_score"] <= 3.0


def test_llm_does_not_overwrite_kev_or_epss(conn, rss_session, monkeypatch):
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
    assert row["brand_name"] is None  # ungrounded model output is rejected


def test_tone_out_of_range_is_clamped(conn):
    upsert_tone(conn, [{"cve_id": CVE_1, "tone_score": 42, "branding": False}])

    assert _enrichment_row(conn)["tone_score"] == pytest.approx(10.0)


def test_tone_without_numeric_value_does_not_write(conn):
    assert upsert_tone(conn, [{"cve_id": CVE_1, "tone_score": "panic"}]) == 0
    assert _enrichment_row(conn) is None


# --------------------------------------------------------------------------
# Heuristic
# --------------------------------------------------------------------------
def test_tone_heuristic_separates_panic_from_advisory():
    assert heuristic_tone("Log4Shell apocalypse!!!") >= 7.0
    assert heuristic_tone("Vendor advisory: patch available for CVE-2026-9001") <= 3.0
    assert 0.0 <= heuristic_tone("") <= 10.0


def test_branding_heuristic_by_known_name_and_camel_case():
    assert heuristic_branding("Log4Shell apocalypse!!!") == (True, "Log4Shell")
    assert heuristic_branding("New flaw dubbed GhostBreak hits routers") == (True, "GhostBreak")
    assert heuristic_branding("CVE-2026-9001 patched in HTTP/2 stack") == (False, None)


# --------------------------------------------------------------------------
# CLI and orchestration
# --------------------------------------------------------------------------
def test_parser_skip_flags():
    args = build_parser().parse_args(["--skip-kev", "--skip-epss", "--skip-rss",
                                      "--skip-github", "--skip-llm"])

    assert (args.skip_kev, args.skip_epss, args.skip_rss, args.skip_github, args.skip_llm) == (
        True, True, True, True, True)
    assert args.rss_only is False


def test_parser_rss_only_and_defaults():
    args = build_parser().parse_args(["--rss-only"])

    assert args.rss_only is True
    assert args.skip_rss is False
    assert args.llm_batch_size == 10


def test_rss_only_does_not_touch_the_network(tmp_path, monkeypatch):
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


def test_run_with_everything_skipped_returns_zeros(tmp_path):
    summary = agent.run(skip_kev=True, skip_epss=True, skip_rss=True, skip_github=True,
                        skip_llm=True, db_path=tmp_path / "humo.db")

    # By key and not by exact dict: every new source returning its own
    # counter broke this test even though nothing was wrong.
    assert summary["kev"] == 0
    assert summary["epss"] == 0
    assert summary["rss"] == {}
    assert summary["poc"] == 0
    assert summary["tone"] == 0
    assert summary["attention"]["nuevas"] == 0


def test_load_sources_config_reads_repo_sources():
    sources = agent.load_sources_config()

    assert isinstance(sources.get("rss"), list) and sources["rss"]
    assert sources["github_search"]["enabled"] is True


def test_load_pocs_does_not_overwrite_count_when_github_rate_limits(conn):
    """A 403 is rate limiting, not "no PoCs": storing 0 would wipe the good count."""
    import requests

    conn.execute("INSERT INTO cves (cve_id, published) VALUES (?, ?)", (CVE_1, "2026-06-01T00:00:00Z"))
    agent.upsert_poc_count(conn, CVE_1, 7)
    agent.upsert_pocs(conn, CVE_1, [{"repo": "a/b", "url": "https://github.com/a/b"}])

    class Respuesta:
        status_code = 403

        def raise_for_status(self):
            raise requests.HTTPError("403 Client Error", response=self)

        def json(self):
            return {}

    class FakeSession:
        def get(self, *args, **kwargs):
            return Respuesta()

    processed = agent.load_pocs(
        conn, [CVE_1], session=FakeSession(), pause=0, sleep=lambda seconds: None,
    )

    assert processed == 0
    assert conn.execute(
        "SELECT poc_count FROM enrichments WHERE cve_id = ?", (CVE_1,)
    ).fetchone()[0] == 7


def test_select_poc_targets_drops_already_loaded_from_queue(conn, rss_session):
    """Without this filter the batch repeats the same top and PoCs never arrive."""
    conn.execute("INSERT INTO cves (cve_id, published) VALUES (?, ?)", ("CVE-2026-7000", "2026-06-01T00:00:00Z"))
    upsert_kev(conn, [{"cveID": "CVE-2026-7000", "dateAdded": "2026-06-02"}])
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    assert agent.select_poc_targets(conn, limit=1) == [CVE_2]
    agent.upsert_pocs(conn, CVE_2, [{"repo": "x/y", "url": "https://github.com/x/y"}])
    agent.record_poc_check(conn, CVE_2, successful=True)
    # Already loaded: the next in the queue becomes the head of the batch.
    assert agent.select_poc_targets(conn, limit=1) == [CVE_1]


def test_select_poc_targets_prioritizes_cves_with_press(conn, rss_session):
    conn.execute("INSERT INTO cves (cve_id, published) VALUES (?, ?)", ("CVE-2026-7000", "2026-06-01T00:00:00Z"))
    upsert_kev(conn, [{"cveID": "CVE-2026-7000", "dateAdded": "2026-06-02"}])
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    targets = agent.select_poc_targets(conn, limit=2)

    # CVEs with more mentions go first; the batch is bounded by limit.
    assert targets == [CVE_2, CVE_1]
    assert agent.select_poc_targets(conn, limit=0) == []


def test_select_tone_targets_takes_one_headline_per_cve(conn, rss_session):
    load_rss(conn, ["https://feeds.example.com/rss"], session=rss_session)

    targets = agent.select_tone_targets(conn, limit=10)

    assert [item["cve_id"] for item in targets] == [CVE_2, CVE_1]  # id DESC
    assert all(item["title"] for item in targets)


# --------------------------------------------------------------------------
# LLM rerank of feeds: drops non-vulns, resolves the CVE and captures nicknames
# --------------------------------------------------------------------------
def test_parse_rerank_reply_accepts_fences_and_prose():
    reply = (
        "Aca va:\n```json\n"
        '[{"i": 1, "cve_id": "CVE-2026-1111", "brand_name": "Log4Shell", "relevant": true}]\n'
        "```"
    )

    items = agent.parse_rerank_reply(reply)

    assert items[0]["cve_id"] == "CVE-2026-1111"
    assert items[0]["brand_name"] == "Log4Shell"


def test_parse_rerank_reply_without_json_returns_empty():
    assert agent.parse_rerank_reply("no pude procesar") == []
    assert agent.parse_rerank_reply(None) == []
    assert agent.parse_rerank_reply("[{roto}]") == []


def test_rerank_entries_maps_by_index_and_drops_invalid_cve():
    entries = [
        {"title": "CVE-2026-2222 Heartbleed", "summary": ""},
        {"title": "Dos", "summary": ""},
        {"title": "Tres", "summary": ""},
    ]
    reply = json.dumps([
        {"i": 1, "cve_id": "cve-2026-2222", "brand_name": "Heartbleed", "relevant": True},
        {"i": 2, "cve_id": "no-es-cve", "brand_name": "Inventado", "relevant": True},
        {"i": 3, "cve_id": None, "brand_name": "SinCve", "relevant": False},
    ])

    out = agent.rerank_entries(entries, completer=lambda prompt: reply)

    assert out[0]["cve_id"] == "CVE-2026-2222"  # normalized to uppercase
    assert out[0]["brand_name"] == "Heartbleed"
    assert out[1]["cve_id"] is None  # invalid format is not propagated
    assert out[1]["brand_name"] is None
    assert out[2]["relevant"] is False
    assert out[2]["brand_name"] is None  # a nickname without a CVE is useless


def test_rerank_entries_llm_down_does_not_lose_entries():
    entries = [{"title": "Uno"}, {"title": "Dos"}]

    def boom(prompt):
        raise RuntimeError("litellm timeout")

    out = agent.rerank_entries(entries, completer=boom)

    assert out == [{}, {}]


def test_mentions_from_rerank_only_takes_vulns_with_cve():
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
