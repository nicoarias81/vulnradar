"""Alert agent tests: rules, dedupe via alerts_sent, dry-run and channels.
No network: the HTTP session is an injected fake."""
from pathlib import Path

import pytest

from agents import alert_agent as agent
from core.db import get_db, init_db

OVERHYPED = "CVE-2026-0001"
QUIET = "CVE-2026-0002"
EARNED = "CVE-2026-0003"
HUMO = "CVE-2026-0004"
SLEEPER = "CVE-2026-0005"

SLACK_URL = "https://hooks.slack.test/services/AAA"
WEBHOOK_URL = "https://alerts.test/hook"


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


class FakeSession:
    """Records POSTs and returns the configured status. Never touches the network."""

    def __init__(self, status_code=200):
        self.status_code = status_code
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return FakeResponse(self.status_code)

    @property
    def urls(self):
        return [call["url"] for call in self.calls]


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


def _add_score(conn, cve_id, *, hype, reality, category, tone=None, media=0,
               in_kev=0, epss=None, poc=0, branding=0, brand_name=None,
               description="Test description"):
    """CVE + enrichment + current score as a single logical row."""
    conn.execute(
        "INSERT INTO cves (cve_id, published, description, cvss_score) VALUES (?, ?, ?, ?)",
        (cve_id, "2026-01-06T12:30:00.000Z", description, 9.8),
    )
    conn.execute(
        """INSERT INTO enrichments
           (cve_id, tone_score, media_count, in_kev, epss, poc_count, branding, brand_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (cve_id, tone, media, in_kev, epss, poc, branding, brand_name),
    )
    conn.execute(
        "INSERT INTO scores (cve_id, hype, reality, category) VALUES (?, ?, ?, ?)",
        (cve_id, hype, reality, category),
    )
    conn.commit()


def _sent_rows(conn, cve_id=None):
    sql = "SELECT * FROM alerts_sent"
    params = ()
    if cve_id is not None:
        sql += " WHERE cve_id = ?"
        params = (cve_id,)
    return conn.execute(sql + " ORDER BY channel, rule", params).fetchall()


def _no_env(**overrides):
    """Empty environment: no channel active by accident from the real environment."""
    env = {}
    env.update(overrides)
    return env


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def test_overhyped_fires_and_quiet_does_not(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    _add_score(conn, QUIET, hype=4.0, reality=2.0, category="Quiet", tone=2.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL)

    assert summary["sent"] == 1
    assert len(session.calls) == 1
    assert OVERHYPED in session.calls[0]["json"]["text"]
    assert QUIET not in str(session.calls[0]["json"])
    assert [row["cve_id"] for row in _sent_rows(conn)] == [OVERHYPED]
    assert _sent_rows(conn)[0]["rule"] == "overhyped"


def test_humo_sleeper_and_earned_rules(conn, db_file):
    # Quiet in category but tone 8 with reality 4.5 -> media hype.
    _add_score(conn, HUMO, hype=6.0, reality=4.5, category="Quiet", tone=8.0)
    # Sleeper: high reality, low hype.
    _add_score(conn, SLEEPER, hype=4.0, reality=7.0, category="Sleeper", tone=2.0)
    _add_score(conn, EARNED, hype=7.0, reality=7.0, category="Earned the hype", tone=5.0)
    session = FakeSession()

    agent.run(db_path=db_file, session=session, env=_no_env(), slack_url=SLACK_URL)

    reglas = {(row["cve_id"], row["rule"]) for row in _sent_rows(conn)}
    assert reglas == {
        (HUMO, "humo"),
        (SLEEPER, "sleeper"),
        (EARNED, "earned_the_hype"),
    }
    assert len(session.calls) == 3


def test_no_scores_means_nothing_to_alert(conn, db_file):
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL)

    assert summary["alerts"] == 0
    assert session.calls == []
    assert _sent_rows(conn) == []


# --------------------------------------------------------------------------
# Dedupe
# --------------------------------------------------------------------------
def test_second_run_does_not_resend(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    first, second = FakeSession(), FakeSession()

    summary_first = agent.run(db_path=db_file, session=first, env=_no_env(),
                              slack_url=SLACK_URL)
    summary_second = agent.run(db_path=db_file, session=second, env=_no_env(),
                               slack_url=SLACK_URL)

    assert summary_first["sent"] == 1
    assert summary_second["sent"] == 0
    assert summary_second["skipped"] == 1
    assert second.calls == []
    assert len(_sent_rows(conn)) == 1


def test_unique_prevents_duplicate_alert(conn):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    alert = agent.evaluate(conn)[0]

    agent.mark_sent(conn, alert, "slack", "hash-1")
    agent.mark_sent(conn, alert, "slack", "hash-2")

    rows = _sent_rows(conn)
    assert len(rows) == 1
    assert rows[0]["payload_hash"] == "hash-1"


# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------
def test_dry_run_does_not_post_or_insert(conn, db_file, capsys):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL, dry_run=True)

    assert session.calls == []          # nothing goes out to the network
    assert _sent_rows(conn) == []       # nothing is written
    assert summary["pending"] == 2      # one per channel
    assert summary["sent"] == 0
    output = capsys.readouterr().out
    assert "[dry-run]" in output
    assert OVERHYPED in output

    # The dry-run does not burn the alert: the real run afterwards does send it.
    post = FakeSession()
    assert agent.run(db_path=db_file, session=post, env=_no_env(),
                     slack_url=SLACK_URL)["sent"] == 1


def test_slack_and_webhook_use_different_urls(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL)

    assert summary["sent"] == 2
    assert sorted(session.urls) == sorted([SLACK_URL, WEBHOOK_URL])

    slack_call = next(call for call in session.calls if call["url"] == SLACK_URL)
    webhook_call = next(call for call in session.calls if call["url"] == WEBHOOK_URL)

    # Slack: text + blocks. Webhook: flat JSON of the event.
    assert "blocks" in slack_call["json"]
    assert webhook_call["json"]["event"] == "vulnradar.alert"
    assert webhook_call["json"]["cve_id"] == OVERHYPED
    assert webhook_call["json"]["rule"] == "overhyped"
    assert webhook_call["json"]["url"].endswith(OVERHYPED)

    canales = {(row["cve_id"], row["channel"]) for row in _sent_rows(conn)}
    assert canales == {(OVERHYPED, "slack"), (OVERHYPED, "webhook")}

    # Client signature: own User-Agent and a 15s timeout on every POST.
    for call in session.calls:
        assert call["headers"]["User-Agent"] == agent.USER_AGENT
        assert call["timeout"] == agent.TIMEOUT_SECONDS


def test_channel_without_url_is_skipped(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url="")

    assert summary["channels"] == ["slack"]
    assert session.urls == [SLACK_URL]
    assert [row["channel"] for row in _sent_rows(conn)] == ["slack"]


def test_env_defines_channel_urls(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    agent.run(
        db_path=db_file, session=session,
        env={agent.SLACK_ENV: SLACK_URL, agent.WEBHOOK_ENV: WEBHOOK_URL},
    )

    assert sorted(session.urls) == sorted([SLACK_URL, WEBHOOK_URL])


def test_skip_slack_leaves_only_the_webhook(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL,
                        skip_slack=True)

    assert summary["channels"] == ["webhook"]
    assert session.urls == [WEBHOOK_URL]


# --------------------------------------------------------------------------
# POST failures
# --------------------------------------------------------------------------
def test_post_500_does_not_mark_and_retry_does_send(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    down, sano = FakeSession(status_code=500), FakeSession(status_code=200)

    summary_caido = agent.run(db_path=db_file, session=down, env=_no_env(),
                              slack_url=SLACK_URL)

    assert summary_caido["failed"] == 1
    assert summary_caido["sent"] == 0
    assert len(down.calls) == 1
    assert _sent_rows(conn) == []  # no row: the alert stays pending

    summary_retry = agent.run(db_path=db_file, session=sano, env=_no_env(),
                              slack_url=SLACK_URL)

    assert summary_retry["sent"] == 1
    assert len(sano.calls) == 1
    assert len(_sent_rows(conn)) == 1


def test_network_exception_does_not_mark_alert(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)

    class BoomSession:
        def __init__(self):
            self.calls = 0

        def post(self, *args, **kwargs):
            self.calls += 1
            raise TimeoutError("timeout simulado")

    session = BoomSession()
    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL)

    assert session.calls == 1
    assert summary["failed"] == 1
    assert _sent_rows(conn) == []


# --------------------------------------------------------------------------
# Schema / init
# --------------------------------------------------------------------------
def test_init_db_creates_alerts_sent(tmp_path):
    path = init_db(tmp_path / "nueva.db")

    conn = get_db(path)
    try:
        from core.db import has_table, table_columns, table_indexes

        tabla = has_table(conn, "alerts_sent")
        columnas = table_columns(conn, "alerts_sent")
        indices = table_indexes(conn, "alerts_sent")
    finally:
        conn.close()

    assert tabla is True
    assert columnas == {"id", "cve_id", "channel", "rule", "payload_hash", "sent_at"}
    assert indices  # the UNIQUE(cve_id, channel, rule) creates its automatic index

    # Idempotent: initializing again breaks nothing.
    init_db(path)


def test_alerts_sent_requires_existing_cve(conn):
    """Active FK: an alert is not recorded for a CVE that is not in the database."""
    with pytest.raises(Exception) as excinfo:
        conn.execute(
            "INSERT INTO alerts_sent (cve_id, channel, rule) VALUES (?, ?, ?)",
            ("CVE-2026-9999", "slack", "overhyped"),
        )

    assert "FOREIGN KEY" in str(excinfo.value).upper()
