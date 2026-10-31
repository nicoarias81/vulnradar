"""Tests del alert agent: reglas, dedupe por alerts_sent, dry-run y canales.
Sin red: la session HTTP es un fake inyectado."""
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
    """Registra los POST y devuelve el status configurado. Nunca sale a la red."""

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
               description="Descripción de prueba"):
    """CVE + enrichment + score vigente en una sola fila lógica."""
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
    """Entorno vacío: ningún canal activo por accidente del entorno real."""
    env = {}
    env.update(overrides)
    return env


# --------------------------------------------------------------------------
# Reglas
# --------------------------------------------------------------------------
def test_overhyped_dispara_y_quiet_no(conn, db_file):
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


def test_reglas_humo_sleeper_y_earned(conn, db_file):
    # Quiet en categoría pero tone 8 con reality 4.5 -> humo mediático.
    _add_score(conn, HUMO, hype=6.0, reality=4.5, category="Quiet", tone=8.0)
    # Sleeper: reality alta, hype bajo.
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


def test_sin_scores_no_hay_nada_para_alertar(conn, db_file):
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL)

    assert summary["alerts"] == 0
    assert session.calls == []
    assert _sent_rows(conn) == []


# --------------------------------------------------------------------------
# Dedupe
# --------------------------------------------------------------------------
def test_segunda_corrida_no_reenvia(conn, db_file):
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


def test_unique_impide_duplicar_la_misma_alerta(conn):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    alert = agent.evaluate(conn)[0]

    agent.mark_sent(conn, alert, "slack", "hash-1")
    agent.mark_sent(conn, alert, "slack", "hash-2")

    rows = _sent_rows(conn)
    assert len(rows) == 1
    assert rows[0]["payload_hash"] == "hash-1"


# --------------------------------------------------------------------------
# Canales
# --------------------------------------------------------------------------
def test_dry_run_no_postea_ni_inserta(conn, db_file, capsys):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL, dry_run=True)

    assert session.calls == []          # nada sale a la red
    assert _sent_rows(conn) == []       # nada se escribe
    assert summary["pending"] == 2      # una por canal
    assert summary["sent"] == 0
    salida = capsys.readouterr().out
    assert "[dry-run]" in salida
    assert OVERHYPED in salida

    # El dry-run no quema la alerta: la corrida real después sí envía.
    post = FakeSession()
    assert agent.run(db_path=db_file, session=post, env=_no_env(),
                     slack_url=SLACK_URL)["sent"] == 1


def test_slack_y_webhook_usan_urls_distintas(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL)

    assert summary["sent"] == 2
    assert sorted(session.urls) == sorted([SLACK_URL, WEBHOOK_URL])

    slack_call = next(call for call in session.calls if call["url"] == SLACK_URL)
    webhook_call = next(call for call in session.calls if call["url"] == WEBHOOK_URL)

    # Slack: text + blocks. Webhook: JSON plano del evento.
    assert "blocks" in slack_call["json"]
    assert webhook_call["json"]["event"] == "humo-vs-miedo.alert"
    assert webhook_call["json"]["cve_id"] == OVERHYPED
    assert webhook_call["json"]["rule"] == "overhyped"
    assert webhook_call["json"]["url"].endswith(OVERHYPED)

    canales = {(row["cve_id"], row["channel"]) for row in _sent_rows(conn)}
    assert canales == {(OVERHYPED, "slack"), (OVERHYPED, "webhook")}

    # Firma de cliente: User-Agent propio y timeout de 15s en cada POST.
    for call in session.calls:
        assert call["headers"]["User-Agent"] == agent.USER_AGENT
        assert call["timeout"] == agent.TIMEOUT_SECONDS


def test_canal_sin_url_se_omite(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url="")

    assert summary["channels"] == ["slack"]
    assert session.urls == [SLACK_URL]
    assert [row["channel"] for row in _sent_rows(conn)] == ["slack"]


def test_env_define_las_urls_de_los_canales(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    agent.run(
        db_path=db_file, session=session,
        env={agent.SLACK_ENV: SLACK_URL, agent.WEBHOOK_ENV: WEBHOOK_URL},
    )

    assert sorted(session.urls) == sorted([SLACK_URL, WEBHOOK_URL])


def test_skip_slack_deja_solo_el_webhook(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    session = FakeSession()

    summary = agent.run(db_path=db_file, session=session, env=_no_env(),
                        slack_url=SLACK_URL, webhook_url=WEBHOOK_URL,
                        skip_slack=True)

    assert summary["channels"] == ["webhook"]
    assert session.urls == [WEBHOOK_URL]


# --------------------------------------------------------------------------
# Fallos de POST
# --------------------------------------------------------------------------
def test_post_500_no_marca_y_el_retry_si_envia(conn, db_file):
    _add_score(conn, OVERHYPED, hype=8.0, reality=3.0, category="Overhyped", tone=3.0)
    caido, sano = FakeSession(status_code=500), FakeSession(status_code=200)

    summary_caido = agent.run(db_path=db_file, session=caido, env=_no_env(),
                              slack_url=SLACK_URL)

    assert summary_caido["failed"] == 1
    assert summary_caido["sent"] == 0
    assert len(caido.calls) == 1
    assert _sent_rows(conn) == []  # sin fila: la alerta sigue pendiente

    summary_retry = agent.run(db_path=db_file, session=sano, env=_no_env(),
                              slack_url=SLACK_URL)

    assert summary_retry["sent"] == 1
    assert len(sano.calls) == 1
    assert len(_sent_rows(conn)) == 1


def test_excepcion_de_red_no_marca_la_alerta(conn, db_file):
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
def test_init_db_crea_alerts_sent(tmp_path):
    path = init_db(tmp_path / "nueva.db")

    conn = get_db(path)
    try:
        tabla = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts_sent'"
        ).fetchone()
        columnas = {row["name"] for row in conn.execute("PRAGMA table_info(alerts_sent)")}
        indices = {row["name"] for row in conn.execute("PRAGMA index_list(alerts_sent)")}
    finally:
        conn.close()

    assert tabla is not None
    assert columnas == {"id", "cve_id", "channel", "rule", "payload_hash", "sent_at"}
    assert indices  # el UNIQUE(cve_id, channel, rule) crea su índice automático

    # Idempotente: inicializar de nuevo no rompe nada.
    init_db(path)


def test_alerts_sent_exige_cve_existente(conn):
    """FK activo: no se registra una alerta de un CVE que no está en la base."""
    with pytest.raises(Exception) as excinfo:
        conn.execute(
            "INSERT INTO alerts_sent (cve_id, channel, rule) VALUES (?, ?, ?)",
            ("CVE-2026-9999", "slack", "overhyped"),
        )

    assert "FOREIGN KEY" in str(excinfo.value).upper()
