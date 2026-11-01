"""The SOC panel is not public: HMAC cookie and environment credentials."""
from __future__ import annotations

import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

import pytest

from core.db import init_db
from dashboard import auth
from dashboard.server import DashboardHandler


def test_without_password_nobody_gets_in(monkeypatch):
    monkeypatch.setenv("SOC_PASSWORD", "")
    monkeypatch.delenv("SOC_USER", raising=False)
    assert auth.configured() is False
    assert auth.check("soc", "soc") is False
    assert auth.authorized(f"{auth.COOKIE}=anything") is False
    assert auth.token() is None


def test_correct_password_issues_valid_cookie(monkeypatch):
    monkeypatch.setenv("SOC_USER", "op")
    monkeypatch.setenv("SOC_PASSWORD", "secret")
    assert auth.check("op", "secret") is True
    assert auth.check("op", "nope") is False
    assert auth.check("otro", "secret") is False
    header = f"{auth.COOKIE}={auth.token()}"
    assert auth.authorized(header) is True
    assert auth.authorized(f"{auth.COOKIE}=deadbeef") is False


def test_overview_does_not_link_soc():
    from dashboard.markup import overview_html

    html = overview_html(
        logo_html="", scatter_div="", timeline_div="", table_rows="",
        total=0, page=0, page_size=6, severity="All severities",
        category="All categories", since="2026-01-01", until="2026-12-31",
    )
    assert "/soc" not in html
    assert "/agentes" not in html
    assert "SOC MONITORING" not in html


def test_login_html_is_not_the_panel():
    from dashboard.markup import login_html

    html = login_html()
    assert "REAL-TIME AGENTS" not in html
    assert "Live processing feed" not in html
    assert "name=\"password\"" in html


@pytest.fixture
def soc_http(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_USER", "op")
    monkeypatch.setenv("SOC_PASSWORD", "secret")
    db_path = tmp_path / "humo.db"
    init_db(db_path)
    monkeypatch.setattr("core.db.DB_PATH", db_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


def _http(httpd: ThreadingHTTPServer, method: str, path: str, *, body: str | None = None, headers: dict | None = None):
    conn = HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=8)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        res = conn.getresponse()
        data = res.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in res.getheaders()}
        return res.status, data, hdrs
    finally:
        conn.close()


def test_soc_without_cookie_shows_login(soc_http):
    status, body, _ = _http(soc_http, "GET", "/soc")
    assert status == 200
    assert "Sign in" in body
    assert "REAL-TIME AGENTS" not in body
    assert "Live processing feed" not in body


def test_agents_without_cookie_shows_login(soc_http):
    status, body, _ = _http(soc_http, "GET", "/agentes")
    assert status == 200
    assert "Sign in" in body
    assert "REAL-TIME AGENTS" not in body


def test_public_page_does_not_expose_soc(soc_http):
    status, body, _ = _http(soc_http, "GET", "/")
    assert status == 200
    assert 'href="/soc"' not in body
    assert "SOC MONITORING" not in body


def test_wrong_login_stays_on_form(soc_http):
    status, body, hdrs = _http(
        soc_http, "POST", "/soc",
        body=urlencode({"user": "op", "password": "nope"}),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200
    assert "Invalid username or password" in body
    assert "set-cookie" not in hdrs
    assert "REAL-TIME AGENTS" not in body


def test_correct_login_opens_panel_and_logout_closes(soc_http):
    status, _, hdrs = _http(
        soc_http, "POST", "/soc",
        body=urlencode({"user": "op", "password": "secret"}),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 303
    cookie = hdrs.get("set-cookie", "")
    assert auth.COOKIE in cookie
    status, body, _ = _http(soc_http, "GET", "/soc", headers={"Cookie": cookie.split(";", 1)[0]})
    assert status == 200
    assert "SOC MONITORING" in body
    assert "REAL-TIME AGENTS" in body
    assert "Sync Agent" in body
    status, _, hdrs = _http(soc_http, "GET", "/soc/logout")
    assert status == 303
    cleared = hdrs.get("set-cookie", "")
    assert "Max-Age=0" in cleared
    status, body, _ = _http(soc_http, "GET", "/soc")
    assert "Sign in" in body
    assert "REAL-TIME AGENTS" not in body
