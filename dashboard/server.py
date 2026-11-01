"""VulnRadar dashboard HTTP server (generated static HTML, port 8501)."""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard import auth
from dashboard.data import find_cve_id, search_products
from dashboard.markup import login_html
from dashboard.screens import agents, detail, overview
from core.db import get_db

SOC_PATHS = {"/soc", "/agentes", "/agents"}


def _search_target(query: str):
    """Exact CVE for the search box (id or nickname): redirects to the card.

    It only covers exact matches; everything else resolves as a filter on the home page.
    """
    text = (query or "").strip()
    if not text:
        return None
    try:
        conn = get_db()
    except Exception:
        return None
    try:
        return find_cve_id(conn, text)
    except Exception:
        return None
    finally:
        conn.close()

# Cache of already rendered HTML: the first request per URL pays the SQL, the
# following ones come from memory while the TTL lasts (the worker rewrites every 15
# min). Pages that depend on the cookie (/soc) are never cached.
_HTML_CACHE: dict[str, tuple[float, str]] = {}
_HTML_TTL = 60.0
_HTML_MAX_ENTRIES = 32
_HTML_MAX_BYTES = 2 * 1024 * 1024
_HTML_LOCK = threading.Lock()


def cached_html(key: str, producer) -> str:
    now = time.monotonic()
    with _HTML_LOCK:
        hit = _HTML_CACHE.get(key)
    if hit and now - hit[0] < _HTML_TTL:
        return hit[1]
    html = producer()
    if len(html) <= _HTML_MAX_BYTES:  # `?all=1` can generate MBs: it is not cached
        with _HTML_LOCK:
            if len(_HTML_CACHE) >= _HTML_MAX_ENTRIES:
                _HTML_CACHE.clear()
            _HTML_CACHE[key] = (now, html)
    return html


class DashboardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qp = {k: (v[-1] if v else "") for k, v in parse_qs(parsed.query).items()}

        if path in ("/health", "/_stcore/health"):
            self._send(200, b"ok", "text/plain; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if path == "/api/products":
            self._products(qp)
            return
        if path == "/soc/logout":
            self._redirect("/soc", extra_headers=[("Set-Cookie", auth.clear_cookie_header())])
            return

        try:
            if path in ("/", "/dashboard"):
                target = _search_target(qp.get("q"))
                if target:
                    self._redirect(f"/cve?cve={target}")
                    return
                html = cached_html(self.path, lambda: overview(qp))
            elif path == "/cve":
                html = cached_html(self.path, lambda: detail(qp))
            elif path in SOC_PATHS:
                html = self._soc(qp)
            else:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
        except Exception as exc:
            sys.stderr.write(f"dashboard error: {exc}\n")
            self._send(500, f"<pre>{exc}</pre>".encode(), "text/html; charset=utf-8")
            return

        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path not in SOC_PATHS:
            self._send(405, b"Method not allowed", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        fields = parse_qs(raw.decode("utf-8", "replace"))
        user = (fields.get("user") or [""])[-1]
        password = (fields.get("password") or [""])[-1]
        if auth.check(user, password):
            self._redirect("/soc", extra_headers=[("Set-Cookie", auth.cookie_header())])
            return
        if not auth.configured():
            error = "SOC panel not configured: set SOC_PASSWORD."
        else:
            error = "Invalid username or password."
        html = login_html(error=error)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _products(self, qp: dict) -> None:
        """Product filter autocomplete.

        There are 60k distinct products: only what matches the typed text is sent.
        """
        text = (qp.get("q") or "").strip()
        if len(text) < 2:
            self._send(200, b"[]", "application/json")
            return
        conn = get_db()
        try:
            rows = search_products(conn, text, limit=20)
        finally:
            conn.close()
        payload = json.dumps(
            [{"p": row["product"], "n": row["n"]} for row in rows]
        ).encode("utf-8")
        self._send(200, payload, "application/json")

    def _soc(self, qp: dict) -> str:
        if auth.authorized(self.headers.get("Cookie")):
            return agents(qp)
        if not auth.configured():
            return login_html(error="SOC panel not configured: set SOC_PASSWORD.")
        return login_html()

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str, extra_headers: list | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()


def serve(host: str = "0.0.0.0", port: int = 8501) -> None:
    httpd = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"VulnRadar en http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
