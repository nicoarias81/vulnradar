"""SOC access with expiring, revocable sessions shared by dashboard instances."""
from __future__ import annotations

import hmac
import os
import secrets
from hashlib import sha256

from core.db import get_db

COOKIE = "hm_soc"
SESSION_SECONDS = 86400


def credentials() -> tuple[str, str]:
    user = (os.getenv("SOC_USER") or "soc").strip() or "soc"
    password = (os.getenv("SOC_PASSWORD") or "").strip()
    return user, password


def configured() -> bool:
    return bool(credentials()[1])


def check(user: str, password: str) -> bool:
    expected_user, expected_password = credentials()
    if not expected_password:
        return False
    user_ok = hmac.compare_digest(user.encode("utf-8"), expected_user.encode("utf-8"))
    pass_ok = hmac.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    return user_ok and pass_ok


def token() -> str | None:
    user, password = credentials()
    if not password:
        return None
    value = secrets.token_urlsafe(32)
    conn = get_db()
    try:
        conn.execute("DELETE FROM soc_sessions WHERE expires_at <= CURRENT_TIMESTAMP")
        conn.execute("""
            INSERT INTO soc_sessions (token_hash, credential_key, expires_at)
            VALUES (?, ?, CURRENT_TIMESTAMP + (? * INTERVAL '1 second'))
        """, (_digest(value), _credential_key(user, password), SESSION_SECONDS))
        conn.commit()
    finally:
        conn.close()
    return value


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _credential_key(user: str, password: str) -> str:
    return hmac.new(password.encode("utf-8"), user.encode("utf-8"), sha256).hexdigest()


def _secure_attribute() -> str:
    return "; Secure" if os.getenv("SOC_COOKIE_SECURE", "0") == "1" else ""


def cookie_header() -> str:
    value = token() or "invalid"
    return f"{COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}" + _secure_attribute()


def clear_cookie_header() -> str:
    return f"{COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" + _secure_attribute()


def authorized(cookie_header: str | None) -> bool:
    user, password = credentials()
    if not password:
        return False
    got = _cookie_value(cookie_header or "", COOKIE)
    if not got or len(got) > 128:
        return False
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT credential_key FROM soc_sessions
            WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP
        """, (_digest(got),)).fetchone()
        return bool(row and hmac.compare_digest(row[0], _credential_key(user, password)))
    finally:
        conn.close()


def revoke(cookie_header: str | None) -> None:
    value = _cookie_value(cookie_header or "", COOKIE)
    if not value or len(value) > 128:
        return
    conn = get_db()
    try:
        conn.execute("DELETE FROM soc_sessions WHERE token_hash = ?", (_digest(value),))
        conn.commit()
    finally:
        conn.close()


def _cookie_value(header: str, name: str) -> str:
    for part in header.split(";"):
        piece = part.strip()
        if piece.startswith(name + "="):
            return piece[len(name) + 1 :]
    return ""
