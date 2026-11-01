"""SOC panel access: it is not public. HMAC cookie with SOC_PASSWORD."""
from __future__ import annotations

import hmac
import os
from hashlib import sha256

COOKIE = "hm_soc"


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
    return hmac.new(password.encode("utf-8"), user.encode("utf-8"), sha256).hexdigest()


def cookie_header() -> str:
    value = token() or "invalid"
    return f"{COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400"


def clear_cookie_header() -> str:
    return f"{COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"


def authorized(cookie_header: str | None) -> bool:
    expected = token()
    if not expected:
        return False
    got = _cookie_value(cookie_header or "", COOKIE)
    if not got:
        return False
    return hmac.compare_digest(got, expected)


def _cookie_value(header: str, name: str) -> str:
    for part in header.split(";"):
        piece = part.strip()
        if piece.startswith(name + "="):
            return piece[len(name) + 1 :]
    return ""
