"""Opaque session tokens (docs/SECURITY.md §2).

The token is 32 random bytes (256 bits) URL-safe encoded; only its SHA-256
hex digest is stored in ``sessions.session_id_hash``. The raw token exists
only inside the HttpOnly cookie and is never returned in JSON.
"""

from __future__ import annotations

import hashlib
import secrets
from http.cookies import SimpleCookie

SESSION_COOKIE_NAME = "warden_session"
TOKEN_BYTES = 32


def generate_session_token() -> str:
    """Generate a new opaque session token (URL-safe, 43 chars)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    """SHA-256 hex digest of the raw token (what the database stores)."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def make_session_cookie(token: str, *, secure: bool, max_age_seconds: int | None = None) -> str:
    """Build the ``Set-Cookie`` value for the session cookie.

    Always HttpOnly + SameSite=Strict + Path=/; ``Secure`` only when the
    deployment is not a localhost dev environment.
    """
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = token
    cookie[SESSION_COOKIE_NAME]["path"] = "/"
    cookie[SESSION_COOKIE_NAME]["httponly"] = True
    cookie[SESSION_COOKIE_NAME]["samesite"] = "strict"
    if secure:
        cookie[SESSION_COOKIE_NAME]["secure"] = True
    if max_age_seconds is not None:
        cookie[SESSION_COOKIE_NAME]["max-age"] = str(max_age_seconds)
    return cookie[SESSION_COOKIE_NAME].OutputString()


def expire_session_cookie(*, secure: bool) -> str:
    """Build a ``Set-Cookie`` value that immediately expires the cookie."""
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = ""
    cookie[SESSION_COOKIE_NAME]["path"] = "/"
    cookie[SESSION_COOKIE_NAME]["httponly"] = True
    cookie[SESSION_COOKIE_NAME]["samesite"] = "strict"
    cookie[SESSION_COOKIE_NAME]["max-age"] = "0"
    if secure:
        cookie[SESSION_COOKIE_NAME]["secure"] = True
    return cookie[SESSION_COOKIE_NAME].OutputString()
