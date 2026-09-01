"""Per-session CSRF tokens and Origin validation (docs/SECURITY.md §2/§10).

One 32-byte CSRF secret is generated per session at login; the database stores
its SHA-256 digest in ``sessions.csrf_secret_hash`` and the raw value is
returned to the browser once in the login response. Every state-changing
request must echo it in the ``X-CSRF-Token`` header, which is compared with a
constant-time digest against the stored hash. Login and terminal handshakes
additionally validate Origin/Referer (API_CONTRACT §3/§11).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

CSRF_SECRET_BYTES = 32
CSRF_HEADER_NAME = "x-csrf-token"


def issue_csrf_secret() -> bytes:
    """Generate a fresh per-session CSRF secret (32 random bytes)."""
    return secrets.token_bytes(CSRF_SECRET_BYTES)


def hash_csrf_secret(secret: bytes) -> str:
    """SHA-256 hex digest of the raw CSRF secret (what the database stores)."""
    return hashlib.sha256(secret).hexdigest()


def encode_csrf_token(secret: bytes) -> str:
    """URL-safe base64 encoding of the raw secret (sent to the browser once)."""
    return base64.urlsafe_b64encode(secret).decode("ascii")


def decode_csrf_token(raw: str) -> bytes:
    """Decode the header value back to bytes; raises ValueError on garbage."""
    return base64.urlsafe_b64decode(raw.encode("ascii") + b"=" * (-len(raw.encode("ascii")) % 4))


def verify_csrf_token(raw_token: str, stored_hash: str) -> bool:
    """Constant-time check that ``raw_token`` digests to ``stored_hash``."""
    try:
        secret = decode_csrf_token(raw_token)
    except ValueError:
        return False
    digest = hash_csrf_secret(secret)
    return hmac.compare_digest(digest, stored_hash)


def normalize_origin(value: str) -> str | None:
    """Normalize ``scheme://host[:port]`` for exact comparison.

    Strips the path, lowercases scheme/host and drops default ports.
    Returns None for values that cannot be an origin (e.g. ``null``).
    """
    value = value.strip()
    if not value or value.lower() == "null":
        return None
    parts = urlsplit(value if "://" in value else f"https://{value}")
    if not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = parts.port
    if port is not None and port in (80, 443):
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return f"{parts.scheme.lower()}://{netloc}"


def is_origin_allowed(
    *,
    origin: str | None,
    referer: str | None,
    allowed_origins: set[str],
) -> bool:
    """Validate Origin (falling back to Referer) against allowed origins.

    Browsers always send Origin on cross-site requests and Referer on
    navigations; absence of both means a non-browser client, which cannot be
    CSRFed by another origin — such requests pass (SameSite=Strict on the
    cookie plus the per-session token still protect the session).
    """
    candidate = origin or referer
    if candidate is None:
        return True
    normalized = normalize_origin(candidate)
    return normalized is not None and normalized in allowed_origins
