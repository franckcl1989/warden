"""Signed short-lived probe tokens (docs/API_CONTRACT.md §4).

A probe token is HMAC-SHA256 (keyed by the session secret with a distinct
context string, so it can never collide with any other signed value) over a
JSON payload:

- ``device_id``: null for pre-save probes, the device id for re-probes;
- ``fingerprint``: SHA-256 of the normalized probe profile (credentials
  digest + endpoint + adapter key) — the token is single-purpose and cannot
  save a different device/profile (API_CONTRACT.md §4, M1T3 brief §4);
- ``expires_at``: 10 minutes after issuance.

Verification enforces signature, fingerprint equality and expiry; anything
else raises ``ProbeTokenError`` which the boundary maps to
``validation_failed`` field=probe_token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime

from pydantic import SecretStr

TOKEN_CONTEXT = b"warden-probe-token-v1"
TOKEN_TTL_SECONDS = 600


class ProbeTokenError(ValueError):
    """Invalid, tampered, expired or profile-mismatched probe token."""


@dataclass(frozen=True)
class ProbeTokenClaims:
    device_id: uuid.UUID | None
    fingerprint: str
    expires_at: datetime


def _encode_body(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_body(body: str) -> dict[str, object]:
    padding = "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body + padding)
    except ValueError as exc:
        raise ProbeTokenError("探测令牌格式无效") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProbeTokenError("探测令牌格式无效") from exc
    if not isinstance(payload, dict):
        raise ProbeTokenError("探测令牌格式无效")
    return payload


class ProbeTokenSigner:
    """Signs and verifies probe tokens (HMAC-SHA256, context-scoped)."""

    def __init__(self, secret: SecretStr | str) -> None:
        self._key = (
            secret.get_secret_value().encode("utf-8")
            if isinstance(secret, SecretStr)
            else secret.encode("utf-8")
        )
        if not self._key:
            msg = "probe token signing secret must not be empty"
            raise ValueError(msg)

    def create(
        self,
        *,
        fingerprint: str,
        device_id: uuid.UUID | None,
        expires_at: datetime,
    ) -> str:
        payload: dict[str, object] = {
            "device_id": str(device_id) if device_id is not None else None,
            "fingerprint": fingerprint,
            "expires_at": expires_at.isoformat(),
        }
        body = _encode_body(payload)
        digest = hmac.new(
            self._key, TOKEN_CONTEXT + b"." + body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        return f"{body}.{digest}"

    def verify(self, token: str, *, fingerprint: str, now: datetime) -> ProbeTokenClaims:
        try:
            body, digest = token.rsplit(".", 1)
        except ValueError as exc:
            raise ProbeTokenError("探测令牌格式无效") from exc
        expected = hmac.new(
            self._key, TOKEN_CONTEXT + b"." + body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(digest, expected):
            raise ProbeTokenError("探测令牌签名无效")
        payload = _decode_body(body)
        raw_device_id = payload.get("device_id")
        raw_fingerprint = payload.get("fingerprint")
        raw_expires_at = payload.get("expires_at")
        if not isinstance(raw_fingerprint, str) or not isinstance(raw_expires_at, str):
            raise ProbeTokenError("探测令牌内容无效")
        if raw_device_id is not None and not isinstance(raw_device_id, str):
            raise ProbeTokenError("探测令牌内容无效")
        device_id = None
        if raw_device_id is not None:
            try:
                device_id = uuid.UUID(raw_device_id)
            except ValueError as exc:
                raise ProbeTokenError("探测令牌内容无效") from exc
        try:
            expires_at = datetime.fromisoformat(raw_expires_at)
        except ValueError as exc:
            raise ProbeTokenError("探测令牌内容无效") from exc
        claims = ProbeTokenClaims(device_id=device_id, fingerprint=raw_fingerprint, expires_at=expires_at)
        if claims.fingerprint != fingerprint:
            raise ProbeTokenError("探测令牌绑定的探测指纹与本次配置不匹配")
        if now >= claims.expires_at:
            raise ProbeTokenError("探测令牌已过期")
        return claims
