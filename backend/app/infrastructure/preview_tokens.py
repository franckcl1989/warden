"""Signed short-lived operation preview tokens (docs/API_CONTRACT.md §6.1).

A preview token is HMAC-SHA256 keyed by the session secret with the distinct
context string ``warden-preview-token-v1`` (it can never collide with the
probe-token context). The payload binds the FULL normalized parameter set plus
user, device, device version, requirement/capability and risk:

- ``user_id`` / ``device_id``: who the preview belongs to;
- ``device_version``: devices.version at preview time — any device change
  between preview and confirm makes the token stale (409 preview_stale);
- ``requirement_id`` / ``capability_key`` / ``risk_level``: the profile;
- ``parameters`` + ``parameter_hash``: the normalized parameters (carried
  inside the signed body because the confirm request body only contains
  ``preview_token`` + ``confirmation_text`` per API_CONTRACT.md §6.1);
- ``expires_at``: 60 seconds after issuance (SECURITY.md §4: 一次性、60 秒
  有效).

Verification raises ``PreviewTokenInvalid`` for signature/format problems
(boundary maps to 422 validation_failed field=preview_token) and
``PreviewTokenExpired`` once the validity window passed (boundary maps to
409 preview_stale reason=expired, M2T4 controller decision). Binding drift is
NOT decided here: the application layer compares claims to the current
device/user state and maps drift to 409 preview_stale.
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

TOKEN_CONTEXT = b"warden-preview-token-v1"
TOKEN_TTL_SECONDS = 60
IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._-]+$"
IDEMPOTENCY_KEY_MIN_LENGTH = 8
IDEMPOTENCY_KEY_MAX_LENGTH = 128


class PreviewTokenError(ValueError):
    """Base class: invalid/expired preview token."""


class PreviewTokenInvalid(PreviewTokenError):
    """Malformed body or bad signature (client cannot fix by re-previewing)."""


class PreviewTokenExpired(PreviewTokenError):
    """Signature valid but the 60-second window closed."""


@dataclass(frozen=True)
class PreviewTokenClaims:
    user_id: uuid.UUID
    device_id: uuid.UUID
    device_version: int
    requirement_id: str
    capability_key: str
    risk_level: str
    parameter_hash: str
    parameters: dict[str, object]
    expires_at: datetime


def _encode_body(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_body(body: str) -> dict[str, object]:
    padding = "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body + padding)
    except ValueError as exc:
        raise PreviewTokenInvalid("预览令牌格式无效") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PreviewTokenInvalid("预览令牌格式无效") from exc
    if not isinstance(payload, dict):
        raise PreviewTokenInvalid("预览令牌格式无效")
    return payload


def _parse_uuid(payload: dict[str, object], key: str) -> uuid.UUID:
    raw = payload.get(key)
    if not isinstance(raw, str):
        raise PreviewTokenInvalid("预览令牌内容无效")
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise PreviewTokenInvalid("预览令牌内容无效") from exc


def _parse_int(payload: dict[str, object], key: str) -> int:
    raw = payload.get(key)
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise PreviewTokenInvalid("预览令牌内容无效")
    return raw


class PreviewTokenSigner:
    """Signs and verifies operation preview tokens (HMAC-SHA256, scoped)."""

    def __init__(self, secret: SecretStr | str) -> None:
        self._key = (
            secret.get_secret_value().encode("utf-8")
            if isinstance(secret, SecretStr)
            else secret.encode("utf-8")
        )
        if not self._key:
            msg = "preview token signing secret must not be empty"
            raise ValueError(msg)

    def create(
        self,
        *,
        user_id: uuid.UUID,
        device_id: uuid.UUID,
        device_version: int,
        requirement_id: str,
        capability_key: str,
        risk_level: str,
        parameters: dict[str, object],
        parameter_hash: str,
        expires_at: datetime,
    ) -> str:
        payload: dict[str, object] = {
            "user_id": str(user_id),
            "device_id": str(device_id),
            "device_version": device_version,
            "requirement_id": requirement_id,
            "capability_key": capability_key,
            "risk_level": risk_level,
            "parameters": parameters,
            "parameter_hash": parameter_hash,
            "expires_at": expires_at.isoformat(),
        }
        body = _encode_body(payload)
        digest = hmac.new(
            self._key, TOKEN_CONTEXT + b"." + body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        return f"{body}.{digest}"

    def verify(self, token: str, *, now: datetime) -> PreviewTokenClaims:
        """Verify signature/format/expiry and return the bound claims."""
        try:
            body, digest = token.rsplit(".", 1)
        except ValueError as exc:
            raise PreviewTokenInvalid("预览令牌格式无效") from exc
        expected = hmac.new(
            self._key, TOKEN_CONTEXT + b"." + body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(digest, expected):
            raise PreviewTokenInvalid("预览令牌签名无效")
        payload = _decode_body(body)
        user_id = _parse_uuid(payload, "user_id")
        device_id = _parse_uuid(payload, "device_id")
        device_version = _parse_int(payload, "device_version")
        requirement_id = payload.get("requirement_id")
        capability_key = payload.get("capability_key")
        risk_level = payload.get("risk_level")
        raw_parameters = payload.get("parameters")
        parameter_hash = payload.get("parameter_hash")
        raw_expires_at = payload.get("expires_at")
        if (
            not isinstance(requirement_id, str)
            or not isinstance(capability_key, str)
            or not isinstance(risk_level, str)
            or not isinstance(raw_parameters, dict)
            or not isinstance(parameter_hash, str)
            or not isinstance(raw_expires_at, str)
        ):
            raise PreviewTokenInvalid("预览令牌内容无效")
        try:
            expires_at = datetime.fromisoformat(raw_expires_at)
        except ValueError as exc:
            raise PreviewTokenInvalid("预览令牌内容无效") from exc
        if now >= expires_at:
            raise PreviewTokenExpired("预览令牌已过期")
        return PreviewTokenClaims(
            user_id=user_id,
            device_id=device_id,
            device_version=device_version,
            requirement_id=requirement_id,
            capability_key=capability_key,
            risk_level=risk_level,
            parameter_hash=parameter_hash,
            parameters=dict(raw_parameters),
            expires_at=expires_at,
        )
