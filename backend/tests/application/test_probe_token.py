"""Probe token tests (M1T3 brief §4, docs/API_CONTRACT.md §4).

Round-trip, expiry, fingerprint binding, tamper rejection and device binding
of the HMAC-signed short-lived probe token.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.infrastructure.probe_tokens import (
    TOKEN_TTL_SECONDS,
    ProbeTokenClaims,
    ProbeTokenError,
    ProbeTokenSigner,
)

SECRET = "s" * 64
NOW = datetime(2026, 9, 1, 8, 0, 0, tzinfo=UTC)
FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64


def make_signer() -> ProbeTokenSigner:
    return ProbeTokenSigner(SECRET)


def make_token(
    signer: ProbeTokenSigner,
    *,
    fingerprint: str = FINGERPRINT,
    device_id: uuid.UUID | None = None,
    expires_at: datetime = NOW + timedelta(seconds=TOKEN_TTL_SECONDS),
) -> str:
    return signer.create(fingerprint=fingerprint, device_id=device_id, expires_at=expires_at)


@pytest.mark.unit
def test_round_trip_returns_claims() -> None:
    signer = make_signer()
    device_id = uuid.uuid4()
    token = make_token(signer, device_id=device_id)
    claims = signer.verify(token, fingerprint=FINGERPRINT, now=NOW)
    expected_expiry = NOW + timedelta(seconds=TOKEN_TTL_SECONDS)
    assert claims == ProbeTokenClaims(
        device_id=device_id, fingerprint=FINGERPRINT, expires_at=expected_expiry
    )
    anonymous = make_token(signer)
    assert signer.verify(anonymous, fingerprint=FINGERPRINT, now=NOW).device_id is None


@pytest.mark.unit
def test_expired_token_rejected() -> None:
    signer = make_signer()
    token = make_token(signer, expires_at=NOW + timedelta(seconds=1))
    with pytest.raises(ProbeTokenError, match="过期"):
        signer.verify(token, fingerprint=FINGERPRINT, now=NOW + timedelta(seconds=2))
    # Exact expiry instant is already invalid.
    with pytest.raises(ProbeTokenError, match="过期"):
        signer.verify(token, fingerprint=FINGERPRINT, now=NOW + timedelta(seconds=1))


@pytest.mark.unit
def test_fingerprint_mismatch_rejected() -> None:
    signer = make_signer()
    token = make_token(signer)
    with pytest.raises(ProbeTokenError, match="指纹"):
        signer.verify(token, fingerprint=OTHER_FINGERPRINT, now=NOW)


@pytest.mark.unit
def test_tampered_token_rejected() -> None:
    signer = make_signer()
    token = make_token(signer)
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    with pytest.raises(ProbeTokenError, match="签名"):
        signer.verify(tampered, fingerprint=FINGERPRINT, now=NOW)


@pytest.mark.unit
def test_malformed_tokens_rejected() -> None:
    signer = make_signer()
    for bad in ("", "no-dot", "a.b.c", "!!!.abc"):
        with pytest.raises(ProbeTokenError):
            signer.verify(bad, fingerprint=FINGERPRINT, now=NOW)


@pytest.mark.unit
def test_different_secret_rejects() -> None:
    token = make_token(make_signer())
    with pytest.raises(ProbeTokenError, match="签名"):
        ProbeTokenSigner("x" * 64).verify(token, fingerprint=FINGERPRINT, now=NOW)


@pytest.mark.unit
def test_empty_secret_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        ProbeTokenSigner("")


@pytest.mark.unit
def test_ttl_constant_is_600_seconds() -> None:
    assert TOKEN_TTL_SECONDS == 600
