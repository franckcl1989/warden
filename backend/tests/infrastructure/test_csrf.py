"""CSRF token and origin validation tests (docs/SECURITY.md §2/§10)."""

from __future__ import annotations

import pytest
from app.infrastructure.csrf import (
    decode_csrf_token,
    encode_csrf_token,
    hash_csrf_secret,
    is_origin_allowed,
    issue_csrf_secret,
    normalize_origin,
    verify_csrf_token,
)


@pytest.mark.unit
def test_token_bound_to_session() -> None:
    secret = issue_csrf_secret()
    stored_hash = hash_csrf_secret(secret)
    raw = encode_csrf_token(secret)
    assert verify_csrf_token(raw, stored_hash) is True


@pytest.mark.unit
def test_wrong_token_fails() -> None:
    secret = issue_csrf_secret()
    stored_hash = hash_csrf_secret(secret)
    other = encode_csrf_token(issue_csrf_secret())
    assert verify_csrf_token(other, stored_hash) is False


@pytest.mark.unit
def test_other_sessions_token_fails() -> None:
    session_a_secret = issue_csrf_secret()
    session_b_secret = issue_csrf_secret()
    session_b_hash = hash_csrf_secret(session_b_secret)
    assert verify_csrf_token(encode_csrf_token(session_a_secret), session_b_hash) is False


@pytest.mark.unit
def test_garbage_header_fails() -> None:
    stored_hash = hash_csrf_secret(issue_csrf_secret())
    assert verify_csrf_token("", stored_hash) is False
    assert verify_csrf_token("not-base64!!", stored_hash) is False
    assert verify_csrf_token("AAAA", stored_hash) is False


@pytest.mark.unit
def test_secret_length_and_storage_are_digests_only() -> None:
    secret = issue_csrf_secret()
    assert len(secret) == 32
    digest = hash_csrf_secret(secret)
    assert len(digest) == 64
    # The stored value is a hex digest of the secret, not the secret itself.
    assert hex(int.from_bytes(secret, "big")) not in digest


@pytest.mark.unit
def test_normalize_origin() -> None:
    assert normalize_origin("https://warden.example/api/v1") == "https://warden.example"
    assert normalize_origin("HTTPS://Warden.Example:443") == "https://warden.example"
    assert normalize_origin("http://localhost:8080") == "http://localhost:8080"
    assert normalize_origin("null") is None
    assert normalize_origin("") is None


@pytest.mark.unit
def test_is_origin_allowed() -> None:
    allowed = {"https://warden.example", "http://localhost:8080"}
    assert is_origin_allowed(origin="https://warden.example", referer=None, allowed_origins=allowed) is True
    assert is_origin_allowed(origin="https://evil.example", referer=None, allowed_origins=allowed) is False
    assert is_origin_allowed(origin="null", referer=None, allowed_origins=allowed) is False
    assert is_origin_allowed(origin=None, referer="https://warden.example/some/path", allowed_origins=allowed) is True
    assert is_origin_allowed(origin=None, referer="https://evil.example/", allowed_origins=allowed) is False
    assert is_origin_allowed(origin=None, referer=None, allowed_origins=allowed) is True
    # Origin wins over Referer when both are present.
    assert is_origin_allowed(
        origin="https://evil.example", referer="https://warden.example/x", allowed_origins=allowed
    ) is False


@pytest.mark.unit
def test_round_trip_through_header_bytes() -> None:
    secret = issue_csrf_secret()
    raw = encode_csrf_token(secret)
    decoded = decode_csrf_token(raw)
    assert decoded == secret
