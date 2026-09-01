"""Infrastructure-level session rules (docs/SECURITY.md §2/§4)."""

from __future__ import annotations

import datetime

import pytest
from app.domain.uuid7 import uuid7
from app.infrastructure.sessions import (
    client_summary,
    is_reauthenticated,
    reauthenticated_until,
    session_is_valid,
)
from app.models.auth import Session as DBSession

NOW = datetime.datetime(2026, 9, 1, 8, 0, 0, tzinfo=datetime.UTC)


def _session(**overrides: object) -> DBSession:
    values: dict[str, object] = {
        "id": uuid7(),
        "session_id_hash": "a" * 64,
        "user_id": uuid7(),
        "last_activity_at": NOW - datetime.timedelta(minutes=1),
        "absolute_expires_at": NOW + datetime.timedelta(hours=12),
        "csrf_secret_hash": "b" * 64,
        "version": 1,
        "revoked_at": None,
        "reauthenticated_at": None,
    }
    values.update(overrides)
    return DBSession(**values)


@pytest.mark.unit
def test_valid_session_within_idle_and_absolute() -> None:
    assert session_is_valid(_session(), NOW, idle_minutes=30) is True


@pytest.mark.unit
def test_revoked_session_invalid() -> None:
    session = _session(revoked_at=NOW - datetime.timedelta(seconds=1))
    assert session_is_valid(session, NOW, idle_minutes=30) is False


@pytest.mark.unit
def test_idle_expiry_slides_from_last_activity() -> None:
    session = _session(last_activity_at=NOW - datetime.timedelta(minutes=31))
    assert session_is_valid(session, NOW, idle_minutes=30) is False
    session.last_activity_at = NOW - datetime.timedelta(minutes=29)
    assert session_is_valid(session, NOW, idle_minutes=30) is True


@pytest.mark.unit
def test_absolute_expiry_is_immutable() -> None:
    session = _session(
        last_activity_at=NOW - datetime.timedelta(seconds=1),
        absolute_expires_at=NOW - datetime.timedelta(minutes=1),
    )
    assert session_is_valid(session, NOW, idle_minutes=30) is False


@pytest.mark.unit
def test_reauth_validity_window_is_five_minutes() -> None:
    session = _session(reauthenticated_at=NOW - datetime.timedelta(minutes=4, seconds=59))
    assert is_reauthenticated(session, NOW, ttl_minutes=5) is True
    assert reauthenticated_until(session, NOW, ttl_minutes=5) == NOW + datetime.timedelta(seconds=1)
    session.reauthenticated_at = NOW - datetime.timedelta(minutes=5, seconds=1)
    assert is_reauthenticated(session, NOW, ttl_minutes=5) is False


@pytest.mark.unit
def test_never_reauthenticated_is_not_valid() -> None:
    assert is_reauthenticated(_session(), NOW, ttl_minutes=5) is False


@pytest.mark.unit
def test_client_summary_combines_source_and_ua() -> None:
    assert client_summary("10.0.0.7", "Mozilla/5.0 x") == "10.0.0.7 Mozilla/5.0 x"
    assert client_summary("10.0.0.7", None) == "10.0.0.7"
    assert client_summary(None, "curl/8") == "curl/8"
    assert client_summary(None, None) is None
