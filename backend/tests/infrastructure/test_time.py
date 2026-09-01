"""Unit tests for UTC and display-timezone helpers (docs/PROJECT_SPEC.md §5)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.infrastructure.time import to_shanghai, utcnow


@pytest.mark.unit
def test_utcnow_is_aware_utc() -> None:
    now = utcnow()
    assert now.tzinfo == UTC
    assert now.utcoffset() == timedelta(0)


@pytest.mark.unit
def test_to_shanghai_shifts_aware_utc() -> None:
    value = datetime(2026, 9, 1, 2, 0, 0, tzinfo=UTC)
    converted = to_shanghai(value)
    assert converted.hour == 10
    assert converted.utcoffset() == timedelta(hours=8)


@pytest.mark.unit
def test_to_shanghai_treats_naive_input_as_utc() -> None:
    converted = to_shanghai(datetime(2026, 9, 1, 2, 0, 0))
    assert converted.hour == 10
    assert converted.tzinfo is not None
