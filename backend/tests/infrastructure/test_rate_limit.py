"""In-process rate limiter tests (docs/API_CONTRACT.md §11, ADR-024)."""

from __future__ import annotations

import pytest
from app.infrastructure.rate_limit import FixedWindowLimiter, RateLimiter


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.mark.unit
def test_login_limit_five_per_minute_sixth_rejected() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(login_per_minute=5, session_per_minute=300, clock=clock)
    for _ in range(5):
        assert limiter.check_login("10.0.0.7").allowed is True
    sixth = limiter.check_login("10.0.0.7")
    assert sixth.allowed is False
    assert 0 < sixth.retry_after_seconds <= 60


@pytest.mark.unit
def test_window_resets_after_sixty_seconds() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(login_per_minute=5, clock=clock)
    for _ in range(5):
        limiter.check_login("10.0.0.7")
    assert limiter.check_login("10.0.0.7").allowed is False
    clock.advance(60)
    assert limiter.check_login("10.0.0.7").allowed is True


@pytest.mark.unit
def test_keys_are_independent() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(login_per_minute=1, clock=clock)
    assert limiter.check_login("10.0.0.7").allowed is True
    assert limiter.check_login("10.0.0.7").allowed is False
    assert limiter.check_login("10.0.0.8").allowed is True
    assert limiter.check_login("10.0.0.9").allowed is True


@pytest.mark.unit
def test_session_limit_is_separate_from_login_limit() -> None:
    clock = _FakeClock()
    limiter = RateLimiter(login_per_minute=1, session_per_minute=1, clock=clock)
    assert limiter.check_login("10.0.0.7").allowed is True
    # Login budget exhausted but session budget untouched:
    assert limiter.check_session("hash-a").allowed is True
    assert limiter.check_session("hash-a").allowed is False
    assert limiter.check_session("hash-b").allowed is True


@pytest.mark.unit
def test_retry_after_is_seconds_until_window_end() -> None:
    clock = _FakeClock(start=30)
    limiter = RateLimiter(login_per_minute=1, clock=clock)
    limiter.check_login("10.0.0.7")
    blocked = limiter.check_login("10.0.0.7")
    assert blocked.allowed is False
    assert blocked.retry_after_seconds == pytest.approx(30)


@pytest.mark.unit
def test_fixed_window_limiter_accepts_injected_limits() -> None:
    clock = _FakeClock()
    limiter = FixedWindowLimiter(limit=3, window_seconds=10, clock=clock)
    for _ in range(3):
        assert limiter.check("k").allowed is True
    assert limiter.check("k").allowed is False
    clock.advance(10)
    assert limiter.check("k").allowed is True
