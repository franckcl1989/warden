"""Deterministic rate-limit windows for API tests (docs/SECURITY.md §13).

The in-process fixed-window limiter (ADR-024; ``app/infrastructure/
rate_limit.py``) aligns its 60-second windows to the process clock. A test
that fires N requests and asserts the (N+1)-th is refused with 429 therefore
depends on the wall clock: when the burst straddles a window boundary the
counter resets mid-test and the expected refusal never happens. That is the
M6T2 flake family (login 429 and its preview/submit/probe/launch siblings):
under full-suite load the N+1 sequential requests can cross a boundary and
the last request is wrongly allowed.

Freezing the limiter clock keeps every request of the test inside one window,
making the tests deterministic at ANY wall-clock time. Only tests that assert
a windowed refusal should call this; each API test gets its own app instance
(function-scoped fixtures), so nothing needs restoring afterwards.
"""

from __future__ import annotations

from app.infrastructure.rate_limit import FixedWindowLimiter, RateLimiter
from fastapi import FastAPI

# All RateLimiter policies currently use 60-second windows; 30.0 is an
# arbitrary instant safely inside the first window so the frozen clock is
# not aligned to a boundary by accident.
_FROZEN_NOW = 30.0


class _FrozenClock:
    """Callable clock pinned to one instant (mid-window)."""

    def __call__(self) -> float:
        return _FROZEN_NOW


def freeze_rate_limit_clock(app: FastAPI) -> None:
    """Freeze every rate-limit window of ``app.state.rate_limiter``.

    Replaces the clock of all six per-policy ``FixedWindowLimiter`` instances
    with a constant, so every request issued after the freeze lands in the
    same window index and the counters behave exactly like a single quiet
    minute, independent of the real wall clock.
    """
    limiter = app.state.rate_limiter
    if not isinstance(limiter, RateLimiter):
        raise TypeError(f"app.state.rate_limiter is not a RateLimiter: {type(limiter)!r}")
    frozen = _FrozenClock()
    for name in ("_login", "_session", "_probe", "_preview", "_submit", "_launch"):
        window: FixedWindowLimiter = getattr(limiter, name)
        window._clock = frozen
