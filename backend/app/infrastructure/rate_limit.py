"""In-process fixed-window rate limiter (ADR-024: no Redis).

Memory-backed and honest about it: the window counters live in this process,
so the limit applies per single-process deployment and resets on restart.
Windows are aligned to the clock (``int(now // window_seconds)``), the clock
is injectable for deterministic tests, and access is locked because FastAPI
runs sync endpoints in a thread pool.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable

Clock = Callable[[], float]


@dataclasses.dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: float


def _real_clock() -> float:
    return time.monotonic()


class FixedWindowLimiter:
    """Per-key fixed-window counter with injectable clock."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock: Clock | None = None,
    ) -> None:
        self._limit = limit
        self._window_seconds = window_seconds
        self._clock = clock if clock is not None else _real_clock
        self._counters: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitResult:
        """Count one attempt for ``key``; return whether it is allowed."""
        now = self._clock()
        window_index = int(now // self._window_seconds)
        window_end = (window_index + 1) * self._window_seconds
        retry_after = max(0.0, window_end - now)
        with self._lock:
            current_window, count = self._counters.get(key, (window_index, 0))
            if current_window != window_index:
                current_window = window_index
                count = 0
            count += 1
            self._counters[key] = (current_window, count)
        if count <= self._limit:
            return RateLimitResult(allowed=True, retry_after_seconds=0.0)
        return RateLimitResult(allowed=False, retry_after_seconds=retry_after)


class RateLimiter:
    """Named policies: login per source IP, authenticated requests per session.

    docs/API_CONTRACT.md §11: login 5/min per IP; ordinary reads and all
    session-bearing requests 300/min per session; device probes 10/min per
    user.
    """

    def __init__(
        self,
        *,
        login_per_minute: int = 5,
        session_per_minute: int = 300,
        probe_per_minute: int = 10,
        clock: Clock | None = None,
    ) -> None:
        self._login = FixedWindowLimiter(limit=login_per_minute, window_seconds=60, clock=clock)
        self._session = FixedWindowLimiter(limit=session_per_minute, window_seconds=60, clock=clock)
        self._probe = FixedWindowLimiter(limit=probe_per_minute, window_seconds=60, clock=clock)

    def check_login(self, source_ip: str) -> RateLimitResult:
        return self._login.check(f"login:{source_ip}")

    def check_session(self, session_id_hash: str) -> RateLimitResult:
        return self._session.check(f"session:{session_id_hash}")

    def check_probe(self, user_id: str) -> RateLimitResult:
        return self._probe.check(f"probe:{user_id}")
