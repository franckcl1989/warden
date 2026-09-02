"""Scheduler loop skeleton (ARCHITECTURE.md §3.3: 调度循环).

The scheduler writes due collection plans as ``scheduled`` collection_runs;
the collection_runs table lands in M2T2, so for M2T1 the tick is a NO-OP that
only proves the advisory-lock guard: at most one scheduler process may run a
tick, which is what prevents double-scheduling once real scheduling lands.

The advisory lock is a session-scoped pg_try_advisory_lock (non-blocking):
when another scheduler holds it, the tick is skipped and the loop simply
waits for the next interval (LISTEN/NOTIFY-style wake-ups are allowed later
as a droppable optimization, ADR-024).
"""

from __future__ import annotations

import threading

import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

# 0x57415244454E0001 = "WARDEN" || 0001; distinct keys keep the scheduler and
# the maintenance loop from serializing against each other.
SCHEDULER_ADVISORY_LOCK_KEY = 0x57415244454E0001

DEFAULT_TICK_SECONDS = 10.0


def try_advisory_lock(session: Session, key: int) -> bool:
    """Non-blocking session-scoped advisory lock; True when acquired."""
    return bool(session.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar())


def release_advisory_lock(session: Session, key: int) -> None:
    session.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})


class Scheduler:
    """Loop structure; collection scheduling is a NO-OP until M2T2."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        tick_seconds: float = DEFAULT_TICK_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._tick_seconds = tick_seconds
        self._log = structlog.get_logger()

    def run_once(self) -> bool:
        """One tick under the advisory lock; returns True when the lock ran it."""
        with self._session_factory() as session:
            if not try_advisory_lock(session, SCHEDULER_ADVISORY_LOCK_KEY):
                return False
            try:
                # M2T1: no collection scheduling yet (M2T2 wires
                # collection_runs creation from devices.next_poll_at).
                self._log.info("scheduler_tick", collection_runs_scheduled=0)
            finally:
                release_advisory_lock(session, SCHEDULER_ADVISORY_LOCK_KEY)
            session.commit()
        return True

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                self._log.exception("scheduler_tick_failed")
            stop_event.wait(self._tick_seconds)
