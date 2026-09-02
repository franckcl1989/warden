"""Scheduler loop (ARCHITECTURE.md §3.3: 调度循环).

Each tick under the session-scoped advisory lock (pg_try_advisory_lock,
non-blocking — at most one scheduler process runs a tick, which is what
prevents double-scheduling) writes due collection plans as ``scheduled``
collection_runs via ``schedule_due_collections`` (M2T2): per enabled+ready
device, one run per DUE collection type (30s reachability/health, 60s
metrics, 120s logs, 6h discovery — ARCHITECTURE.md §8), then advances the
device's next_poll_at to the next due instant across all types.
"""

from __future__ import annotations

import threading

import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.application.collection import schedule_due_collections
from app.config import WardenSettings, get_settings
from app.infrastructure.time import utcnow

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
    """One advisory-lock-guarded scheduling pass per tick."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        tick_seconds: float = DEFAULT_TICK_SECONDS,
        settings: WardenSettings | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._tick_seconds = tick_seconds
        self._settings = settings if settings is not None else get_settings()
        self._log = structlog.get_logger()

    def run_once(self) -> bool:
        """One tick under the advisory lock; returns True when the lock ran it."""
        with self._session_factory() as session:
            if not try_advisory_lock(session, SCHEDULER_ADVISORY_LOCK_KEY):
                return False
            try:
                scheduled = schedule_due_collections(
                    session, now=utcnow(), settings=self._settings
                )
                self._log.info("scheduler_tick", collection_runs_scheduled=scheduled)
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
