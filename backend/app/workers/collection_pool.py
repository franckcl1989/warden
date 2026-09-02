"""Collection concurrency pool (ARCHITECTURE.md §3.3: 采集池).

M2T1 defines the pool shape only: the ``collection_runs`` table and its claim
function land in M2T2, so the pool claims nothing and its loop stays idle.
The independent concurrency cap (``max_workers``) is deployment configuration
(settings.collection_workers), never a product page or a capacity promise
(ADR-027).
"""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.workers.concurrency import ConcurrencyPool, TaskHandler


class CollectionPool(ConcurrencyPool):
    """Collection pool skeleton; the claim function arrives in M2T2."""

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        max_workers: int,
        lease_seconds: int,
        lease_owner: str,
        handler: TaskHandler | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        super().__init__(
            name="collection-pool",
            max_workers=max_workers,
            session_factory=session_factory,
            # M2T2 wires claim_collection_run here; until then nothing is
            # claimable so the pool polls and finds nothing (honest idle).
            claimer=lambda session, *, lease_owner, lease_seconds: None,
            handler=handler,
            lease_seconds=lease_seconds,
            lease_owner=lease_owner,
            poll_interval=poll_interval,
        )
