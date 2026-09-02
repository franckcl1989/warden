"""Collection concurrency pool (ARCHITECTURE.md §3.3: 采集池).

M2T2 wires the collection claim and executor: the pool claims ``collection_runs``
with ``claim_collection_run`` (FOR UPDATE SKIP LOCKED + lease) and runs the
M2T2 pipeline (``run_collection``) for each claimed run. The independent
concurrency cap (``max_workers``) is deployment configuration
(settings.collection_workers), never a product page or a capacity promise
(ADR-027).

Failure handling differs from the operation pool on purpose: collection runs
have no event stream, so a handler failure (or missing handler) simply
releases the lease with the state left ``running`` — the lease-expired
running run is claimable again (pure read, no dispatch fence) and no
fabricated result is ever persisted.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.application.collection import run_collection
from app.config import WardenSettings, get_settings
from app.infrastructure.crypto import CredentialKeyring
from app.infrastructure.observation_store import claim_collection_run, release_collection_lease
from app.workers.concurrency import ConcurrencyPool, TaskHandler


class CollectionPool(ConcurrencyPool):
    """Collection pool: claims collection_runs and executes the M2T2 pipeline."""

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        max_workers: int,
        lease_seconds: int,
        lease_owner: str,
        settings: WardenSettings | None = None,
        keyring: CredentialKeyring | None = None,
        handler: TaskHandler | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self._settings = settings if settings is not None else get_settings()
        self._keyring = keyring
        super().__init__(
            name="collection-pool",
            max_workers=max_workers,
            session_factory=session_factory,
            claimer=claim_collection_run,
            handler=handler if handler is not None else self._default_handler,
            lease_seconds=lease_seconds,
            lease_owner=lease_owner,
            poll_interval=poll_interval,
        )

    def _default_handler(self, task: Any) -> None:
        if self._keyring is None:
            msg = "collection pool requires a credential keyring"
            raise RuntimeError(msg)
        with self._session_factory() as session:
            run_collection(
                session,
                task,
                settings=self._settings,
                keyring=self._keyring,
            )
            session.commit()

    def _handle_noop(self, task: Any) -> None:
        self._release_for_recovery(task)

    def _release_for_recovery(self, task: Any) -> None:
        try:
            with self._session_factory() as session:
                release_collection_lease(session, run_id=task.id, owner=self._lease_owner)
                session.commit()
        except Exception:
            self._log.exception(
                "collection_lease_release_failed",
                pool=self._name,
                run_id=str(getattr(task, "id", None)),
                message="lease will expire naturally and the next claim will reclaim the run",
            )
