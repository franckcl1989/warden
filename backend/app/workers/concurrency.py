"""Shared worker pool: N threads claim and process tasks (ARCHITECTURE.md §3.3).

One thread per slot; every claim/transition runs in its own transaction
(DATA_MODEL.md §11: one DB transaction per claim/transition + event append).
The pool never keeps a second queue state in memory: the claim comes from
``claim_task`` (FOR UPDATE SKIP LOCKED + lease) and the task row in
PostgreSQL stays the only execution authorization (ADR-024).

M2T1 skeleton honesty:

- with ``handler=None`` the pool appends a ``handler_not_configured`` event
  and releases the lease WITHOUT changing the task state — the task stays
  ``running`` with an expired lease and the maintenance recovery sweep
  requeues it (fence-less) or parks it for verify-only (fenced). Real
  operation execution lands in M2T6 with an injected ``OperationExecutor``.
- a handler exception is never swallowed into a fabricated result: the pool
  logs it, releases the lease and lets recovery decide per the dispatch fence.

Threads are daemons so a hung handler cannot block interpreter shutdown; the
database connection is returned on process exit and the lease recovery sweep
takes over (ARCHITECTURE.md §7 失败与恢复).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Protocol

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.domain.operation import TaskState
from app.infrastructure.logging import bind_task_context
from app.infrastructure.tasks import append_event, claim_task, release_lease


class TaskClaimer(Protocol):
    """Claim protocol: M2T1 claims operation_tasks; M2T2 adds collection_runs."""

    def __call__(
        self,
        session: Session,
        *,
        lease_owner: str,
        lease_seconds: int,
    ) -> Any | None: ...


class TaskHandler(Protocol):
    """Processes one claimed task. M2T6 injects the OperationExecutor."""

    def __call__(self, task: Any) -> None: ...


class ConcurrencyPool:
    """Claim-loop pool with independent concurrency cap and graceful drain.

    Each worker thread repeatedly: claim (own transaction) -> run the handler
    outside the claim transaction -> poll. Claim errors are logged and backed
    off; handler errors release the lease for recovery (never re-execute).
    """

    def __init__(
        self,
        *,
        name: str,
        max_workers: int,
        session_factory: sessionmaker[Session],
        claimer: TaskClaimer | None = None,
        handler: TaskHandler | None = None,
        lease_seconds: int,
        lease_owner: str,
        poll_interval: float = 1.0,
    ) -> None:
        self._name = name
        self._max_workers = max_workers
        self._session_factory = session_factory
        # claimer defaults to the operation-task claim; M2T2 injects the
        # collection_runs claimer with the same protocol shape.
        self._claimer = claimer if claimer is not None else claim_task
        self._handler = handler
        self._lease_seconds = lease_seconds
        self._lease_owner = lease_owner
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._log = structlog.get_logger()

    def start(self) -> None:
        for index in range(self._max_workers):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"{self._name}-{index}",
                args=(index,),
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self, timeout: float = 15.0) -> None:
        """Signal shutdown and wait for in-flight work to drain."""
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._log.info("worker_pool_stopped", pool=self._name, threads=len(self._threads))

    def _worker_loop(self, index: int) -> None:
        while not self._stop.is_set():
            try:
                task = self._claim_once()
            except Exception:
                self._log.exception("claim_failed", pool=self._name, worker_index=index)
                time.sleep(self._poll_interval)
                continue
            if task is None:
                time.sleep(self._poll_interval)
                continue
            bind_task_context(task_id=str(task.id), device_id=str(getattr(task, "device_id", None)))
            try:
                if self._handler is not None:
                    self._handler(task)
                else:
                    self._handle_noop(task)
            except Exception:
                self._log.exception(
                    "handler_failed",
                    pool=self._name,
                    task_id=str(task.id),
                    message="task released for recovery; never re-executed",
                )
                self._release_for_recovery(task)

    def _claim_once(self) -> Any | None:
        with self._session_factory() as session:
            task = self._claimer(
                session,
                lease_owner=self._lease_owner,
                lease_seconds=self._lease_seconds,
            )
            session.commit()
        return task

    def _handle_noop(self, task: Any) -> None:
        """M2T1: no handler configured — release the task for recovery, honestly."""
        with self._session_factory() as session:
            append_event(
                session,
                task_id=task.id,
                state=TaskState.RUNNING.value,
                message="handler_not_configured: no executor wired yet (M2T6); task released for recovery",
            )
            release_lease(session, task_id=task.id, owner=self._lease_owner)
            session.commit()
        self._log.info("handler_not_configured", pool=self._name, task_id=str(task.id))

    def _release_for_recovery(self, task: Any) -> None:
        try:
            with self._session_factory() as session:
                append_event(
                    session,
                    task_id=task.id,
                    state=TaskState.RUNNING.value,
                    message="handler_failed: task returned for fence-aware recovery",
                )
                release_lease(session, task_id=task.id, owner=self._lease_owner)
                session.commit()
        except Exception:
            self._log.exception(
                "lease_release_failed",
                pool=self._name,
                task_id=str(task.id),
                message="lease will expire naturally and recovery will take over",
            )
