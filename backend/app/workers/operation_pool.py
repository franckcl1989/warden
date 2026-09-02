"""Operation concurrency pool (ARCHITECTURE.md §3.3: 操作池).

Claims only ``channel=task`` human operations (contracts/operations.json
profile semantics drive preflight/fence/execute/verify in M2T6). The pool
claims through TWO conditional paths in one pass (M2T6):

- ``claim_task``: the oldest queued task (device-mutex aware) — the executor
  runs the full preflight -> dispatch fence -> execute -> verify flow;
- ``claim_verify_only_task``: a parked fenced task whose worker died (lease
  cleared by the maintenance sweep) — the executor then ONLY verifies/read-
  backs (DEVICE_ADAPTERS.md §9: 有副作用 profile 在 fence 后只查 job/回读).

``handler`` is injected by M2T6 (the ``OperationExecutor``); with
``handler=None`` the M2T1 noop behavior applies (claim, event, expired lease,
fence-aware recovery).
"""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.tasks import (
    claim_task,
    claim_verify_only_task,
)
from app.workers.concurrency import ConcurrencyPool, TaskHandler


def claim_operation_task(
    session: Session,
    *,
    lease_owner: str,
    lease_seconds: int,
) -> object:
    """Claim the next queued task; fall back to a parked verify-only task.

    Queued tasks are drained first so the pool never starves fresh work
    behind a long-verifying recovery; both claims are conditional
    UPDATE ... RETURNING in the caller's transaction.
    """
    task = claim_task(
        session,
        lease_owner=lease_owner,
        lease_seconds=lease_seconds,
    )
    if task is not None:
        return task
    return claim_verify_only_task(
        session,
        lease_owner=lease_owner,
        lease_seconds=lease_seconds,
    )


class OperationPool(ConcurrencyPool):
    """Operation pool: one claim loop per ``max_workers`` slot.

    M2T6 wires the ``OperationExecutor`` as the handler; the claimer serves
    both queued execution tasks and parked verify-only recovery tasks.
    """

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
            name="operation-pool",
            max_workers=max_workers,
            session_factory=session_factory,
            claimer=claim_operation_task,
            handler=handler,
            lease_seconds=lease_seconds,
            lease_owner=lease_owner,
            poll_interval=poll_interval,
        )
