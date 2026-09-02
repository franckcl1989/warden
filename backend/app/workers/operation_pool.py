"""Operation concurrency pool (ARCHITECTURE.md §3.3: 操作池).

Claims only ``channel=task`` human operations (contracts/operations.json
profile semantics drive preflight/fence/execute/verify in M2T6); the claim
itself is scope-aware through ``claim_task`` and the DB mutex index. M2T1 runs
with ``handler=None``: the pool claims, appends events and releases leases
for recovery — it never executes a device call and never fabricates a result.
"""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.workers.concurrency import ConcurrencyPool, TaskHandler


class OperationPool(ConcurrencyPool):
    """Operation pool: one claim loop per ``max_workers`` slot.

    ``handler`` is injected by M2T6 (the OperationExecutor performing
    preflight -> dispatch fence -> adapter execute -> verify). Until then the
    noop behavior applies: claimed tasks get a ``handler_not_configured``
    event and an expired lease, then the maintenance recovery sweep decides
    per dispatch fence (requeue / verify_only / verification_required).
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
            claimer=None,
            handler=handler,
            lease_seconds=lease_seconds,
            lease_owner=lease_owner,
            poll_interval=poll_interval,
        )
