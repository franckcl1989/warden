"""Operation task persistence: atomic claim, leases, recovery/timeout scans, events.

docs/DATA_MODEL.md §7 (model), §11 (事务边界: one transaction per
claim/transition + event append), ARCHITECTURE.md §6 (条件更新/唯一约束/行锁
是唯一执行授权), ADR-024 (PostgreSQL persistent task queue — no Redis/Celery/
outbox). The task row itself is the execution authorization; these functions
only ever write through conditional UPDATEs guarded by state/lease so a stale
or second worker cannot corrupt a task.

Claim semantics (ARCHITECTURE.md §3.3, DATA_MODEL.md §7.1):

- ``FOR UPDATE SKIP LOCKED`` picks the oldest queued task without blocking on
  rows another worker is claiming;
- the device mutex is enforced by the partial unique index
  ``uq_operation_tasks_active_mutex`` (migration 0005) and mirrored here with
  a NOT EXISTS guard for defense in depth: tasks whose conflict_scope is in
  MUTEX_SCOPES never claim while another active task holds the same
  (device_id, conflict_scope);
- the claim UPDATE + its ``running`` event commit in the same transaction.

``claim_task`` is parameterized with ``extra_conditions`` so the M2T2
collection pool reuses the same claim machinery for ``collection_runs``.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Sequence
from typing import Any, cast

from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.domain.operation import MUTEX_SCOPES, TERMINAL_STATES, TaskState
from app.models.operation import OperationTask, OperationTaskEvent

ACTIVE_MUTEX_STATES = ("queued", "running", "waiting_device")

# States the executor may drive under its own lease (execution + async job
# polling) and that lease recovery may scan (DEVICE_ADAPTERS.md §9: a crashed
# worker polling a persisted job must be recovered to verify-only, never
# re-executed).
EXECUTING_STATES = (TaskState.RUNNING.value, TaskState.WAITING_DEVICE.value)

# The maintenance scans compare leases against a caller-provided ``now`` so
# tests can drive expiry deterministically; the caller defaults to utcnow().
ScanNow = datetime.datetime


def _lease_expiry_expression(lease_seconds: int) -> Any:
    """SQL expression ``now() + lease_seconds`` (database clock is authoritative)."""
    return func.now() + datetime.timedelta(seconds=lease_seconds)


def append_event(
    session: Session,
    *,
    task_id: uuid.UUID,
    state: str,
    step: str | None = None,
    progress_percent: int | None = None,
    message: str | None = None,
    device_job_id: str | None = None,
) -> None:
    """Append one immutable event row in the caller's transaction."""
    session.add(
        OperationTaskEvent(
            task_id=task_id,
            state=state,
            step=step,
            progress_percent=progress_percent,
            message=message,
            device_job_id=device_job_id,
        )
    )


def _conditional_update(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str | None,
    states: Sequence[str],
    values: dict[str, object],
) -> OperationTask | None:
    """One guarded transition UPDATE returning the fresh row.

    Every worker write is a conditional UPDATE (state + lease owner guard) so
    a stale executor or a concurrent maintenance sweep can never corrupt a
    task (ARCHITECTURE.md §6: 条件更新是唯一执行授权). Returns None when the
    guard did not match (task lost, cancelled, or transitioned by recovery).
    """
    where = [OperationTask.id == task_id, OperationTask.state.in_(states)]
    if owner is not None:
        where.append(OperationTask.lease_owner == owner)
    stmt = (
        update(OperationTask)
        .where(*where)
        .values(**values, updated_at=func.now(), version=OperationTask.version + 1)
        .returning(OperationTask)
    )
    return session.execute(stmt).scalar_one_or_none()


def claim_task(
    session: Session,
    *,
    lease_owner: str,
    lease_seconds: int,
    extra_conditions: Sequence[Any] = (),
) -> OperationTask | None:
    """Atomically claim the oldest claimable queued task and return it.

    The claim is a single conditional UPDATE ... WHERE id IN (SELECT ... FOR
    UPDATE SKIP LOCKED LIMIT 1) RETURNING *: the lease write and the transition
    to running happen in one statement, and the ``running`` event is appended
    in the same transaction (DATA_MODEL.md §11). Returns None when nothing is
    claimable. ``extra_conditions`` lets M2T2 add collection-pool filters.
    """
    other = OperationTask.__table__.alias("mutex")
    mutex_guard = or_(
        ~OperationTask.conflict_scope.in_(MUTEX_SCOPES),
        ~exists(
            select(other.c.id).where(
                and_(
                    other.c.device_id == OperationTask.device_id,
                    other.c.conflict_scope == OperationTask.conflict_scope,
                    other.c.state.in_(ACTIVE_MUTEX_STATES),
                    other.c.id != OperationTask.id,
                )
            )
        ),
    )
    candidate = (
        select(OperationTask.id)
        .where(
            OperationTask.state == TaskState.QUEUED.value,
            mutex_guard,
            *extra_conditions,
        )
        .order_by(OperationTask.created_at, OperationTask.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    stmt = (
        update(OperationTask)
        .where(OperationTask.id.in_(candidate))
        .values(
            state=TaskState.RUNNING.value,
            lease_owner=lease_owner,
            lease_expires_at=_lease_expiry_expression(lease_seconds),
            started_at=func.coalesce(OperationTask.started_at, func.now()),
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    )
    task = session.execute(stmt).scalar_one_or_none()
    if task is not None:
        append_event(
            session,
            task_id=task.id,
            state=task.state,
            message="claimed",
        )
    return task


def renew_lease(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str,
    lease_seconds: int,
) -> bool:
    """Extend a lease the caller still owns; False when lost/expired/unknown.

    The conditional UPDATE requires the exact owner and a not-yet-expired
    lease; a task whose lease expired or was re-claimed is not renewed
    (a heartbeat is never a reason to extend someone else's execution).
    ``waiting_device`` joins the guard in M2T6: the executor renews its lease
    while polling a persisted device job.
    """
    result = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.lease_owner == owner,
            OperationTask.state.in_(EXECUTING_STATES),
            OperationTask.lease_expires_at > func.now(),
        )
        .values(lease_expires_at=_lease_expiry_expression(lease_seconds))
    )
    return cast(CursorResult[Any], result).rowcount == 1


def release_lease(session: Session, *, task_id: uuid.UUID, owner: str) -> bool:
    """Release a lease owned by ``owner`` and mark it immediately expired.

    Used by the pool when a handler is missing or failed: the state stays
    ``running`` (honest: nothing else claimed it yet) but the lease is
    expired, so the recovery scan picks the task up and applies the
    fence-aware recovery action (requeue / verify_only / verification_required).
    """
    result = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.lease_owner == owner,
            OperationTask.state == TaskState.RUNNING.value,
        )
        .values(lease_owner=None, lease_expires_at=func.now())
    )
    return cast(CursorResult[Any], result).rowcount == 1


def clear_lease(session: Session, *, task_id: uuid.UUID) -> bool:
    """Drop the lease of a running task without changing its state.

    Used by the maintenance loop after a fenced task is parked for
    verify-only: the task stays ``running`` (awaiting the M2T6 verify claim
    path) but is no longer a recovery-scan candidate, so the recovery event
    is appended exactly once instead of every maintenance cycle.

    The UPDATE requires an existing lease (``lease_expires_at IS NOT NULL``),
    so a task whose lease was already cleared no longer matches: two
    maintenance passes that both scanned the same expired-lease candidate
    cannot each append the verify-only event (single-event-per-task
    invariant). Owner is not part of the guard because the pool's
    ``release_lease`` already nulls the owner while leaving an (immediately
    expired) lease timestamp for recovery to act on.
    """
    result = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.state.in_(EXECUTING_STATES),
            OperationTask.lease_expires_at.is_not(None),
        )
        .values(lease_owner=None, lease_expires_at=None)
    )
    return cast(CursorResult[Any], result).rowcount == 1


def claim_verify_only_task(
    session: Session,
    *,
    lease_owner: str,
    lease_seconds: int,
) -> OperationTask | None:
    """Claim a parked verify-only task (M2T6 executor recovery consumption).

    The maintenance sweep parks fenced tasks whose worker died
    (``clear_lease``: state stays running/waiting_device, lease cleared). The
    operation pool claims those parked rows here: the executor then ONLY
    verifies/read-backs (DEVICE_ADAPTERS.md §9 — a fenced side-effect task is
    never executed twice). The claim is one conditional UPDATE ... RETURNING
    with the same lease semantics as ``claim_task``; candidates need the
    dispatch fence committed and must not already be past ``timeout_at`` (the
    timeout sweep owns tasks that crossed their deadline).
    """
    candidate = (
        select(OperationTask.id)
        .where(
            OperationTask.state.in_(EXECUTING_STATES),
            OperationTask.lease_owner.is_(None),
            OperationTask.lease_expires_at.is_(None),
            OperationTask.dispatch_started_at.is_not(None),
            or_(
                OperationTask.timeout_at.is_(None),
                OperationTask.timeout_at > func.now(),
            ),
        )
        .order_by(OperationTask.updated_at, OperationTask.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    stmt = (
        update(OperationTask)
        .where(OperationTask.id.in_(candidate))
        .values(
            lease_owner=lease_owner,
            lease_expires_at=_lease_expiry_expression(lease_seconds),
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    )
    task = session.execute(stmt).scalar_one_or_none()
    if task is not None:
        append_event(
            session,
            task_id=task.id,
            state=task.state,
            message="claimed for recovery verify: dispatch fence present — only read-back/verify allowed",
        )
    return task


def dispatch_fence(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str,
    now: datetime.datetime,
    adapter_version: str,
    plan_hash: str,
    parameter_hash: str,
) -> OperationTask | None:
    """Commit the irreversible dispatch fence (DEVICE_ADAPTERS.md §9).

    ``dispatch_started_at`` + adapter version + plan/parameter hashes are
    written and committed BEFORE any device-changing call is allowed; the
    UPDATE is guarded by the caller's lease and ``dispatch_started_at IS
    NULL`` so a second executor can never fence twice. The fence event is
    appended in the same transaction (DATA_MODEL.md §11).
    """
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.lease_owner == owner,
            OperationTask.state == TaskState.RUNNING.value,
            OperationTask.dispatch_started_at.is_(None),
        )
        .values(
            dispatch_started_at=now,
            adapter_version=adapter_version,
            plan_hash=plan_hash,
            parameter_hash=parameter_hash,
            updated_at=now,
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is not None:
        append_event(
            session,
            task_id=task.id,
            state=task.state,
            message=(
                "dispatch_fence: 已提交派发围栏（适配器版本与计划散列已固定）"
                "——此后崩溃只允许回读核验"
            ),
        )
    return task


def update_progress(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str,
    progress_percent: int,
    current_step: str | None = None,
    message: str | None = None,
    device_job_id: str | None = None,
) -> OperationTask | None:
    """Persist one throttled progress point (event + row) under the lease.

    Guards on the exact owner and executing states; the executor throttles
    the CALL cadence — this helper stays a plain conditional write. The job
    id column is only ever written when the executor passes one (a progress
    write never clears an already-persisted device_job_id).
    """
    values: dict[str, object] = {
        "progress_percent": progress_percent,
        "current_step": current_step,
    }
    if device_job_id is not None:
        values["device_job_id"] = device_job_id
    task = _conditional_update(
        session,
        task_id=task_id,
        owner=owner,
        states=EXECUTING_STATES,
        values=values,
    )
    if task is None:
        return None
    append_event(
        session,
        task_id=task.id,
        state=task.state,
        step=current_step,
        progress_percent=progress_percent,
        message=message,
        device_job_id=task.device_job_id,
    )
    return task


def enter_waiting_device(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str,
    device_job_id: str,
) -> OperationTask | None:
    """running -> waiting_device after the vendor job id is persisted.

    DATA_MODEL.md §7.1: 存在时只查询，不重复创建 — the job id lands in the row
    (and its event) BEFORE the executor starts polling, so a crash after this
    point can only ever resume querying the SAME job.
    """
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.lease_owner == owner,
            OperationTask.state == TaskState.RUNNING.value,
        )
        .values(
            state=TaskState.WAITING_DEVICE.value,
            device_job_id=device_job_id,
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is not None:
        append_event(
            session,
            task_id=task.id,
            state=task.state,
            device_job_id=device_job_id,
            message="等待设备异步作业完成（作业 ID 已持久化，仅查询原作业）",
        )
    return task


def transition_task(
    session: Session,
    *,
    task_id: uuid.UUID,
    owner: str,
    to_state: TaskState,
    message: str,
    now: datetime.datetime,
    result_summary: str | None = None,
    error_code: str | None = None,
    error_detail: str | None = None,
    verification_state: str | None = None,
    evidence: dict[str, object] | None = None,
) -> OperationTask | None:
    """One executor-driven transition out of running/waiting_device.

    Covers the terminal states (succeeded/failed/timed_out — ``finished_at``
    recorded) and the verification_required holding state (kept open, error
    ``ambiguous_result``). The state write + append-only event commit in the
    CALLER's transaction; the executor additionally records audit + ui_events
    in the same transaction (DATA_MODEL.md §11). Returns None when the lease/
    state guard did not match (superseded by recovery or timeout sweep).
    """
    terminal = to_state in TERMINAL_STATES
    values: dict[str, object] = {
        "state": to_state.value,
        "lease_owner": None,
        "lease_expires_at": None,
        "result_summary": result_summary,
        "error_code": error_code,
        "error_detail": error_detail,
        "verification_state": verification_state,
        "evidence": evidence,
    }
    if terminal:
        values["finished_at"] = func.coalesce(OperationTask.finished_at, now)
    task = _conditional_update(
        session,
        task_id=task_id,
        owner=owner,
        states=EXECUTING_STATES,
        values=values,
    )
    if task is None:
        return None
    append_event(session, task_id=task.id, state=task.state, message=message)
    return task


def recovery_scan(session: Session, *, now: ScanNow) -> list[OperationTask]:
    """Running/waiting_device tasks whose lease has expired (recovery candidates).

    Tasks with no lease (parked verify-only) are intentionally skipped.
    ``waiting_device`` rows joined the scan in M2T6: a worker polling a
    persisted device job may crash, and recovery must park such tasks for
    verify-only (never re-execute — DEVICE_ADAPTERS.md §9).
    """
    rows = session.scalars(
        select(OperationTask).where(
            OperationTask.state.in_(EXECUTING_STATES),
            OperationTask.lease_expires_at.is_not(None),
            OperationTask.lease_expires_at <= now,
        )
    ).all()
    return list(rows)


def timeout_scan(session: Session, *, now: ScanNow) -> list[OperationTask]:
    """Running/waiting_device tasks whose timeout_at has passed."""
    rows = session.scalars(
        select(OperationTask).where(
            OperationTask.state.in_((TaskState.RUNNING.value, TaskState.WAITING_DEVICE.value)),
            OperationTask.timeout_at.is_not(None),
            OperationTask.timeout_at <= now,
        )
    ).all()
    return list(rows)


def requeue_task(
    session: Session,
    *,
    task_id: uuid.UUID,
    message: str,
    attempt_count: int | None = None,
) -> bool:
    """Recovery requeue: running -> queued with the lease cleared.

    This is the recovery transition (not part of the DATA_MODEL §7.2 visible
    diagram); the caller must have decided via ``recover_task`` that no
    dispatch fence exists (or a read-only task without a device job may start
    a new attempt). The conditional UPDATE guards on state='running' so a
    concurrent transition makes this a no-op. The maintenance sweep passes
    ``attempt_count`` for READ profiles (M2T6): each requeue grants one more
    attempt, bounded by ``operation_read_max_attempts`` (migration 0012).
    """
    values: dict[str, object] = {
        "state": TaskState.QUEUED.value,
        "lease_owner": None,
        "lease_expires_at": None,
        "updated_at": func.now(),
        "version": OperationTask.version + 1,
    }
    if attempt_count is not None:
        values["attempt_count"] = attempt_count
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.state == TaskState.RUNNING.value,
        )
        .values(**values)
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is None:
        return False
    append_event(session, task_id=task.id, state=task.state, message=message)
    return True


def mark_timeout(
    session: Session,
    *,
    task_id: uuid.UUID,
    to_state: TaskState,
    message: str,
    error_code: str | None = None,
) -> bool:
    """Timeout sweep transition: running/waiting_device -> timed_out | verification_required.

    ``to_state`` must come from ``timeout_transition`` (domain); the caller
    resolves the profile from the generated registry — the sweep never guesses
    per-operation semantics. Terminal ``timed_out`` records finished_at;
    ``verification_required`` is a holding state and keeps the task open.
    """
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.state.in_((TaskState.RUNNING.value, TaskState.WAITING_DEVICE.value)),
        )
        .values(
            state=to_state.value,
            lease_owner=None,
            lease_expires_at=None,
            error_code=error_code,
            finished_at=func.coalesce(OperationTask.finished_at, func.now())
            if to_state is TaskState.TIMED_OUT
            else OperationTask.finished_at,
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is None:
        return False
    append_event(session, task_id=task.id, state=task.state, message=message)
    return True


def fail_recovered_task(
    session: Session,
    *,
    task_id: uuid.UUID,
    error_code: str,
    error_detail: str,
    message: str,
) -> bool:
    """Recovery terminal failure: running -> failed (M2T6 read attempt cap).

    The maintenance sweep fails a READ task terminally when its crash-driven
    requeues reached ``operation_read_max_attempts`` (migration 0012):
    requeueing a crashing worker forever would spin the pool, and the task
    never dispatched (fence-less reads only requeue) so no device call is
    at stake. The conditional UPDATE guards on state='running'; the caller
    adds audit + ui_events in the same transaction.
    """
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.state == TaskState.RUNNING.value,
        )
        .values(
            state=TaskState.FAILED.value,
            lease_owner=None,
            lease_expires_at=None,
            error_code=error_code,
            error_detail=error_detail,
            result_summary=message,
            finished_at=func.now(),
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is None:
        return False
    append_event(session, task_id=task.id, state=task.state, message=message)
    return True


def mark_verification_required(
    session: Session,
    *,
    task_id: uuid.UUID,
    message: str,
) -> bool:
    """Recovery ambiguity: running -> verification_required (error ambiguous_result).

    Used when recovery cannot prove success or failure (DEVICE_ADAPTERS.md §9:
    无法证明成功或失败：进入 verification_required). The task keeps its
    evidence/history; M2T6 wires the verify/resolve flows
    (API_CONTRACT.md §6.2).
    """
    task = session.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task_id,
            OperationTask.state == TaskState.RUNNING.value,
        )
        .values(
            state=TaskState.VERIFICATION_REQUIRED.value,
            lease_owner=None,
            lease_expires_at=None,
            error_code="ambiguous_result",
            updated_at=func.now(),
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if task is None:
        return False
    append_event(session, task_id=task.id, state=task.state, message=message)
    return True
