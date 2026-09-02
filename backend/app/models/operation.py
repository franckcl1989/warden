"""ORM models for operation tasks and their append-only event stream.

docs/DATA_MODEL.md §7.1-§7.3. Column layout mirrors migration
``0005_operation_tasks`` exactly. ``operation_task_events`` is append-only at
two levels (like ``audit_logs``, DATA_MODEL.md §7.3): the database trigger and
the ORM listeners below, so application code cannot silently update or delete
history rows through the session either.

The device mutex (DATA_MODEL.md §7.1) is enforced by the partial unique index
``uq_operation_tasks_active_mutex`` from the migration: at most one active
(queued/running/waiting_device) task per (device_id, conflict_scope) for the
mutex scopes device/component:disk. ``conflict_scope`` is copied from the
operations.json profile at task creation (M2T5). ``attempt_count`` (migration
0012) counts crash-driven recovery requeues of READ-only profiles: a
fence-less read task may start a new attempt bounded by the deployment setting
``operation_read_max_attempts`` (DATA_MODEL.md §7.2); side-effect profiles
never re-execute after the dispatch fence and never consume attempts
(DEVICE_ADAPTERS.md §9).
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.operation import ALL_TASK_STATES
from app.domain.uuid7 import uuid7
from app.models.base import Base

RISK_LEVELS = ("low", "medium", "high")
TASK_STATES = ALL_TASK_STATES
IDEMPOTENCY_KEY_MIN_LENGTH = 8
IDEMPOTENCY_KEY_MAX_LENGTH = 128


class OperationTaskAppendOnlyError(RuntimeError):
    """Raised by the ORM layer when code attempts to mutate an event row."""


class OperationTask(Base):
    """One persisted human operation instance (docs/DATA_MODEL.md §7.1).

    The row itself is the only execution authorization (ADR-024): workers
    claim it with conditional UPDATE + lease and never maintain a second
    queue state. ``dispatch_started_at`` is the irreversible dispatch fence
    (DEVICE_ADAPTERS.md §9) and must be committed BEFORE any device call.
    """

    __tablename__ = "operation_tasks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    requirement_id: Mapped[str] = mapped_column(String(32), nullable=False)
    capability_key: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    parameters: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    conflict_scope: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    current_step: Mapped[str | None] = mapped_column(Text)
    lease_owner: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    dispatch_started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    plan_hash: Mapped[str | None] = mapped_column(String(64))
    parameter_hash: Mapped[str | None] = mapped_column(String(64))
    adapter_version: Mapped[str | None] = mapped_column(String(32))
    device_job_id: Mapped[str | None] = mapped_column(String(128))
    timeout_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(32))
    error_detail: Mapped[str | None] = mapped_column(Text)
    verification_state: Mapped[str | None] = mapped_column(String(16))
    evidence: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    __table_args__ = (
        Index("ix_operation_tasks_state_lease", "state", "lease_expires_at"),
        Index("ix_operation_tasks_state_timeout", "state", "timeout_at"),
        Index("ix_operation_tasks_device_created", "device_id", "created_at"),
        Index("ix_operation_tasks_requested_by_created", "requested_by", "created_at"),
        CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="ck_operation_tasks_risk_level"),
        CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9._-]+$' AND char_length(idempotency_key) BETWEEN 8 AND 128",
            name="ck_operation_tasks_idempotency_key",
        ),
        CheckConstraint(
            "char_length(conflict_scope) BETWEEN 1 AND 32",
            name="ck_operation_tasks_conflict_scope",
        ),
        CheckConstraint(
            "state IN ('queued', 'running', 'waiting_device', 'succeeded', 'failed', "
            "'timed_out', 'cancelled', 'verification_required')",
            name="ck_operation_tasks_state",
        ),
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_operation_tasks_progress_percent",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_operation_tasks_attempt_count"),
        CheckConstraint("version >= 1", name="ck_operation_tasks_version"),
    )
    # docs/DATA_MODEL.md §7.1: 同一设备存在 running/waiting_device 变更任务时，
    # 数据库约束阻止第二个冲突任务进入运行。The device mutex is enforced by the
    # partial UNIQUE index ``uq_operation_tasks_active_mutex`` declared in
    # migration 0005 (partial predicates cannot be expressed on the model).


class OperationTaskEvent(Base):
    """Append-only progress event for a task (docs/DATA_MODEL.md §7.3).

    ``state`` is the task state AT the time of the event; ``message`` is a
    sanitized human-readable summary (no credentials, no vendor response
    bodies, no file paths — SECURITY.md §10/§12).
    """

    __tablename__ = "operation_task_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("operation_tasks.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    step: Mapped[str | None] = mapped_column(String(128))
    progress_percent: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str | None] = mapped_column(Text)
    device_job_id: Mapped[str | None] = mapped_column(String(128))
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_operation_task_events_task_occurred", "task_id", "occurred_at"),
        CheckConstraint(
            "progress_percent IS NULL OR (progress_percent >= 0 AND progress_percent <= 100)",
            name="ck_operation_task_events_progress_percent",
        ),
    )


class PreviewTokenUse(Base):
    """Single-use ledger for operation preview tokens (migration 0010).

    SECURITY.md §4 item 7 (一次性) + §13 (重放确认令牌不能产生第二次执行):
    the signed 60 s TTL is not enough on its own — within the window a
    replayed token with a fresh Idempotency-Key would create a second task
    for non-mutex conflict scopes. Every issued token hash is INSERTed at
    issue time; confirm atomically claims the row (conditional UPDATE on
    ``consumed_at IS NULL``) in the SAME transaction that creates the task,
    so a replay matches zero rows and a rolled-back confirm un-consumes.

    The table is purgeable (rows only cover the token window): the retention
    sweep removes them after a 1-hour lifetime
    (``application/maintenance.py``); 0010 transferred ownership to
    ``warden_app`` so the sweep's DELETE runs as the worker account.
    """

    __tablename__ = "preview_token_uses"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operation_tasks.id", ondelete="CASCADE")
    )

    __table_args__ = (
        Index("ix_preview_token_uses_expires_at", "expires_at"),
        CheckConstraint(
            "(consumed_at IS NULL AND consumed_by_task_id IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_by_task_id IS NOT NULL)",
            name="ck_preview_token_uses_consumed",
        ),
    )


@event.listens_for(OperationTaskEvent, "before_update")
def _reject_event_update(_mapper: object, _connection: object, _target: object) -> None:
    raise OperationTaskAppendOnlyError("operation_task_events is append-only: updates are rejected")


@event.listens_for(OperationTaskEvent, "before_delete")
def _reject_event_delete(_mapper: object, _connection: object, _target: object) -> None:
    raise OperationTaskAppendOnlyError("operation_task_events is append-only: deletes are rejected")
