"""Operation tasks and their append-only event stream (docs/DATA_MODEL.md §7).

M2T1 (PLT-05 操作任务与恢复 / PLT-03 采集任务持久化): the PostgreSQL-backed
task engine foundation (ADR-024). ``operation_tasks`` is the row that IS the
execution authorization: workers claim it with conditional UPDATE + lease
(``FOR UPDATE SKIP LOCKED``), transitions and their events commit in the same
transaction (DATA_MODEL.md §11), and the lease recovery + timeout sweeps are
the worker maintenance loop's inputs.

Design notes:

- ``conflict_scope`` is copied verbatim from the operations.json profile at
  task creation (M2T5); the engine never invents per-operation mutex logic.
- Device mutex (DATA_MODEL.md §7.1: 同一设备存在 running/waiting_device 变更
  任务时，数据库约束阻止第二个冲突任务进入运行): the partial UNIQUE index
  ``uq_operation_tasks_active_mutex`` on ``(device_id, conflict_scope)`` over
  ``state IN ('queued','running','waiting_device')`` AND
  ``conflict_scope IN ('device','component:disk')``. For 0.1.0 both scopes map
  to device-level mutual exclusion — two component:disk tasks (e.g. two SMART
  tests) on one device never run concurrently. This is slightly conservative
  and deliberately documented; read scopes (device_read / device_read_heavy)
  and launch scopes are excluded and may overlap freely.
- ``operation_task_events`` is append-only like ``audit_logs`` (DATA_MODEL.md
  §7.3): a PL/pgSQL trigger rejects UPDATE/DELETE and the ORM model raises in
  before_update/before_delete listeners. The task row itself remains editable
  by the engine (state/lease/progress), only the event history is immutable.
- ``idempotency_key`` is validated by a CHECK constraint (8-128 chars,
  ``^[A-Za-z0-9._-]+$``) and is unique per requester (DATA_MODEL.md §7.1:
  unique ``(requested_by, idempotency_key)``).

Rollback plan: downgrade drops the triggers, the trigger function and the
indexes before dropping the tables (reverse dependency order). Data
validation: the CHECK constraints (state/risk_level/idempotency_key/
conflict_scope/progress_percent/version) reject out-of-contract values at the
database; the partial unique index rejects conflicting active tasks. Space
estimate: one bounded row per task plus an append-only event stream — both
retention-managed (365 days, DATA_MODEL.md §10); no capacity promises are made
here (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_operation_tasks"
down_revision = "0004_audit_db_permissions"
branch_labels = None
depends_on = None

APPEND_ONLY_TRIGGER_FUNCTION = "reject_operation_task_events_modification"

TASK_STATES = (
    "queued",
    "running",
    "waiting_device",
    "succeeded",
    "failed",
    "timed_out",
    "cancelled",
    "verification_required",
)
MUTEX_SCOPES = ("device", "component:disk")


def upgrade() -> None:
    op.create_table(
        "operation_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("requirement_id", sa.String(length=32), nullable=False),
        sa.Column("capability_key", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("parameters", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("conflict_scope", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_step", sa.Text(), nullable=True),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dispatch_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("plan_hash", sa.String(length=64), nullable=True),
        sa.Column("parameter_hash", sa.String(length=64), nullable=True),
        sa.Column("adapter_version", sa.String(length=32), nullable=True),
        sa.Column("device_job_id", sa.String(length=128), nullable=True),
        sa.Column("timeout_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("verification_state", sa.String(length=16), nullable=True),
        sa.Column("evidence", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("risk_level IN ('low', 'medium', 'high')", name="ck_operation_tasks_risk_level"),
        sa.CheckConstraint(
            "idempotency_key ~ '^[A-Za-z0-9._-]+$' AND char_length(idempotency_key) BETWEEN 8 AND 128",
            name="ck_operation_tasks_idempotency_key",
        ),
        sa.CheckConstraint("char_length(conflict_scope) BETWEEN 1 AND 32", name="ck_operation_tasks_conflict_scope"),
        sa.CheckConstraint(
            "state IN ('queued', 'running', 'waiting_device', 'succeeded', 'failed', "
            "'timed_out', 'cancelled', 'verification_required')",
            name="ck_operation_tasks_state",
        ),
        sa.CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_operation_tasks_progress_percent",
        ),
        sa.CheckConstraint("version >= 1", name="ck_operation_tasks_version"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("requested_by", "idempotency_key", name="uq_operation_tasks_requested_by_idempotency"),
    )

    op.create_index("ix_operation_tasks_state_lease", "operation_tasks", ["state", "lease_expires_at"])
    op.create_index("ix_operation_tasks_state_timeout", "operation_tasks", ["state", "timeout_at"])
    op.create_index("ix_operation_tasks_device_created", "operation_tasks", ["device_id", "created_at"])
    op.create_index("ix_operation_tasks_requested_by_created", "operation_tasks", ["requested_by", "created_at"])
    # Device mutex: one active (queued/running/waiting_device) task per
    # (device_id, conflict_scope) for the mutex scopes only. Read and launch
    # scopes are excluded so read tasks may overlap (ARCHITECTURE.md §6).
    op.create_index(
        "uq_operation_tasks_active_mutex",
        "operation_tasks",
        ["device_id", "conflict_scope"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('queued', 'running', 'waiting_device') AND conflict_scope IN ('device', 'component:disk')"
        ),
    )

    op.create_table(
        "operation_task_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("step", sa.String(length=128), nullable=True),
        sa.Column("progress_percent", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("device_job_id", sa.String(length=128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "progress_percent IS NULL OR (progress_percent >= 0 AND progress_percent <= 100)",
            name="ck_operation_task_events_progress_percent",
        ),
        sa.ForeignKeyConstraint(["task_id"], ["operation_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_operation_task_events_task_occurred", "operation_task_events", ["task_id", "occurred_at"])

    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'operation_task_events is append-only';
        END;
        $$
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER operation_task_events_no_update
        BEFORE UPDATE ON operation_task_events
        FOR EACH ROW EXECUTE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER operation_task_events_no_delete
        BEFORE DELETE ON operation_task_events
        FOR EACH ROW EXECUTE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS operation_task_events_no_update ON operation_task_events")
    op.execute("DROP TRIGGER IF EXISTS operation_task_events_no_delete ON operation_task_events")
    op.execute(f"DROP FUNCTION IF EXISTS {APPEND_ONLY_TRIGGER_FUNCTION}()")
    op.drop_index("ix_operation_task_events_task_occurred", table_name="operation_task_events")
    op.drop_table("operation_task_events")
    op.drop_index("uq_operation_tasks_active_mutex", table_name="operation_tasks")
    op.drop_index("ix_operation_tasks_requested_by_created", table_name="operation_tasks")
    op.drop_index("ix_operation_tasks_device_created", table_name="operation_tasks")
    op.drop_index("ix_operation_tasks_state_timeout", table_name="operation_tasks")
    op.drop_index("ix_operation_tasks_state_lease", table_name="operation_tasks")
    op.drop_table("operation_tasks")
