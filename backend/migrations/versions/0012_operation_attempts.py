"""Read-profile attempt bound on operation tasks (M2T6).

PLT-05 操作任务执行 (docs/DATA_MODEL.md §7.2, DEVICE_ADAPTERS.md §9): a
crash-driven recovery requeue of a READ-only profile starts a NEW attempt
(``side_effect=false`` may retry the read call, bounded; a task with a
persisted ``device_job_id`` only ever queries the original job). The
``attempt_count`` column counts the recovery requeues already granted: the
maintenance sweep requeues a fence-less read task only while
``attempt_count < operation_read_max_attempts - 1`` (the initial run is
attempt 1) and otherwise fails the task terminally instead of spinning a
crashing worker forever. Side-effect profiles never re-execute after the
dispatch fence and never consume an attempt (DEVICE_ADAPTERS.md §9).

Additive column on the EXISTING ``operation_tasks`` table: no new tables, no
new sequences, no ownership/privilege changes (the 0008 ownership transfer and
0009 blanket S/I/U grants already cover ``operation_tasks``; ALTER TABLE ADD
COLUMN runs as ``warden_migrate``).

Rollback plan: downgrade drops the column and its CHECK constraint (SQLite
irrelevant — PostgreSQL only; ``ALTER TABLE ... DROP CONSTRAINT`` then ``DROP
COLUMN``). Data validation: the CHECK ``attempt_count >= 0`` mirrors the ORM
model; the value only ever moves 0 -> 1 -> ... at recovery requeues, bounded
by the deployment setting. Space estimate: one small integer per operation
task row — bounded by task volume; no capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_operation_attempts"
down_revision = "0011_files"
branch_labels = None
depends_on = None

CHECK_NAME = "ck_operation_tasks_attempt_count"


def upgrade() -> None:
    op.add_column(
        "operation_tasks",
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        CHECK_NAME,
        "operation_tasks",
        "attempt_count >= 0",
    )


def downgrade() -> None:
    op.drop_constraint(CHECK_NAME, "operation_tasks", type_="check")
    op.drop_column("operation_tasks", "attempt_count")
