"""Metric rollup tables: metric_rollups_5m and metric_rollups_1h (M2T3).

docs/DATA_MODEL.md §5.4 (only numeric gauge/rate windows get min/max/avg/last/
count/quality — states are never numerically aggregated; the joint unique key
is device/component/metric/window_start; 5m derives from raw points and 1h
from closed 5m windows, both idempotently recomputable), §10 (retention: 5m
rollups 30 days, 1h rollups 180 days — both deleted by window_start, so NO
partitioning on the rollup tables; the daily maintenance sweep deletes by the
window_start index added below), §12 (additive migration).

Design notes:

- ``window_start`` is the UTC-aligned window start (5-minute / 1-hour
  boundaries); a window covers [window_start, window_start + interval) and
  only fully closed windows are ever written (M2T3 brief: 幂等重算 from closed
  windows).
- The COALESCE(component_id, <zero-uuid>) unique expression mirrors
  metric_points/metric_latest (0006): NULL component_id (device-scope rows)
  stays unique-consistent with component-scoped rows, and gives the upsert a
  conflict target for idempotent regeneration.
- ``collection_run_id`` carries the provenance of the last aggregated point
  (nullable — rollup windows may aggregate many runs).
- CHECK constraints keep the storage honest: exactly the numeric gauge
  statistics with count >= 1 and contract quality values; value statistics
  are NOT NULL because a row is only created for a window that had points.

Rollback plan: downgrade drops both tables (indexes drop implicitly).
Data validation: CHECK constraints reject count < 1, non-contract quality and
NULL statistics. Space estimate: one row per (device, component, metric,
closed window) — bounded by the tiered retention of DATA_MODEL.md §10; no
capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_rollups"
down_revision = "0006_collection_metrics"
branch_labels = None
depends_on = None

ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def _create_rollup_table(table_name: str, index_name: str) -> None:
    op.create_table(
        table_name,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("metric_key", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("min_value", sa.Float(), nullable=False),
        sa.Column("max_value", sa.Float(), nullable=False),
        sa.Column("avg_value", sa.Float(), nullable=False),
        sa.Column("last_value", sa.Float(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("quality", sa.String(length=16), nullable=False),
        sa.Column("collection_run_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint("count >= 1", name=f"ck_{table_name}_count"),
        sa.CheckConstraint(
            "quality IN ('good', 'partial')", name=f"ck_{table_name}_quality"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["collection_run_id"], ["collection_runs.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # DATA_MODEL.md §5.4: 联合唯一键为设备、组件、指标和窗口开始 (COALESCE
    # keeps device-scope rows consistent with component-scoped rows).
    op.create_index(
        f"uq_{index_name}",
        table_name,
        [
            sa.text("device_id"),
            sa.text(f"COALESCE(component_id, '{ZERO_UUID}')"),
            sa.text("metric_key"),
            sa.text("window_start"),
        ],
        unique=True,
    )
    op.create_index(
        f"ix_{index_name}_series",
        table_name,
        [sa.text("device_id"), sa.text("component_id"), sa.text("metric_key"), sa.text("window_start DESC")],
    )
    # Retention deletes and the 1h-from-5m aggregation read by window_start:
    # a leading window_start index keeps the daily sweep and the per-pass
    # aggregation off full table scans (DATA_MODEL.md §10).
    op.create_index(f"ix_{index_name}_window_start", table_name, ["window_start"])


def upgrade() -> None:
    _create_rollup_table("metric_rollups_5m", "metric_rollups_5m")
    _create_rollup_table("metric_rollups_1h", "metric_rollups_1h")


def downgrade() -> None:
    op.drop_table("metric_rollups_1h")
    op.drop_table("metric_rollups_5m")
