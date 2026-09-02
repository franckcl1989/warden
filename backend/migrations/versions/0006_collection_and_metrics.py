"""Collection runs, metrics/events/errors storage, alerts and ui_events.

M2T2 (PLT-03 采集与状态语义 / PLT-04 当前问题展示): the monitoring heart —
docs/DATA_MODEL.md §5 (collection_runs/metric_points/metric_latest/
device_events/collection_observation_errors EXACT fields, quality, unique
keys, partition rules), §6 (alerts: dedupe_key, active/resolved, 恢复规则),
§11 (事务边界: 采集批次一个事务; ui_events 与实体变更同事务写).

Design notes:

- ``collection_runs`` carries the PostgreSQL task-queue semantics of ADR-024:
  state + lease fields, claimed with ``FOR UPDATE SKIP LOCKED``. The partial
  unique index ``uq_collection_runs_active`` enforces DATA_MODEL.md §5.1
  (同一设备同一采集类型最多一个 scheduled/running) at the database.
- ``metric_points`` is partitioned by day on ``observed_at`` (DATA_MODEL.md
  §5.2: 按 observed_at 日分区，预创建未来 14 天). Because PostgreSQL requires
  every unique constraint on a partitioned table to include the partition
  key, the primary key is composite ``(id, observed_at)`` and the at-least-once
  dedupe unique index is on
  ``(device_id, COALESCE(component_id, <zero-uuid>), metric_key, observed_at,
  source)`` — the coalesce makes a NULL component_id (device-scope metric)
  unique-consistent with component-scoped rows (ARCHITECTURE.md §6: 指标允许
 至少一次写入，唯一键去重). ``value_text`` is reserved for enum/boolean
  values (application-validated against contracts/metrics.json — the database
  cannot know the metric type), and exactly one of value_double/value_text is
  always non-null (CHECK).
- ``device_events`` dedup follows DATA_MODEL.md §5.5: native event ID
  preferred (unique ``(device_id, source, native_event_id)`` with NULLS NOT
  DISTINCT so NULL IDs dedupe consistently), and a stable content-hash dedupe
  for events without a native ID (partial unique index over
  ``(device_id, source, dedupe_hash)`` WHERE ``native_event_id IS NULL``).
- ``alerts`` stores the open_after/resolve_after counter durably in
  ``signal_count`` (M2T2 decision: no in-memory counters); the partial unique
  index ``uq_alerts_active_dedupe`` enforces DATA_MODEL.md §6.1 (同一
  dedupe_key 最多一条 active) at the database.
- ``ui_events`` is the short-lived SSE stream (DATA_MODEL.md §11): a BIGSERIAL
  id IS the SSE event id (Last-Event-ID ordering), retained 10 minutes by the
  maintenance loop (M2T3 wires the cleanup; the 10-minute window is a
  deployment concern, not a product page).
- ``devices.collection_state`` is the per-type last-finished map
  ``{collection_type: ISO-8601 finished_at}`` (M2T2 decision: computing
  per-type due-ness from collection_runs history per tick is too expensive;
  the JSONB column is updated in the same transaction that completes a run).

Rollback plan: downgrade drops all M2T2 tables in reverse dependency order
(partitioned metric_points first, which drops its partitions implicitly), then
the added ``devices.collection_state`` column, then the partition helper
function. Data validation: the CHECK constraints (collection_type/state,
quality, exactly-one-value, event severity/source, alert severity/status/
counters) reject out-of-contract values at the database, and the partial
unique indexes reject conflicting active runs/alerts and duplicate
points/events. Space estimate: bounded rows per run/observation/event plus a
day-partitioned points table with retention-managed partitions (DATA_MODEL.md
§10); no capacity promises are made here (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_collection_metrics"
down_revision = "0005_operation_tasks"
branch_labels = None
depends_on = None

ZERO_UUID = "00000000-0000-0000-0000-000000000000"
PARTITION_FUNCTION = "create_metric_partition"
METRIC_PARTITION_DAYS = 14

COLLECTION_TYPES = ("reachability", "health", "metrics", "logs", "discovery")
COLLECTION_STATES = ("scheduled", "running", "succeeded", "partial", "failed", "cancelled")
EVENT_SEVERITIES = ("unknown", "info", "warning", "critical")
EVENT_SOURCES = ("redfish_sel", "dsm_log", "snmp_trap", "syslog", "poll", "oem_log")


def upgrade() -> None:
    # Per-type last-run map maintained on run completion (M2T2 decision,
    # documented in the migration docstring).
    op.add_column(
        "devices",
        sa.Column(
            "collection_state",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    op.create_table(
        "collection_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("collection_type", sa.String(length=16), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "collection_type IN ('reachability', 'health', 'metrics', 'logs', 'discovery')",
            name="ck_collection_runs_collection_type",
        ),
        sa.CheckConstraint(
            "state IN ('scheduled', 'running', 'succeeded', 'partial', 'failed', 'cancelled')",
            name="ck_collection_runs_state",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_collection_runs_attempt_count"),
        sa.CheckConstraint("success_count >= 0", name="ck_collection_runs_success_count"),
        sa.CheckConstraint("failure_count >= 0", name="ck_collection_runs_failure_count"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_collection_runs_device_scheduled", "collection_runs", ["device_id", "scheduled_at"]
    )
    op.create_index(
        "ix_collection_runs_state_scheduled", "collection_runs", ["state", "scheduled_at"]
    )
    # DATA_MODEL.md §5.1: 同一设备同一采集类型最多一个 scheduled/running.
    op.create_index(
        "uq_collection_runs_active",
        "collection_runs",
        ["device_id", "collection_type"],
        unique=True,
        postgresql_where=sa.text("state IN ('scheduled', 'running')"),
    )

    op.create_table(
        "metric_points",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("metric_key", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("value_double", sa.Float(), nullable=True),
        sa.Column("value_text", sa.String(length=64), nullable=True),
        sa.Column("unit", sa.String(length=32), nullable=True),
        sa.Column("quality", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("collection_run_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint("quality IN ('good', 'partial', 'error')", name="ck_metric_points_quality"),
        sa.CheckConstraint(
            "(value_double IS NULL) <> (value_text IS NULL)",
            name="ck_metric_points_exactly_one_value",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["collection_run_id"], ["collection_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", "observed_at"),
        postgresql_partition_by="RANGE (observed_at)",
    )
    op.create_index(
        "uq_metric_points_dedup",
        "metric_points",
        [
            sa.text("device_id"),
            sa.text(f"COALESCE(component_id, '{ZERO_UUID}')"),
            sa.text("metric_key"),
            sa.text("observed_at"),
            sa.text("source"),
        ],
        unique=True,
    )
    op.create_index(
        "ix_metric_points_series",
        "metric_points",
        ["device_id", "component_id", "metric_key", "observed_at"],
    )

    op.create_table(
        "metric_latest",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("metric_key", sa.String(length=64), nullable=False),
        sa.Column("value_double", sa.Float(), nullable=True),
        sa.Column("value_text", sa.String(length=64), nullable=True),
        sa.Column("unit", sa.String(length=32), nullable=True),
        sa.Column("quality", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collection_run_id", sa.Uuid(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("quality IN ('good', 'partial', 'error')", name="ck_metric_latest_quality"),
        sa.CheckConstraint(
            "(value_double IS NULL) <> (value_text IS NULL)",
            name="ck_metric_latest_exactly_one_value",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["collection_run_id"], ["collection_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_metric_latest_device_component_key",
        "metric_latest",
        [
            sa.text("device_id"),
            sa.text(f"COALESCE(component_id, '{ZERO_UUID}')"),
            sa.text("metric_key"),
        ],
        unique=True,
    )

    op.create_table(
        "device_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("native_event_id", sa.String(length=128), nullable=True),
        sa.Column("dedupe_hash", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.CheckConstraint(
            "severity IN ('unknown', 'info', 'warning', 'critical')",
            name="ck_device_events_severity",
        ),
        sa.CheckConstraint(
            "source IN ('redfish_sel', 'dsm_log', 'snmp_trap', 'syslog', 'poll', 'oem_log')",
            name="ck_device_events_source",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_device_events_device_occurred",
        "device_events",
        [sa.text("device_id"), sa.text("occurred_at DESC")],
    )
    # DATA_MODEL.md §5.5: native event ID dedupe (NULLS NOT DISTINCT keeps
    # NULL-ID rows consistent) and content-hash dedupe for events without an ID.
    op.create_index(
        "uq_device_events_native",
        "device_events",
        ["device_id", "source", "native_event_id"],
        unique=True,
        postgresql_nulls_not_distinct=True,
    )
    op.create_index(
        "uq_device_events_hash",
        "device_events",
        ["device_id", "source", "dedupe_hash"],
        unique=True,
        postgresql_where=sa.text("native_event_id IS NULL"),
    )

    op.create_table(
        "collection_observation_errors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("collection_run_id", sa.Uuid(), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("metric_key_or_event_key", sa.String(length=64), nullable=True),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("error_code", sa.String(length=32), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["collection_run_id"], ["collection_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_collection_observation_errors_run",
        "collection_observation_errors",
        ["collection_run_id"],
    )
    op.create_index(
        "ix_collection_observation_errors_device_occurred",
        "collection_observation_errors",
        ["device_id", "occurred_at"],
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("component_id", sa.Uuid(), nullable=True),
        sa.Column("rule_key", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("evidence", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column("signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("severity IN ('warning', 'critical')", name="ck_alerts_severity"),
        sa.CheckConstraint("status IN ('active', 'resolved')", name="ck_alerts_status"),
        sa.CheckConstraint("signal_count >= 0", name="ck_alerts_signal_count"),
        sa.CheckConstraint("version >= 1", name="ck_alerts_version"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_device_status", "alerts", ["device_id", "status"])
    op.create_index("ix_alerts_status_last_occurred", "alerts", ["status", "last_occurred_at"])
    # DATA_MODEL.md §6.1: 同一 dedupe_key 最多一条 active.
    op.create_index(
        "uq_alerts_active_dedupe",
        "alerts",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "ui_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ui_events_occurred", "ui_events", ["occurred_at"])

    # Day-partition helper + pre-created partition window (DATA_MODEL.md §5.2:
    # 按 observed_at 日分区，预创建未来 14 天). M2T3 wires the daily call into
    # the maintenance loop; the function is created here so both the migration
    # and the maintenance loop share one implementation. Plain literals: the
    # function name is fixed migration history (no interpolation needed).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION create_metric_partition(target_date date)
        RETURNS boolean
        LANGUAGE plpgsql
        AS $$
        DECLARE
            part_name text := 'metric_points_' || to_char(target_date, 'YYYY_MM_DD');
        BEGIN
            IF to_regclass('public.' || part_name) IS NOT NULL THEN
                RETURN false;
            END IF;
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF metric_points FOR VALUES FROM (%L) TO (%L)',
                part_name,
                target_date::timestamp,
                (target_date + 1)::timestamp
            );
            RETURN true;
        END;
        $$
        """
    )
    # 14 days: today through today+13 (plain literal — fixed migration history).
    op.execute(
        """
        SELECT create_metric_partition(day::date)
        FROM generate_series(current_date, current_date + 13, '1 day'::interval) AS day
        """
    )
def downgrade() -> None:
    op.drop_index("uq_alerts_active_dedupe", table_name="alerts")
    op.drop_index("ix_alerts_status_last_occurred", table_name="alerts")
    op.drop_index("ix_alerts_device_status", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_ui_events_occurred", table_name="ui_events")
    op.drop_table("ui_events")
    op.drop_index("ix_collection_observation_errors_device_occurred", table_name="collection_observation_errors")
    op.drop_index("ix_collection_observation_errors_run", table_name="collection_observation_errors")
    op.drop_table("collection_observation_errors")
    op.drop_index("uq_device_events_hash", table_name="device_events")
    op.drop_index("uq_device_events_native", table_name="device_events")
    op.drop_index("ix_device_events_device_occurred", table_name="device_events")
    op.drop_table("device_events")
    op.drop_index("uq_metric_latest_device_component_key", table_name="metric_latest")
    op.drop_table("metric_latest")
    op.drop_index("ix_metric_points_series", table_name="metric_points")
    op.drop_index("uq_metric_points_dedup", table_name="metric_points")
    op.drop_table("metric_points")
    op.drop_index("uq_collection_runs_active", table_name="collection_runs")
    op.drop_index("ix_collection_runs_state_scheduled", table_name="collection_runs")
    op.drop_index("ix_collection_runs_device_scheduled", table_name="collection_runs")
    op.drop_table("collection_runs")
    op.drop_column("devices", "collection_state")
    op.execute(f"DROP FUNCTION IF EXISTS {PARTITION_FUNCTION}(date)")
