"""Replace metric COALESCE-expression unique indexes with partial pairs (M6T4b).

M6T4b (platform reliability, PLT-03 foundation): the metric uniqueness
indexes built in 0006/0007 were COALESCE *expression* indexes, and the
matching upserts targeted them with a conflict arbiter that contained a
PARAMETER — SQLAlchemy renders ``func.coalesce(column, cast('0000…', Uuid))``
as ``coalesce(component_id, $1::uuid)``. psycopg3 auto-prepares a statement
after ``prepare_threshold`` (default 5) executions on the same connection;
once the server switches that prepared statement to a GENERIC plan the
parameter can no longer be folded into the index-inference comparison and
PostgreSQL raises

    InvalidColumnReference: there is no unique or exclusion constraint
    matching the ON CONFLICT specification

intermittently (the M6T4 load smoke recorded 9 handler_failed in the
collection pool; the minimal repro fails 30-50 of 60 under default settings
and 0/120 with auto-prepare disabled — LOAD_SMOKE.md, M6T4 report §3).

This migration makes correctness independent of planner/prepare behaviour:
each COALESCE expression index becomes TWO partial unique indexes whose
predicates are constant, parameter-free expressions (``component_id IS NOT
NULL`` / ``component_id IS NULL``), so the ON CONFLICT arbiter clauses that
match them (plain column lists + constant predicates) never depend on plan
caching:

    metric_points   uq_metric_points_dedup
                    -> uq_metric_points_dedup_component (device_id,
                       component_id, metric_key, observed_at, source)
                       WHERE component_id IS NOT NULL
                    -> uq_metric_points_dedup_device (device_id, metric_key,
                       observed_at, source) WHERE component_id IS NULL
    metric_latest   uq_metric_latest_device_component_key
                    -> uq_metric_latest_series_component (device_id,
                       component_id, metric_key) WHERE component_id IS NOT NULL
                    -> uq_metric_latest_series_device (device_id, metric_key)
                       WHERE component_id IS NULL
    metric_rollups_5m / _1h (0007) mirror the metric_latest shape with
                       window_start appended (…_component / …_device).

The COALESCE semantics are preserved exactly: the expression never merged a
NULL component_id row with a real component's row — it only mapped NULL to
the zero-uuid *placeholder* so NULL rows got a real key — and the pair keeps
every NULL-component (device-scope) row unique per (device, metric_key,
…) within its own partition while component-scoped rows stay unique per
(device, component_id, metric_key, …). Only a hypothetical real component
whose id were the zero uuid would now coexist with a device-scope row of the
same key (no component row can ever have that id: components ids come from
the pipeline, and the FK only ever SET NULLs on deletion).

metric_points is day-partitioned: PostgreSQL propagates the parent's unique
index (partial predicate included) to every partition; the partition key
(observed_at) is part of both pair members, so per-partition uniqueness is
global uniqueness and the at-least-once dedupe keeps working for the
DO NOTHING (no-arbiter) point inserts.

The store upserts (observation_store.persist_observation_batch for
metric_latest, application/maintenance.py for the rollups) now split rows by
component_id NULL-ness and issue two statements whose arbiters are
``ON CONFLICT (…) WHERE component_id IS (NOT) NULL DO UPDATE`` — column
lists and constant predicates only, no parameters anywhere in the conflict
target.

Rollback plan: downgrade drops the pair and recreates the exact 0006/0007
expression indexes (same names/definitions) so old code keeps working and a
full ``downgrade base`` stays clean. Existing data never violates either
shape: the pair is strictly weaker than the expression index (the only
relaxed case is the impossible zero-uuid-component row above).
Data validation: the partial unique pairs enforce the same duplicate
rejection as the expression indexes for every real row shape (regression:
tests/infrastructure/test_upsert_prepare.py). Space estimate: two narrower
indexes replace one expression index per table — no capacity promises
(ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_metric_dedupe_partial"
down_revision = "0015_system_state"
branch_labels = None
depends_on = None

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

# (table, expression index name + definition, pair names): the column lists
# are static migration history (no interpolation beyond the fixed ZERO_UUID).
_TABLE_INDEXES = (
    {
        "table": "metric_points",
        "expression_name": "uq_metric_points_dedup",
        "expression_columns": [
            "device_id",
            f"COALESCE(component_id, '{ZERO_UUID}')",
            "metric_key",
            "observed_at",
            "source",
        ],
        "component_name": "uq_metric_points_dedup_component",
        "component_columns": ["device_id", "component_id", "metric_key", "observed_at", "source"],
        "device_name": "uq_metric_points_dedup_device",
        "device_columns": ["device_id", "metric_key", "observed_at", "source"],
    },
    {
        "table": "metric_latest",
        "expression_name": "uq_metric_latest_device_component_key",
        "expression_columns": ["device_id", f"COALESCE(component_id, '{ZERO_UUID}')", "metric_key"],
        "component_name": "uq_metric_latest_series_component",
        "component_columns": ["device_id", "component_id", "metric_key"],
        "device_name": "uq_metric_latest_series_device",
        "device_columns": ["device_id", "metric_key"],
    },
    {
        "table": "metric_rollups_5m",
        "expression_name": "uq_metric_rollups_5m",
        "expression_columns": [
            "device_id",
            f"COALESCE(component_id, '{ZERO_UUID}')",
            "metric_key",
            "window_start",
        ],
        "component_name": "uq_metric_rollups_5m_component",
        "component_columns": ["device_id", "component_id", "metric_key", "window_start"],
        "device_name": "uq_metric_rollups_5m_device",
        "device_columns": ["device_id", "metric_key", "window_start"],
    },
    {
        "table": "metric_rollups_1h",
        "expression_name": "uq_metric_rollups_1h",
        "expression_columns": [
            "device_id",
            f"COALESCE(component_id, '{ZERO_UUID}')",
            "metric_key",
            "window_start",
        ],
        "component_name": "uq_metric_rollups_1h_component",
        "component_columns": ["device_id", "component_id", "metric_key", "window_start"],
        "device_name": "uq_metric_rollups_1h_device",
        "device_columns": ["device_id", "metric_key", "window_start"],
    },
)


def upgrade() -> None:
    for config in _TABLE_INDEXES:
        op.drop_index(config["expression_name"], table_name=config["table"])
        op.create_index(
            config["component_name"],
            config["table"],
            config["component_columns"],
            unique=True,
            postgresql_where=sa.text("component_id IS NOT NULL"),
        )
        op.create_index(
            config["device_name"],
            config["table"],
            config["device_columns"],
            unique=True,
            postgresql_where=sa.text("component_id IS NULL"),
        )


def downgrade() -> None:
    for config in reversed(_TABLE_INDEXES):
        op.drop_index(config["component_name"], table_name=config["table"])
        op.drop_index(config["device_name"], table_name=config["table"])
        op.create_index(
            config["expression_name"],
            config["table"],
            [sa.text(column) for column in config["expression_columns"]],
            unique=True,
        )
