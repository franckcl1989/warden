"""ORM models for the observation pipeline (docs/DATA_MODEL.md §5/§6/§11).

Column layout mirrors migration ``0006_collection_and_metrics`` exactly.
Notes that matter for ORM usage:

- ``metric_points`` is day-partitioned (``postgresql_partition_by``); the
  composite primary key ``(id, observed_at)`` reflects the PostgreSQL rule
  that unique keys on partitioned tables must include the partition key. The
  at-least-once dedupe index is a COALESCE expression index declared in the
  migration (expression indexes are not mirrored as model constraints).
- ``device_events``/``alerts`` dedupe is enforced by partial unique indexes
  declared in the migration (partial predicates are not model constraints).
- ``ui_events.id`` is BIGSERIAL — the SSE event id (Last-Event-ID ordering).
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.uuid7 import uuid7
from app.models.base import Base

COLLECTION_TYPES = ("reachability", "health", "metrics", "logs", "discovery")
COLLECTION_STATES = ("scheduled", "running", "succeeded", "partial", "failed", "cancelled")
EVENT_SEVERITIES = ("unknown", "info", "warning", "critical")
EVENT_SOURCES = ("redfish_sel", "dsm_log", "snmp_trap", "syslog", "poll", "oem_log")
ALERT_STATUSES = ("active", "resolved")
METRIC_QUALITIES = ("good", "partial", "error")


class CollectionRun(Base):
    """One planned device read pass (docs/DATA_MODEL.md §5.1, ADR-024).

    The row itself is the execution authorization: workers claim it with a
    conditional UPDATE + lease (FOR UPDATE SKIP LOCKED); the partial unique
    index ``uq_collection_runs_active`` guarantees at most one
    scheduled/running run per (device_id, collection_type).
    """

    __tablename__ = "collection_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    collection_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scheduled_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    error_code: Mapped[str | None] = mapped_column(String(32))
    error_summary: Mapped[str | None] = mapped_column(Text)
    lease_owner: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_collection_runs_device_scheduled", "device_id", "scheduled_at"),
        Index("ix_collection_runs_state_scheduled", "state", "scheduled_at"),
        CheckConstraint(
            "collection_type IN ('reachability', 'health', 'metrics', 'logs', 'discovery')",
            name="ck_collection_runs_collection_type",
        ),
        CheckConstraint(
            "state IN ('scheduled', 'running', 'succeeded', 'partial', 'failed', 'cancelled')",
            name="ck_collection_runs_state",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_collection_runs_attempt_count"),
        CheckConstraint("success_count >= 0", name="ck_collection_runs_success_count"),
        CheckConstraint("failure_count >= 0", name="ck_collection_runs_failure_count"),
    )
    # DATA_MODEL.md §5.1: one scheduled/running run per (device, type) is
    # enforced by the partial unique index ``uq_collection_runs_active``
    # declared in migration 0006.


class MetricPoint(Base):
    """One raw observation point (docs/DATA_MODEL.md §5.2), day-partitioned."""

    __tablename__ = "metric_points"
    __table_args__ = (
        CheckConstraint("quality IN ('good', 'partial', 'error')", name="ck_metric_points_quality"),
        CheckConstraint(
            "(value_double IS NULL) <> (value_text IS NULL)",
            name="ck_metric_points_exactly_one_value",
        ),
        Index("ix_metric_points_series", "device_id", "component_id", "metric_key", "observed_at"),
        {"postgresql_partition_by": "RANGE (observed_at)"},
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    observed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), primary_key=True, nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    metric_key: Mapped[str] = mapped_column(String(64), nullable=False)
    value_double: Mapped[float | None] = mapped_column(Float)
    value_text: Mapped[str | None] = mapped_column(String(64))
    unit: Mapped[str | None] = mapped_column(String(32))
    quality: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="SET NULL")
    )


class MetricLatest(Base):
    """Current trusted value per (device, component, metric) (DATA_MODEL §5.3)."""

    __tablename__ = "metric_latest"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    metric_key: Mapped[str] = mapped_column(String(64), nullable=False)
    value_double: Mapped[float | None] = mapped_column(Float)
    value_text: Mapped[str | None] = mapped_column(String(64))
    unit: Mapped[str | None] = mapped_column(String(32))
    quality: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("quality IN ('good', 'partial', 'error')", name="ck_metric_latest_quality"),
        CheckConstraint(
            "(value_double IS NULL) <> (value_text IS NULL)",
            name="ck_metric_latest_exactly_one_value",
        ),
    )
    # UNIQUE (device_id, COALESCE(component_id, zero-uuid), metric_key) is the
    # expression index ``uq_metric_latest_device_component_key`` from 0006.


class MetricRollup5m(Base):
    """5-minute numeric-gauge window aggregate (docs/DATA_MODEL.md §5.4).

    Columns mirror migration ``0007_rollups`` exactly. Only closed UTC-aligned
    5-minute windows of numeric gauge keys are written (state/boolean/
    monotonic_counter series are never numerically aggregated). Rows are
    idempotently regenerated (ON CONFLICT DO UPDATE on the COALESCE expression
    index). Not partitioned: retention deletes by ``window_start``.
    """

    __tablename__ = "metric_rollups_5m"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    metric_key: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    min_value: Mapped[float] = mapped_column(Float, nullable=False)
    max_value: Mapped[float] = mapped_column(Float, nullable=False)
    avg_value: Mapped[float] = mapped_column(Float, nullable=False)
    last_value: Mapped[float] = mapped_column(Float, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    quality: Mapped[str] = mapped_column(String(16), nullable=False)
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("count >= 1", name="ck_metric_rollups_5m_count"),
        CheckConstraint("quality IN ('good', 'partial')", name="ck_metric_rollups_5m_quality"),
    )
    # UNIQUE (device_id, COALESCE(component_id, zero-uuid), metric_key,
    # window_start) + the series/window_start indexes are declared in 0007.


class MetricRollup1h(Base):
    """1-hour numeric-gauge aggregate of twelve closed 5m windows (§5.4)."""

    __tablename__ = "metric_rollups_1h"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    metric_key: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    min_value: Mapped[float] = mapped_column(Float, nullable=False)
    max_value: Mapped[float] = mapped_column(Float, nullable=False)
    avg_value: Mapped[float] = mapped_column(Float, nullable=False)
    last_value: Mapped[float] = mapped_column(Float, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    quality: Mapped[str] = mapped_column(String(16), nullable=False)
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("count >= 1", name="ck_metric_rollups_1h_count"),
        CheckConstraint("quality IN ('good', 'partial')", name="ck_metric_rollups_1h_quality"),
    )
    # Same unique/series/window_start indexes as metric_rollups_5m (0007).


class DeviceEvent(Base):
    """A time-point fact from SEL/logs/traps/syslog/poll (docs/DATA_MODEL.md §5.5)."""

    __tablename__ = "device_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    native_event_id: Mapped[str | None] = mapped_column(String(128))
    dedupe_hash: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index("ix_device_events_device_occurred", "device_id", text("occurred_at DESC")),
        CheckConstraint(
            "severity IN ('unknown', 'info', 'warning', 'critical')",
            name="ck_device_events_severity",
        ),
        CheckConstraint(
            "source IN ('redfish_sel', 'dsm_log', 'snmp_trap', 'syslog', 'poll', 'oem_log')",
            name="ck_device_events_source",
        ),
    )
    # Dedupe unique indexes (native id with NULLS NOT DISTINCT, content-hash
    # partial) are declared in migration 0006.


class CollectionObservationError(Base):
    """Per-observation failure record (docs/DATA_MODEL.md §5.2)."""

    __tablename__ = "collection_observation_errors"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    collection_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("collection_runs.id", ondelete="CASCADE")
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    metric_key_or_event_key: Mapped[str | None] = mapped_column(String(64))
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    error_code: Mapped[str] = mapped_column(String(32), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_collection_observation_errors_run", "collection_run_id"),
        Index("ix_collection_observation_errors_device_occurred", "device_id", "occurred_at"),
    )


class Alert(Base):
    """An open or resolved current problem (docs/DATA_MODEL.md §6, ADR-025)."""

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("components.id", ondelete="SET NULL"))
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    first_occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    signal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_alerts_device_status", "device_id", "status"),
        Index("ix_alerts_status_last_occurred", "status", "last_occurred_at"),
        CheckConstraint("severity IN ('warning', 'critical')", name="ck_alerts_severity"),
        CheckConstraint("status IN ('active', 'resolved')", name="ck_alerts_status"),
        CheckConstraint("signal_count >= 0", name="ck_alerts_signal_count"),
        CheckConstraint("version >= 1", name="ck_alerts_version"),
    )
    # DATA_MODEL.md §6.1: one active alert per dedupe_key via the partial
    # unique index ``uq_alerts_active_dedupe`` declared in migration 0006.


class UiEvent(Base):
    """Short-lived SSE payload (docs/DATA_MODEL.md §11): BIGSERIAL id = SSE id."""

    __tablename__ = "ui_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_ui_events_occurred", "occurred_at"),)
