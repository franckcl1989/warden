"""Rollup generation and retention maintenance (M2T3).

docs/DATA_MODEL.md §5.4 (rollups: gauge-only, closed windows, idempotent
regeneration), §10 (tiered retention table), DEPLOYMENT.md §9.3 (每 5 分钟
生成指标聚合; 每日创建未来分区并执行保留清理), ARCHITECTURE.md §3.3 (维护循环).
The workers/maintenance.py loop calls these on their cadences; tests call them
directly with an injected ``now``.

Rollup semantics:

- ``generate_rollups`` regenerates every closed 5-minute window in
  [max(floor5(now) - REGENERATION_LOOKBACK, raw retention floor,
  marker + 5m), floor5(now)) from raw metric_points. The just-closed window
  plus a small lookback lets points committed a few minutes late fold in;
  the marker (newest existing 5m row) catches windows up after worker
  downtime, bounded by the raw retention floor — a window whose raw points
  were already dropped can never be rebuilt.
- The 1h pass targets every fully closed hour whose newest (last) window lies
  in that range — the pass that closes an hour's last window builds its
  hourly row, and a catch-up pass re-closes every gap hour the same way.
  Aggregation is the documented choice of DATA_MODEL.md §5.4: min of the
  window minimums, max of the window maximums, simple mean of the window
  averages with count summed, last value of the newest window, quality
  ``partial`` when any window is partial. Only windows that have rows
  contribute — a window without data has no row and is never invented.
- Both tables are upserted (ON CONFLICT DO UPDATE on the COALESCE key), so
  regeneration is idempotent: a rerun converges to identical rows.

Retention semantics (DATA_MODEL.md §10) and the production privilege model
(migration 0008_retention_grants):

- The maintenance worker runs as ``warden_app``, which OWNS the purgeable
  tables after 0008 — that ownership is what makes this sweep deployable:
  warden_app can DELETE rows and DROP old metric_points partitions, and it
  has CREATE on schema public to pre-create the future partition window.
  audit_logs/operation_task_events stay owned by the migration role with
  their REVOKE + append-only triggers (0002/0005) — never touched here.
- Raw metric_points leave by DROP of whole day partitions whose range END is
  at or before the cutoff (day granularity is the documented precision of the
  partition scheme — the partition that straddles the cutoff is kept whole).
- Every other purgeable table is batch-deleted in PK-ordered chunks of
  ``DELETE_BATCH_SIZE``, counted (DATA_MODEL.md §10: 分批删除).
- Terminal operation tasks age out by DELETE **only when no event row exists**:
  the 0005 append-only trigger on operation_task_events (DATABASE-level,
  ADR-030) makes the FK cascade impossible — PostgreSQL fires child row
  triggers on FK actions, so deleting an evented task raises. Eventless
  terminal tasks (never claimed/transitioned) are the only ones removable at
  the application layer; evented tasks stay with their append-only stream
  and leave only through out-of-band database administration (ADR-030).
- Sessions are cleaned 30 days after revocation or absolute expiry, except
  sessions referenced by audit_logs.session_id: the FK is ON DELETE SET NULL
  and the 0002 audit trigger rejects that internal UPDATE (PostgreSQL fires
  child BEFORE UPDATE triggers on FK SET NULL actions), so an audit-linked
  session survives as long as its audit rows do — the audit stream is
  permanent (ADR-030), and the sweep records honest counts instead of
  crashing on a daily cadence.
- The append-only streams themselves (audit_logs, operation_task_events) are
  exempt from automatic retention purge (ADR-030): the sweep probes their
  no-delete triggers once per pass and reports
  ``audit_skipped_append_only`` / ``operation_task_events_skipped_append_only``
  so a tampered trigger state (flag False) is visible instead of silently
  deleting history. ui_events keep their 10-minute SSE window
  (DATA_MODEL.md §11).
"""

from __future__ import annotations

import contextlib
import datetime
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import Uuid, cast, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.application.files import storage_key
from app.config import WardenSettings
from app.generated.metrics import METRIC_DEFINITIONS
from app.infrastructure.audit import AuditLogger
from app.infrastructure.files import FileStorage, FileStorageError
from app.infrastructure.observation_store import ensure_metric_partitions
from app.models.files import File, FileLink
from app.models.launch import LaunchSession
from app.models.observation import (
    MetricPoint,
    MetricRollup1h,
    MetricRollup5m,
)
from app.models.operation import OperationTask
from app.models.terminal import TerminalSession

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

FIVE_MINUTES = datetime.timedelta(minutes=5)
ONE_HOUR = datetime.timedelta(hours=1)

# A closed window keeps being regenerated for this long after it closes so
# points committed a few minutes late (a collection run finishing across a
# window boundary) still fold into the aggregate. Always below the raw
# retention, so the source points are guaranteed to exist.
ROLLUP_REGENERATION_LOOKBACK = datetime.timedelta(minutes=15)

# ui_events retention (DATA_MODEL.md §11: SSE 窗口保留 10 分钟).
UI_EVENT_RETENTION = datetime.timedelta(minutes=10)
# Preview-token ledger retention (migration 0010): each row covers one
# 60-second token window plus a margin; consumed rows carry no value past it
# (the audit trail lives in audit_logs.operation.create, which is permanent).
PREVIEW_TOKEN_USE_RETENTION = datetime.timedelta(hours=1)
# Login session cleanup (DATA_MODEL.md §10: 登录会话 过期后 30 天清理).
SESSION_CLEANUP_DELAY = datetime.timedelta(days=30)
# Launch-session one-time tickets (API_CONTRACT.md §7, migration 0013):
# issued rows are marked ``expired`` once their 60-second window passes
# (bookkeeping — the single-use claim checks ``expires_at`` itself), and rows
# leave after a 30-day lifetime like login sessions (the audit trail in
# audit_logs is permanent).
LAUNCH_SESSION_CLEANUP_DELAY = datetime.timedelta(days=30)
# Browser-terminal sessions (API_CONTRACT.md §7/§11, migration 0014): rows
# leave 30 days after close (or after open when never closed — a crashed
# API must never leave a forever-open row blocking the per-device-1 cap).
TERMINAL_SESSION_CLEANUP_DELAY = datetime.timedelta(days=30)

# Chunk size for retention batch deletes (DATA_MODEL.md §10: 分批删除).
DELETE_BATCH_SIZE = 2000

# Only gauge series are numerically aggregated (DATA_MODEL.md §5.4): states
# stay change points, counters stay raw values.
GAUGE_METRIC_KEYS = frozenset(
    key for key, definition in METRIC_DEFINITIONS.items() if definition.series == "gauge"
)

# Table names the chunked delete helper may target. The SQL per table is a
# FULLY STATIC literal below (no interpolation anywhere): the sweep never
# builds SQL from input. audit_logs/operation_task_events are deliberately
# absent — they are append-only (0002/0005 triggers + 0004 REVOKE, ADR-030)
# and are never batch-deleted here.
_RETENTION_TABLES = frozenset(
    {
        "metric_rollups_5m",
        "metric_rollups_1h",
        "device_events",
        "alerts",
        "preview_token_uses",
        "operation_tasks",
        "ui_events",
        "sessions",
        "launch_sessions",
    }
)

_PARTITION_NAME_PATTERN = re.compile(r"^metric_points_\d{4}_\d{2}_\d{2}$")

# Chunked deletes keep every statement bounded (DATA_MODEL.md §10: 分批删除);
# DELETE_BATCH_SIZE is inlined as the literal 2000 below.
_CHUNKED_DELETE_SQL: dict[str, str] = {
    "metric_rollups_5m": (
        "DELETE FROM metric_rollups_5m WHERE id IN "
        "(SELECT id FROM metric_rollups_5m WHERE window_start < :cutoff ORDER BY id LIMIT 2000)"
    ),
    "metric_rollups_1h": (
        "DELETE FROM metric_rollups_1h WHERE id IN "
        "(SELECT id FROM metric_rollups_1h WHERE window_start < :cutoff ORDER BY id LIMIT 2000)"
    ),
    "device_events": (
        "DELETE FROM device_events WHERE id IN "
        "(SELECT id FROM device_events WHERE occurred_at < :cutoff ORDER BY id LIMIT 2000)"
    ),
    "alerts": (
        "DELETE FROM alerts WHERE id IN "
        "(SELECT id FROM alerts WHERE status = 'resolved' AND resolved_at < :cutoff "
        "ORDER BY id LIMIT 2000)"
    ),
    "preview_token_uses": (
        # Single-use preview-token ledger (migration 0010): rows only cover
        # the 60-second token window plus the retention margin — expired
        # unconsumed AND consumed rows older than the cutoff carry no value
        # (the task/audit trail is permanent). Runs as warden_app, which owns
        # the table after 0010 (0008 ownership pattern).
        "DELETE FROM preview_token_uses WHERE id IN "
        "(SELECT id FROM preview_token_uses WHERE expires_at < :cutoff "
        "ORDER BY id LIMIT 2000)"
    ),
    "operation_tasks": (
        # Only terminal states (finished_at is set exactly on terminal
        # states); queued/running/verification_required are never touched.
        # The NOT EXISTS guard keeps the 0005 append-only stream intact: the
        # FK cascade from a task with event rows would fire the
        # operation_task_events no-delete trigger (PostgreSQL fires child row
        # triggers on FK actions), so only eventless terminal tasks can be
        # removed at the application layer (ADR-030).
        "DELETE FROM operation_tasks WHERE id IN "
        "(SELECT id FROM operation_tasks WHERE state IN "
        "('succeeded', 'failed', 'timed_out', 'cancelled') AND finished_at < :cutoff "
        "AND NOT EXISTS (SELECT 1 FROM operation_task_events e WHERE e.task_id = operation_tasks.id) "
        "ORDER BY id LIMIT 2000)"
    ),
    "ui_events": (
        "DELETE FROM ui_events WHERE id IN "
        "(SELECT id FROM ui_events WHERE occurred_at < :cutoff ORDER BY id LIMIT 2000)"
    ),
    "sessions": (
        # audit_logs.session_id is FK ON DELETE SET NULL; the 0002 audit
        # trigger rejects the internal UPDATE PostgreSQL performs for the FK
        # action, so an audit-referenced session cannot be deleted while its
        # audit rows live (audit is permanent, ADR-030). The NOT EXISTS guard
        # keeps the sweep from crashing on a daily cadence; such sessions
        # leave only through out-of-band database administration.
        "DELETE FROM sessions WHERE id IN "
        "(SELECT s.id FROM sessions s "
        "WHERE ((s.revoked_at IS NOT NULL AND s.revoked_at < :cutoff) "
        "OR (s.revoked_at IS NULL AND s.absolute_expires_at < :cutoff)) "
        "AND NOT EXISTS (SELECT 1 FROM audit_logs a WHERE a.session_id = s.id) "
        "ORDER BY s.id LIMIT 2000)"
    ),
    "launch_sessions": (
        # One-time launch tickets (migration 0013): rows only cover the
        # 60-second ticket window plus the 30-day retention margin. Any
        # status older than the cutoff is expired history — the permanent
        # record is audit_logs (launch.create / launch.consume), never this
        # row. Runs as warden_app, which owns the table (0013, 0008 model).
        # Terminal rows FK-restrict their ticket, but they are purged first
        # in the same pass (enforce_retention order), so a 30-day-old ticket
        # whose terminal history already left is deletable here.
        "DELETE FROM launch_sessions WHERE id IN "
        "(SELECT id FROM launch_sessions WHERE expires_at < :cutoff "
        "ORDER BY id LIMIT 2000)"
    ),
    "terminal_sessions": (
        # Browser-terminal sessions (migration 0014): one row per terminal
        # session, closed within minutes-to-hours of opening; rows leave 30
        # days after close (or after open when never closed — a crashed API
        # row that the stale-close sweep missed must not live forever). The
        # permanent record is audit_logs (terminal.handshake_ok /
        # handshake_failed / closed), never this row — and terminal CONTENT
        # was never stored here (SECURITY.md §8).
        "DELETE FROM terminal_sessions WHERE id IN "
        "(SELECT id FROM terminal_sessions "
        "WHERE COALESCE(closed_at, opened_at) < :cutoff "
        "ORDER BY id LIMIT 2000)"
    ),
}


def floor_interval(value: datetime.datetime, interval: datetime.timedelta) -> datetime.datetime:
    """Floor an aware UTC datetime to a UTC-aligned ``interval`` boundary."""
    epoch_seconds = value.timestamp()
    floored = int(epoch_seconds // interval.total_seconds()) * interval.total_seconds()
    return datetime.datetime.fromtimestamp(floored, tz=datetime.UTC)


def _floor_5m(value: datetime.datetime) -> datetime.datetime:
    return floor_interval(value, FIVE_MINUTES)


def _floor_hour(value: datetime.datetime) -> datetime.datetime:
    return floor_interval(value, ONE_HOUR)


@dataclass
class RollupReport:
    """Counters from one rollup pass (returned for tests and logs)."""

    rows_5m: int = 0
    rows_1h: int = 0
    range_start: datetime.datetime | None = None
    range_end: datetime.datetime | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class RetentionReport:
    """Counters from one retention pass (DATA_MODEL.md §10 记录清理数量)."""

    partitions_dropped: list[str] = field(default_factory=list)
    rollup_5m_deleted: int = 0
    rollup_1h_deleted: int = 0
    device_events_deleted: int = 0
    resolved_alerts_deleted: int = 0
    preview_token_uses_deleted: int = 0
    operation_tasks_deleted: int = 0
    ui_events_deleted: int = 0
    sessions_deleted: int = 0
    # Append-only streams (audit_logs, operation_task_events) are exempt from
    # automatic retention purge (ADR-030): the flags report that the 0002/
    # 0005 no-delete triggers were present (True), so a tampered trigger
    # state becomes visible instead of silently deleting history.
    audit_skipped_append_only: bool = False
    operation_task_events_skipped_append_only: bool = False
    # M3T4 launch tickets (migration 0013): issued rows marked expired past
    # their 60-second window, and rows purged after the 30-day lifetime.
    launch_sessions_expired: int = 0
    launch_sessions_deleted: int = 0
    # M5T4 browser-terminal sessions (migration 0014, ARCHITECTURE.md §5.4):
    # a crashed API leaves open rows behind — the sweep closes rows whose
    # stored activity/idle or total bound passed (same reasons as the live
    # in-process timers) and purges closed rows after 30 days. The counts
    # report how many rows THIS pass closed for each bound.
    terminal_sessions_closed_idle: int = 0
    terminal_sessions_closed_max: int = 0
    terminal_sessions_deleted: int = 0

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class _PointAccumulator:
    """Per (device, component, metric, window) state while aggregating raw points."""

    device_id: uuid.UUID
    component_id: uuid.UUID | None
    metric_key: str
    window_start: datetime.datetime
    min_value: float
    max_value: float
    sum_value: float
    count: int
    last_value: float
    quality: str
    collection_run_id: uuid.UUID | None

    def add(self, value: float, quality: str, run_id: uuid.UUID | None) -> None:
        if value < self.min_value:
            self.min_value = value
        if value > self.max_value:
            self.max_value = value
        self.sum_value += value
        self.count += 1
        self.last_value = value
        self.collection_run_id = run_id
        if quality == "partial":
            self.quality = "partial"


@dataclass
class _WindowAccumulator:
    """Per (device, component, metric) state while aggregating 5m windows."""

    device_id: uuid.UUID
    component_id: uuid.UUID | None
    metric_key: str
    hour_start: datetime.datetime
    min_value: float
    max_value: float
    avg_sum: float
    count: int
    windows: int
    last_value: float
    quality: str
    collection_run_id: uuid.UUID | None

    def add(
        self,
        *,
        min_value: float,
        max_value: float,
        avg_value: float,
        last_value: float,
        count: int,
        quality: str,
        run_id: uuid.UUID | None,
    ) -> None:
        if min_value < self.min_value:
            self.min_value = min_value
        if max_value > self.max_value:
            self.max_value = max_value
        self.avg_sum += avg_value
        self.count += count
        self.windows += 1
        # Windows arrive ordered by window_start: the newest one wins.
        self.last_value = last_value
        self.collection_run_id = run_id
        if quality == "partial":
            self.quality = "partial"


def _upsert_rollups_5m(db: Session, rows: list[dict[str, object]]) -> int:
    """Idempotent 5m regeneration: ON CONFLICT DO UPDATE (COALESCE key).

    The arbiter mirrors the expression index of migration 0007 exactly
    (same pattern as the metric_latest upsert in observation_store, 0006).
    The statement is all-or-nothing, so the parameter count IS the number of
    windows processed (multi-row executemany rowcounts are not reliable).
    """
    if not rows:
        return 0
    db.execute(
        pg_insert(MetricRollup5m)
        .values(rows)
        .on_conflict_do_update(
            index_elements=[
                MetricRollup5m.device_id,
                func.coalesce(MetricRollup5m.component_id, cast(ZERO_UUID, Uuid)),
                MetricRollup5m.metric_key,
                MetricRollup5m.window_start,
            ],
            set_={
                "min_value": pg_insert(MetricRollup5m).excluded.min_value,
                "max_value": pg_insert(MetricRollup5m).excluded.max_value,
                "avg_value": pg_insert(MetricRollup5m).excluded.avg_value,
                "last_value": pg_insert(MetricRollup5m).excluded.last_value,
                "count": pg_insert(MetricRollup5m).excluded.count,
                "quality": pg_insert(MetricRollup5m).excluded.quality,
                "collection_run_id": pg_insert(MetricRollup5m).excluded.collection_run_id,
            },
        )
    )
    return len(rows)


def _upsert_rollups_1h(db: Session, rows: list[dict[str, object]]) -> int:
    if not rows:
        return 0
    db.execute(
        pg_insert(MetricRollup1h)
        .values(rows)
        .on_conflict_do_update(
            index_elements=[
                MetricRollup1h.device_id,
                func.coalesce(MetricRollup1h.component_id, cast(ZERO_UUID, Uuid)),
                MetricRollup1h.metric_key,
                MetricRollup1h.window_start,
            ],
            set_={
                "min_value": pg_insert(MetricRollup1h).excluded.min_value,
                "max_value": pg_insert(MetricRollup1h).excluded.max_value,
                "avg_value": pg_insert(MetricRollup1h).excluded.avg_value,
                "last_value": pg_insert(MetricRollup1h).excluded.last_value,
                "count": pg_insert(MetricRollup1h).excluded.count,
                "quality": pg_insert(MetricRollup1h).excluded.quality,
                "collection_run_id": pg_insert(MetricRollup1h).excluded.collection_run_id,
            },
        )
    )
    return len(rows)


def _five_minute_window_rows(
    db: Session, *, start: datetime.datetime, end: datetime.datetime
) -> list[dict[str, object]]:
    """Aggregate raw gauge points in [start, end) into 5m rollup parameters.

    One row per (device, COALESCE(component), metric_key, window_start) with
    min/max/simple-avg/last-by-time/count; window quality is ``partial`` when
    any point in it is partial; collection_run_id comes from the newest point.
    """
    points = db.execute(
        select(
            MetricPoint.device_id,
            MetricPoint.component_id,
            MetricPoint.metric_key,
            MetricPoint.observed_at,
            MetricPoint.value_double,
            MetricPoint.quality,
            MetricPoint.collection_run_id,
        )
        .where(
            MetricPoint.observed_at >= start,
            MetricPoint.observed_at < end,
            MetricPoint.metric_key.in_(GAUGE_METRIC_KEYS),
            MetricPoint.value_double.is_not(None),
        )
        .order_by(MetricPoint.observed_at.asc())
    ).all()
    groups: dict[tuple[uuid.UUID, uuid.UUID, str, datetime.datetime], _PointAccumulator] = {}
    for device_id, component_id, metric_key, observed_at, value, quality, run_id in points:
        key = (device_id, _component_key(component_id), metric_key, _floor_5m(observed_at))
        group = groups.get(key)
        if group is None:
            groups[key] = _PointAccumulator(
                device_id=device_id,
                component_id=component_id,
                metric_key=metric_key,
                window_start=_floor_5m(observed_at),
                min_value=float(value),
                max_value=float(value),
                sum_value=float(value),
                count=1,
                last_value=float(value),
                quality="partial" if quality == "partial" else "good",
                collection_run_id=run_id,
            )
        else:
            group.add(float(value), quality, run_id)
    return [
        {
            "device_id": group.device_id,
            "component_id": group.component_id,
            "metric_key": group.metric_key,
            "window_start": group.window_start,
            "min_value": group.min_value,
            "max_value": group.max_value,
            "avg_value": group.sum_value / group.count,
            "last_value": group.last_value,
            "count": group.count,
            "quality": group.quality,
            "collection_run_id": group.collection_run_id,
        }
        for group in groups.values()
    ]


def _hourly_window_rows(
    db: Session,
    *,
    hour_start: datetime.datetime,
) -> list[dict[str, object]]:
    """Aggregate the closed 5m rows of hour [hour_start, hour_start + 1h).

    Documented choice (DATA_MODEL.md §5.4, M2T3 brief): min of the window
    minimums, max of the window maximums, simple mean of the window averages,
    count summed, last value from the newest window, quality partial when any
    window is partial. Only windows that have rows contribute.
    """
    rows = db.execute(
        select(
            MetricRollup5m.device_id,
            MetricRollup5m.component_id,
            MetricRollup5m.metric_key,
            MetricRollup5m.min_value,
            MetricRollup5m.max_value,
            MetricRollup5m.avg_value,
            MetricRollup5m.last_value,
            MetricRollup5m.count,
            MetricRollup5m.quality,
            MetricRollup5m.collection_run_id,
        )
        .where(
            MetricRollup5m.window_start >= hour_start,
            MetricRollup5m.window_start < hour_start + ONE_HOUR,
        )
        .order_by(MetricRollup5m.window_start.asc())
    ).all()
    groups: dict[tuple[uuid.UUID, uuid.UUID, str], _WindowAccumulator] = {}
    for (
        device_id,
        component_id,
        metric_key,
        min_value,
        max_value,
        avg_value,
        last_value,
        count,
        quality,
        run_id,
    ) in rows:
        key = (device_id, _component_key(component_id), metric_key)
        group = groups.get(key)
        if group is None:
            groups[key] = _WindowAccumulator(
                device_id=device_id,
                component_id=component_id,
                metric_key=metric_key,
                hour_start=hour_start,
                min_value=float(min_value),
                max_value=float(max_value),
                avg_sum=float(avg_value),
                count=int(count),
                windows=1,
                last_value=float(last_value),
                quality="partial" if quality == "partial" else "good",
                collection_run_id=run_id,
            )
        else:
            group.add(
                min_value=float(min_value),
                max_value=float(max_value),
                avg_value=float(avg_value),
                last_value=float(last_value),
                count=int(count),
                quality=quality,
                run_id=run_id,
            )
    return [
        {
            "device_id": group.device_id,
            "component_id": group.component_id,
            "metric_key": group.metric_key,
            "window_start": group.hour_start,
            "min_value": group.min_value,
            "max_value": group.max_value,
            # Simple mean of the window averages (documented choice): sparse
            # hours average over the windows that have rows, never over
            # invented empty windows.
            "avg_value": group.avg_sum / group.windows,
            "last_value": group.last_value,
            "count": group.count,
            "quality": group.quality,
            "collection_run_id": group.collection_run_id,
        }
        for group in groups.values()
    ]


def _component_key(component_id: uuid.UUID | None) -> uuid.UUID:
    return component_id if component_id is not None else uuid.UUID(ZERO_UUID)


def generate_rollups(
    db: Session,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
) -> RollupReport:
    """Generate/regenerate rollups for closed windows (the caller commits).

    Range: [max(floor5(now) - lookback, marker + 5m, raw retention floor),
    floor5(now)) — see the module docstring for the catch-up semantics.

    The lookback is bounded (``ROLLUP_REGENERATION_LOOKBACK`` = 15 minutes):
    a point committed later than 15 minutes after its window closed is
    preserved in raw metric_points / metric_latest but is NOT folded into the
    5m/1h aggregates (collection commits happen within seconds in this
    design; the bound keeps regeneration reads small and is never allowed to
    reach into raw-retention-dropped windows).
    """
    floor = _floor_5m(now)
    marker = db.scalar(select(func.max(MetricRollup5m.window_start)))
    raw_floor = floor - datetime.timedelta(days=settings.raw_retention_days)
    # Regenerate the closed windows of the last lookback; when the newest
    # existing 5m row is older than the lookback (worker downtime), extend the
    # range back to marker + 5m so every window that still has raw points gets
    # rolled up. Never earlier than the raw retention floor.
    start = floor - ROLLUP_REGENERATION_LOOKBACK
    if marker is not None:
        start = min(start, marker + FIVE_MINUTES)
    start = max(start, raw_floor)
    if start >= floor:
        return RollupReport()
    report = RollupReport(range_start=start, range_end=floor)

    report.rows_5m = _upsert_rollups_5m(
        db, _five_minute_window_rows(db, start=start, end=floor)
    )

    # Hourly targets: fully closed hours whose newest window is in the range.
    hour = _floor_hour(start - datetime.timedelta(minutes=55))
    last_closed_hour = _floor_hour(floor)
    while hour + ONE_HOUR <= last_closed_hour:
        if hour + datetime.timedelta(minutes=55) >= start:
            report.rows_1h += _upsert_rollups_1h(
                db, _hourly_window_rows(db, hour_start=hour)
            )
        hour += ONE_HOUR
    return report


def ensure_partitions(db: Session, *, now: datetime.datetime) -> int:
    """Create daily metric_points partitions for the next 14 days (idempotent).

    docs/DEPLOYMENT.md §9.2: PostgreSQL 日分区未来至少预创建 14 天. Migration
    0006 pre-creates the same window at install; the daily maintenance call
    keeps the window rolling. Runs as warden_app in production, which OWNS
    metric_points and holds CREATE on schema public after 0008 + the
    deployment init script (partition creation requires schema CREATE even
    for the parent's owner — PG18). Returns how many partitions were created.
    """
    return ensure_metric_partitions(db, start_date=now.date(), days=14)


def _metric_partition_bounds(
    db: Session,
) -> list[tuple[str, datetime.datetime]]:
    """[(name, range_start)] of the metric_points day partitions.

    The lower bound is parsed from the partition bound expression written by
    ``create_metric_partition`` (0006): a partition holds
    [range_start, range_start + 1 day). Only partitions whose names match the
    helper's own naming convention are returned (defense in depth before any
    DROP).
    """
    rows = db.execute(
        text(
            """
            SELECT child.relname, pg_get_expr(child.relpartbound, child.oid)
            FROM pg_inherits
            JOIN pg_class child ON child.oid = pg_inherits.inhrelid
            JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
            WHERE parent.relname = 'metric_points'
            """
        )
    ).all()
    partitions: list[tuple[str, datetime.datetime]] = []
    for name, bound in rows:
        if not _PARTITION_NAME_PATTERN.match(str(name)):
            continue
        lower = _range_lower_bound(str(bound))
        if lower is not None:
            partitions.append((str(name), lower))
    return partitions


def _range_lower_bound(bound: str) -> datetime.datetime | None:
    """Extract the FOR VALUES FROM lower bound of a partition expression."""
    marker = "FROM ("
    start = bound.find(marker)
    if start < 0:
        return None
    tail = bound[start + len(marker) :]
    end = tail.find(")")
    if end < 0:
        return None
    raw = tail[:end].strip().strip("'")
    try:
        parsed = datetime.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed


def _chunked_delete(db: Session, table: str, params: dict[str, object]) -> int:
    """Delete matching rows in PK-ordered batches; returns the total count.

    ``table`` must name a static SQL literal in ``_CHUNKED_DELETE_SQL`` (the
    whitelist above); every value is a bound parameter. Raw SQL is deliberate:
    ORM-level append-only listeners must not fire for retention sweeps (the
    database triggers on audit_logs/operation_task_events are probed
    separately by the caller).
    """
    statement = _CHUNKED_DELETE_SQL.get(table)
    if statement is None:
        msg = f"refusing retention delete on unknown table: {table}"
        raise ValueError(msg)
    deleted = 0
    while True:
        result = db.execute(text(statement), params)
        # text() statements return a Result without a typed rowcount: the
        # chunk count comes from the cursor (same cast as observation_store).
        rowcount = typing_cast(Any, result).rowcount
        if rowcount is None or rowcount == 0:
            return deleted
        deleted += int(rowcount)


def _expire_launch_sessions(db: Session, *, now: datetime.datetime) -> int:
    """Mark issued launch tickets past their 60-second window as expired.

    Bookkeeping for migration 0013: the single-use claim already refuses
    rows whose ``expires_at`` passed, so this only keeps the status column
    honest (the concurrency guards count only ``issued`` rows that are not
    yet past ``expires_at``). Runs as warden_app in production (0013
    ownership; UPDATE comes from the blanket S/I/U grant).
    """
    result = db.execute(
        update(LaunchSession)
        .where(
            LaunchSession.status == "issued",
            LaunchSession.expires_at <= now,
        )
        .values(status="expired")
    )
    rowcount = typing_cast(Any, result).rowcount
    return int(rowcount) if rowcount is not None else 0


def _close_stale_terminal_sessions(
    db: Session,
    *,
    settings: WardenSettings,
    audit: AuditLogger | None,
    now: datetime.datetime,
) -> tuple[int, int, list[TerminalSession]]:
    """Close OPEN browser-terminal rows whose bounds provably passed.

    ARCHITECTURE.md §5.4 (会话最长 2 小时、空闲 15 分钟断开) is enforced live
    by the API process AND here: a crashed API must not leave an open row
    behind forever (it would permanently block the per-device-1 / per-user-3
    caps of API_CONTRACT.md §11). The same reasons as the live timers are
    used; the conditional close is idempotent (a live timer that wins the
    race closes + audits itself, this sweep then matches zero rows). Audit
    rows record the sweep close with no actor (system-driven) and never any
    content. Returns (idle_closed, max_closed, closed_rows).
    """
    idle_rows = _close_by(
        db,
        reason="idle_timeout",
        predicate=TerminalSession.last_activity_at
        <= now - datetime.timedelta(seconds=settings.terminal_session_idle_seconds),
        now=now,
    )
    max_rows = _close_by(
        db,
        reason="max_duration",
        predicate=TerminalSession.opened_at
        <= now - datetime.timedelta(seconds=settings.terminal_session_max_seconds),
        now=now,
    )
    closed_rows = idle_rows + max_rows
    if audit is not None:
        for row in closed_rows:
            audit.record(
                action="terminal.closed",
                resource_type="terminal_session",
                resource_id=str(row.id),
                device_id=row.device_id,
                requirement_id=row.requirement_id,
                result="success",
                detail={
                    "reason": row.close_reason,
                    "protocol": row.protocol,
                    "capability_key": row.capability_key,
                    "trigger": "retention",
                },
            )
    return len(idle_rows), len(max_rows), closed_rows


def _close_by(
    db: Session,
    *,
    reason: str,
    predicate: Any,
    now: datetime.datetime,
) -> list[TerminalSession]:
    """One bounded close statement; returns the rows THIS call closed."""
    return list(
        db.scalars(
            update(TerminalSession)
            .where(TerminalSession.status == "open", predicate)
            .values(status="closed", closed_at=now, close_reason=reason)
            .returning(TerminalSession)
        ).all()
    )


def _append_only_trigger_exists(db: Session, table: str, trigger: str) -> bool:
    """True when an append-only trigger protects ``table`` (0002/0005).

    The audit (0002) and operation_task_events (0005) triggers reject UPDATE/
    DELETE for every role; 0004 additionally revoked the app account's audit
    DELETE. ADR-030 exempts both streams from automatic retention purge, so
    the sweep probes them once per pass and reports the protection state
    (``*_skipped_append_only``) instead of attempting a DELETE that must
    fail — a tampered trigger state shows up as False in the report.
    """
    exists = db.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger "
            "WHERE tgrelid = CAST(:table AS regclass) AND tgname = :trigger)"
        ),
        {"table": table, "trigger": trigger},
    ).scalar()
    return bool(exists)


def enforce_retention(
    db: Session,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
    audit: AuditLogger | None = None,
) -> RetentionReport:
    """Enforce the tiered retention (DATA_MODEL.md §10); the caller commits.

    Production runs this as warden_app, which OWNS the purgeable tables after
    migration 0008 — the DROP/UPDATE/DELETE below are therefore real,
    deployable behavior. The append-only streams are never touched (ADR-030;
    see the module docstring for the exact exemptions and the PostgreSQL
    trigger/ownership mechanics). ``audit`` (optional, file-retention
    pattern) records system-driven terminal closes without an actor.
    """
    report = RetentionReport()

    # Raw points: drop whole day partitions whose range END is at/before the
    # cutoff (partition-granular retention is the documented precision; the
    # straddling partition is kept whole with its retained slice).
    cutoff = now - datetime.timedelta(days=settings.raw_retention_days)
    for name, range_start in _metric_partition_bounds(db):
        if range_start + datetime.timedelta(days=1) <= cutoff:
            db.execute(text(f'DROP TABLE IF EXISTS "{name}"'))  # noqa: S608 - name regex-validated above
            report.partitions_dropped.append(name)

    def _days_ago(days: int) -> datetime.datetime:
        return now - datetime.timedelta(days=days)

    report.rollup_5m_deleted = _chunked_delete(
        db,
        "metric_rollups_5m",
        {"cutoff": _days_ago(settings.rollup_5m_retention_days)},
    )
    report.rollup_1h_deleted = _chunked_delete(
        db,
        "metric_rollups_1h",
        {"cutoff": _days_ago(settings.rollup_1h_retention_days)},
    )
    report.device_events_deleted = _chunked_delete(
        db,
        "device_events",
        {"cutoff": _days_ago(settings.event_retention_days)},
    )
    # Only resolved alerts age out; active alerts stay until the engine
    # resolves them (DATA_MODEL.md §6.1/§10).
    report.resolved_alerts_deleted = _chunked_delete(
        db,
        "alerts",
        {"cutoff": _days_ago(settings.resolved_alert_retention_days)},
    )
    # Preview-token single-use ledger rows (migration 0010): expired and
    # consumed rows leave after a 1-hour lifetime (the 60 s token window plus
    # margin is all they cover; confirm rejects any token past its window).
    report.preview_token_uses_deleted = _chunked_delete(
        db,
        "preview_token_uses",
        {"cutoff": now - PREVIEW_TOKEN_USE_RETENTION},
    )
    # Terminal tasks age out by DELETE — the chunked statement's NOT EXISTS
    # guard keeps the 0005 append-only stream intact (see the SQL comment):
    # evented tasks stay with their history (ADR-030), eventless terminal
    # tasks are the only ones removable at the application layer. Terminal
    # states only; queued/running/verification_required are never touched.
    report.operation_tasks_deleted = _chunked_delete(
        db,
        "operation_tasks",
        {"cutoff": _days_ago(settings.operation_retention_days)},
    )
    report.ui_events_deleted = _chunked_delete(
        db,
        "ui_events",
        {"cutoff": now - UI_EVENT_RETENTION},
    )
    # Sessions 30 days after revocation/absolute expiry; audit-referenced
    # sessions are exempt (the NOT EXISTS guard in the SQL — the 0002 audit
    # trigger rejects the FK SET NULL, so they live as long as their audit
    # rows, ADR-030).
    report.sessions_deleted = _chunked_delete(
        db,
        "sessions",
        {"cutoff": now - SESSION_CLEANUP_DELAY},
    )
    # Browser-terminal sessions (M5T4, migration 0014): close rows whose
    # idle/total bound provably passed (crash recovery — same reasons and
    # semantics as the live API timers; idempotent conditional closes), then
    # purge closed rows after the 30-day lifetime. The purge runs BEFORE the
    # launch purge below: terminal rows FK-restrict their launch ticket, so
    # the ticket can only leave once its terminal history is gone.
    (
        report.terminal_sessions_closed_idle,
        report.terminal_sessions_closed_max,
        _closed_terminal_rows,
    ) = _close_stale_terminal_sessions(
        db, settings=settings, audit=audit, now=now
    )
    report.terminal_sessions_deleted = _chunked_delete(
        db,
        "terminal_sessions",
        {"cutoff": now - TERMINAL_SESSION_CLEANUP_DELAY},
    )
    # Launch tickets (M3T4, migration 0013): issued rows past their
    # 60-second window become ``expired`` (bookkeeping — the single-use
    # claim checks ``expires_at`` at read time, so an expired row can never
    # be consumed), then every row older than the 30-day lifetime is purged
    # (expired first so a just-expired row is not deleted a day early).
    report.launch_sessions_expired = _expire_launch_sessions(db, now=now)
    report.launch_sessions_deleted = _chunked_delete(
        db,
        "launch_sessions",
        {"cutoff": now - LAUNCH_SESSION_CLEANUP_DELAY},
    )
    # DATA_MODEL.md §10 lists audit rows and task events at 365 days, but both
    # streams are append-only at the database (0002/0005 triggers + the 0004
    # REVOKE on audit_logs; operation_task_events also has no DELETE grant
    # after 0008). ADR-030: they are EXEMPT from automatic retention purge —
    # physical cleanup is an out-of-band DBA operation in 0.1.0. The probes
    # report the protection state once per pass (True = trigger present), so
    # a tampered database becomes visible instead of failing the pass or
    # silently deleting history.
    report.audit_skipped_append_only = _append_only_trigger_exists(
        db, "audit_logs", "audit_logs_no_delete"
    )
    report.operation_task_events_skipped_append_only = _append_only_trigger_exists(
        db, "operation_task_events", "operation_task_events_no_delete"
    )
    return report


# ---------------------------------------------------------------------------
# File retention (DATA_MODEL.md §10 rows for 支持包/操作日志/配置备份/固件-ISO,
# M2T5). Runs from the same maintenance pass as ``enforce_retention``; the
# file rows/tickets live on the volume + the migration-0011 tables.
# ---------------------------------------------------------------------------

# DATA_MODEL.md §10: 支持包/操作日志 30 天 (可由管理员延长 — the platform has
# no product API for extension in 0.1.0; a needed bundle is re-uploaded).
# Logical delete keeps the row (audit-visible lifecycle); the PHYSICAL bytes
# leave 7 days later (SECURITY.md §9: 物理清理前检查任务引用并写审计).
PHYSICAL_CLEANUP_DELAY = datetime.timedelta(days=7)
# Upload sessions abandoned mid-stream (client vanished): rows + spool close
# after 24 h (the 2-concurrent-upload limit counts only live uploading rows).
ABANDONED_UPLOAD_DELAY = datetime.timedelta(hours=24)
# Expired/revoked tickets keep one extra day for forensics, then purge.
TICKET_PURGE_MARGIN = datetime.timedelta(days=1)

# Operation-task states that still reference a file (active links block
# logical delete with a 409 and delay physical cleanup).
_FILE_ACTIVE_TASK_STATES = ("queued", "running", "waiting_device")


@dataclass
class FileRetentionReport:
    """Counters of one file-retention sweep (DATA_MODEL.md §10 记录清理数量)."""

    storage_unavailable: bool = False
    support_bundles_deleted: int = 0
    operation_logs_deleted: int = 0
    config_backups_deleted: int = 0
    abandoned_uploads_deleted: int = 0
    orphaned_upload_spools_removed: int = 0
    tickets_deleted: int = 0
    physical_files_removed: int = 0

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _file_has_active_task_link(db: Session, file_id: uuid.UUID) -> bool:
    """True when any queued/running/waiting_device task links the file."""
    exists = db.scalar(
        select(FileLink.id)
        .join(OperationTask, OperationTask.id == FileLink.task_id)
        .where(
            FileLink.file_id == file_id,
            OperationTask.state.in_(_FILE_ACTIVE_TASK_STATES),
        )
        .limit(1)
    )
    return exists is not None


def _logically_delete_file(
    db: Session,
    row: File,
    *,
    audit: AuditLogger | None,
    reason: str,
    detail: dict[str, object],
) -> None:
    row.status = "deleted"
    row.version += 1
    if audit is not None:
        audit.record(
            action="file.retention_delete",
            resource_type="file",
            resource_id=str(row.id),
            requirement_id="PLT-06",
            result="success",
            detail={
                "file_type": row.file_type,
                "size_bytes": row.size_bytes,
                "reason": reason,
                **detail,
            },
        )


def _prune_expired_files(
    db: Session,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
    audit: AuditLogger | None,
    report: FileRetentionReport,
) -> None:
    """30-day logical delete of ready support bundles / operation logs.

    Rows referenced by an ACTIVE task are skipped (they cannot be aged out
    from under an executing operation); terminal-task links do not protect
    the bytes — retention says bundles leave after 30 days (DATA_MODEL.md
    §10) and the task history references the file row, not its bytes.
    """
    cutoff = now - datetime.timedelta(days=settings.support_bundle_retention_days)
    while True:
        candidates = list(
            db.scalars(
                select(File)
                .where(
                    File.status == "ready",
                    File.file_type.in_(("support_bundle", "operation_log")),
                    File.created_at < cutoff,
                )
                .order_by(File.id)
                .limit(DELETE_BATCH_SIZE)
            ).all()
        )
        if not candidates:
            return
        changed_in_batch = 0
        for row in candidates:
            if _file_has_active_task_link(db, row.id):
                continue
            _logically_delete_file(
                db,
                row,
                audit=audit,
                reason="retention_30d",
                detail={"created_at": row.created_at.isoformat()},
            )
            if row.file_type == "support_bundle":
                report.support_bundles_deleted += 1
            else:
                report.operation_logs_deleted += 1
            changed_in_batch += 1
        # A full batch of active-task-linked candidates cannot make progress:
        # stop instead of re-selecting them forever (the next daily pass
        # retries after their tasks finish).
        if changed_in_batch == 0:
            return


def _prune_config_backups(
    db: Session,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
    audit: AuditLogger | None,
    report: FileRetentionReport,
) -> None:
    """Config backups: keep the newest 10 per device, minimum age 90 days.

    DATA_MODEL.md §10 (配置备份: 默认保留最近 10 份/设备，至少 90 天): a backup
    is pruned when it is BEYOND the newest ``keep`` per device AND older than
    the minimum age — recent backups (rank > keep but younger than the
    minimum age) stay until they reach the age rule, then leave when they are
    no longer in the newest set. Active-task-linked backups are never pruned.
    """
    min_age_cutoff = now - datetime.timedelta(days=settings.config_backup_min_days)
    keep = settings.config_backup_keep_per_device
    rows = db.execute(
        select(File.id, File.created_at, FileLink.device_id)
        .join(FileLink, FileLink.file_id == File.id)
        .where(
            File.status == "ready",
            File.file_type == "config_backup",
            FileLink.purpose == "output_config_backup",
            FileLink.device_id.is_not(None),
        )
        .order_by(File.created_at.desc())
    ).all()
    per_device: dict[uuid.UUID, list[tuple[uuid.UUID, datetime.datetime]]] = {}
    for file_id, created_at, device_id in rows:
        per_device.setdefault(device_id, []).append((file_id, created_at))
    for device_id, backups in per_device.items():
        # Rows are ordered newest-first; dedupe against double links.
        seen: set[uuid.UUID] = set()
        rank = 0
        for file_id, created_at in backups:
            if file_id in seen:
                continue
            seen.add(file_id)
            if rank < keep or created_at >= min_age_cutoff:
                rank += 1
                continue
            row = db.get(File, file_id)
            if row is None or _file_has_active_task_link(db, file_id):
                rank += 1
                continue
            _logically_delete_file(
                db,
                row,
                audit=audit,
                reason="config_backup_prune",
                detail={
                    "device_id": str(device_id),
                    "keep_per_device": keep,
                    "created_at": created_at.isoformat(),
                },
            )
            report.config_backups_deleted += 1
            rank += 1


def _close_abandoned_uploads(
    db: Session,
    *,
    now: datetime.datetime,
    storage: FileStorage,
    audit: AuditLogger | None,
    report: FileRetentionReport,
) -> None:
    """Upload sessions older than 24 h without content: close row + spool."""
    cutoff = now - ABANDONED_UPLOAD_DELAY
    while True:
        candidates = list(
            db.scalars(
                select(File)
                .where(File.status == "uploading", File.created_at < cutoff)
                .order_by(File.id)
                .limit(DELETE_BATCH_SIZE)
            ).all()
        )
        if not candidates:
            return
        for row in candidates:
            _logically_delete_file(
                db,
                row,
                audit=audit,
                reason="abandoned_upload",
                detail={"created_at": row.created_at.isoformat()},
            )
            with contextlib.suppress(FileStorageError):
                storage.remove_upload(str(row.id))  # volume sweep retries otherwise
            report.abandoned_uploads_deleted += 1


def _sweep_orphaned_spools(
    *,
    now: datetime.datetime,
    storage: FileStorage,
    report: FileRetentionReport,
) -> None:
    """Volume backstop for spool residue no row references any more.

    A crash between the row close-out commit and the spool unlink leaves an
    orphaned ``tmp/<upload-id>`` (and a crash between a finalize copy and
    its atomic rename leaves ``tmp/finalize-*`` residue). The row-driven
    pass above ran first, so by now every spool of a live uploading row is
    younger than the abandoned margin — an mtime sweep with the same cutoff
    can only remove true residue.
    """
    report.orphaned_upload_spools_removed = storage.delete_stale_uploads(
        cutoff=now - ABANDONED_UPLOAD_DELAY
    )


def _physically_clean_deleted_files(
    db: Session,
    *,
    now: datetime.datetime,
    storage: FileStorage,
    audit: AuditLogger | None,
    report: FileRetentionReport,
) -> None:
    """Physical bytes of logically deleted rows leave 7 days later.

    SECURITY.md §9: 物理清理前检查任务引用并写审计. Guards before the volume
    delete: no ACTIVE task link, and no other live row (uploading/ready/
    quarantined) shares the same physical storage key — two identical plain
    uploads point at one content-addressed file, so the bytes stay while ANY
    live row needs them. Encrypted rows own distinct per-row files (their
    storage keys embed the row id) and are unaffected by the twin check.
    """
    cutoff = now - PHYSICAL_CLEANUP_DELAY
    live_statuses = ("uploading", "ready", "quarantined")
    while True:
        candidates = list(
            db.scalars(
                select(File)
                .where(File.status == "deleted", File.updated_at < cutoff)
                .order_by(File.id)
                .limit(DELETE_BATCH_SIZE)
            ).all()
        )
        if not candidates:
            return
        changed_in_batch = 0
        for row in candidates:
            if row.storage_name is None or row.sha256 is None:
                continue  # never completed: no physical bytes to remove
            if _file_has_active_task_link(db, row.id):
                continue
            twin = db.scalar(
                select(File.id)
                .where(
                    File.storage_name == row.storage_name,
                    File.encrypted == row.encrypted,
                    File.status.in_(live_statuses),
                    File.id != row.id,
                )
                .limit(1)
            )
            if twin is not None:
                continue
            storage_key_value = storage_key(row)
            try:
                if not storage.delete(storage_key_value):
                    continue  # already gone (e.g. a twin cleanup removed it)
            except FileStorageError:
                continue  # volume hiccup: the next daily pass retries
            # Record the cleanup time so the batch loop never re-selects this
            # row (its status stays ``deleted`` for the audit-visible
            # lifecycle; updated_at marks when the bytes left).
            logical_deleted_at = row.updated_at
            row.updated_at = now
            report.physical_files_removed += 1
            changed_in_batch += 1
            if audit is not None:
                audit.record(
                    action="file.physical_cleanup",
                    resource_type="file",
                    resource_id=str(row.id),
                    requirement_id="PLT-06",
                    result="success",
                    detail={
                        "file_type": row.file_type,
                        "size_bytes": row.size_bytes,
                        "encrypted": row.encrypted,
                        "logical_deleted_at": logical_deleted_at.isoformat(),
                        "cleaned_at": now.isoformat(),
                    },
                )
        # A full batch of rows that cannot leave yet (active links / live
        # twins / never-completed) makes no progress: stop re-selecting them
        # (the next daily pass re-checks).
        if changed_in_batch == 0:
            return


def _purge_expired_tickets(
    db: Session,
    *,
    now: datetime.datetime,
    report: FileRetentionReport,
) -> None:
    """Expired/revoked tickets are purged one day past expiry (counted)."""
    cutoff = now - TICKET_PURGE_MARGIN
    while True:
        result = db.execute(
            text(
                "DELETE FROM device_file_tickets WHERE id IN "
                "(SELECT id FROM device_file_tickets WHERE expires_at < :cutoff "
                "ORDER BY id LIMIT 2000)"
            ),
            {"cutoff": cutoff},
        )
        rowcount = typing_cast(Any, result).rowcount
        if rowcount is None or rowcount == 0:
            return
        report.tickets_deleted += int(rowcount)


def enforce_file_retention(
    db: Session,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
    storage: FileStorage,
    audit: AuditLogger | None = None,
) -> FileRetentionReport:
    """File-layer retention sweep; the caller commits.

    Runs as warden_app in production: the migration-0011 ownership model
    (warden_app owns files/file_links/device_file_tickets — the files-row
    UPDATEs come from the blanket S/I/U grant, the ticket DELETEs from
    ownership, exactly like the 0010 ledger). The file volume is probed
    first: a dead volume reports ``storage_unavailable`` and the pass is
    skipped loudly instead of pretending to clean.
    """
    report = FileRetentionReport()
    try:
        storage.check_available()
    except FileStorageError:
        report.storage_unavailable = True
        return report
    _prune_expired_files(db, now=now, settings=settings, audit=audit, report=report)
    _prune_config_backups(db, now=now, settings=settings, audit=audit, report=report)
    _close_abandoned_uploads(db, now=now, storage=storage, audit=audit, report=report)
    _sweep_orphaned_spools(now=now, storage=storage, report=report)
    _physically_clean_deleted_files(db, now=now, storage=storage, audit=audit, report=report)
    _purge_expired_tickets(db, now=now, report=report)
    return report
