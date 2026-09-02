"""Rollup generation and retention maintenance (M2T3).

docs/DATA_MODEL.md 搂5.4 (rollups: gauge-only, closed windows, idempotent
regeneration), 搂10 (tiered retention table), DEPLOYMENT.md 搂9.3 (姣?5 鍒嗛挓
鐢熸垚鎸囨爣鑱氬悎; 姣忔棩鍒涘缓鏈潵鍒嗗尯骞舵墽琛屼繚鐣欐竻鐞?, ARCHITECTURE.md 搂3.3 (缁存姢寰幆).
The workers/maintenance.py loop calls these on their cadences; tests call them
directly with an injected ``now``.

Rollup semantics:

- ``generate_rollups`` regenerates every closed 5-minute window in
  [max(floor5(now) - REGENERATION_LOOKBACK, raw retention floor,
  marker + 5m), floor5(now)) from raw metric_points. The just-closed window
  plus a small lookback lets points committed a few minutes late fold in;
  the marker (newest existing 5m row) catches windows up after worker
  downtime, bounded by the raw retention floor 鈥?a window whose raw points
  were already dropped can never be rebuilt.
- The 1h pass targets every fully closed hour whose newest (last) window lies
  in that range 鈥?the pass that closes an hour's last window builds its
  hourly row, and a catch-up pass re-closes every gap hour the same way.
  Aggregation is the documented choice of DATA_MODEL.md 搂5.4: min of the
  window minimums, max of the window maximums, simple mean of the window
  averages with count summed, last value of the newest window, quality
  ``partial`` when any window is partial. Only windows that have rows
  contribute 鈥?a window without data has no row and is never invented.
- Both tables are upserted (ON CONFLICT DO UPDATE on the COALESCE key), so
  regeneration is idempotent: a rerun converges to identical rows.

Retention semantics (DATA_MODEL.md 搂10):

- raw metric_points leave by DROP of whole day partitions whose range END is
  at or before the cutoff (day granularity is the documented precision of the
  partition scheme 鈥?the partition that straddles the cutoff is kept whole);
- every other table is batch-deleted (PK-ordered chunks of
  ``DELETE_BATCH_SIZE``, counted 鈥?DATA_MODEL.md 搂10: 鍒嗘壒鍒犻櫎);
- operation tasks and audit logs are NEVER deleted here: their event/audit
  streams are protected by DB-level append-only triggers (0005 for
  operation_task_events 鈥?a task cannot be removed while its event stream
  exists 鈥?and 0002 plus the 0004 REVOKE for audit_logs). The sweep probes
  the triggers once per pass and reports the skips
  (``operation_tasks_skipped_append_only`` / ``audit_skipped_append_only``);
  those rows leave only through database administration. Task volume is
  human-triggered, so the unbounded-but-small history is the accepted
  0.1.0 trade-off against weakening append-only (ADR-028);
- ui_events keep their 10-minute SSE window (DATA_MODEL.md 搂11); sessions are
  cleaned 30 days after revocation or absolute expiry (DATA_MODEL.md 搂10).
"""

from __future__ import annotations

import datetime
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import Uuid, cast, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import WardenSettings
from app.generated.metrics import METRIC_DEFINITIONS
from app.infrastructure.observation_store import ensure_metric_partitions
from app.models.observation import (
    MetricPoint,
    MetricRollup1h,
    MetricRollup5m,
)

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

FIVE_MINUTES = datetime.timedelta(minutes=5)
ONE_HOUR = datetime.timedelta(hours=1)

# A closed window keeps being regenerated for this long after it closes so
# points committed a few minutes late (a collection run finishing across a
# window boundary) still fold into the aggregate. Always below the raw
# retention, so the source points are guaranteed to exist.
ROLLUP_REGENERATION_LOOKBACK = datetime.timedelta(minutes=15)

# ui_events retention (DATA_MODEL.md 搂11: SSE 绐楀彛淇濈暀 10 鍒嗛挓).
UI_EVENT_RETENTION = datetime.timedelta(minutes=10)
# Login session cleanup (DATA_MODEL.md 搂10: 鐧诲綍浼氳瘽 杩囨湡鍚?30 澶╂竻鐞?.
SESSION_CLEANUP_DELAY = datetime.timedelta(days=30)

# Chunk size for retention batch deletes (DATA_MODEL.md 搂10: 鍒嗘壒鍒犻櫎).
DELETE_BATCH_SIZE = 2000

# Only gauge series are numerically aggregated (DATA_MODEL.md 搂5.4): states
# stay change points, counters stay raw values.
GAUGE_METRIC_KEYS = frozenset(
    key for key, definition in METRIC_DEFINITIONS.items() if definition.series == "gauge"
)

# Table names the chunked delete helper may target. The SQL per table is a
# FULLY STATIC literal below (no interpolation anywhere): the sweep never
# builds SQL from input.
_RETENTION_TABLES = frozenset(
    {
        "metric_rollups_5m",
        "metric_rollups_1h",
        "device_events",
        "alerts",
        "operation_tasks",
        "ui_events",
        "sessions",
        "audit_logs",
    }
)

_PARTITION_NAME_PATTERN = re.compile(r"^metric_points_\d{4}_\d{2}_\d{2}$")

# Chunked deletes keep every statement bounded (DATA_MODEL.md 搂10: 鍒嗘壒鍒犻櫎);
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
    "operation_tasks": (
        "DELETE FROM operation_tasks WHERE id IN "
        "(SELECT id FROM operation_tasks WHERE state IN "
        "('succeeded', 'failed', 'timed_out', 'cancelled') AND finished_at < :cutoff "
        "ORDER BY id LIMIT 2000)"
    ),
    "ui_events": (
        "DELETE FROM ui_events WHERE id IN "
        "(SELECT id FROM ui_events WHERE occurred_at < :cutoff ORDER BY id LIMIT 2000)"
    ),
    "sessions": (
        "DELETE FROM sessions WHERE id IN "
        "(SELECT id FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at < :cutoff) "
        "OR (revoked_at IS NULL AND absolute_expires_at < :cutoff) "
        "ORDER BY id LIMIT 2000)"
    ),
    "audit_logs": (
        "DELETE FROM audit_logs WHERE id IN "
        "(SELECT id FROM audit_logs WHERE occurred_at < :cutoff "
        "AND (task_id IS NULL OR task_id NOT IN (SELECT id FROM operation_tasks)) "
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
    """Counters from one retention pass (DATA_MODEL.md 搂10 璁板綍娓呯悊鏁伴噺)."""

    partitions_dropped: list[str] = field(default_factory=list)
    rollup_5m_deleted: int = 0
    rollup_1h_deleted: int = 0
    device_events_deleted: int = 0
    resolved_alerts_deleted: int = 0
    operation_tasks_deleted: int = 0
    ui_events_deleted: int = 0
    sessions_deleted: int = 0
    audit_deleted: int = 0
    audit_skipped_append_only: bool = False
    operation_tasks_skipped_append_only: bool = False

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

    Documented choice (DATA_MODEL.md 搂5.4, M2T3 brief): min of the window
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
    floor5(now)) 鈥?see the module docstring for the catch-up semantics.
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

    docs/DEPLOYMENT.md 搂9.2: PostgreSQL 鏃ュ垎鍖烘湭鏉ヨ嚦灏戦鍒涘缓 14 澶? Migration
    0006 pre-creates the same window at install; the daily maintenance call
    keeps the window rolling. Returns how many partitions were created.
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


def _append_only_trigger_exists(db: Session, table: str, trigger: str) -> bool:
    """True when an append-only trigger protects ``table`` (0002/0005).

    The audit (0002) and operation_task_events (0005) triggers reject DELETE
    for every role; 0004 additionally revoked the app account's audit DELETE.
    The sweep probes once per pass and reports the skip instead of raising on
    a daily cadence.
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
) -> RetentionReport:
    """Enforce the tiered retention (DATA_MODEL.md 搂10); the caller commits."""
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
    # DATA_MODEL.md §10 lists 操作任务与任务事件 at 365 days, but the
    # operation_task_events append-only trigger (0005, DATA_MODEL.md §7.3
    # 禁止更新/删除历史事件) makes the FK cascade impossible — a task cannot
    # be removed while its event stream exists. Same resolution as audit:
    # report the skip; events/tasks leave only through database administration.
    # (Task volume is human-triggered, so the unbounded-but-small history is
    # acceptable for 0.1.0 versus weakening append-only.)
    if _append_only_trigger_exists(db, "operation_task_events", "operation_task_events_no_delete"):
        report.operation_tasks_skipped_append_only = True
    else:
        # Only terminal states (finished_at is set exactly on terminal
        # states); queued/running/verification_required are never touched.
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
    report.sessions_deleted = _chunked_delete(
        db,
        "sessions",
        {"cutoff": now - SESSION_CLEANUP_DELAY},
    )
    # DATA_MODEL.md §10 lists audit rows at 365 days ("且不得早于关联任务"),
    # but the baseline append-only enforcement (0002 trigger + 0004 REVOKE,
    # ADR-028 / SECURITY.md §12) makes application-layer deletes impossible.
    # Report the skip instead of attempting a DELETE that must fail; audit
    # history leaves only through database administration.
    if _append_only_trigger_exists(db, "audit_logs", "audit_logs_no_delete"):
        report.audit_skipped_append_only = True
    else:
        report.audit_deleted = _chunked_delete(
            db,
            "audit_logs",
            {"cutoff": _days_ago(settings.audit_retention_days)},
        )
    return report
