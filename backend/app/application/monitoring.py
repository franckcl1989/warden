"""Monitoring read use cases (PLT-03/PLT-04): metrics, overview, alerts.

docs/API_CONTRACT.md §4-§5 (devices components/events lists, monitoring
queries with the §5 resolution rules), DATA_MODEL.md §5-§6, PRODUCT_DESIGN.md
§3 (overview), §6.3-6.4 (freshness and current-problem semantics).

Query semantics:

- latest metrics come from ``metric_latest`` (current trusted values only,
  DATA_MODEL.md §5.3); freshness is computed from each row's observed_at and
  the collection interval of the type that refreshes the key (PRODUCT_DESIGN
  §6.3: fresh <= 2x, stale <= 3x, expired > 3x, unknown when never observed);
- the series endpoint applies API_CONTRACT.md §5 resolution selection to
  numeric gauge keys (raw within 7d, 5m rollups to 30d, 1h rollups to 180d,
  coarser client requests honored, finer rejected) and always serves raw
  change points for state/boolean/monotonic_counter keys (DATA_MODEL.md §5.4:
  those series are never numerically aggregated);
- the overview counts real tables only: unknown states are counted as unknown
  and never shown as zero; attention problems come ONLY from engine-created
  active alerts (PRODUCT_DESIGN.md §6.4), ranked offline > critical severity
  > warning severity > data.expired; recent operations stay empty until M2T4;
- the alerts API shows only rows the alert engine created (no synthetic
  rows); the list omits evidence, the single-record view returns it plus the
  first/last/resolved timeline (DATA_MODEL.md §6.1 — no separate timeline
  table exists; evidence covers it);
- device components list shows current (non-retired) components; the events
  list never exposes the raw JSONB detail blob beyond what the event row
  itself carries (message/severity/timestamps) — device log bodies are
  product data but support detail stays on the write path only.
"""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field

from sqlalchemy import ColumnElement, Row, func, select
from sqlalchemy.orm import Session

from app.config import WardenSettings
from app.domain.contracts import MetricDefinition
from app.domain.observation import FreshnessCalculator
from app.generated.metrics import METRIC_DEFINITIONS
from app.models.devices import Component, Device
from app.models.observation import (
    Alert,
    CollectionRun,
    DeviceEvent,
    MetricLatest,
    MetricPoint,
    MetricRollup1h,
    MetricRollup5m,
)
from app.models.operation import OperationTask

DEVICE_TYPES = ("server", "synology_nas", "core_switch", "access_switch")
REACHABILITY_STATES = ("unknown", "online", "offline")
HEALTH_STATES = ("unknown", "healthy", "warning", "critical")

# PRODUCT_DESIGN.md §3.3 attention ordering: 离线 > 严重 > 警告 > 数据过期.
_ATTENTION_RANK: dict[str, int] = {
    "device.offline": 0,
    "critical": 1,
    "warning": 2,
    "data.expired": 3,
}


@dataclass(frozen=True)
class LatestMetricItemData:
    """One metric_latest row rendered for the latest-metrics endpoint."""

    metric_key: str
    value: float | str | bool | None
    unit: str | None
    quality: str
    observed_at: datetime.datetime
    source: str
    freshness: str


@dataclass(frozen=True)
class LatestGroup:
    """One metric_latest group for the latest-metrics endpoint."""

    component: tuple[uuid.UUID, str, str, str] | None  # (id, kind, native_id, name)
    metrics: tuple[LatestMetricItemData, ...]


@dataclass(frozen=True)
class SeriesPoint:
    """One point of a metric series (raw value or window aggregate)."""

    timestamp: datetime.datetime
    value: float | str | bool | None
    quality: str
    source: str | None = None
    min_value: float | None = None
    max_value: float | None = None
    last_value: float | None = None
    count: int | None = None


@dataclass(frozen=True)
class SeriesResult:
    """A metric time series with its per-series metadata (API_CONTRACT §5)."""

    metric_key: str
    series_kind: str  # gauge | state | monotonic_counter
    value_type: str  # number | integer | enum | boolean
    unit: str | None
    resolution: str  # actual resolution served (raw | 5m | 1h)
    points: tuple[SeriesPoint, ...]


def _component_label(
    db: Session, component_id: uuid.UUID | None
) -> tuple[uuid.UUID, str, str, str] | None:
    if component_id is None:
        return None
    row = db.get(Component, component_id)
    if row is None:
        return None
    return (row.id, row.kind, row.native_id, row.name)


def _interval_for_metric(
    metric_key: str, settings: WardenSettings, intervals: dict[str, int]
) -> int:
    from app.application.collection import collection_type_for_capability_key

    return intervals[collection_type_for_capability_key(metric_key)]


def list_latest_metrics(
    db: Session,
    *,
    device: Device,
    page: int,
    page_size: int,
    now: datetime.datetime,
    settings: WardenSettings,
) -> tuple[list[LatestGroup], int]:
    """metric_latest rows grouped by component; pages run over the groups.

    The endpoint answers "current values per component" (API_CONTRACT.md §5),
    so pagination is per component group, not per raw row: rows are grouped
    first and the page slices the groups (each group carries every supported
    series' current value for that component).
    """
    from app.application.collection import collection_intervals

    intervals = collection_intervals(settings)
    rows = list(
        db.scalars(
            select(MetricLatest)
            .where(MetricLatest.device_id == device.id)
            .order_by(MetricLatest.metric_key.asc())
        ).all()
    )
    components: dict[uuid.UUID | None, list[LatestMetricItemData]] = {}
    for row in rows:
        definition = METRIC_DEFINITIONS.get(row.metric_key)
        interval = _interval_for_metric(row.metric_key, settings, intervals)
        metric_view = LatestMetricItemData(
            metric_key=row.metric_key,
            value=_decode_value(definition, row.value_double, row.value_text),
            unit=row.unit,
            quality=row.quality,
            observed_at=row.observed_at,
            source=row.source,
            freshness=FreshnessCalculator.freshness(row.observed_at, interval, now),
        )
        components.setdefault(row.component_id, []).append(metric_view)
    grouped = [
        LatestGroup(
            component=_component_label(db, component_id),
            metrics=tuple(metrics),
        )
        for component_id, metrics in components.items()
    ]
    total = len(grouped)
    start = (page - 1) * page_size
    return grouped[start : start + page_size], total


def _decode_value(
    definition: MetricDefinition | None,
    value_double: float | None,
    value_text: str | None,
) -> float | str | bool | None:
    if value_text is not None:
        if definition is not None and definition.value_type == "boolean":
            return value_text == "true"
        return value_text
    return value_double


def _raw_points(
    db: Session,
    *,
    device_id: uuid.UUID,
    component_id: uuid.UUID | None,
    metric_key: str,
    from_: datetime.datetime,
    to_: datetime.datetime,
) -> tuple[SeriesPoint, ...]:
    rows = db.execute(
        select(
            MetricPoint.observed_at,
            MetricPoint.value_double,
            MetricPoint.value_text,
            MetricPoint.quality,
            MetricPoint.source,
        )
        .where(
            MetricPoint.device_id == device_id,
            MetricPoint.metric_key == metric_key,
            MetricPoint.observed_at >= from_,
            MetricPoint.observed_at < to_,
        )
        .order_by(MetricPoint.observed_at.asc())
    ).all()
    definition = METRIC_DEFINITIONS.get(metric_key)
    return tuple(
        SeriesPoint(
            timestamp=row[0],
            value=_decode_value(definition, row[1], row[2]),
            quality=row[3],
            source=row[4],
        )
        for row in rows
    )


def _rollup_points(
    db: Session,
    model: type[MetricRollup5m] | type[MetricRollup1h],
    *,
    device_id: uuid.UUID,
    component_id: uuid.UUID | None,
    metric_key: str,
    from_: datetime.datetime,
    to_: datetime.datetime,
) -> tuple[SeriesPoint, ...]:
    rows = db.execute(
        select(
            model.window_start,
            model.min_value,
            model.max_value,
            model.avg_value,
            model.last_value,
            model.count,
            model.quality,
        )
        .where(
            model.device_id == device_id,
            model.metric_key == metric_key,
            model.component_id == component_id,
            model.window_start >= from_,
            model.window_start < to_,
        )
        .order_by(model.window_start.asc())
    ).all()
    return tuple(
        SeriesPoint(
            timestamp=row[0],
            value=row[3],  # avg is the chart value (M2T3 brief)
            quality=row[6],
            source=None,
            min_value=row[1],
            max_value=row[2],
            last_value=row[4],
            count=row[5],
        )
        for row in rows
    )


def read_series(
    db: Session,
    *,
    device: Device,
    metric_key: str,
    component_id: uuid.UUID | None,
    from_: datetime.datetime,
    to_: datetime.datetime,
    resolution: str,
) -> SeriesResult:
    """Read one metric series per the API_CONTRACT §5 resolution rules.

    ``resolution`` is the already-validated ACTUAL resolution to serve
    (resolution selection and its 422s happen in the API layer): gauge keys
    read raw points or the 5m/1h rollup tables; state/boolean/monotonic_counter
    keys always read raw change points/checkpoints (never aggregated).
    """
    definition = METRIC_DEFINITIONS[metric_key]
    if definition.series == "gauge":
        if resolution == "raw":
            points = _raw_points(
                db,
                device_id=device.id,
                component_id=component_id,
                metric_key=metric_key,
                from_=from_,
                to_=to_,
            )
        elif resolution == "5m":
            points = _rollup_points(
                db,
                MetricRollup5m,
                device_id=device.id,
                component_id=component_id,
                metric_key=metric_key,
                from_=from_,
                to_=to_,
            )
        else:
            points = _rollup_points(
                db,
                MetricRollup1h,
                device_id=device.id,
                component_id=component_id,
                metric_key=metric_key,
                from_=from_,
                to_=to_,
            )
        actual = resolution
    else:
        # State/boolean/counter series are stored as sparse raw points; the
        # rollup tables never aggregate them (DATA_MODEL.md §5.4).
        points = _raw_points(
            db,
            device_id=device.id,
            component_id=component_id,
            metric_key=metric_key,
            from_=from_,
            to_=to_,
        )
        actual = "raw"
    return SeriesResult(
        metric_key=metric_key,
        series_kind=definition.series,
        value_type=definition.value_type,
        unit=definition.unit,
        resolution=actual,
        points=points,
    )


def list_collection_runs(
    db: Session,
    *,
    device: Device,
    page: int,
    page_size: int,
    collection_type: str | None,
    state: str | None,
) -> tuple[list[CollectionRun], int]:
    """Collection-run history (API_CONTRACT §5): lease internals never leak."""
    filters: list[ColumnElement[bool]] = [CollectionRun.device_id == device.id]
    if collection_type is not None:
        filters.append(CollectionRun.collection_type == collection_type)
    if state is not None:
        filters.append(CollectionRun.state == state)
    base = select(CollectionRun).where(*filters)
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = list(
        db.scalars(
            base.order_by(CollectionRun.scheduled_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


@dataclass(frozen=True)
class ProblemView:
    """One active alert rendered for the overview attention list."""

    id: uuid.UUID
    rule_key: str
    severity: str
    title: str
    first_occurred_at: datetime.datetime
    last_occurred_at: datetime.datetime


@dataclass(frozen=True)
class OverviewAttention:
    """One device in the overview attention list (PRODUCT_DESIGN.md §3.3)."""

    device_id: uuid.UUID
    device_name: str
    device_type: str
    vendor: str | None
    model: str | None
    last_collected_at: datetime.datetime | None
    rank: int
    problems: tuple[ProblemView, ...]


@dataclass
class _AttentionAccumulator:
    """Mutable per-device attention state built from the active-alert scan."""

    device_id: uuid.UUID
    device_name: str
    device_type: str
    vendor: str | None
    model: str | None
    last_collected_at: datetime.datetime | None
    rank: int
    problems: list[ProblemView] = field(default_factory=list)

    def merge(self, rank: int, problem: ProblemView) -> None:
        self.rank = min(self.rank, rank)
        self.problems.append(problem)

    def to_view(self) -> OverviewAttention:
        return OverviewAttention(
            device_id=self.device_id,
            device_name=self.device_name,
            device_type=self.device_type,
            vendor=self.vendor,
            model=self.model,
            last_collected_at=self.last_collected_at,
            rank=self.rank,
            problems=tuple(self.problems),
        )


@dataclass(frozen=True)
class OverviewData:
    """The /overview payload (PRODUCT_DESIGN.md §3)."""

    device_total: int
    reachability: dict[str, int]
    health: dict[str, int]
    active_critical_alerts: int
    operations_running: int
    operations_verification_required: int
    device_types: dict[str, dict[str, dict[str, int]]]
    attention: tuple[OverviewAttention, ...]
    recent_operations: tuple[tuple[object, ...], ...] = ()
    as_of: datetime.datetime | None = None


def _alert_problem_view(alert: Alert) -> ProblemView:
    return ProblemView(
        id=alert.id,
        rule_key=alert.rule_key,
        severity=alert.severity,
        title=alert.title,
        first_occurred_at=alert.first_occurred_at,
        last_occurred_at=alert.last_occurred_at,
    )


def _attention_rank(alert: Alert) -> int:
    if alert.rule_key == "device.offline":
        return _ATTENTION_RANK["device.offline"]
    if alert.rule_key == "data.expired":
        return _ATTENTION_RANK["data.expired"]
    return _ATTENTION_RANK.get(alert.severity, _ATTENTION_RANK["warning"])


def build_overview(db: Session, *, now: datetime.datetime) -> OverviewData:
    """Counts from real tables (never fabricated); attention from active
    alerts only; recent operations empty until M2T4."""
    device_count_rows = db.execute(
        select(Device.reachability, func.count()).group_by(Device.reachability)
    ).all()
    reachability = {key: int(count) for key, count in device_count_rows}
    health_rows = db.execute(
        select(Device.health, func.count()).group_by(Device.health)
    ).all()
    health = {key: int(count) for key, count in health_rows}
    device_total = int(db.scalar(select(func.count()).select_from(Device)) or 0)
    active_critical = int(
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status == "active", Alert.severity == "critical")
        )
        or 0
    )
    open_states = ("running", "waiting_device")
    running_tasks = int(
        db.scalar(
            select(func.count())
            .select_from(OperationTask)
            .where(OperationTask.state.in_(open_states))
        )
        or 0
    )
    verification_required = int(
        db.scalar(
            select(func.count())
            .select_from(OperationTask)
            .where(OperationTask.state == "verification_required")
        )
        or 0
    )

    device_types: dict[str, dict[str, dict[str, int]]] = {}
    for device_type in DEVICE_TYPES:
        type_rows = db.execute(
            select(Device.reachability, Device.health, func.count())
            .where(Device.device_type == device_type)
            .group_by(Device.reachability, Device.health)
        ).all()
        per_type: dict[str, dict[str, int]] = {
            "reachability": dict.fromkeys(REACHABILITY_STATES, 0),
            "health": dict.fromkeys(HEALTH_STATES, 0),
        }
        for reach, state_health, count in type_rows:
            per_type["reachability"][reach] += int(count)
            per_type["health"][state_health] += int(count)
        device_types[device_type] = per_type

    # Attention: devices with ACTIVE engine alerts, ranked and ordered per
    # PRODUCT_DESIGN.md §3.3. Unknown devices never appear here (no alert
    # without engine evidence).
    alert_rows = db.execute(
        select(
            Alert,
            Device.name,
            Device.device_type,
            Device.vendor,
            Device.model,
            Device.last_collected_at,
        )
        .join(Device, Device.id == Alert.device_id)
        .where(Alert.status == "active")
        .order_by(Alert.first_occurred_at.asc())
    ).all()
    by_device: dict[uuid.UUID, _AttentionAccumulator] = {}
    for alert, name, device_type, vendor, model, last_collected_at in alert_rows:
        entry = by_device.get(alert.device_id)
        if entry is None:
            entry = _AttentionAccumulator(
                device_id=alert.device_id,
                device_name=name,
                device_type=device_type,
                vendor=vendor,
                model=model,
                last_collected_at=last_collected_at,
                rank=_attention_rank(alert),
            )
            by_device[alert.device_id] = entry
        entry.merge(_attention_rank(alert), _alert_problem_view(alert))
    attention = tuple(
        entry.to_view()
        for entry in sorted(by_device.values(), key=lambda item: (item.rank, item.device_name))
    )

    return OverviewData(
        device_total=device_total,
        reachability={state: reachability.get(state, 0) for state in REACHABILITY_STATES},
        health={state: health.get(state, 0) for state in HEALTH_STATES},
        active_critical_alerts=active_critical,
        operations_running=running_tasks,
        operations_verification_required=verification_required,
        device_types=device_types,
        attention=attention,
        recent_operations=(),
        as_of=now,
    )


def list_alerts(
    db: Session,
    *,
    page: int,
    page_size: int,
    status: str | None,
    device_id: uuid.UUID | None,
    severity: str | None,
    rule_key: str | None,
) -> tuple[list[Row[tuple[Alert, str, str]]], int]:
    """Alert summaries joined with the device name (evidence stays in the
    detail view; the list is the API_CONTRACT.md §5 列表)."""
    filters: list[ColumnElement[bool]] = [Alert.device_id == Device.id]
    if status is not None:
        filters.append(Alert.status == status)
    if device_id is not None:
        filters.append(Alert.device_id == device_id)
    if severity is not None:
        filters.append(Alert.severity == severity)
    if rule_key is not None:
        filters.append(Alert.rule_key == rule_key)
    base = select(Alert, Device.name, Device.device_type).where(*filters)
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = list(
        db.execute(
            base.order_by(Alert.first_occurred_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


def get_alert_row(
    db: Session, alert_id: uuid.UUID
) -> Row[tuple[Alert, str, str]] | None:
    """The full engine-created alert record (evidence + timeline included)."""
    return db.execute(
        select(Alert, Device.name, Device.device_type)
        .join(Device, Device.id == Alert.device_id)
        .where(Alert.id == alert_id)
    ).first()


def list_components(
    db: Session,
    *,
    device: Device,
    page: int,
    page_size: int,
    kind: str | None,
    status: str | None,
) -> tuple[list[Component], int]:
    """Current (non-retired) components, kind/status filtered."""
    filters: list[ColumnElement[bool]] = [
        Component.device_id == device.id,
        Component.retired_at.is_(None),
    ]
    if kind is not None:
        filters.append(Component.kind == kind)
    if status is not None:
        filters.append(Component.status == status)
    base = select(Component).where(*filters)
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = list(
        db.scalars(
            base.order_by(Component.kind.asc(), Component.native_id.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total


def list_device_events(
    db: Session,
    *,
    device: Device,
    page: int,
    page_size: int,
    severity: str | None,
    event_type: str | None,
    source: str | None,
    from_: datetime.datetime | None,
    to_: datetime.datetime | None,
) -> tuple[list[DeviceEvent], int]:
    """Device event history (API_CONTRACT.md §4): severity/type/source/time
    filters, newest first. The JSONB detail blob stays on the write path."""
    filters: list[ColumnElement[bool]] = [DeviceEvent.device_id == device.id]
    if severity is not None:
        filters.append(DeviceEvent.severity == severity)
    if event_type is not None:
        filters.append(DeviceEvent.event_type == event_type)
    if source is not None:
        filters.append(DeviceEvent.source == source)
    if from_ is not None:
        filters.append(DeviceEvent.occurred_at >= from_)
    if to_ is not None:
        filters.append(DeviceEvent.occurred_at <= to_)
    base = select(DeviceEvent).where(*filters)
    total = int(db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = list(
        db.scalars(
            base.order_by(DeviceEvent.occurred_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
    )
    return rows, total
