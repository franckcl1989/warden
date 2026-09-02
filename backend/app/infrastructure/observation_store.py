"""Observation persistence: claim, batch writes, alert transitions, partitions.

docs/DATA_MODEL.md §5 (exact fields/quality/unique keys), §6 (alerts), §11
(采集批次一个事务), ARCHITECTURE.md §6 (唯一键去重: 指标允许至少一次写入).
Everything in this module participates in the caller's transaction — the
collection pipeline commits exactly once per batch.

- ``claim_collection_run`` reuses the M2T1 claim shape (FOR UPDATE SKIP
  LOCKED + lease) for ``collection_runs``. Claimable is ``scheduled`` OR a
  ``running`` row whose lease expired: collection is a pure read with no
  dispatch fence, so an expired-lease running run was either committed
  (terminal state) or never committed (nothing persisted) — re-claiming and
  re-running is honest and is what keeps a crashed worker from permanently
  blocking a device (the partial unique index forbids a second scheduled run).
- batch persistence uses INSERT .. ON CONFLICT DO NOTHING (metric points,
  events) and an upsert on the COALESCE expression index (metric_latest);
  validation against contracts/metrics.json + events.json happens here — a
  bad value becomes an ``ObservationError`` row, never a fabricated point.
- ``apply_alert_signals`` turns evaluator signals into durable
  open/resolve/refresh/count transitions with the ``signal_count`` counter
  (M2T2 decision: durable counters on the alert row, no in-memory state).
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import Uuid, and_, cast, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.domain.adapter import (
    ComponentObserved,
    EventObservation,
    Observation,
    ObservationBatch,
    ObservationError,
    Quality,
    canonical_json,
)
from app.domain.contracts import AlertRule
from app.domain.observation import ActiveAlertView, AlertSignal, decide_alert
from app.generated.events import EVENT_DEFINITIONS
from app.generated.metrics import ENUM_SETS, METRIC_DEFINITIONS
from app.models.devices import Component
from app.models.observation import (
    Alert,
    CollectionObservationError,
    CollectionRun,
    DeviceEvent,
    MetricLatest,
    MetricPoint,
)

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

_EVENT_SEVERITIES = ("unknown", "info", "warning", "critical")


def _parse_iso(value: object) -> datetime.datetime | None:
    if isinstance(value, str):
        try:
            parsed = datetime.datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=datetime.UTC)
        return parsed
    return None


def collection_state_last_run(
    device_state: dict[str, object], collection_type: str
) -> datetime.datetime | None:
    """Last finished_at for a collection type from devices.collection_state."""
    return _parse_iso(device_state.get(collection_type))


def claim_collection_run(
    session: Session,
    *,
    lease_owner: str,
    lease_seconds: int,
) -> CollectionRun | None:
    """Atomically claim the oldest claimable collection run (see module doc).

    The lease write and the transition to running happen in one conditional
    UPDATE; ``attempt_count`` is incremented so recovery/requeues are visible.
    """
    candidate = (
        select(CollectionRun.id)
        .where(
            or_(
                CollectionRun.state == "scheduled",
                and_(
                    CollectionRun.state == "running",
                    CollectionRun.lease_expires_at.is_not(None),
                    CollectionRun.lease_expires_at <= func.now(),
                ),
            )
        )
        .order_by(CollectionRun.scheduled_at, CollectionRun.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    stmt = (
        update(CollectionRun)
        .where(CollectionRun.id.in_(candidate))
        .values(
            state="running",
            lease_owner=lease_owner,
            lease_expires_at=func.now() + datetime.timedelta(seconds=lease_seconds),
            started_at=func.coalesce(CollectionRun.started_at, func.now()),
            attempt_count=CollectionRun.attempt_count + 1,
            updated_at=func.now(),
        )
        .returning(CollectionRun)
    )
    return session.execute(stmt).scalar_one_or_none()


def release_collection_lease(session: Session, *, run_id: uuid.UUID, owner: str) -> bool:
    """Release a collection run lease without changing its state.

    The run stays ``running`` with an immediately-expired lease so the next
    claim (or the claim of an expired-lease running run) can reclaim it.
    """
    result = session.execute(
        update(CollectionRun)
        .where(
            CollectionRun.id == run_id,
            CollectionRun.lease_owner == owner,
            CollectionRun.state == "running",
        )
        .values(lease_owner=None, lease_expires_at=func.now())
    )
    return bool(typing_cast(Any, result).rowcount == 1)


def upsert_components(
    db: Session,
    *,
    device_id: uuid.UUID,
    components: Sequence[ComponentObserved],
    now: datetime.datetime,
) -> dict[tuple[str, str], uuid.UUID]:
    """Upsert observed components and soft-retire the device's missing ones.

    Returns ``{(kind, native_id): component_id}`` for observation resolution.
    Only components of the batch are refreshed; components absent from a
    NON-EMPTY batch are retired (``retired_at``) — an empty components list
    (adapter did not report inventory this pass) never retires anything.
    """
    existing = {
        (row.kind, row.native_id): row
        for row in db.scalars(select(Component).where(Component.device_id == device_id)).all()
    }
    component_ids: dict[tuple[str, str], uuid.UUID] = {}
    if components:
        seen: set[tuple[str, str]] = set()
        for component in components:
            key = (component.kind, component.native_id)
            seen.add(key)
            row = existing.get(key)
            if row is None:
                row = Component(
                    device_id=device_id,
                    kind=component.kind,
                    native_id=component.native_id,
                    name=component.name,
                    status=component.status,
                    properties=dict(component.properties),
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(row)
                db.flush()
                existing[key] = row
            else:
                row.name = component.name
                row.status = component.status
                row.properties = dict(component.properties)
                row.last_seen_at = now
            component_ids[key] = row.id
        for key, row in existing.items():
            if key not in seen and row.retired_at is None:
                row.retired_at = now
    else:
        component_ids = {key: row.id for key, row in existing.items() if row.retired_at is None}
    return component_ids


def _resolve_component_id(
    db: Session, *, device_id: uuid.UUID, component_ids: dict[tuple[str, str], uuid.UUID]
) -> dict[tuple[str, str], uuid.UUID]:
    """Merge the batch component map with previously discovered components."""
    known = {
        (row.kind, row.native_id): row.id
        for row in db.scalars(
            select(Component).where(
                Component.device_id == device_id, Component.retired_at.is_(None)
            )
        ).all()
    }
    merged = dict(component_ids)
    merged.update(known)
    return merged


def _observation_point(metric_key: str, obs: Observation) -> tuple[dict[str, object], str] | ObservationError:
    """Validate one observation against contracts/metrics.json.

    Returns ``(point_dict, quality)`` or an ``ObservationError`` — a missing/
    invalid value is never fabricated into a 0/normal point (ADR-014).
    """
    metric = METRIC_DEFINITIONS.get(metric_key)
    if metric is None:
        return ObservationError(
            key=metric_key,
            error_code="protocol_error",
            stage="validate",
            detail="指标键不在 contracts/metrics.json 中",
        )
    value = obs.value
    if metric.value_type in ("number", "integer"):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return ObservationError(
                key=metric_key,
                error_code="protocol_error",
                stage="validate",
                detail="数值指标收到非数值观测",
            )
        quality = "good" if obs.quality is Quality.GOOD else "partial"
        if metric.range is not None and not (metric.range[0] <= float(value) <= metric.range[1]):
            # Out-of-contract range: keep the honest value but mark partial
            # (the observation is real but suspect — never clipped to range).
            quality = "partial"
        return (
            {
                "metric_key": metric_key,
                "value_double": float(value),
                "value_text": None,
                "unit": metric.unit,
                "quality": quality,
            },
            quality,
        )
    if metric.value_type == "boolean":
        if not isinstance(value, bool):
            return ObservationError(
                key=metric_key,
                error_code="protocol_error",
                stage="validate",
                detail="布尔指标收到非布尔观测",
            )
        quality = "good" if obs.quality is Quality.GOOD else "partial"
        return (
            {
                "metric_key": metric_key,
                "value_double": None,
                "value_text": "true" if value else "false",
                "unit": None,
                "quality": quality,
            },
            quality,
        )
    if metric.value_type == "enum":
        if not isinstance(value, str) or value not in ENUM_SETS.get(metric.enum_set or "", ()):
            return ObservationError(
                key=metric_key,
                error_code="protocol_error",
                stage="validate",
                detail="枚举指标值不在契约 enum_set 中",
            )
        quality = "good" if obs.quality is Quality.GOOD else "partial"
        return (
            {
                "metric_key": metric_key,
                "value_double": None,
                "value_text": value,
                "unit": None,
                "quality": quality,
            },
            quality,
        )
    return ObservationError(
        key=metric_key,
        error_code="protocol_error",
        stage="validate",
        detail="指标 value_type 不受支持",
    )


def event_dedupe_hash(event: EventObservation) -> str:
    """Stable content hash for events without a native ID (DATA_MODEL.md §5.5).

    The hash covers type/component/message only — NOT occurred_at — so the
    same event re-reported (retry, re-poll) dedupes against the partial unique
    index ``uq_device_events_hash``.
    """
    payload = {
        "event_type": event.event_type,
        "component_kind": event.component_kind,
        "component_native_id": event.component_native_id,
        "message": event.message,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _event_row(
    device_id: uuid.UUID,
    event: EventObservation,
    *,
    component_id: uuid.UUID | None,
    now: datetime.datetime,
) -> dict[str, object] | ObservationError:
    definition = EVENT_DEFINITIONS.get(event.event_type)
    if definition is None:
        return ObservationError(
            key=event.event_type,
            error_code="protocol_error",
            stage="validate",
            detail="事件键不在 contracts/events.json 中",
        )
    if event.source not in definition.sources:
        return ObservationError(
            key=event.event_type,
            error_code="protocol_error",
            stage="validate",
            detail="事件来源不在契约 sources 中",
        )
    if event.severity not in _EVENT_SEVERITIES:
        return ObservationError(
            key=event.event_type,
            error_code="protocol_error",
            stage="validate",
            detail="事件严重级别未归一化",
        )
    if "component_native_id" in definition.required_fields and event.component_native_id is None:
        return ObservationError(
            key=event.event_type,
            error_code="protocol_error",
            stage="validate",
            detail="事件缺少必需字段 component_native_id",
        )
    native = event.native_event_id
    return {
        "device_id": device_id,
        "component_id": component_id,
        "event_type": event.event_type,
        "severity": event.severity,
        "message": event.message,
        "occurred_at": event.occurred_at,
        "received_at": now,
        "source": event.source,
        "native_event_id": native,
        "dedupe_hash": None if native is not None else event_dedupe_hash(event),
        "detail": dict(event.detail),
    }


@dataclass
class PersistOutcome:
    """Counters from one batch persistence (drives the run terminal state)."""

    successes: int = 0
    errors: int = 0
    points_written: int = 0
    points_deduped: int = 0
    latest_written: int = 0
    events_written: int = 0
    events_deduped: int = 0


def persist_observation_batch(
    db: Session,
    *,
    device_id: uuid.UUID,
    batch: ObservationBatch,
    run_id: uuid.UUID,
    now: datetime.datetime,
) -> PersistOutcome:
    """Persist one ObservationBatch in the caller's transaction.

    - components: upsert + retire missing (soft);
    - metric_points: good/partial observations only, INSERT .. ON CONFLICT DO
      NOTHING (at-least-once dedupe via the COALESCE unique index); a point
      with a duplicate unique key is counted as deduped, never overwritten;
    - metric_latest: upsert on the COALESCE unique index — good observations
      only (a partial value is suspect and must not become "current");
    - device_events: dedup via the native-id and content-hash unique indexes;
    - observation errors (adapter errors, validation failures, error-quality
      observations) go to collection_observation_errors; the run-level
      terminal state is derived by the caller from ``PersistOutcome``.
    """
    outcome = PersistOutcome()
    component_ids = upsert_components(db, device_id=device_id, components=batch.components, now=now)
    component_ids = _resolve_component_id(db, device_id=device_id, component_ids=component_ids)

    point_params: list[dict[str, object]] = []
    latest_params: list[dict[str, object]] = []
    error_rows: list[dict[str, object]] = []
    for obs in batch.observations:
        if obs.quality is Quality.ERROR:
            outcome.errors += 1
            error_rows.append(
                _error_row(
                    device_id, run_id, obs.metric_key, error_code="protocol_error",
                    stage="validate", detail="观测质量标记为 error，未写入指标点", now=now,
                )
            )
            continue
        component_id = _component_id(component_ids, obs.component_kind, obs.component_native_id)
        if component_id is None and obs.component_kind is not None:
            outcome.errors += 1
            error_rows.append(
                _error_row(
                    device_id, run_id, obs.metric_key, error_code="protocol_error",
                    stage="validate", detail="观测引用了设备未知的组件", now=now,
                )
            )
            continue
        point = _observation_point(obs.metric_key, obs)
        if isinstance(point, ObservationError):
            outcome.errors += 1
            error_rows.append(
                _error_row(
                    device_id, run_id, point.key, error_code=point.error_code,
                    stage=point.stage, detail=point.detail, now=now,
                )
            )
            continue
        point_dict, quality = point
        outcome.successes += 1
        if quality == "good":
            latest_params.append(
                {
                    "device_id": device_id,
                    "component_id": component_id,
                    "metric_key": point_dict["metric_key"],
                    "value_double": point_dict["value_double"],
                    "value_text": point_dict["value_text"],
                    "unit": point_dict["unit"],
                    "quality": quality,
                    "source": obs.source,
                    "observed_at": obs.observed_at,
                    "collection_run_id": run_id,
                }
            )
        point_params.append(
            {
                "id": uuid.uuid4(),
                "device_id": device_id,
                "component_id": component_id,
                "metric_key": point_dict["metric_key"],
                "observed_at": obs.observed_at,
                "value_double": point_dict["value_double"],
                "value_text": point_dict["value_text"],
                "unit": point_dict["unit"],
                "quality": quality,
                "source": obs.source,
                "collection_run_id": run_id,
            }
        )

    if point_params:
        # RETURNING turns the executemany into one multi-row INSERT whose
        # returned rows are exactly the rows actually inserted (deduped rows
        # are skipped by ON CONFLICT DO NOTHING).
        result = db.execute(
            pg_insert(MetricPoint).on_conflict_do_nothing().returning(MetricPoint.id), point_params
        )
        inserted = len(result.all())
        outcome.points_written = inserted
        outcome.points_deduped = len(point_params) - inserted
    if latest_params:
        outcome.latest_written = len(latest_params)
        db.execute(
            pg_insert(MetricLatest)
            .values(latest_params)
            .on_conflict_do_update(
                index_elements=[
                    MetricLatest.device_id,
                    func.coalesce(MetricLatest.component_id, cast(ZERO_UUID, Uuid)),
                    MetricLatest.metric_key,
                ],
                set_={
                    "value_double": pg_insert(MetricLatest).excluded.value_double,
                    "value_text": pg_insert(MetricLatest).excluded.value_text,
                    "unit": pg_insert(MetricLatest).excluded.unit,
                    "quality": pg_insert(MetricLatest).excluded.quality,
                    "source": pg_insert(MetricLatest).excluded.source,
                    "observed_at": pg_insert(MetricLatest).excluded.observed_at,
                    "collection_run_id": pg_insert(MetricLatest).excluded.collection_run_id,
                    "updated_at": func.now(),
                },
            )
        )

    event_params: list[dict[str, object]] = []
    for event in batch.events:
        component_id = _component_id(component_ids, event.component_kind, event.component_native_id)
        if component_id is None and event.component_kind is not None:
            outcome.errors += 1
            error_rows.append(
                _error_row(
                    device_id, run_id, event.event_type, error_code="protocol_error",
                    stage="validate", detail="事件引用了设备未知的组件", now=now,
                )
            )
            continue
        row = _event_row(device_id, event, component_id=component_id, now=now)
        if isinstance(row, ObservationError):
            outcome.errors += 1
            error_rows.append(
                _error_row(
                    device_id, run_id, row.key, error_code=row.error_code,
                    stage=row.stage, detail=row.detail, now=now,
                )
            )
            continue
        event_params.append(row)
    if event_params:
        result = db.execute(
            pg_insert(DeviceEvent).on_conflict_do_nothing().returning(DeviceEvent.id), event_params
        )
        inserted = len(result.all())
        outcome.events_written = inserted
        outcome.events_deduped = len(event_params) - inserted

    for error in batch.errors:
        outcome.errors += 1
        error_rows.append(
            _error_row(
                device_id, run_id, error.key, error_code=error.error_code,
                stage=error.stage, detail=error.detail, now=now,
            )
        )
    if error_rows:
        db.execute(pg_insert(CollectionObservationError).values(error_rows))
    return outcome


def _component_id(
    component_ids: dict[tuple[str, str], uuid.UUID], kind: str | None, native_id: str | None
) -> uuid.UUID | None:
    if kind is None or native_id is None:
        return None
    return component_ids.get((kind, native_id))


def _error_row(
    device_id: uuid.UUID,
    run_id: uuid.UUID | None,
    key: str | None,
    *,
    error_code: str,
    stage: str,
    detail: str | None,
    now: datetime.datetime,
) -> dict[str, object]:
    return {
        "collection_run_id": run_id,
        "device_id": device_id,
        "metric_key_or_event_key": key,
        "component_id": None,
        "error_code": error_code,
        "stage": stage,
        "detail": detail,
        "occurred_at": now,
    }


def apply_alert_signals(
    db: Session,
    *,
    device_id: uuid.UUID,
    signals: Sequence[AlertSignal],
    rules_by_key: dict[str, AlertRule],
    now: datetime.datetime,
) -> list[tuple[str, uuid.UUID]]:
    """Apply evaluator signals to the alerts table (DATA_MODEL.md §6, ADR-025).

    Returns ``[(event_type, alert_id), ...]`` for the caller to write
    ui_events in the same transaction (alert.opened/alert.resolved/
    alert.updated). The partial unique index ``uq_alerts_active_dedupe``
    guards the one-active-per-dedupe invariant at the database.
    """
    active = {
        row.dedupe_key: row
        for row in db.scalars(
            select(Alert).where(Alert.device_id == device_id, Alert.status == "active")
        ).all()
    }
    ui_events: list[tuple[str, uuid.UUID]] = []
    for signal in signals:
        rule = rules_by_key.get(signal.rule_key)
        if rule is None:
            continue
        current = active.get(signal.dedupe_key)
        view = (
            ActiveAlertView(dedupe_key=signal.dedupe_key, signal_count=current.signal_count)
            if current is not None
            else None
        )
        decision = decide_alert(rule, view, signal)
        if decision.action == "open":
            alert = Alert(
                device_id=device_id,
                component_id=signal.component_id,
                rule_key=signal.rule_key,
                severity=decision.severity or "critical",
                status="active",
                title=decision.title or signal.title,
                evidence=decision.evidence,
                first_occurred_at=now,
                last_occurred_at=now,
                dedupe_key=signal.dedupe_key,
                signal_count=0,
                version=1,
            )
            db.add(alert)
            db.flush()
            active[signal.dedupe_key] = alert
            ui_events.append(("alert.opened", alert.id))
        elif decision.action == "resolve" and current is not None:
            current.status = "resolved"
            current.resolved_at = now
            current.last_occurred_at = now
            current.signal_count = decision.signal_count
            current.version += 1
            ui_events.append(("alert.resolved", current.id))
        elif decision.action == "refresh" and current is not None:
            current.severity = decision.severity or current.severity
            current.title = decision.title or current.title
            current.evidence = decision.evidence
            current.last_occurred_at = now
            current.signal_count = 0
            current.version += 1
            ui_events.append(("alert.updated", current.id))
        elif decision.action == "count" and current is not None:
            current.signal_count = decision.signal_count
        elif decision.action == "reset_count" and current is not None:
            current.signal_count = 0
    return ui_events


def ensure_metric_partitions(session: Session, *, start_date: datetime.date, days: int) -> int:
    """Create daily metric_points partitions for ``days`` days from start_date.

    The SQL function ``create_metric_partition`` (migration 0006) is
    idempotent and returns True when it created a partition; M2T3 wires the
    daily maintenance call.
    """
    created = 0
    for offset in range(days):
        day = start_date + datetime.timedelta(days=offset)
        result = session.execute(text("SELECT create_metric_partition(:day)"), {"day": day})
        if result.scalar() is True:
            created += 1
    return created
