"""Collection orchestration: scheduling, claiming and the run pipeline (M2T2).

docs/ARCHITECTURE.md §5.1 (6-step collection data flow), §3.3 (调度循环/采集池),
§8 (periods: 30s reachability+health / 60s metrics / 120s logs / 6h discovery),
DATA_MODEL.md §11 (采集批次一个事务: components/metrics/events/errors/alerts/
device state commit together), DEVICE_ADAPTERS.md §2.3 (batch semantics).

Flow per run: scheduler writes ``scheduled`` rows -> pool claims with
FOR UPDATE SKIP LOCKED + lease -> adapter ``collect`` -> ONE transaction
persists components/metrics/events/errors, recomputes reachability and
refreshes health from batches carrying health evidence
(``_compute_health``: connectivity-only runs never regress the health
column, PRODUCT_DESIGN.md §6.2), derives the run terminal state, runs the
alert engine (process_collection_events) and writes ui_events -> the caller
commits.

Failure semantics: an ObservationError per metric is batch-partial (successes
persist, run=partial); an adapter-level failure marks the run failed with a
stable error code and feeds the reachability tracker a failure event;
``authentication_failed`` additionally backs off the next poll to 5x the
interval (credential errors must not churn high-frequency retries,
ARCHITECTURE.md §7).
"""

from __future__ import annotations

import datetime
import json
import uuid
from collections.abc import Sequence

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.adapters.registry import UnknownAdapterError, get_adapter
from app.config import WardenSettings
from app.domain.adapter import (
    AdapterError,
    CollectionRequest,
    DeviceSession,
    ObservationBatch,
    Quality,
)
from app.domain.observation import (
    AlertEvaluator,
    CapabilityGroupFreshness,
    DeviceAlertSnapshot,
    FreshnessCalculator,
    HealthAggregator,
    MetricSignal,
    ReachabilityState,
    ReachabilityTracker,
    health_state_from_outcome,
    outcome_for_metric,
)
from app.generated.alerts import ALERT_RULES, BOOLEAN_VALUE_MAPS, ENUM_VALUE_MAPS
from app.generated.capabilities import REQUIREMENTS
from app.generated.events import EVENT_DEFINITIONS
from app.generated.metrics import METRIC_DEFINITIONS
from app.infrastructure.crypto import CredentialKeyring, DecryptionError, EncryptedSecret, credential_aad
from app.infrastructure.observation_store import (
    apply_alert_signals,
    collection_state_last_run,
    persist_observation_batch,
    supported_capability_keys,
)
from app.infrastructure.time import utcnow
from app.models.devices import Device, DeviceCredential
from app.models.observation import CollectionRun, MetricLatest, UiEvent

# ARCHITECTURE.md §8 default periods; reachability and health share the 30s
# interval (基础可达性和综合健康：30 秒).
HEALTH_COLLECTION_INTERVAL_ALIAS = "reachability"

# Backoff multiplier applied to the collection type's interval after an
# authentication_failed run (ARCHITECTURE.md §7: 凭据错误停止高频重试).
AUTH_FAILURE_BACKOFF_MULTIPLIER = 5

AUTH_FAILURE_BACKOFF_KEY = "_backoff"


def collection_intervals(settings: WardenSettings) -> dict[str, int]:
    """Per-collection-type interval in seconds (deployment configuration)."""
    return {
        "reachability": settings.reachability_interval_seconds,
        "health": settings.reachability_interval_seconds,
        "metrics": settings.metrics_interval_seconds,
        "logs": settings.logs_interval_seconds,
        "discovery": settings.discovery_interval_seconds,
    }


def collection_type_for_capability_key(capability_key: str) -> str:
    """Capability key -> the collection type whose cadence refreshes it.

    Single documented mapping (docs/ARCHITECTURE.md §8) used by the data
    freshness computation:

    - metrics.json keys — health and metric values (设备指标、端口、磁盘、
      电源、风扇) — are carried by the ``metrics`` collection -> metrics
      interval;
    - events.json keys (SEL/DSM 日志/交换机关键日志) by the ``logs``
      collection -> logs interval;
    - everything else (operations, capability discovery: 资产、FRU、固件、
      能力发现) by the ``discovery`` collection -> discovery interval.
    """
    if capability_key in METRIC_DEFINITIONS:
        return "metrics"
    if capability_key in EVENT_DEFINITIONS:
        return "logs"
    return "discovery"


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


def _backoff_until(
    device: Device, collection_type: str, *, now: datetime.datetime
) -> datetime.datetime | None:
    """Credential-error backoff for one collection type (or None)."""
    state = device.collection_state or {}
    backoff = state.get(AUTH_FAILURE_BACKOFF_KEY)
    if isinstance(backoff, dict):
        until = _parse_iso(backoff.get(collection_type))
        if until is not None and until > now:
            return until
    return None


def _next_due_for_type(
    device: Device,
    *,
    collection_type: str,
    interval: int,
    now: datetime.datetime,
    pending_types: frozenset[str],
    scheduled_types: frozenset[str],
) -> datetime.datetime:
    """Next due time for one collection type (backoff-aware).

    - a credential-error backoff (``_backoff`` in collection_state) rules
      until it expires;
    - a pending (scheduled/running) run or a just-scheduled type wakes at
      now + interval (do not pile up duplicate rows);
    - otherwise next due is last_finished_at + interval.
    """
    backed_off = _backoff_until(device, collection_type, now=now)
    if backed_off is not None:
        return backed_off
    if collection_type in pending_types or collection_type in scheduled_types:
        return now + datetime.timedelta(seconds=interval)
    last = collection_state_last_run(device.collection_state or {}, collection_type)
    if last is None:
        return now
    return last + datetime.timedelta(seconds=interval)


def recompute_next_poll(
    device: Device,
    *,
    now: datetime.datetime,
    settings: WardenSettings,
    pending_types: frozenset[str] = frozenset(),
    scheduled_types: frozenset[str] = frozenset(),
) -> datetime.datetime:
    """The device wakes when ANY collection type is next due.

    Shared by the scheduler (after creating due runs) and the run pipeline
    (after completing one run) so next_poll_at never drifts apart.
    """
    intervals = collection_intervals(settings)
    return min(
        _next_due_for_type(
            device,
            collection_type=ctype,
            interval=interval,
            now=now,
            pending_types=pending_types,
            scheduled_types=scheduled_types,
        )
        for ctype, interval in intervals.items()
    )


def schedule_due_collections(db: Session, *, now: datetime.datetime, settings: WardenSettings) -> int:
    """Scheduler step (ARCHITECTURE.md §3.3/§5.1 step 1): write due runs.

    For every enabled+ready device whose next_poll_at is due (or never set),
    create one ``scheduled`` collection_run per DUE collection type and
    advance next_poll_at. The partial unique index ``uq_collection_runs_active``
    is the second line of defense against double-scheduling: types that
    already have a scheduled/running run are skipped here.
    """
    devices = db.scalars(
        select(Device).where(
            Device.enabled.is_(True),
            Device.readiness == "ready",
            or_(Device.next_poll_at.is_(None), Device.next_poll_at <= now),
        )
    ).all()
    if not devices:
        return 0
    intervals = collection_intervals(settings)
    pending_by_device: dict[uuid.UUID, set[str]] = {}
    for run in db.scalars(
        select(CollectionRun).where(
            CollectionRun.device_id.in_([device.id for device in devices]),
            CollectionRun.state.in_(("scheduled", "running")),
        )
    ).all():
        pending_by_device.setdefault(run.device_id, set()).add(run.collection_type)

    scheduled_count = 0
    for device in devices:
        pending: frozenset[str] = frozenset(pending_by_device.get(device.id, set()))
        due: list[str] = []
        for ctype, interval in intervals.items():
            if ctype in pending:
                continue
            if _backoff_until(device, ctype, now=now) is not None:
                continue  # credential-error backoff: do not re-schedule yet
            last = collection_state_last_run(device.collection_state or {}, ctype)
            if last is None or last + datetime.timedelta(seconds=interval) <= now:
                due.append(ctype)
        for ctype in due:
            db.add(
                CollectionRun(
                    device_id=device.id,
                    collection_type=ctype,
                    scheduled_at=now,
                    state="scheduled",
                    attempt_count=0,
                )
            )
            scheduled_count += 1
        device.next_poll_at = recompute_next_poll(
            device,
            now=now,
            settings=settings,
            pending_types=pending,
            scheduled_types=frozenset(due),
        )
    return scheduled_count


def build_device_session(
    db: Session, *, device: Device, keyring: CredentialKeyring
) -> DeviceSession:
    """Build the per-run session: decrypted credentials inside the call boundary.

    Raises ``AdapterError(not_configured)`` when the device has no credential
    row and ``AdapterError(internal_error)`` when the stored ciphertext cannot
    be decrypted (platform-side problem, never leaked).
    """
    credential = db.get(DeviceCredential, device.id)
    if credential is None:
        raise AdapterError("not_configured", "设备凭据不存在", stage="prepare")
    encrypted = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    try:
        plaintext = keyring.decrypt(
            encrypted,
            aad=credential_aad(str(device.id), device.adapter_key, credential.secret_schema_version),
        )
    except DecryptionError as exc:
        raise AdapterError("internal_error", "设备凭据解密失败", stage="prepare") from exc
    credentials = json.loads(plaintext)
    if not isinstance(credentials, dict):
        raise AdapterError("internal_error", "设备凭据内容无效", stage="prepare")
    return DeviceSession(
        device_id=device.id,
        management_endpoint=device.management_endpoint,
        connection_config=dict(device.connection_config),
        credentials=credentials,
    )


def emit_ui_event(
    db: Session,
    *,
    entity_type: str,
    entity_id: uuid.UUID | None,
    version: int,
    event_type: str,
    payload: dict[str, object],
) -> None:
    """One light SSE payload, written in the caller's transaction (DATA_MODEL §11)."""
    db.add(
        UiEvent(
            entity_type=entity_type,
            entity_id=entity_id,
            version=version,
            event_type=event_type,
            payload=payload,
        )
    )


def _supported_metric_keys(db: Session, *, device_id: uuid.UUID) -> frozenset[str]:
    """Supported contract metric keys (device_capabilities, ADR-014).

    Single source with the persist filter (observation_store.
    supported_capability_keys) so a metric is either supported everywhere —
    point written, latest updated, signal possible — or nowhere.
    """
    return frozenset(
        key
        for key in supported_capability_keys(db, device_id=device_id)
        if key in METRIC_DEFINITIONS
    )


def _compute_health(
    batch: ObservationBatch,
    *,
    supported_metric_keys: frozenset[str],
) -> str | None:
    """Health from explicit batch health evidence (PRODUCT_DESIGN.md §6.2, ADR-010).

    Health evidence = the alert value maps applied to every observed metric
    with a health-relevant alert_policy (normal -> healthy, warning ->
    warning, critical -> critical, no_decision -> no evidence). A metric is
    health-relevant when its contract alert_policy is a real health/status
    policy (health/status/detected_is_critical/broken_is_critical/
    true_is_critical — i.e. any policy other than none and connectivity):
    ``connectivity.management`` feeds REACHABILITY, not health — §6.2 requires
    the device to explicitly report health or a certified full health
    evidence set to be healthy, so a connectivity-only run must never regress
    the health column.

    Returns ``None`` when the batch carries NO health evidence (for example a
    NAS reachability/health run emitting only connectivity.management, or an
    empty batch): the caller then leaves ``devices.health`` unchanged — no
    evidence is not a recovery signal and must not overwrite the last trusted
    health. When evidence is present, ``health.overall`` remains the key
    health signal: if the device supports it but this batch produced no good
    observation, the health stays ``unknown`` (关键采集缺失/部分失败 -> unknown).
    """
    states: list[str] = []
    has_health_evidence = False
    for obs in batch.observations:
        if obs.quality not in (Quality.GOOD, Quality.PARTIAL):
            continue
        metric = METRIC_DEFINITIONS.get(obs.metric_key)
        if metric is None or metric.alert_policy in ("none", "connectivity"):
            continue
        has_health_evidence = True
        outcome = outcome_for_metric(metric, obs.value, enum_maps=ENUM_VALUE_MAPS, boolean_maps=BOOLEAN_VALUE_MAPS)
        state = health_state_from_outcome(outcome)
        if state is not None:
            states.append(state)
    if not has_health_evidence:
        return None
    if "health.overall" in supported_metric_keys and not any(
        obs.metric_key == "health.overall" and obs.quality is Quality.GOOD for obs in batch.observations
    ):
        return "unknown"
    return HealthAggregator.aggregate(states)


def _apply_reachability(
    device: Device,
    *,
    event: str,
) -> bool:
    """Update device reachability via the tracker; True when it changed."""
    current = ReachabilityState(
        reachability=device.reachability,
        consecutive_failures=device.consecutive_failures,
        consecutive_successes=device.consecutive_successes,
    )
    next_state = ReachabilityTracker.update(current, event)
    changed = next_state != current
    device.reachability = next_state.reachability
    device.consecutive_failures = next_state.consecutive_failures
    device.consecutive_successes = next_state.consecutive_successes
    if device.reachability == "offline":
        device.last_known_health = device.health
    return changed


def _finish_run_failed(
    db: Session,
    *,
    run: CollectionRun,
    device: Device,
    error_code: str,
    error_summary: str,
    now: datetime.datetime,
    settings: WardenSettings,
    stage: str = "collect",
    failure_event: bool = True,
) -> None:
    """Adapter-level failure: run failed + observation error + device state.

    ``failure_event`` feeds the reachability tracker (device not collectible);
    ``authentication_failed`` backs off the next poll to 5x the interval.
    """
    run.state = "failed"
    run.error_code = error_code
    run.error_summary = error_summary
    run.finished_at = now
    run.failure_count = 1
    from app.models.observation import CollectionObservationError

    db.add(
        CollectionObservationError(
            collection_run_id=run.id,
            device_id=device.id,
            metric_key_or_event_key=None,
            error_code=error_code,
            stage=stage,
            detail=error_summary,
            occurred_at=now,
        )
    )
    if failure_event:
        _apply_reachability(device, event="failure")
    if error_code == "authentication_failed":
        interval = collection_intervals(settings)[run.collection_type]
        backoff_until = now + datetime.timedelta(seconds=interval * AUTH_FAILURE_BACKOFF_MULTIPLIER)
        state = dict(device.collection_state or {})
        backoff = state.setdefault(AUTH_FAILURE_BACKOFF_KEY, {})
        if isinstance(backoff, dict):
            backoff[run.collection_type] = backoff_until.isoformat()
        device.collection_state = state
    # The alert engine also runs on failures: device.offline opens on the
    # third consecutive failure, data.expired keeps aging, status alerts
    # refresh with their (unchanged) current state.
    process_collection_events(db, device=device, now=now, settings=settings)
    _complete_device_schedule(
        db,
        run=run,
        device=device,
        now=now,
        settings=settings,
    )


def _complete_device_schedule(
    db: Session,
    *,
    run: CollectionRun,
    device: Device,
    now: datetime.datetime,
    settings: WardenSettings,
) -> None:
    """Shared completion bookkeeping: collection_state, next_poll_at, ui_event."""
    state = dict(device.collection_state or {})
    state[run.collection_type] = now.isoformat()
    device.collection_state = state
    pending = {
        row.collection_type
        for row in db.scalars(
            select(CollectionRun).where(
                CollectionRun.device_id == device.id,
                CollectionRun.id != run.id,
                CollectionRun.state.in_(("scheduled", "running")),
            )
        ).all()
    }
    device.next_poll_at = recompute_next_poll(
        device,
        now=now,
        settings=settings,
        pending_types=frozenset(pending),
        scheduled_types=frozenset({run.collection_type}),
    )
    emit_ui_event(
        db,
        entity_type="device",
        entity_id=device.id,
        version=device.version,
        event_type="device.updated",
        payload={
            "reachability": device.reachability,
            "health": device.health,
            "last_collected_at": device.last_collected_at.isoformat()
            if device.last_collected_at is not None
            else None,
        },
    )


def _latest_value(row: MetricLatest) -> object:
    metric = METRIC_DEFINITIONS.get(row.metric_key)
    if metric is None:
        return row.value_text if row.value_text is not None else row.value_double
    if metric.value_type == "boolean":
        return row.value_text == "true"
    if metric.value_type in ("number", "integer"):
        return row.value_double
    return row.value_text


def _capability_freshness(
    db: Session,
    *,
    device: Device,
    supported_metric_keys: frozenset[str],
    latest_rows: Sequence[MetricLatest],
    now: datetime.datetime,
    settings: WardenSettings,
) -> tuple[CapabilityGroupFreshness, ...]:
    """Per capability group (requirement) freshness from metric_latest times.

    A group is evaluated only when it has at least one supported metric; the
    group state is the worst freshness among the group's supported metrics
    (a supported-but-never-observed metric contributes ``unknown``, which
    blocks ``fresh`` resolution — conservative, ADR-025 policy.resolution).

    The freshness cadence comes from the per-collection-type intervals in
    settings via ``collection_type_for_capability_key`` (the single
    key->collection-type mapping, ARCHITECTURE.md §8): each metric's age is
    judged against the interval of the collection type that refreshes it.
    """
    intervals = collection_intervals(settings)
    groups: list[CapabilityGroupFreshness] = []
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != device.device_type or requirement.kind != "monitoring":
            continue
        group_metrics = [key for key in requirement.metrics if key in supported_metric_keys]
        if not group_metrics:
            continue
        # The slowest refresher cadence among the group's metrics (all
        # metrics.json keys map to the ``metrics`` collection type).
        group_interval = max(
            intervals[collection_type_for_capability_key(key)] for key in group_metrics
        )
        states: list[str] = []
        for metric_key in group_metrics:
            rows = [row for row in latest_rows if row.metric_key == metric_key]
            if not rows:
                states.append("unknown")
                continue
            for row in rows:
                states.append(
                    FreshnessCalculator.freshness(row.observed_at, group_interval, now)
                )
        groups.append(
            CapabilityGroupFreshness(
                requirement_id=requirement.id,
                state=FreshnessCalculator.group_freshness(states),
            )
        )
    return tuple(groups)


def _component_labels(
    db: Session, *, device_id: uuid.UUID
) -> dict[uuid.UUID, tuple[str, str]]:
    from app.models.devices import Component

    return {
        row.id: (row.kind, row.native_id)
        for row in db.scalars(select(Component).where(Component.device_id == device_id)).all()
    }


def _build_alert_snapshot(
    db: Session,
    *,
    device: Device,
    now: datetime.datetime,
    settings: WardenSettings,
) -> DeviceAlertSnapshot:
    supported = _supported_metric_keys(db, device_id=device.id)
    latest_rows = list(
        db.scalars(
            select(MetricLatest).where(MetricLatest.device_id == device.id)
        ).all()
    )
    labels = _component_labels(db, device_id=device.id)
    signals = tuple(
        MetricSignal(
            metric_key=row.metric_key,
            value=_latest_value(row),
            observed_at=row.observed_at,
            quality=row.quality,
            component_kind=labels.get(row.component_id, (None, None))[0] if row.component_id else None,
            component_native_id=labels.get(row.component_id, (None, None))[1] if row.component_id else None,
            component_id=row.component_id,
        )
        for row in latest_rows
        if row.metric_key in supported  # the evaluator only sees supported metrics (ADR-014)
    )
    return DeviceAlertSnapshot(
        device_id=device.id,
        reachability=device.reachability,
        consecutive_failures=device.consecutive_failures,
        consecutive_successes=device.consecutive_successes,
        supported_metric_keys=supported,
        metric_signals=signals,
        group_freshness=_capability_freshness(
            db,
            device=device,
            supported_metric_keys=supported,
            latest_rows=latest_rows,
            now=now,
            settings=settings,
        ),
    )


def process_collection_events(
    db: Session, *, device: Device, now: datetime.datetime, settings: WardenSettings
) -> None:
    """Alert engine step (ARCHITECTURE.md §5.1 step 5), same transaction.

    Builds the current-state snapshot, evaluates contracts/alert-rules.json
    ONLY (ADR-025), applies open/resolve/refresh transitions with durable
    counters, and writes alert ui_events.
    """
    evaluator = AlertEvaluator()
    snapshot = _build_alert_snapshot(db, device=device, now=now, settings=settings)
    signals = evaluator.evaluate(snapshot)
    rules_by_key = {rule.rule_key: rule for rule in ALERT_RULES}
    for event_type, alert_id in apply_alert_signals(
        db, device_id=device.id, signals=signals, rules_by_key=rules_by_key, now=now
    ):
        emit_ui_event(
            db,
            entity_type="alert",
            entity_id=alert_id,
            version=1,
            event_type=event_type,
            payload={"device_id": str(device.id)},
        )


def run_collection(
    db: Session,
    run_id: uuid.UUID,
    *,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    now: datetime.datetime | None = None,
) -> None:
    """Execute one claimed collection run end-to-end (ARCHITECTURE.md §5.1).

    ``run_id`` identifies the claimed run; the run row is RE-LOADED inside
    this session so every terminal-state mutation (state/success_count/
    failure_count/finished_at/error_code/error_summary) attaches to this
    session's identity map and commits with the batch. Callers claim in one
    session (``claim_collection_run``) and execute in another (the collection
    pool, ``--once``, the smoke script): passing a detached instance across
    would silently drop those writes, leaving the run ``running`` forever.

    The adapter call happens first; everything else (batch persistence,
    reachability/health, run terminal state, alerts, ui_events, device
    schedule) commits in ONE transaction (DATA_MODEL.md §11). The caller
    commits.
    """
    now = now or utcnow()
    run = db.get(CollectionRun, run_id)
    if run is None:
        msg = f"collection run not found: {run_id}"
        raise ValueError(msg)
    device = db.get(Device, run.device_id)
    if device is None:
        run.state = "failed"
        run.error_code = "internal_error"
        run.error_summary = "设备记录不存在"
        run.finished_at = now
        return
    adapter = get_adapter(device.adapter_key)
    state = device.collection_state or {}
    request = CollectionRequest(
        device_id=device.id,
        collection_type=run.collection_type,
        now=now,
        last_run_at=collection_state_last_run(state, run.collection_type),
    )
    try:
        session_ctx = build_device_session(db, device=device, keyring=keyring)
        batch = adapter.collect(session_ctx, request)
    except AdapterError as exc:
        _finish_run_failed(
            db,
            run=run,
            device=device,
            error_code=exc.code,
            error_summary=exc.message,
            now=now,
            settings=settings,
            stage=exc.stage,
        )
        return
    except UnknownAdapterError:
        _finish_run_failed(
            db,
            run=run,
            device=device,
            error_code="internal_error",
            error_summary="设备适配器未注册",
            now=now,
            settings=settings,
            stage="prepare",
        )
        return

    outcome = persist_observation_batch(
        db, device_id=device.id, batch=batch, run_id=run.id, now=now
    )
    if outcome.errors == 0:
        run.state = "succeeded"
    elif outcome.successes == 0:
        run.state = "failed"
    else:
        run.state = "partial"
    run.success_count = outcome.successes
    run.failure_count = outcome.errors
    run.finished_at = now

    _apply_reachability(device, event="success")
    supported = _supported_metric_keys(db, device_id=device.id)
    # Health updates ONLY from batches carrying health evidence (M4T2 review
    # ruling, PRODUCT_DESIGN.md §6.2): a connectivity-only reachability/health
    # run returns None and must not regress the last trusted health.
    health = _compute_health(batch, supported_metric_keys=supported)
    if health is not None:
        device.health = health
    device.last_seen_at = now
    if run.state in ("succeeded", "partial"):
        device.last_collected_at = now
    if device.reachability == "offline":
        device.last_known_health = device.health

    process_collection_events(db, device=device, now=now, settings=settings)
    _complete_device_schedule(db, run=run, device=device, now=now, settings=settings)
