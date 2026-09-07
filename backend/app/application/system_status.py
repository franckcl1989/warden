"""GET /system/status derivation (M6T3b, PLT-08).

docs/ARCHITECTURE.md §9: /system/status 直接汇总 API/Worker/数据库/文件卷/
接收器状态、采集失败和待核验任务 (0.1.0 不提供 Prometheus 指标端点).
API_CONTRACT.md §9 (受保护的组件状态和队列摘要), DEPLOYMENT.md §9.2
(PostgreSQL 任务领取延迟超过两个采集周期时在系统状态页显示严重状态).

Component derivations — every status is derived from durable evidence, never
fabricated:

- ``api``: ``ok`` — this request was served by a live API process.
- ``database``: ``ok`` while the status queries succeed. A database outage is
  surfaced as the endpoint's 503 ``dependency_unavailable`` (the existing
  readiness posture — PostgreSQL 故障时系统拒绝新硬件操作), never as a fake
  component row; ``degraded`` is a documented type-level state with no honest
  0.1.0 derivation and is therefore not produced.
- ``file_storage``: a writable-check probe on the configured volume root
  (mkdir of the storage layout, same check the upload/download paths run),
  cached ≤30 s per process (FILE_PROBE_CACHE_TTL_SECONDS). Detail never
  includes server paths (SECURITY posture — no file paths in responses).
- ``worker``: ``stopped`` when the last recorded worker activity
  (max updated_at over collection_runs/operation_tasks — the rows only the
  worker process writes) is older than 2 × ``task_lease_seconds``, or when
  there is pending work but no activity history at all; ``degraded`` when the
  oldest scheduled-but-unclaimed collection run waited longer than 2 × its
  own collection-type interval (DEPLOYMENT §9.2 领取延迟超过两个采集周期);
  ``ok`` otherwise. A deployment with NO work rows and no pending work is
  reported ``ok`` with an explanatory detail: 0.1.0 has no durable worker
  heartbeat (no tables beyond 0015), so an idle site cannot be distinguished
  from a stopped worker by DB activity — the idle convention is documented
  and the lag/activity fields stay visible for interpretation.
- ``ingest``: the single-row ingest_heartbeat.updated_at IS the process-alive
  stamp (written at startup and every heartbeat interval, events or not).
  ``stopped`` when the stamp is missing or older than 3 × the configured
  heartbeat interval; ``ok`` otherwise. A site with no configured events is
  legitimately idle (last_received_at NULL) and is NOT ``degraded`` — the
  documented idle-vs-degraded semantics; ``degraded`` has no honest durable
  derivation in 0.1.0 (drop counters are process-local) and is not produced.
"""

from __future__ import annotations

import datetime
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.application.collection import collection_intervals
from app.application.system_state import get_ingest_heartbeat, get_system_state
from app.config import WardenSettings
from app.infrastructure.files import FileStorage, FileStorageError
from app.infrastructure.time import utcnow
from app.models.devices import Device
from app.models.observation import CollectionRun
from app.models.operation import OperationTask

# Writable-probe cache TTL (≤30 s per the M6T3b brief); keyed per storage
# root so one API process serves exactly one root (ARCHITECTURE single
# process) and tests may probe distinct roots.
FILE_PROBE_CACHE_TTL_SECONDS = 30.0

# Ingest stopped threshold: alive stamps arrive every
# ``ingest_heartbeat_interval_seconds``; 3 missed intervals bound transient
# scheduling/DB hiccups without hiding a dead receiver for long.
INGEST_STALE_MULTIPLE = 3

# Worker stopped threshold (brief: 无 DB 活动超过 2× 租约).
WORKER_STALE_MULTIPLE = 2

# Collection-run claim-lag severity (DEPLOYMENT §9.2: 超过两个采集周期).
COLLECTION_LAG_MULTIPLE = 2

# Cap on the "current failures" list (last-failed device+type pairs): a
# bounded summary, never an unbounded failure dump.
CURRENT_FAILURES_LIMIT = 20

# Operation-task states that make up the queue summary + pending-work signal.
_TASK_QUEUE_STATES = ("queued", "running", "waiting_device", "verification_required")

ACTIVE_TASK_STATES = frozenset(_TASK_QUEUE_STATES)


@dataclass(frozen=True)
class ComponentStatus:
    """One component's honest status + optional human detail."""

    status: str
    detail: str = ""


@dataclass(frozen=True)
class WorkerStatus(ComponentStatus):
    last_activity_at: datetime.datetime | None = None
    collection_lag_seconds: int | None = None


@dataclass(frozen=True)
class IngestStatus(ComponentStatus):
    events_received_total: int = 0
    last_received_at: datetime.datetime | None = None


@dataclass(frozen=True)
class CurrentFailure:
    device_id: uuid.UUID
    device_name: str
    collection_type: str
    error_code: str | None
    failed_at: datetime.datetime


@dataclass(frozen=True)
class SystemStatusReport:
    as_of: datetime.datetime
    maintenance_active: bool
    maintenance_since: datetime.datetime | None
    maintenance_reason: str | None
    api: ComponentStatus
    database: ComponentStatus
    file_storage: ComponentStatus
    worker: WorkerStatus
    ingest: IngestStatus
    operation_task_counts: dict[str, int]
    oldest_queued_age_seconds: int | None
    last_24h_outcomes: dict[str, int]
    current_failures: list[CurrentFailure] = field(default_factory=list)
    verification_required_count: int = 0
    verification_required_oldest_at: datetime.datetime | None = None


# ---------------------------------------------------------------------------
# File-storage writable probe (TTL-cached per root)
# ---------------------------------------------------------------------------


class _FileProbeCache:
    """Per-root writable-probe result cache (≤30 s, thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, ComponentStatus]] = {}

    def get(self, key: str, *, now: float) -> ComponentStatus | None:
        with self._lock:
            entry = self._entries.get(key)
        if entry is None:
            return None
        cached_at, status = entry
        if now - cached_at > FILE_PROBE_CACHE_TTL_SECONDS:
            return None
        return status

    def set(self, key: str, status: ComponentStatus, *, now: float) -> None:
        with self._lock:
            self._entries[key] = (now, status)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_file_probe_cache = _FileProbeCache()


def probe_file_storage(
    root: Path,
    *,
    cache: _FileProbeCache | None = None,
) -> ComponentStatus:
    """Writable-check the configured storage root (cached ≤30 s).

    ``root`` is the resolved file-store root; the probe runs the same
    availability check the upload/download paths run
    (FileStorage.check_available). Detail is generic Chinese text — server
    paths are never included in responses.
    """
    probe_cache = cache if cache is not None else _file_probe_cache
    key = str(root)
    now = time.monotonic()
    cached = probe_cache.get(key, now=now)
    if cached is not None:
        return cached
    try:
        storage = FileStorage(root)
        storage.check_available()
        status = ComponentStatus(status="ok", detail="文件卷可写")
    except (FileStorageError, OSError):
        status = ComponentStatus(status="unavailable", detail="文件卷不可用（只读或挂载异常）")
    probe_cache.set(key, status, now=now)
    return status


def clear_file_probe_cache() -> None:
    """Test hook: drop every cached probe result."""
    _file_probe_cache.clear()


# ---------------------------------------------------------------------------
# Worker derivation
# ---------------------------------------------------------------------------


def _worker_activity_cutoff(settings: WardenSettings, now: datetime.datetime) -> datetime.datetime:
    return now - datetime.timedelta(seconds=settings.task_lease_seconds * WORKER_STALE_MULTIPLE)


def _last_worker_activity(db: Session) -> datetime.datetime | None:
    """Newest row write by the worker process (collection/operation tables).

    Both tables carry ``updated_at`` on every transition the worker writes
    (claim, progress, terminal state, lease release); the maintenance loop
    shares the worker process but only writes rows these tables reference or
    rollup/retention rows without their own activity signal — the collection
    + operation traffic is the durable activity evidence (module docstring).
    """
    run_max = db.scalar(select(func.max(CollectionRun.updated_at)))
    task_max = db.scalar(select(func.max(OperationTask.updated_at)))
    values = [value for value in (run_max, task_max) if value is not None]
    return max(values) if values else None


def _oldest_unclaimed_run(db: Session) -> CollectionRun | None:
    """The oldest scheduled-but-unclaimed collection run (DEPLOYMENT §9.2)."""
    return db.scalar(
        select(CollectionRun)
        .where(CollectionRun.state == "scheduled")
        .order_by(CollectionRun.scheduled_at.asc())
        .limit(1)
    )


def _has_pending_work(db: Session) -> bool:
    """True when unclaimed runs or non-terminal tasks exist."""
    has_runs = db.scalar(select(CollectionRun.id).where(CollectionRun.state == "scheduled").limit(1))
    if has_runs is not None:
        return True
    has_tasks = db.scalar(select(OperationTask.id).where(OperationTask.state.in_(ACTIVE_TASK_STATES)).limit(1))
    return has_tasks is not None


def _derive_worker(
    db: Session,
    *,
    settings: WardenSettings,
    now: datetime.datetime,
) -> WorkerStatus:
    """Worker status from durable activity/lag evidence (module docstring)."""
    last_activity = _last_worker_activity(db)
    oldest_run = _oldest_unclaimed_run(db)
    lag_seconds: int | None = None
    lag_severe = False
    if oldest_run is not None:
        lag_seconds = max(0, int((now - oldest_run.scheduled_at).total_seconds()))
        intervals = collection_intervals(settings)
        interval = intervals.get(oldest_run.collection_type)
        if interval is not None:
            lag_severe = lag_seconds > interval * COLLECTION_LAG_MULTIPLE

    if last_activity is None:
        if _has_pending_work(db):
            return WorkerStatus(
                status="stopped",
                detail="存在待处理采集/任务但没有活动记录：Worker 可能未运行",
                last_activity_at=None,
                collection_lag_seconds=lag_seconds,
            )
        return WorkerStatus(
            status="ok",
            detail="尚无采集/任务活动记录（空转站点：无证据可判，按空闲处理）",
            last_activity_at=None,
            collection_lag_seconds=lag_seconds,
        )

    cutoff = _worker_activity_cutoff(settings, now)
    stale_seconds = settings.task_lease_seconds * WORKER_STALE_MULTIPLE
    if last_activity < cutoff:
        return WorkerStatus(
            status="stopped",
            detail=f"Worker 最近活动早于 {stale_seconds} 秒（2×任务租约）",
            last_activity_at=last_activity,
            collection_lag_seconds=lag_seconds,
        )
    if lag_severe:
        return WorkerStatus(
            status="degraded",
            detail="存在超过两个采集周期未被领取的采集任务",
            last_activity_at=last_activity,
            collection_lag_seconds=lag_seconds,
        )
    return WorkerStatus(
        status="ok",
        detail="",
        last_activity_at=last_activity,
        collection_lag_seconds=lag_seconds,
    )


# ---------------------------------------------------------------------------
# Ingest derivation
# ---------------------------------------------------------------------------


def _derive_ingest(
    db: Session,
    *,
    settings: WardenSettings,
    now: datetime.datetime,
) -> IngestStatus:
    """Ingest status from the durable heartbeat (idle is NOT degraded)."""
    events_total, last_received_at, updated_at = get_ingest_heartbeat(db)
    if updated_at is None:
        return IngestStatus(
            status="stopped",
            detail="无接收器心跳记录：事件接收进程可能未启动",
            events_received_total=events_total,
            last_received_at=last_received_at,
        )
    stale_before = now - datetime.timedelta(seconds=settings.ingest_heartbeat_interval_seconds * INGEST_STALE_MULTIPLE)
    if updated_at < stale_before:
        return IngestStatus(
            status="stopped",
            detail="接收器心跳过期：事件接收进程可能已停止",
            events_received_total=events_total,
            last_received_at=last_received_at,
        )
    return IngestStatus(
        status="ok",
        detail="",
        events_received_total=events_total,
        last_received_at=last_received_at,
    )


# ---------------------------------------------------------------------------
# Queues / collection / verification summaries
# ---------------------------------------------------------------------------


def _operation_queue_summary(db: Session) -> tuple[dict[str, int], datetime.datetime | None]:
    counts = dict.fromkeys(_TASK_QUEUE_STATES, 0)
    rows = db.execute(
        select(OperationTask.state, func.count(OperationTask.id))
        .where(OperationTask.state.in_(ACTIVE_TASK_STATES))
        .group_by(OperationTask.state)
    ).all()
    for state, count in rows:
        counts[state] = int(count)
    oldest_queued_at = db.scalar(select(func.min(OperationTask.created_at)).where(OperationTask.state == "queued"))
    return counts, oldest_queued_at


def _collection_outcomes(db: Session, now: datetime.datetime) -> dict[str, int]:
    cutoff = now - datetime.timedelta(hours=24)
    rows = db.execute(
        select(CollectionRun.state, func.count(CollectionRun.id))
        .where(
            CollectionRun.state.in_(("succeeded", "partial", "failed")),
            CollectionRun.finished_at >= cutoff,
        )
        .group_by(CollectionRun.state)
    ).all()
    outcomes = {"succeeded": 0, "partial": 0, "failed": 0}
    for state, count in rows:
        outcomes[state] = int(count)
    return outcomes


def _current_failures(
    db: Session, now: datetime.datetime
) -> list[tuple[uuid.UUID, str, str, str | None, datetime.datetime]]:
    """Latest-run-failed (device, collection_type) pairs of the last 24 h.

    "当前采集失败摘要": for every device+type whose NEWEST run in the window
    ended failed, one summary row with the newest failure time + error code.
    Bounded to CURRENT_FAILURES_LIMIT by recency.
    """
    cutoff = now - datetime.timedelta(hours=24)
    rows = db.execute(
        select(Device.id, Device.name, CollectionRun.collection_type)
        .join(CollectionRun, CollectionRun.device_id == Device.id)
        .where(
            CollectionRun.state == "failed",
            CollectionRun.finished_at >= cutoff,
        )
        .distinct(Device.id, CollectionRun.collection_type)
    ).all()
    items: list[tuple[uuid.UUID, str, str, str | None, datetime.datetime]] = []
    for device_id, device_name, collection_type in rows:
        latest = db.scalar(
            select(CollectionRun)
            .where(
                CollectionRun.device_id == device_id,
                CollectionRun.collection_type == collection_type,
                CollectionRun.state == "failed",
                CollectionRun.finished_at >= cutoff,
            )
            .order_by(CollectionRun.finished_at.desc())
            .limit(1)
        )
        if latest is None or latest.finished_at is None:
            continue
        items.append(
            (
                device_id,
                str(device_name),
                str(collection_type),
                latest.error_code,
                latest.finished_at,
            )
        )
    items.sort(key=lambda item: item[4], reverse=True)
    return items[:CURRENT_FAILURES_LIMIT]


def _verification_summary(db: Session) -> tuple[int, datetime.datetime | None]:
    oldest = db.scalar(select(func.min(OperationTask.created_at)).where(OperationTask.state == "verification_required"))
    count = db.scalar(select(func.count(OperationTask.id)).where(OperationTask.state == "verification_required"))
    return int(count or 0), oldest


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def build_system_status(
    db: Session,
    *,
    settings: WardenSettings,
    now: datetime.datetime | None = None,
) -> SystemStatusReport:
    """Assemble the /system/status report from one DB session (+ disk probe).

    Runs entirely in one request: every aggregate below is a bounded query;
    a database failure propagates as ``dependency_unavailable`` from the
    session (never a fabricated component row).
    """
    timestamp = now if now is not None else utcnow()
    state = get_system_state(db)
    queue_counts, oldest_queued_at = _operation_queue_summary(db)
    verification_count, verification_oldest = _verification_summary(db)
    report = SystemStatusReport(
        as_of=timestamp,
        maintenance_active=state.maintenance_mode,
        maintenance_since=state.maintenance_since,
        maintenance_reason=state.maintenance_reason,
        api=ComponentStatus(status="ok"),
        database=ComponentStatus(status="ok", detail="数据库连接正常"),
        file_storage=probe_file_storage(settings.resolved_file_store_root),
        worker=_derive_worker(db, settings=settings, now=timestamp),
        ingest=_derive_ingest(db, settings=settings, now=timestamp),
        operation_task_counts=queue_counts,
        oldest_queued_age_seconds=(
            max(0, int((timestamp - oldest_queued_at).total_seconds())) if oldest_queued_at is not None else None
        ),
        last_24h_outcomes=_collection_outcomes(db, timestamp),
        current_failures=[
            CurrentFailure(
                device_id=device_id,
                device_name=device_name,
                collection_type=collection_type,
                error_code=error_code,
                failed_at=failed_at,
            )
            for device_id, device_name, collection_type, error_code, failed_at in _current_failures(db, timestamp)
        ],
        verification_required_count=verification_count,
        verification_required_oldest_at=verification_oldest,
    )
    return report
