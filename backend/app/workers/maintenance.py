"""Maintenance loop: lease recovery + timeout sweep + rollups/retention.

Two scans run under the scheduler-style advisory lock, then every candidate is
processed in its own transaction (DATA_MODEL.md §11) with conditional
UPDATEs, so a second maintenance loop or a concurrent worker transition makes
a candidate a harmless no-op:

- lease recovery (recovery_scan): running tasks whose lease expired are
  classified by the pure ``recover_task`` fence logic (DEVICE_ADAPTERS.md §9)
  using the profile from the GENERATED registry (never hardcoded):
    - no dispatch fence / read-only without a device job  -> requeue (queued)
    - fenced side-effect task (or read with a persisted job) -> verify_only:
      an event is appended once and the lease is cleared (task stays running;
      the M2T6 verify path claims fenced tasks and only read-backs)
    - verification already failed to prove -> verification_required
- timeout sweep (timeout_scan): running/waiting_device tasks past timeout_at
  are classified by the pure ``timeout_transition`` profile semantics into
  ``timed_out`` (terminal, finished_at recorded; unfenced or read-only — the
  action never ran or has no device-side effect to verify) or
  ``verification_required`` (fenced side-effect task: the device may have
  accepted the action, e.g. an expected_disconnect action with no
  reconnect/identity evidence — never auto-replay).
- metric rollups (generate_rollups) run on the DEPLOYMENT.md §9.3 cadence
  (every 5 minutes) and retention + the future partition window
  (enforce_retention + ensure_partitions) run daily, both inside the same
  advisory-lock transaction and reported through MaintenanceReport. Cadences
  are instance state, so exactly one pass in the fleet runs each job; the
  first pass of a fresh process runs both (that is also what the ``--once``
  smoke exercises).
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import asdict, dataclass

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.application.maintenance import (
    enforce_file_retention,
    enforce_retention,
    ensure_partitions,
    generate_rollups,
)
from app.config import WardenSettings, get_settings
from app.domain.operation import (
    RecoveryAction,
    TaskFence,
    TaskState,
    recover_task,
    timeout_transition,
)
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.audit import AuditLogger
from app.infrastructure.files import FileStorage
from app.infrastructure.tasks import (
    append_event,
    clear_lease,
    mark_timeout,
    mark_verification_required,
    recovery_scan,
    requeue_task,
    timeout_scan,
)
from app.infrastructure.time import utcnow
from app.models.operation import OperationTask
from app.workers.scheduler import (
    DEFAULT_TICK_SECONDS,
    release_advisory_lock,
    try_advisory_lock,
)

MAINTENANCE_ADVISORY_LOCK_KEY = 0x57415244454E0002

# DEPLOYMENT.md §9.3: 每 5 分钟生成指标聚合; 每日创建未来分区并执行保留清理.
ROLLUP_CADENCE_SECONDS = 300.0
RETENTION_CADENCE_SECONDS = 86400.0

VERIFY_ONLY_EVENT_MESSAGE = (
    "recovery_verify_only: dispatch fence present; only verify/read-back allowed (execution wiring lands M2T6)"
)
REQUEUE_EVENT_MESSAGE = "recovery_requeued: no dispatch fence; task reclaimable after full precondition recheck"


@dataclass
class MaintenanceReport:
    """Counters from one maintenance pass (used by tests and /system/status)."""

    lock_acquired: bool = False
    requeued: int = 0
    verify_only: int = 0
    verification_required: int = 0
    timed_out: int = 0
    skipped_missing_profile: int = 0
    # M2T3 rollup/retention counters (0 when the pass skipped a cadence).
    rollup_rows_5m: int = 0
    rollup_rows_1h: int = 0
    partitions_dropped: int = 0
    rollup_5m_deleted: int = 0
    rollup_1h_deleted: int = 0
    device_events_deleted: int = 0
    resolved_alerts_deleted: int = 0
    preview_token_uses_deleted: int = 0
    operation_tasks_deleted: int = 0
    operation_task_events_skipped_append_only: bool = False
    ui_events_deleted: int = 0
    sessions_deleted: int = 0
    audit_skipped_append_only: bool = False
    partitions_created: int = 0
    # M2T5 file retention counters (0 when the pass skipped a cadence or no
    # file storage is configured for the loop).
    file_retention_storage_unavailable: bool = False
    support_bundles_deleted: int = 0
    operation_logs_deleted: int = 0
    config_backups_deleted: int = 0
    abandoned_uploads_deleted: int = 0
    orphaned_upload_spools_removed: int = 0
    tickets_deleted: int = 0
    physical_files_removed: int = 0

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


class MaintenanceLoop:
    """Runs the sweeps plus the rollup/retention jobs; one pass = run_once()."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        tick_seconds: float = DEFAULT_TICK_SECONDS,
        rollup_cadence_seconds: float = ROLLUP_CADENCE_SECONDS,
        retention_cadence_seconds: float = RETENTION_CADENCE_SECONDS,
        settings: WardenSettings | None = None,
        file_storage: FileStorage | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._tick_seconds = tick_seconds
        self._settings = settings if settings is not None else get_settings()
        self._log = structlog.get_logger()
        self._rollup_cadence = rollup_cadence_seconds
        self._retention_cadence = retention_cadence_seconds
        # M2T5: file-layer retention (logical aging, physical cleanup, ticket
        # purge) needs the volume; audit rows for cleanup go through the
        # app-level logger (its own transaction) when provided.
        self._file_storage = file_storage
        self._audit_logger = audit_logger
        # None => due: the first pass of a fresh loop (and the --once smoke)
        # runs the full maintenance job set.
        self._next_rollup_at: datetime.datetime | None = None
        self._next_retention_at: datetime.datetime | None = None

    def run_once(self) -> MaintenanceReport:
        """One maintenance pass; returns counters (report.lock_acquired=False
        when another maintenance loop holds the advisory lock)."""
        report = MaintenanceReport()
        with self._session_factory() as session:
            if not try_advisory_lock(session, MAINTENANCE_ADVISORY_LOCK_KEY):
                return report
            try:
                now = utcnow()
                recovery_candidates = recovery_scan(session, now=now)
                timeout_candidates = timeout_scan(session, now=now)
                if self._next_rollup_at is None or now >= self._next_rollup_at:
                    self._run_rollups(session, report, now)
                if self._next_retention_at is None or now >= self._next_retention_at:
                    self._run_retention(session, report, now)
            finally:
                release_advisory_lock(session, MAINTENANCE_ADVISORY_LOCK_KEY)
            session.commit()
        report.lock_acquired = True
        for task in recovery_candidates:
            self._recover_one(task.id, report)
        for task in timeout_candidates:
            self._timeout_one(task.id, report)
        return report

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                report = self.run_once()
                if report.lock_acquired:
                    self._log.info(
                        "maintenance_pass",
                        requeued=report.requeued,
                        verify_only=report.verify_only,
                        verification_required=report.verification_required,
                        timed_out=report.timed_out,
                        rollup_rows_5m=report.rollup_rows_5m,
                        rollup_rows_1h=report.rollup_rows_1h,
                        partitions_dropped=report.partitions_dropped,
                        partitions_created=report.partitions_created,
                        file_retention_storage_unavailable=report.file_retention_storage_unavailable,
                        support_bundles_deleted=report.support_bundles_deleted,
                        operation_logs_deleted=report.operation_logs_deleted,
                        config_backups_deleted=report.config_backups_deleted,
                        abandoned_uploads_deleted=report.abandoned_uploads_deleted,
                        orphaned_upload_spools_removed=report.orphaned_upload_spools_removed,
                        tickets_deleted=report.tickets_deleted,
                        physical_files_removed=report.physical_files_removed,
                    )
            except Exception:
                self._log.exception("maintenance_pass_failed")
            stop_event.wait(self._tick_seconds)

    def _run_rollups(
        self,
        session: Session,
        report: MaintenanceReport,
        now: datetime.datetime,
    ) -> None:
        rollup_report = generate_rollups(session, now=now, settings=self._settings)
        self._next_rollup_at = now + datetime.timedelta(seconds=self._rollup_cadence)
        report.rollup_rows_5m = rollup_report.rows_5m
        report.rollup_rows_1h = rollup_report.rows_1h

    def _run_retention(
        self,
        session: Session,
        report: MaintenanceReport,
        now: datetime.datetime,
    ) -> None:
        retention_report = enforce_retention(session, now=now, settings=self._settings)
        report.partitions_dropped = len(retention_report.partitions_dropped)
        report.rollup_5m_deleted = retention_report.rollup_5m_deleted
        report.rollup_1h_deleted = retention_report.rollup_1h_deleted
        report.device_events_deleted = retention_report.device_events_deleted
        report.resolved_alerts_deleted = retention_report.resolved_alerts_deleted
        report.preview_token_uses_deleted = retention_report.preview_token_uses_deleted
        report.operation_tasks_deleted = retention_report.operation_tasks_deleted
        report.operation_task_events_skipped_append_only = (
            retention_report.operation_task_events_skipped_append_only
        )
        report.ui_events_deleted = retention_report.ui_events_deleted
        report.sessions_deleted = retention_report.sessions_deleted
        report.audit_skipped_append_only = retention_report.audit_skipped_append_only
        report.partitions_created = ensure_partitions(session, now=now)
        if self._file_storage is not None:
            file_report = enforce_file_retention(
                session,
                now=now,
                settings=self._settings,
                storage=self._file_storage,
                audit=self._audit_logger,
            )
            report.file_retention_storage_unavailable = file_report.storage_unavailable
            report.support_bundles_deleted = file_report.support_bundles_deleted
            report.operation_logs_deleted = file_report.operation_logs_deleted
            report.config_backups_deleted = file_report.config_backups_deleted
            report.abandoned_uploads_deleted = file_report.abandoned_uploads_deleted
            report.orphaned_upload_spools_removed = file_report.orphaned_upload_spools_removed
            report.tickets_deleted = file_report.tickets_deleted
            report.physical_files_removed = file_report.physical_files_removed
        self._next_retention_at = now + datetime.timedelta(seconds=self._retention_cadence)

    def _recover_one(self, task_id: object, report: MaintenanceReport) -> None:
        with self._session_factory() as session:
            task = session.get(OperationTask, task_id)
            if task is None:
                return
            profile = OPERATION_PROFILES.get(f"{task.requirement_id}:{task.capability_key}")
            if profile is None:
                report.skipped_missing_profile += 1
                self._log.warning(
                    "recovery_skipped_missing_profile",
                    task_id=str(task.id),
                    profile=f"{task.requirement_id}:{task.capability_key}",
                )
                return
            action = recover_task(
                TaskFence(task.dispatch_started_at, task.device_job_id),
                side_effect=profile.side_effect,
                verification_state=task.verification_state,
            )
            if action is RecoveryAction.REQUEUE:
                if requeue_task(session, task_id=task.id, message=REQUEUE_EVENT_MESSAGE):
                    report.requeued += 1
            elif action is RecoveryAction.REPORT_AMBIGUOUS:
                if mark_verification_required(
                    session,
                    task_id=task.id,
                    message="recovery_ambiguous: cannot prove success or failure; awaiting human verification",
                ):
                    report.verification_required += 1
            else:  # VERIFY_ONLY
                if clear_lease(session, task_id=task.id):
                    append_event(
                        session,
                        task_id=task.id,
                        state=TaskState.RUNNING.value,
                        message=VERIFY_ONLY_EVENT_MESSAGE,
                    )
                    report.verify_only += 1
            session.commit()

    def _timeout_one(self, task_id: object, report: MaintenanceReport) -> None:
        with self._session_factory() as session:
            task = session.get(OperationTask, task_id)
            if task is None:
                return
            profile = OPERATION_PROFILES.get(f"{task.requirement_id}:{task.capability_key}")
            if profile is None:
                report.skipped_missing_profile += 1
                self._log.warning(
                    "timeout_skipped_missing_profile",
                    task_id=str(task.id),
                    profile=f"{task.requirement_id}:{task.capability_key}",
                )
                return
            fence = TaskFence(task.dispatch_started_at, task.device_job_id)
            to_state = timeout_transition(fence, profile)
            if to_state is TaskState.VERIFICATION_REQUIRED:
                changed = mark_timeout(
                    session,
                    task_id=task.id,
                    to_state=to_state,
                    error_code="ambiguous_result",
                    message=(
                        "timeout_ambiguous: dispatch fence present with no positive "
                        "no-execution evidence — the device may have accepted the "
                        "action; awaiting verification (never auto-replay)"
                    ),
                )
            else:
                changed = mark_timeout(
                    session,
                    task_id=task.id,
                    to_state=to_state,
                    message=(
                        "timeout with no evidence of continued execution "
                        "(never dispatched or read-only profile)"
                    ),
                )
            if changed:
                if to_state is TaskState.VERIFICATION_REQUIRED:
                    report.verification_required += 1
                else:
                    report.timed_out += 1
            session.commit()
