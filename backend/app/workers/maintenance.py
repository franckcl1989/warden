"""Maintenance loop: lease recovery + timeout sweep (ARCHITECTURE.md §3.3/§7).

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
  ``timed_out`` (terminal, finished_at recorded) or ``verification_required``
  (ambiguous: device may have accepted the action).
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.domain.operation import (
    RecoveryAction,
    TaskFence,
    TaskState,
    recover_task,
    timeout_transition,
)
from app.generated.operations import OPERATION_PROFILES
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

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


class MaintenanceLoop:
    """Runs the recovery and timeout sweeps; one pass = run_once()."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        tick_seconds: float = DEFAULT_TICK_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._tick_seconds = tick_seconds
        self._log = structlog.get_logger()

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
                    )
            except Exception:
                self._log.exception("maintenance_pass_failed")
            stop_event.wait(self._tick_seconds)

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
                    message="timeout with possible device-side effect; awaiting verification",
                )
            else:
                changed = mark_timeout(
                    session,
                    task_id=task.id,
                    to_state=to_state,
                    message="timeout with no evidence of continued execution",
                )
            if changed:
                if to_state is TaskState.VERIFICATION_REQUIRED:
                    report.verification_required += 1
                else:
                    report.timed_out += 1
            session.commit()
