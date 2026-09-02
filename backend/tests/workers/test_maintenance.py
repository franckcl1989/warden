"""Maintenance loop integration tests on the real PostgreSQL.

One maintenance pass must: requeue fence-less tasks with expired leases,
park fenced side-effect tasks as verify_only (event once, lease cleared),
move tasks whose verification failed into verification_required, and apply
the profile-driven timeout outcomes: fenced side-effect -> verification_required
(device may have accepted the action), unfenced or read-only -> timed_out.
Every decision reads the generated operations registry — never hardcoded
per-operation logic. The advisory lock is exercised too.
"""

from __future__ import annotations

import datetime

from app.infrastructure.db import create_session_factory
from app.infrastructure.tasks import recovery_scan
from app.infrastructure.time import utcnow
from app.models.operation import OperationTaskEvent
from app.workers.maintenance import (
    MAINTENANCE_ADVISORY_LOCK_KEY,
    MaintenanceLoop,
    MaintenanceReport,
)
from app.workers.scheduler import release_advisory_lock, try_advisory_lock
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.task_factories import make_device, make_task, make_user

NOW = datetime.datetime.now(datetime.UTC)
PAST = NOW - datetime.timedelta(hours=1)
FUTURE = NOW + datetime.timedelta(hours=1)

POWER_ON = ("SRV-ACT-02", "power.on")  # side_effect=true, expected_disconnect=false
MANAGER_RESET = ("SRV-ACT-01", "manager.reset")  # side_effect=true, expected_disconnect=true
SUPPORT_BUNDLE = ("NAS-ACT-03", "logs.support_bundle.collect")  # side_effect=false (read profile)
FIRMWARE_QUERY = ("SRV-ACT-06", "firmware.query")  # side_effect=false (read profile)


def _expired_running(
    db_session: Session,
    *,
    requirement: str,
    capability: str,
    dispatch_started_at: datetime.datetime | None,
    device_job_id: str | None = None,
    verification_state: str | None = None,
    index: int = 0,
    idempotency_key: str = "maint-key",
):
    device = make_device(db_session, index=index)
    return make_task(
        db_session,
        device_id=device.id,
        requested_by=make_user(db_session, index=index).id,
        index=index,
        requirement_id=requirement,
        capability_key=capability,
        state="running",
        lease_owner="dead-worker",
        lease_expires_at=PAST,
        dispatch_started_at=dispatch_started_at,
        device_job_id=device_job_id,
        verification_state=verification_state,
        idempotency_key=f"{idempotency_key}-{index}",
    )


class TestRecovery:
    def test_fence_less_expired_lease_is_requeued(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=None,
            index=1,
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.lock_acquired is True
        assert report.requeued == 1
        db_session.refresh(task)
        assert task.state == "queued"
        assert task.lease_owner is None and task.lease_expires_at is None
        events = db_session.scalars(select(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id)).all()
        assert events[-1].state == "queued"
        assert "recovery_requeued" in events[-1].message

    def test_fenced_side_effect_task_is_parked_for_verify_only(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=NOW,
            index=2,
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.verify_only == 1
        db_session.refresh(task)
        assert task.state == "running"
        assert task.lease_owner is None and task.lease_expires_at is None
        events = db_session.scalars(select(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id)).all()
        assert "recovery_verify_only" in events[-1].message

    def test_parked_task_is_not_recovered_twice(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=NOW,
            index=3,
        )
        factory = create_session_factory(db_session.bind)
        first = MaintenanceLoop(factory).run_once()
        second = MaintenanceLoop(factory).run_once()
        assert first.verify_only == 1
        assert second.verify_only == 0
        events = db_session.scalars(select(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id)).all()
        verify_events = [e for e in events if "recovery_verify_only" in (e.message or "")]
        assert len(verify_events) == 1

    def test_two_pass_scans_of_same_fenced_task_emit_one_verify_event(self, db_session: Session) -> None:
        # Two worker processes can both scan the same expired-lease fenced
        # task: each pass scans under the advisory lock but processes AFTER
        # releasing it, so pass B's scan can still see the candidate while
        # pass A is processing it. Both passes then process the same task;
        # clear_lease must be a no-op for the second pass (lease already
        # cleared), so the recovery_verify_only event is appended exactly
        # once (single-event-per-task invariant).
        task = _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=NOW,
            index=30,
        )
        factory = create_session_factory(db_session.bind)
        loop = MaintenanceLoop(factory)
        first_scan: list = []
        second_scan: list = []
        for scanned in (first_scan, second_scan):
            with factory() as session:
                assert try_advisory_lock(session, MAINTENANCE_ADVISORY_LOCK_KEY) is True
                scanned.extend(recovery_scan(session, now=utcnow()))
                release_advisory_lock(session, MAINTENANCE_ADVISORY_LOCK_KEY)
                session.commit()
        assert {t.id for t in first_scan} == {task.id}
        assert {t.id for t in second_scan} == {task.id}
        first = MaintenanceReport()
        second = MaintenanceReport()
        for t in first_scan:
            loop._recover_one(t.id, first)
        for t in second_scan:
            loop._recover_one(t.id, second)
        assert first.verify_only == 1
        assert second.verify_only == 0
        db_session.refresh(task)
        assert task.state == "running"
        assert task.lease_owner is None and task.lease_expires_at is None
        events = db_session.scalars(select(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id)).all()
        verify_events = [e for e in events if "recovery_verify_only" in (e.message or "")]
        assert len(verify_events) == 1

    def test_read_task_with_device_job_is_verify_only(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=SUPPORT_BUNDLE[0],
            capability=SUPPORT_BUNDLE[1],
            dispatch_started_at=NOW,
            device_job_id="job-1",
            index=4,
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.verify_only == 1
        assert report.requeued == 0
        db_session.refresh(task)
        assert task.state == "running"

    def test_read_task_without_job_is_requeued_as_new_attempt(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=SUPPORT_BUNDLE[0],
            capability=SUPPORT_BUNDLE[1],
            dispatch_started_at=NOW,
            device_job_id=None,
            index=5,
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.requeued == 1
        db_session.refresh(task)
        assert task.state == "queued"

    def test_failed_verification_becomes_verification_required(self, db_session: Session) -> None:
        task = _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=NOW,
            verification_state="failed",
            index=6,
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.verification_required == 1
        db_session.refresh(task)
        assert task.state == "verification_required"
        assert task.error_code == "ambiguous_result"

    def test_active_lease_is_untouched(self, db_session: Session) -> None:
        device = make_device(db_session, index=7)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=7).id,
            index=7,
            requirement_id=POWER_ON[0],
            capability_key=POWER_ON[1],
            state="running",
            lease_owner="alive-worker",
            lease_expires_at=FUTURE,
            dispatch_started_at=NOW,
            idempotency_key="maint-active-7",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.requeued == 0 and report.verify_only == 0
        db_session.refresh(task)
        assert task.state == "running"
        assert task.lease_owner == "alive-worker"

    def test_second_maintenance_loop_is_excluded_by_advisory_lock(self, db_session: Session) -> None:
        _expired_running(
            db_session,
            requirement=POWER_ON[0],
            capability=POWER_ON[1],
            dispatch_started_at=None,
            index=8,
        )
        # The lock is held on the test session itself (the dev server only
        # allows ~two application connections), so the maintenance pass must
        # find the lock taken and skip the whole cycle.
        assert try_advisory_lock(db_session, MAINTENANCE_ADVISORY_LOCK_KEY) is True
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.lock_acquired is False
        release_advisory_lock(db_session, MAINTENANCE_ADVISORY_LOCK_KEY)
        db_session.commit()


class TestTimeoutSweep:
    def test_expected_disconnect_fenced_timeout_is_ambiguous(self, db_session: Session) -> None:
        # manager.reset: expected_disconnect=true and the dispatch fence was
        # committed — the timeout shows NO reconnect/identity evidence, which
        # is genuinely ambiguous (the device may have accepted the reset).
        # The task must land in verification_required, never terminal
        # timed_out (which would permit a clean-looking retry of a
        # possibly-executed action).
        device = make_device(db_session, index=20)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=20).id,
            index=20,
            requirement_id=MANAGER_RESET[0],
            capability_key=MANAGER_RESET[1],
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            dispatch_started_at=NOW,
            timeout_at=PAST,
            idempotency_key="timeout-reset-20",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.verification_required == 1
        db_session.refresh(task)
        assert task.state == "verification_required"
        assert task.error_code == "ambiguous_result"
        assert task.finished_at is None

    def test_fenced_ambiguous_timeout_becomes_verification_required(self, db_session: Session) -> None:
        # power.on: fenced, ambiguity defined -> verification_required
        device = make_device(db_session, index=21)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=21).id,
            index=21,
            requirement_id=POWER_ON[0],
            capability_key=POWER_ON[1],
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            dispatch_started_at=NOW,
            timeout_at=PAST,
            idempotency_key="timeout-poweron-21",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.verification_required == 1
        db_session.refresh(task)
        assert task.state == "verification_required"
        assert task.error_code == "ambiguous_result"
        assert task.finished_at is None

    def test_fenced_read_profile_timeout_becomes_timed_out(self, db_session: Session) -> None:
        # firmware.query: read-only profile (side_effect=false) — a read has
        # no irreversible device-side effect, so even fenced the timeout is
        # clean and retryable.
        device = make_device(db_session, index=22)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=22).id,
            index=22,
            requirement_id=FIRMWARE_QUERY[0],
            capability_key=FIRMWARE_QUERY[1],
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            dispatch_started_at=NOW,
            timeout_at=PAST,
            idempotency_key="timeout-query-22",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.timed_out == 1
        db_session.refresh(task)
        assert task.state == "timed_out"

    def test_fenced_read_profile_with_job_timeout_becomes_timed_out(self, db_session: Session) -> None:
        # logs.support_bundle.collect: read-only with a persisted device job
        # and real ambiguity text — still a read, so the timeout is clean
        # (side_effect=false retry rules), not verification_required.
        device = make_device(db_session, index=25)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=25).id,
            index=25,
            requirement_id=SUPPORT_BUNDLE[0],
            capability_key=SUPPORT_BUNDLE[1],
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            dispatch_started_at=NOW,
            device_job_id="job-1",
            timeout_at=PAST,
            idempotency_key="timeout-bundle-25",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.timed_out == 1
        db_session.refresh(task)
        assert task.state == "timed_out"

    def test_unfenced_timeout_becomes_timed_out_even_for_side_effect_profile(self, db_session: Session) -> None:
        device = make_device(db_session, index=23)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=23).id,
            index=23,
            requirement_id=POWER_ON[0],
            capability_key=POWER_ON[1],
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            dispatch_started_at=None,
            timeout_at=PAST,
            idempotency_key="timeout-unfenced-23",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.timed_out == 1
        db_session.refresh(task)
        assert task.state == "timed_out"

    def test_queued_task_with_overdue_timeout_is_untouched(self, db_session: Session) -> None:
        device = make_device(db_session, index=24)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=make_user(db_session, index=24).id,
            index=24,
            requirement_id=POWER_ON[0],
            capability_key=POWER_ON[1],
            state="queued",
            timeout_at=PAST,
            idempotency_key="timeout-queued-24",
        )
        factory = create_session_factory(db_session.bind)
        report = MaintenanceLoop(factory).run_once()
        assert report.timed_out == 0 and report.verification_required == 0
        db_session.refresh(task)
        assert task.state == "queued"
