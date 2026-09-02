"""Operation executor stage-path tests on the real PostgreSQL (M2T6).

Drives the executor the way the pool does: claim (own transaction) -> handler
with the executor under the pool's lease. Covers every stage decision:
preflight rejection/drift, dispatch fence ordering, explicit failure,
adapter-timeout mapping, ambiguity, job polling (waiting_device + lease
renewals), read-profile crash retry and the verify-only recovery consumption.
Terminal state + audit + ui_events land in one transaction
(DATA_MODEL.md §11) — asserted via row + audit + ui_event state after each
run.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.adapters import get_adapter
from app.adapters.fake import FAKE_DEVICE_JOB_ID, SimulatedWorkerCrash
from app.application.operations import build_snapshot
from app.config import WardenSettings
from app.domain.adapter import OperationProgress
from app.domain.operation import TaskState
from app.domain.operation_plan import OperationRequest, plan_operation
from app.infrastructure.audit import AuditLogger
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.tasks import (
    claim_task,
    claim_verify_only_task,
    release_lease,
)
from app.infrastructure.time import utcnow
from app.models.auth import AuditLog
from app.models.devices import Device
from app.models.observation import UiEvent
from app.models.operation import OperationTask, OperationTaskEvent
from app.workers.maintenance import MaintenanceLoop
from app.workers.operation_executor import OperationExecutor
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from tests.observation_factories import make_collection_device, make_keyring
from tests.task_factories import make_user

POWER_ON = ("SRV-ACT-02", "power.on")  # side_effect=true, expected_disconnect=false
ASSET_REFRESH = ("SRV-ACT-07", "asset.refresh")  # side_effect=false (read profile)
OWNER = "test-executor"


def _pool_engine(dsn: str):
    """Worker engine: tiny pool (dev server caps connections at ~8)."""
    return create_engine(
        dsn_with_psycopg_dialect(dsn),
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
        pool_size=1,
        max_overflow=1,
    )


def _executor_settings(dsn: str) -> WardenSettings:
    return WardenSettings(
        postgres_dsn=dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        operation_job_poll_interval_seconds=0.05,
    )


def _claim_one(factory: sessionmaker[Session], *, owner: str = OWNER) -> OperationTask | None:
    with factory() as session:
        task = claim_task(session, lease_owner=owner, lease_seconds=300)
        session.commit()
        return task


def _seed_execution_task(
    db: Session,
    *,
    connection_config: dict[str, object] | None = None,
    requirement_id: str = POWER_ON[0],
    capability_key: str = POWER_ON[1],
    timeout_seconds: int | None = None,
    plan_hash: str | None = "computed",
) -> tuple[Device, OperationTask]:
    """Device (capabilities + encrypted credentials) + one queued task that a
    real confirm would have created (hashes/adapter_version/timeout set)."""
    device = make_collection_device(db, index=_next_index(), connection_config=connection_config)
    user = make_user(db, index=_next_index())
    snapshot = build_snapshot(db, device)
    plan = plan_operation(snapshot, OperationRequest(capability_key=capability_key, parameters={}))
    task = OperationTask(
        requirement_id=requirement_id,
        capability_key=capability_key,
        device_id=device.id,
        requested_by=user.id,
        risk_level=plan.risk_level,
        parameters={},
        idempotency_key=f"exec-seed-{uuid.uuid4().hex[:12]}",
        conflict_scope=plan.conflict_scope,
        state=TaskState.QUEUED.value,
        plan_hash=plan.plan_hash if plan_hash == "computed" else plan_hash,
        parameter_hash=plan.parameter_hash,
        adapter_version=plan.adapter_version,
        timeout_at=utcnow()
        + datetime.timedelta(seconds=timeout_seconds if timeout_seconds is not None else plan.timeout_seconds),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return device, task


def _seed_parked_task(
    db: Session,
    *,
    connection_config: dict[str, object] | None = None,
    requirement_id: str = POWER_ON[0],
    capability_key: str = POWER_ON[1],
    device_job_id: str | None = None,
    evidence: dict[str, object] | None = None,
    state: str = "running",
    timeout_at: datetime.datetime | None = None,
) -> tuple[Device, OperationTask]:
    """A fenced task whose lease was cleared (maintenance verify-only park)."""
    device = make_collection_device(db, index=_next_index(), connection_config=connection_config)
    user = make_user(db, index=_next_index())
    task = OperationTask(
        requirement_id=requirement_id,
        capability_key=capability_key,
        device_id=device.id,
        requested_by=user.id,
        risk_level="low" if requirement_id == ASSET_REFRESH[0] else "high",
        parameters={},
        idempotency_key=f"exec-parked-{uuid.uuid4().hex[:12]}",
        conflict_scope="device_read" if requirement_id == ASSET_REFRESH[0] else "device",
        state=state,
        dispatch_started_at=utcnow(),
        device_job_id=device_job_id,
        timeout_at=timeout_at or (utcnow() + datetime.timedelta(minutes=30)),
        evidence=evidence,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return device, task


_counter = 0


def _next_index() -> int:
    global _counter
    _counter += 1
    return _counter


def _refresh(db_session: Session, task_id: uuid.UUID) -> OperationTask:
    db_session.expire_all()
    row = db_session.get(OperationTask, task_id)
    assert row is not None
    return row


def _ui_event_types(db: Session, task_id: uuid.UUID) -> list[str]:
    return list(
        db.scalars(
            select(UiEvent.event_type).where(UiEvent.entity_id == task_id).order_by(UiEvent.id)
        ).all()
    )


def _audit_finishes(db: Session, task_id: uuid.UUID) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.action == "operation.finish", AuditLog.task_id == task_id)
            .order_by(AuditLog.created_at)
        ).all()
    )


class TestExecutionPaths:
    def _executor(
        self,
        factory: sessionmaker[Session],
        settings: WardenSettings,
        *,
        audit: bool = True,
        progress_min: float | None = None,
    ) -> OperationExecutor:
        return OperationExecutor(
            session_factory=factory,
            lease_owner=OWNER,
            lease_seconds=300,
            settings=settings,
            keyring=make_keyring(),
            audit_logger=AuditLogger(factory) if audit else None,
            progress_min_interval_seconds=progress_min,
        )

    def test_happy_path_succeeds_with_fence_audit_and_ui_events(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db)
            claimed = _claim_one(factory)
            assert claimed is not None and claimed.id == task.id
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
                assert row.adapter_version == "0.1.0"
                assert row.verification_state == "passed"
                assert row.finished_at is not None
                assert row.error_code is None
                assert row.evidence is not None
                assert set(row.evidence) == {"execution", "verification"}
                events = db.scalars(
                    select(OperationTaskEvent)
                    .where(OperationTaskEvent.task_id == task.id)
                    .order_by(OperationTaskEvent.occurred_at)
                ).all()
                states = [e.state for e in events]
                messages = [e.message or "" for e in events]
                assert states[-1] == "succeeded"
                assert any("dispatch_fence" in m for m in messages)
                assert _ui_event_types(db, task.id) == ["operation.updated"] * 2
                starts = db.scalars(
                    select(AuditLog).where(
                        AuditLog.action == "operation.start", AuditLog.task_id == task.id
                    )
                ).all()
                assert len(starts) == 1 and starts[0].result == "dispatched"
                assert len(_audit_finishes(db, task.id)) == 1
        finally:
            engine.dispose()

    def test_preflight_rejection_fails_before_fence(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"fail_preflight_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.dispatch_started_at is None
                assert row.error_code == "validation_failed"
        finally:
            engine.dispose()

    def test_preflight_stale_fails_with_preview_stale(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"stale_preflight_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.dispatch_started_at is None
                assert row.error_code == "preview_stale"
                assert "重新预览" in (row.error_detail or "")
        finally:
            engine.dispose()

    def test_plan_drift_fails_before_fence(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, plan_hash="a" * 64)
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.dispatch_started_at is None
                assert row.error_code == "validation_failed"
                assert "计划已漂移" in (row.error_detail or "")
        finally:
            engine.dispose()

    def test_disabled_device_fails_validation(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                device, task = _seed_execution_task(db)
                device.enabled = False
                db.commit()
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.dispatch_started_at is None
                assert row.error_code == "validation_failed"
        finally:
            engine.dispose()

    def test_execute_explicit_failure_is_failed_never_retried(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"execute_fail_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.dispatch_started_at is not None
                assert row.error_code == "operation_failed"
                assert row.finished_at is not None
            # Terminal: nothing claims it again.
            assert _claim_one(factory) is None
        finally:
            engine.dispose()

    def test_execute_adapter_timeout_maps_to_verification_required(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db, connection_config={"execute_timeout_mode": True}
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "verification_required"
                assert row.dispatch_started_at is not None
                assert row.error_code == "ambiguous_result"
                assert row.finished_at is None
                assert len(_audit_finishes(db, task.id)) == 1
        finally:
            engine.dispose()

    def test_ambiguous_verification_enters_verification_required(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db, connection_config={"verify_ambiguous_mode": True}
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "verification_required"
                assert row.error_code == "ambiguous_result"
                assert row.evidence is not None
                assert row.evidence["verification"]["ambiguous"] is True
                assert row.finished_at is None
        finally:
            engine.dispose()

    def test_verify_explicit_failure_marks_failed(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"verify_fail_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.verification_state == "failed"
                assert row.error_code == "operation_failed"
        finally:
            engine.dispose()

    def test_read_profile_timeout_error_maps_to_timed_out(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db,
                    requirement_id=ASSET_REFRESH[0],
                    capability_key=ASSET_REFRESH[1],
                    connection_config={"execute_timeout_mode": True},
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "timed_out"
                assert row.dispatch_started_at is not None
                assert row.finished_at is not None
        finally:
            engine.dispose()

    def test_expired_deadline_before_fence_is_timed_out(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, timeout_seconds=-1)
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "timed_out"
                assert row.dispatch_started_at is None
        finally:
            engine.dispose()

    def test_read_profile_happy_path(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db, requirement_id=ASSET_REFRESH[0], capability_key=ASSET_REFRESH[1]
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
        finally:
            engine.dispose()

    def test_slow_mode_progress_is_throttled(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"slow_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            # A 60 s throttle window: only the first callback and the final
            # 100% point may persist, however fast/slow the callbacks fire.
            self._executor(factory, settings, audit=False, progress_min=60.0)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.progress_percent == 100
                progress_events = db.scalars(
                    select(OperationTaskEvent)
                    .where(
                        OperationTaskEvent.task_id == task.id,
                        OperationTaskEvent.progress_percent.is_not(None),
                    )
                    .order_by(OperationTaskEvent.occurred_at)
                ).all()
                values = [e.progress_percent for e in progress_events]
                assert values == [20, 100]
        finally:
            engine.dispose()


class TestJobPolling:
    def _executor(self, factory: sessionmaker[Session], settings: WardenSettings) -> OperationExecutor:
        return OperationExecutor(
            session_factory=factory,
            lease_owner=OWNER,
            lease_seconds=300,
            settings=settings,
            keyring=make_keyring(),
            audit_logger=AuditLogger(factory),
        )

    def test_device_job_is_persisted_then_polled_to_success(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                device, task = _seed_execution_task(
                    db,
                    connection_config={"device_job_mode": True, "job_poll_rounds": 2},
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.device_job_id == FAKE_DEVICE_JOB_ID
                states = list(
                    db.scalars(
                        select(OperationTaskEvent.state)
                        .where(OperationTaskEvent.task_id == task.id)
                        .order_by(OperationTaskEvent.occurred_at)
                    ).all()
                )
                assert "waiting_device" in states
                assert states[-1] == "succeeded"
                assert "operation.updated" in _ui_event_types(db, task.id)
            fake = get_adapter("fake.simple")
            assert fake._job_poll_calls.get(str(device.id)) == 3  # 2 pending + final verdict
        finally:
            engine.dispose()

    def test_device_job_eventual_failure_is_failed(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db,
                    connection_config={
                        "device_job_mode": True,
                        "job_poll_rounds": 1,
                        "job_poll_fail_mode": True,
                    },
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            self._executor(factory, settings)(claimed)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.error_code == "operation_failed"
                assert row.device_job_id == FAKE_DEVICE_JOB_ID
        finally:
            engine.dispose()


class TestCrashRecovery:
    """Fence-aware crash recovery: park -> verify-only consumption (M2T6)."""

    def _executor(self, factory: sessionmaker[Session], settings: WardenSettings) -> OperationExecutor:
        return OperationExecutor(
            session_factory=factory,
            lease_owner=OWNER,
            lease_seconds=300,
            settings=settings,
            keyring=make_keyring(),
            audit_logger=AuditLogger(factory),
        )

    def test_crash_after_fence_verify_only_consumption_never_reexecutes(
        self, fresh_test_db_dsn: str, monkeypatch
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        fake = get_adapter("fake.simple")
        execute_calls: list[int] = []

        original_execute = fake.execute_operation

        def counting_execute(session, plan, progress: OperationProgress):
            execute_calls.append(1)
            return original_execute(session, plan, progress)

        monkeypatch.setattr(fake, "execute_operation", counting_execute)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db, connection_config={"crash_after_fence_mode": True}
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            # The executor "dies" inside execute: the exception propagates.
            with pytest.raises(SimulatedWorkerCrash):
                self._executor(factory, settings)(claimed)
            # The pool would release the lease; do it the same way.
            with factory() as db:
                release_lease(db, task_id=task.id, owner=OWNER)
                db.commit()
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "running"
                assert row.dispatch_started_at is not None
            # Maintenance parks the fenced task for verify-only.
            report = MaintenanceLoop(factory, settings=settings).run_once()
            assert report.verify_only == 1
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "running"
                assert row.lease_owner is None and row.lease_expires_at is None
            # The next worker claims the parked task and only verifies.
            with factory() as session:
                parked = claim_verify_only_task(session, lease_owner=OWNER, lease_seconds=300)
                session.commit()
            assert parked is not None and parked.id == task.id
            self._executor(factory, settings)(parked)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.verification_state == "passed"
                assert len(_audit_finishes(db, task.id)) == 1
            assert len(execute_calls) == 1
        finally:
            engine.dispose()

    def test_crash_before_fence_requeues_and_succeeds_once(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        fake = get_adapter("fake.simple")
        execute_calls: list[int] = []
        original_execute = fake.execute_operation

        def counting_execute(session, plan, progress: OperationProgress):
            execute_calls.append(1)
            return original_execute(session, plan, progress)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(fake, "execute_operation", counting_execute)
        try:
            with factory() as db:
                _, task = _seed_execution_task(db, connection_config={"crash_before_fence_mode": True})
            claimed = _claim_one(factory)
            assert claimed is not None
            with pytest.raises(SimulatedWorkerCrash):
                self._executor(factory, settings)(claimed)
            with factory() as db:
                release_lease(db, task_id=task.id, owner=OWNER)
                db.commit()
            report = MaintenanceLoop(factory, settings=settings).run_once()
            assert report.requeued == 1
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "queued"
                assert row.dispatch_started_at is None
            # The crash mode fired once per device: the retry runs to success.
            retried = _claim_one(factory)
            assert retried is not None and retried.id == task.id
            self._executor(factory, settings)(retried)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
            assert len(execute_calls) == 1
        finally:
            monkeypatch.undo()
            engine.dispose()

    def test_read_crash_before_fence_requeues_with_attempt_count(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db,
                    requirement_id=ASSET_REFRESH[0],
                    capability_key=ASSET_REFRESH[1],
                    connection_config={"crash_before_fence_mode": True},
                )
            claimed = _claim_one(factory)
            assert claimed is not None
            with pytest.raises(SimulatedWorkerCrash):
                self._executor(factory, settings)(claimed)
            with factory() as db:
                release_lease(db, task_id=task.id, owner=OWNER)
                db.commit()
            report = MaintenanceLoop(factory, settings=settings).run_once()
            assert report.requeued == 1
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "queued"
                assert row.attempt_count == 1
            retried = _claim_one(factory)
            assert retried is not None
            self._executor(factory, settings)(retried)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
                assert row.attempt_count == 1
        finally:
            engine.dispose()

    def test_read_crash_attempt_cap_fails_task_terminally(self, fresh_test_db_dsn: str) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _, task = _seed_execution_task(
                    db,
                    requirement_id=ASSET_REFRESH[0],
                    capability_key=ASSET_REFRESH[1],
                    connection_config={"crash_before_fence_mode": True},
                )
            # Grant one requeue already: the next recovery hits the cap.
            with factory() as db:
                row = db.get(OperationTask, task.id)
                assert row is not None
                row.state = "running"
                row.attempt_count = 1
                row.lease_owner = "dead-worker"
                row.lease_expires_at = utcnow() - datetime.timedelta(minutes=5)
                db.commit()
            report = MaintenanceLoop(
                factory, settings=settings, audit_logger=AuditLogger(factory)
            ).run_once()
            assert report.recovery_failed == 1
            assert report.requeued == 0
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "failed"
                assert row.error_code == "network_unreachable"
                assert row.finished_at is not None
                assert row.evidence is None
                assert len(_audit_finishes(db, task.id)) == 1
                assert "operation.updated" in _ui_event_types(db, task.id)
        finally:
            engine.dispose()

    def test_parked_fenced_task_past_deadline_stays_for_timeout_sweep(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _seed_parked_task(db, timeout_at=utcnow() - datetime.timedelta(minutes=1))
            with factory() as session:
                parked = claim_verify_only_task(session, lease_owner=OWNER, lease_seconds=300)
                session.commit()
            assert parked is None
            report = MaintenanceLoop(factory, settings=settings).run_once()
            assert report.verification_required == 1
            with factory() as db:
                rows = db.scalars(select(OperationTask)).all()
                assert len(rows) == 1 and rows[0].state == "verification_required"
        finally:
            engine.dispose()

    def test_waiting_device_expired_lease_is_parked_then_verify_only(
        self, fresh_test_db_dsn: str
    ) -> None:
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        settings = _executor_settings(fresh_test_db_dsn)
        try:
            with factory() as db:
                _device, task = _seed_parked_task(
                    db,
                    state="waiting_device",
                    device_job_id=FAKE_DEVICE_JOB_ID,
                    connection_config={"device_job_mode": True, "job_poll_rounds": 1},
                )
            # Parked verify-only rows have NO lease; give this one an expired
            # lease (a worker died while polling) and let recovery park it.
            with factory() as db:
                row = db.get(OperationTask, task.id)
                assert row is not None
                row.lease_owner = "dead-poller"
                row.lease_expires_at = utcnow() - datetime.timedelta(minutes=5)
                db.commit()
            report = MaintenanceLoop(factory, settings=settings).run_once()
            assert report.verify_only == 1
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "waiting_device"
                assert row.lease_owner is None
            with factory() as session:
                parked = claim_verify_only_task(session, lease_owner=OWNER, lease_seconds=300)
                session.commit()
            assert parked is not None and parked.id == task.id
            self._executor(factory, settings)(parked)
            with factory() as db:
                row = _refresh(db, task.id)
                assert row.state == "succeeded"
        finally:
            engine.dispose()
