"""M2T6 fault-injection E2E suite (integration, real PostgreSQL).

End-to-end through the API + the real worker components (operation pool with
the executor, maintenance loop) over one shared database — the M2 gate:
"假设备执行成功、明确失败、超时、Worker 崩溃和结果不明的端到端流程；
API/Worker/主机重启恢复通过".

Every scenario records its asserted counts (execute calls, terminal states,
attempt_count, audit/ui_events rows). Fence ordering is sacred: the crash
after the dispatch fence may only be consumed by verify-only (execute_count
stays 1), ambiguous never becomes failed + auto-replay, and terminal state +
audit + ui_events land in one transaction.
"""

from __future__ import annotations

import datetime
import time
import uuid

import pytest
from app.adapters import get_adapter
from app.adapters.fake import FAKE_DEVICE_JOB_ID
from app.application.operations import build_snapshot
from app.config import WardenSettings
from app.domain.adapter import OperationProgress
from app.domain.operation_plan import OperationRequest, plan_operation
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.time import utcnow
from app.main import create_app
from app.models.auth import AuditLog
from app.models.observation import UiEvent
from app.models.operation import OperationTask, OperationTaskEvent
from app.workers.maintenance import MaintenanceLoop
from app.workers.operation_executor import OperationExecutor
from app.workers.operation_pool import OperationPool
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, create_user, login_csrf
from tests.api.test_devices import create_device, probe_and_get_token
from tests.observation_factories import make_collection_device, make_keyring
from tests.task_factories import make_user

POWER_ON = ("SRV-ACT-02", "power.on")  # side_effect=true
ASSET_REFRESH = ("SRV-ACT-07", "asset.refresh")  # side_effect=false
OPERATOR_PASSWORD = "Op!pass-2026-Strong"

TERMINAL_STATES = ("succeeded", "failed", "timed_out", "verification_required")


def _worker_settings(dsn: str) -> WardenSettings:
    return WardenSettings(
        postgres_dsn=dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        operation_job_poll_interval_seconds=0.05,
    )


def _keyring_from_file(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


class WorkerRig:
    """In-process worker components over one database (like run.py wiring)."""

    def __init__(
        self,
        dsn: str,
        settings: WardenSettings,
        *,
        owner: str,
        keyring: CredentialKeyring | None = None,
    ) -> None:
        self.settings = settings
        self.owner = owner
        self.keyring = keyring if keyring is not None else make_keyring()
        self.engine = create_engine(
            dsn_with_psycopg_dialect(dsn),
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5},
            pool_size=1,
            max_overflow=1,
        )
        self.factory: sessionmaker[Session] = create_session_factory(self.engine)
        self.audit_logger = AuditLogger(self.factory)
        self._pool: OperationPool | None = None

    def executor(self) -> OperationExecutor:
        return OperationExecutor(
            session_factory=self.factory,
            lease_owner=self.owner,
            lease_seconds=300,
            settings=self.settings,
            keyring=self.keyring,
            audit_logger=self.audit_logger,
        )

    def start_pool(self) -> OperationPool:
        self._pool = OperationPool(
            session_factory=self.factory,
            max_workers=1,
            lease_seconds=300,
            lease_owner=self.owner,
            handler=self.executor(),
            poll_interval=0.05,
        )
        self._pool.start()
        return self._pool

    def stop_pool(self) -> None:
        if self._pool is not None:
            self._pool.stop(timeout=10)
            self._pool = None

    def maintenance_once(self) -> object:
        return MaintenanceLoop(
            self.factory, settings=self.settings, audit_logger=self.audit_logger
        ).run_once()

    def close(self) -> None:
        self.stop_pool()
        self.engine.dispose()

    def wait_terminal(
        self,
        task_id: uuid.UUID,
        *,
        states: tuple[str, ...] = TERMINAL_STATES,
        timeout: float = 60.0,
    ) -> OperationTask:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.factory() as session:
                row = session.get(OperationTask, task_id)
                if row is not None and row.state in states:
                    return row
            time.sleep(0.05)
        msg = f"task {task_id} did not reach {states} within {timeout}s"
        raise AssertionError(msg)


def _seed_task(
    db: Session,
    *,
    connection_config: dict[str, object] | None = None,
    requirement: str = POWER_ON[0],
    capability: str = POWER_ON[1],
) -> OperationTask:
    device = make_collection_device(db, connection_config=connection_config)
    user = make_user(db)
    snapshot = build_snapshot(db, device)
    plan = plan_operation(snapshot, OperationRequest(capability_key=capability, parameters={}))
    task = OperationTask(
        requirement_id=requirement,
        capability_key=capability,
        device_id=device.id,
        requested_by=user.id,
        risk_level=plan.risk_level,
        parameters={},
        idempotency_key=f"e2e-{uuid.uuid4().hex[:16]}",
        conflict_scope=plan.conflict_scope,
        state="queued",
        plan_hash=plan.plan_hash,
        parameter_hash=plan.parameter_hash,
        adapter_version=plan.adapter_version,
        timeout_at=utcnow() + datetime.timedelta(seconds=plan.timeout_seconds),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _audit_rows(db: Session, task_id: uuid.UUID) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.task_id == task_id)
            .order_by(AuditLog.created_at)
        ).all()
    )


def _ui_event_rows(db: Session, task_id: uuid.UUID) -> list[UiEvent]:
    return list(
        db.scalars(select(UiEvent).where(UiEvent.entity_id == task_id).order_by(UiEvent.id)).all()
    )


def _event_states(db: Session, task_id: uuid.UUID) -> list[str]:
    return list(
        db.scalars(
            select(OperationTaskEvent.state)
            .where(OperationTaskEvent.task_id == task_id)
            .order_by(OperationTaskEvent.occurred_at)
        ).all()
    )


@pytest.fixture
def http_env(fresh_test_db_dsn: str, tmp_path):
    """API app + client + worker rig over ONE fresh database (HTTP scenarios)."""
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    settings = WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs="192.0.2.0/24",
        credential_master_key_file=key_file,
        session_secret_file=session_file,
    )
    app = create_app(settings)
    rig = WorkerRig(
        fresh_test_db_dsn,
        _worker_settings(fresh_test_db_dsn),
        owner="e2e-worker",
        keyring=_keyring_from_file(settings),
    )
    try:
        with TestClient(app) as client:
            yield client, rig, settings
    finally:
        rig.close()
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.fixture
def rig_env(fresh_test_db_dsn: str):
    """Worker rig only (directly seeded devices/tasks). Yields (rig, factory)."""
    rig = WorkerRig(fresh_test_db_dsn, _worker_settings(fresh_test_db_dsn), owner="e2e-worker")
    try:
        yield rig, rig.factory
    finally:
        rig.close()


def _onboard_server(
    client: TestClient,
    admin_csrf: str,
    *,
    name: str,
    connection_config: dict[str, object] | None = None,
) -> str:
    probe_kwargs: dict[str, object] = {}
    if connection_config is not None:
        probe_kwargs["connection_config"] = connection_config
    probe = probe_and_get_token(client, admin_csrf, **probe_kwargs)
    assert probe["ok"] is True
    created = create_device(
        client,
        admin_csrf,
        token=probe["probe_token"],
        name=name,
        connection_config=connection_config,
    )
    assert created.status_code == 201
    return str(created.json()["id"])


def _http_confirm_power_on(
    client: TestClient,
    csrf: str,
    device_id: str,
    *,
    idempotency_key: str,
    confirmation_text: str = "fake-srv-e2e",
) -> str:
    preview = client.post(
        f"/api/v1/devices/{device_id}/operation-previews",
        json={"capability_key": "power.on", "parameters": {}},
        headers={"X-CSRF-Token": csrf},
    )
    assert preview.status_code == 200, preview.text
    token = str(preview.json()["preview_token"])
    confirmed = client.post(
        f"/api/v1/devices/{device_id}/operations",
        json={"preview_token": token, "confirmation_text": confirmation_text},
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": idempotency_key},
    )
    assert confirmed.status_code == 202, confirmed.text
    return str(confirmed.json()["id"])


def _count_executes(monkeypatch) -> list[int]:
    fake = get_adapter("fake.simple")
    calls: list[int] = []
    original = fake.execute_operation

    def counting(session, plan, progress: OperationProgress):
        calls.append(1)
        return original(session, plan, progress)

    monkeypatch.setattr(fake, "execute_operation", counting)
    return calls


class TestHttpWorkerFlow:
    def test_high_risk_confirm_chain_runs_through_worker(self, http_env, monkeypatch) -> None:
        """Login -> probe -> onboard -> reauth -> preview+confirm (SRV-ACT-02
        power.on) -> pool executes -> succeeded; audit + task events + ui
        events present; execute called exactly once."""
        client, rig, settings = http_env
        factory = rig.factory
        with factory() as session:
            create_admin(session)
        response, admin_csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        device_id = _onboard_server(client, admin_csrf, name="fake-srv-e2e")
        with factory() as session:
            create_user(
                session,
                username="e2e-operator",
                password=OPERATOR_PASSWORD,
                role="operator",
                display_name="E2E 运维员",
            )
        response, operator_csrf = login_csrf(client, "e2e-operator", OPERATOR_PASSWORD)
        assert response.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/reauth",
                json={"password": OPERATOR_PASSWORD},
                headers={"X-CSRF-Token": operator_csrf},
            ).status_code
            == 200
        )
        calls = _count_executes(monkeypatch)
        task_id = _http_confirm_power_on(
            client, operator_csrf, device_id, idempotency_key="e2e-happy-key-0001"
        )
        # The operator's cookie session is on the TestClient; query the task
        # as the same session to assert the task list/detail views.
        queued = client.get(f"/api/v1/operations/{task_id}")
        assert queued.status_code == 200 and queued.json()["state"] == "queued"

        rig.start_pool()
        try:
            row = rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.dispatch_started_at is not None
        assert len(calls) == 1

        detail = client.get(f"/api/v1/operations/{task_id}")
        body = detail.json()
        assert body["state"] == "succeeded"
        assert body["verification_state"] == "passed"
        event_states = [e["state"] for e in body["events"]]
        assert event_states[-1] == "succeeded"

        with factory() as session:
            worker_actions = [
                row.action
                for row in _audit_rows(session, uuid.UUID(task_id))
                if row.action in ("operation.start", "operation.finish")
            ]
            assert worker_actions == ["operation.start", "operation.finish"]
            finishes = [
                row
                for row in _audit_rows(session, uuid.UUID(task_id))
                if row.action == "operation.finish"
            ]
            assert finishes[0].result == "succeeded"
            ui_rows = _ui_event_rows(session, uuid.UUID(task_id))
            assert [e.event_type for e in ui_rows] == ["operation.updated", "operation.updated"]

        # Worker "restart": a NEW worker instance (same DB) runs a fresh task.
        response, operator_csrf = login_csrf(client, "e2e-operator", OPERATOR_PASSWORD)
        assert response.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/reauth",
                json={"password": OPERATOR_PASSWORD},
                headers={"X-CSRF-Token": operator_csrf},
            ).status_code
            == 200
        )
        restarted = WorkerRig(
            str(settings.postgres_dsn),
            _worker_settings(str(settings.postgres_dsn)),
            owner="e2e-worker-restarted",
            keyring=_keyring_from_file(settings),
        )
        try:
            task2 = _http_confirm_power_on(
                client, operator_csrf, device_id, idempotency_key="e2e-restart-key-0002"
            )
            restarted.start_pool()
            try:
                row2 = restarted.wait_terminal(uuid.UUID(task2), states=("succeeded",))
            finally:
                restarted.stop_pool()
            assert row2.state == "succeeded"
        finally:
            restarted.close()
        assert len(calls) == 2  # one execute per task, never a replay


class TestFaultInjection:
    def test_explicit_device_failure_is_failed_and_never_retried(self, rig_env, monkeypatch) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(session, connection_config={"execute_fail_mode": True})
            task_id = task.id
        calls = _count_executes(monkeypatch)
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("failed",))
        finally:
            rig.stop_pool()
        assert row.state == "failed"
        assert row.error_code == "operation_failed"
        assert row.dispatch_started_at is not None
        with db() as session:
            assert len(calls) == 1
            finishes = [a for a in _audit_rows(session, task_id) if a.action == "operation.finish"]
            assert len(finishes) == 1 and finishes[0].result == "failed"
        # No auto-retry: a second pool pass claims nothing.
        rig.start_pool()
        try:
            time.sleep(1.0)
        finally:
            rig.stop_pool()
        assert len(calls) == 1
        with db() as session:
            row = session.get(OperationTask, task_id)
            assert row is not None and row.state == "failed"

    def test_adapter_timeout_after_fence_enters_verification_required(self, rig_env) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(session, connection_config={"execute_timeout_mode": True})
            task_id = task.id
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("verification_required",))
        finally:
            rig.stop_pool()
        assert row.state == "verification_required"
        assert row.dispatch_started_at is not None
        assert row.error_code == "ambiguous_result"
        assert row.finished_at is None
        with db() as session:
            finishes = [a for a in _audit_rows(session, task_id) if a.action == "operation.finish"]
            assert len(finishes) == 1 and finishes[0].result == "verification_required"

    def test_crash_after_fence_recovers_verify_only_succeeded_execute_once(
        self, rig_env, monkeypatch
    ) -> None:
        """Worker "dies" after the fence; maintenance parks it; the next
        worker consumes verify-only and the task succeeds with execute called
        EXACTLY ONCE (never re-executed)."""
        rig, db = rig_env
        with db() as session:
            task = _seed_task(session, connection_config={"crash_after_fence_mode": True})
            task_id = task.id
        calls = _count_executes(monkeypatch)
        rig.start_pool()
        try:
            deadline = time.monotonic() + 30
            fenced = None
            while time.monotonic() < deadline:
                with db() as session:
                    row = session.get(OperationTask, task_id)
                    if row is not None and row.dispatch_started_at is not None:
                        fenced = row
                        break
                time.sleep(0.05)
            assert fenced is not None, "dispatch fence was not committed"
        finally:
            rig.stop_pool()
        # The crashed task: released by the pool, fence present, no result.
        with db() as session:
            row = session.get(OperationTask, task_id)
            assert row is not None
            assert row.state == "running" and row.dispatch_started_at is not None
        report = rig.maintenance_once()
        assert report.verify_only == 1
        with db() as session:
            row = session.get(OperationTask, task_id)
            assert row is not None and row.lease_owner is None
        # "Worker restart": the next pool claims the parked task and verify
        # only. The crash mode fired once, and verify does not call execute.
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("succeeded",))
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.verification_state == "passed"
        assert len(calls) == 1
        with db() as session:
            finishes = [a for a in _audit_rows(session, task_id) if a.action == "operation.finish"]
            assert len(finishes) == 1 and finishes[0].result == "succeeded"

    def test_crash_before_fence_requeues_and_succeeds_once(self, rig_env, monkeypatch) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(session, connection_config={"crash_before_fence_mode": True})
            task_id = task.id
        calls = _count_executes(monkeypatch)
        rig.start_pool()
        try:
            deadline = time.monotonic() + 30
            crashed = False
            while time.monotonic() < deadline:
                with db() as session:
                    row = session.get(OperationTask, task_id)
                    if row is not None and row.state == "running" and row.lease_expires_at is not None:
                        crashed = True
                        break
                time.sleep(0.05)
            assert crashed, "crash did not release the task"
        finally:
            rig.stop_pool()
        assert len(calls) == 0  # the crash happened before any device call
        report = rig.maintenance_once()
        assert report.requeued == 1
        with db() as session:
            row = session.get(OperationTask, task_id)
            assert row is not None and row.state == "queued"
            assert row.dispatch_started_at is None
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("succeeded",))
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.dispatch_started_at is not None
        assert len(calls) == 1

    def test_read_profile_crash_requeues_with_attempt_and_succeeds(self, rig_env) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(
                session,
                requirement=ASSET_REFRESH[0],
                capability=ASSET_REFRESH[1],
                connection_config={"crash_before_fence_mode": True},
            )
            task_id = task.id
        rig.start_pool()
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                with db() as session:
                    row = session.get(OperationTask, task_id)
                    if row is not None and row.state == "running" and row.lease_expires_at is not None:
                        break
                time.sleep(0.05)
        finally:
            rig.stop_pool()
        report = rig.maintenance_once()
        assert report.requeued == 1
        with db() as session:
            row = session.get(OperationTask, task_id)
            assert row is not None and row.state == "queued"
            assert row.attempt_count == 1
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("succeeded",))
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.attempt_count == 1

    def test_ambiguous_enters_verification_required_then_admin_verify_and_resolve(
        self, http_env, monkeypatch
    ) -> None:
        client, rig, _settings = http_env
        factory = rig.factory
        with factory() as session:
            create_admin(session)
        response, admin_csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        calls = _count_executes(monkeypatch)
        # The action is accepted but the connection drops and verification
        # cannot prove either outcome: verification_required, never failed.
        device_id = _onboard_server(
            client,
            admin_csrf,
            name="fake-srv-amb",
            connection_config={
                "ambiguous_mode": True,
                "verify_ambiguous_mode": True,
            },
        )
        with factory() as session:
            create_user(
                session,
                username="e2e-operator",
                password=OPERATOR_PASSWORD,
                role="operator",
                display_name="E2E 运维员",
            )
        response, operator_csrf = login_csrf(client, "e2e-operator", OPERATOR_PASSWORD)
        assert response.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/reauth",
                json={"password": OPERATOR_PASSWORD},
                headers={"X-CSRF-Token": operator_csrf},
            ).status_code
            == 200
        )
        task_id = _http_confirm_power_on(
            client,
            operator_csrf,
            device_id,
            idempotency_key="e2e-amb-key-0001",
            confirmation_text="fake-srv-amb",
        )
        rig.start_pool()
        try:
            row = rig.wait_terminal(uuid.UUID(task_id), states=("verification_required",))
        finally:
            rig.stop_pool()
        assert row.state == "verification_required"
        assert row.error_code == "ambiguous_result"
        assert len(calls) == 1
        with factory() as session:
            finishes = [a for a in _audit_rows(session, uuid.UUID(task_id)) if a.action == "operation.finish"]
            assert finishes[0].result == "verification_required"

        # The field team proves the outcome; the device config no longer makes
        # verification ambiguous, and the admin read-back verify succeeds.
        with factory() as session:
            from app.models.devices import Device

            task_row = session.get(OperationTask, uuid.UUID(task_id))
            assert task_row is not None
            dev = session.get(Device, task_row.device_id)
            assert dev is not None
            dev.connection_config = {"ambiguous_mode": True}
            session.commit()
        response, admin_csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        verified = client.post(
            f"/api/v1/operations/{task_id}/verify", headers={"X-CSRF-Token": admin_csrf}
        )
        assert verified.status_code == 200
        assert verified.json()["state"] == "succeeded"
        assert len(calls) == 1  # verify read-backs, never re-executes

        # A second ambiguous task resolved from evidence marks failed.
        # (Re-login as the operator: the admin login replaced the cookie;
        # re-arm verify ambiguity so the executor cannot prove the outcome.)
        with factory() as session:
            from app.models.devices import Device as DeviceModel

            dev = session.get(DeviceModel, uuid.UUID(device_id))
            assert dev is not None
            dev.connection_config = {"ambiguous_mode": True, "verify_ambiguous_mode": True}
            session.commit()
        response, operator_csrf = login_csrf(client, "e2e-operator", OPERATOR_PASSWORD)
        assert response.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/reauth",
                json={"password": OPERATOR_PASSWORD},
                headers={"X-CSRF-Token": operator_csrf},
            ).status_code
            == 200
        )
        task2_id = _http_confirm_power_on(
            client,
            operator_csrf,
            device_id,
            idempotency_key="e2e-amb-key-0002",
            confirmation_text="fake-srv-amb",
        )
        rig.start_pool()
        try:
            rig.wait_terminal(uuid.UUID(task2_id), states=("verification_required",))
        finally:
            rig.stop_pool()
        response, admin_csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        resolved = client.post(
            f"/api/v1/operations/{task2_id}/resolve-verification",
            json={
                "outcome": "failed",
                "evidence_type": "device_ui",
                "reference": "BMC 页面显示系统仍为关机",
                "reason": "现场查看 BMC 页面确认操作未生效",
            },
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert resolved.status_code == 200
        assert resolved.json()["state"] == "failed"
        assert len(calls) == 2

    def test_device_job_mode_transitions_through_waiting_device(self, rig_env, monkeypatch) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(
                session,
                connection_config={"device_job_mode": True, "job_poll_rounds": 1},
            )
            task_id = task.id
        calls = _count_executes(monkeypatch)
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("succeeded",))
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.device_job_id == FAKE_DEVICE_JOB_ID
        with db() as session:
            states = _event_states(session, task_id)
            assert "waiting_device" in states
            assert states[-1] == "succeeded"
            assert "operation.updated" in [e.event_type for e in _ui_event_rows(session, task_id)]
            finishes = [a for a in _audit_rows(session, task_id) if a.action == "operation.finish"]
            assert finishes[0].result == "succeeded"
        assert len(calls) == 1

    def test_slow_mode_progress_and_ui_events_through_pool(self, rig_env) -> None:
        rig, db = rig_env
        with db() as session:
            task = _seed_task(session, connection_config={"slow_mode": True})
            task_id = task.id
        rig.start_pool()
        try:
            row = rig.wait_terminal(task_id, states=("succeeded",), timeout=90.0)
        finally:
            rig.stop_pool()
        assert row.state == "succeeded"
        assert row.progress_percent == 100
        with db() as session:
            progress = session.scalars(
                select(OperationTaskEvent.progress_percent)
                .where(
                    OperationTaskEvent.task_id == task_id,
                    OperationTaskEvent.progress_percent.is_not(None),
                )
                .order_by(OperationTaskEvent.occurred_at)
            ).all()
            assert progress[0] == 20
            assert progress[-1] == 100
            ui_events = _ui_event_rows(session, task_id)
            assert len(ui_events) >= 1
            assert [e.event_type for e in ui_events] == ["operation.updated", "operation.updated"]
