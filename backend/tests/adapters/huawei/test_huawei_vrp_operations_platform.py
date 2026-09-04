"""M5T3 platform slices: the real worker runs the Huawei VRP switch
operations against the VRP SSH simulator (integration, real PostgreSQL).

Each op family runs through the real platform boundary — onboarding with a
pinned SSH host-key fingerprint, preview/confirm or seeded tasks, the
dispatch fence, the VRP CLI/SFTP execute + read-back verify, encrypted
artifact/file rows, audit:

1. core device.restart -> succeeded with disconnect/uptime evidence;
2. core interface.admin.set (GE0/0/2 down) -> admin_state readback;
3. access poe.port.set cycle (off_seconds 5) -> off-then-on proof;
4. core logs.diagnostic.collect -> encrypted operation_log artifact with
   the completion marker;
5. core config.backup -> encrypted config_backup artifact + metadata, then
   config.restore of that file -> fingerprint round trip succeeded;
6. access firmware.update (uploaded warden-sim image) -> version + boot
   image readback; no device-pull ticket is issued (SFTP push path).

The simulator is a TEST DEVICE SIMULATOR, never hardware evidence.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from app.config import WardenSettings
from app.domain.operation_plan import OperationRequest, plan_operation
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.time import utcnow
from app.main import create_app
from app.models.operation import OperationTask
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from tests.adapters.huawei.conftest import SIM_HOST, V3_AUTH_KEY, V3_PRIV_KEY, V3_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, login_csrf
from tests.e2e.test_worker_execution import WorkerRig
from tests.simulators.vrp.device import SSH_PASSWORD, SSH_USERNAME
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
CORE_ADAPTER_KEY = "switch.huawei_vrp_core"
ACCESS_ADAPTER_KEY = "switch.huawei_vrp_access"
TERMINAL_STATES = ("succeeded", "failed", "timed_out", "verification_required")
UTC = datetime.UTC


def _core_credentials() -> dict[str, object]:
    return {
        "snmp": {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY},
        "ssh": {"username": SSH_USERNAME, "password": SSH_PASSWORD},
    }


def _access_credentials() -> dict[str, object]:
    return _core_credentials()


@contextmanager
def _resolve_simulator(monkeypatch: pytest.MonkeyPatch, port: int) -> Iterator[None]:
    monkeypatch.setattr(
        DeviceEndpointPolicy, "resolve_endpoint", _resolve_endpoint_factory(port)
    )
    yield


def _resolve_endpoint_factory(port: int):
    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, host, requested_port, allowed_ports
        return ipaddress.ip_address(SIM_HOST), port

    return resolve


def _settings(fresh_test_db_dsn: str, tmp_path) -> WardenSettings:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    file_key_file = tmp_path / "file_master.key"
    file_key_file.write_text("F" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs=f"{SIM_HOST}/32",
        credential_master_key_file=key_file,
        file_master_key_file=file_key_file,
        session_secret_file=session_file,
        file_store_root=tmp_path / "files",
        operation_job_poll_interval_seconds=0.05,
        ingest_bind_host="127.0.0.1",
    )


def _keyring(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


def _onboard(
    http: TestClient,
    snmp_port: int,
    ssh_port: int,
    *,
    name: str,
    adapter_key: str,
    device_type: str,
    credentials: dict[str, object],
    vrp_fingerprint: str,
) -> dict[str, object]:
    response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    connection_config = {
        "snmp_version": "v3",
        "port": snmp_port,
        "ssh_port": ssh_port,
        "ssh_host_fingerprint": vrp_fingerprint,
    }
    probe = http.post(
        f"{API}/device-probes",
        json={
            "device_type": device_type,
            "adapter_key": adapter_key,
            "management_endpoint": SIM_HOST,
            "connection_config": connection_config,
            "credentials": credentials,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, body
    created = http.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": device_type,
            "adapter_key": adapter_key,
            "management_endpoint": SIM_HOST,
            "connection_config": connection_config,
            "credentials": credentials,
            "enabled": True,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _seed_task(
    factory,
    *,
    device_id: uuid.UUID,
    capability_key: str,
    parameters: dict[str, object],
    timeout_seconds: int | None = None,
) -> uuid.UUID:
    from app.models.devices import Device

    with factory() as session:
        device = session.get(Device, device_id)
        assert device is not None
        user_id = session.execute(
            text("SELECT id FROM users WHERE username = 'admin'")
        ).scalar_one()
        snapshot = __import__("app.application.operations", fromlist=["build_snapshot"]).build_snapshot(
            session, device
        )
        plan = plan_operation(
            snapshot, OperationRequest(capability_key=capability_key, parameters=parameters)
        )
        task = OperationTask(
            requirement_id=plan.requirement_id,
            capability_key=capability_key,
            device_id=device_id,
            requested_by=user_id,
            risk_level=plan.risk_level,
            parameters=parameters,
            idempotency_key=f"m5t3-slice-{uuid.uuid4().hex[:16]}",
            conflict_scope=plan.conflict_scope,
            state="queued",
            plan_hash=plan.plan_hash,
            parameter_hash=plan.parameter_hash,
            adapter_version=plan.adapter_version,
            timeout_at=utcnow() + datetime.timedelta(seconds=timeout_seconds or plan.timeout_seconds),
        )
        session.add(task)
        session.commit()
        session.refresh(task)
        return task.id


def _wait_terminal(rig: WorkerRig, task_id: uuid.UUID, states: tuple[str, ...]) -> OperationTask:
    return rig.wait_terminal(task_id, states=states, timeout=90.0)


def _task_evidence(session, task_id: uuid.UUID) -> dict[str, object]:
    row = session.execute(
        text("SELECT evidence FROM operation_tasks WHERE id = :id"), {"id": task_id}
    ).scalar_one()
    return dict(row) if row else {}


def _finish_audit(session, task_id: uuid.UUID) -> str:
    return session.execute(
        text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
        {"id": task_id},
    ).scalar_one()


def _upload_file(http: TestClient, csrf: str, *, file_type: str, filename: str, content: bytes) -> str:
    created = http.post(
        f"{API}/files/uploads",
        json={"file_type": file_type, "size_bytes": len(content), "original_filename": filename},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    upload_id = str(created.json()["id"])
    put = http.put(
        f"{API}/files/uploads/{upload_id}/content",
        content=content,
        headers={"X-CSRF-Token": csrf},
    )
    assert put.status_code == 200, put.text
    completed = http.post(
        f"{API}/files/uploads/{upload_id}/complete",
        headers={"X-CSRF-Token": csrf},
    )
    assert completed.status_code == 200, completed.text
    return upload_id


def _run_pool_task(rig: WorkerRig, task_id: uuid.UUID, states: tuple[str, ...] = TERMINAL_STATES) -> OperationTask:
    rig.start_pool()
    try:
        return _wait_terminal(rig, task_id, states)
    finally:
        rig.stop_pool()


class VrpSliceRig:
    """One slice environment: real API + worker over one database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        snmp_port: int,
        ssh_port: int,
    ) -> None:
        self.settings = _settings(fresh_test_db_dsn, tmp_path)
        self.app = create_app(self.settings)
        self.factory = create_session_factory(
            create_engine(dsn_with_psycopg_dialect(fresh_test_db_dsn), pool_pre_ping=True)
        )
        self.keyring = _keyring(self.settings)
        self.rig = WorkerRig(
            fresh_test_db_dsn, self.settings, owner="m5t3-slice-worker", keyring=self.keyring
        )
        with self.factory() as session:
            create_admin(session)
        self._monkeypatch = monkeypatch
        # The SSRF policy resolves the SNMP probe port; the SSH connects run
        # against the literal 127.0.0.1 endpoint + configured ssh_port.
        monkeypatch.setattr(
            DeviceEndpointPolicy,
            "resolve_endpoint",
            _resolve_endpoint_factory(snmp_port),
        )
        del ssh_port

    def close(self) -> None:
        self.rig.close()
        engine = self.app.state.engine
        if engine is not None:
            engine.dispose()


def _switch_and_vrp(switch_agent, profile_key: str):
    """Boot the SNMP switch agent + the VRP SSH sim (same model identity)."""

    @contextmanager
    def boot():
        with switch_agent(profile_key=profile_key) as snmp_handle, running_vrp_server(
            profile_key
        ) as vrp_handle:
            yield snmp_handle, vrp_handle

    return boot()


class TestCoreRestartSlice:
    def test_restart_runs_through_the_worker(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "core_s5732") as (snmp_handle, vrp_handle):
            vrp_handle.device.knobs.restart_blip_seconds = 0.8
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-core-restart",
                        adapter_key=CORE_ADAPTER_KEY,
                        device_type="core_switch",
                        credentials=_core_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                task_id = _seed_task(
                    rig.factory,
                    device_id=uuid.UUID(onboarded["id"]),
                    capability_key="device.restart",
                    parameters={},
                )
                row = _run_pool_task(rig.rig, task_id, states=("succeeded",))
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
                evidence = row.evidence or {}
                assert evidence["execution"]["action"] == "reboot"
                verification = evidence["verification"]
                assert verification["disconnect_observed"] is True
                assert verification["uptime_reset_seconds"] < 300
                assert verification["identity_verified"]["model"] == "S5732-H48XUM2CC"
                with rig.factory() as session:
                    assert _finish_audit(session, row.id) == "succeeded"
                    raw = _task_evidence(session, row.id)
                    assert raw["execution"]["save_prompt_answered"] is False
            finally:
                rig.close()


class TestCoreInterfaceSlice:
    def test_interface_admin_set_readback_through_worker(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "core_s5732") as (snmp_handle, vrp_handle):
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-core-interface",
                        adapter_key=CORE_ADAPTER_KEY,
                        device_type="core_switch",
                        credentials=_core_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                task_id = _seed_task(
                    rig.factory,
                    device_id=uuid.UUID(onboarded["id"]),
                    capability_key="interface.admin.set",
                    parameters={"interface_id": "GigabitEthernet0/0/2", "enabled": False},
                )
                row = _run_pool_task(rig.rig, task_id, states=("succeeded",))
                assert row.state == "succeeded"
                evidence = row.evidence or {}
                verification = evidence["verification"]
                assert verification["admin_state_readback"] == "down"
                with rig.factory() as session:
                    assert _finish_audit(session, row.id) == "succeeded"
                snapshot = vrp_handle.device.snapshot()
                assert "GigabitEthernet0/0/2" in snapshot["admin_down"]
            finally:
                rig.close()


class TestAccessPoeSlice:
    def test_poe_cycle_off_transition_through_worker(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "access_s5735") as (snmp_handle, vrp_handle):
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-access-poe",
                        adapter_key=ACCESS_ADAPTER_KEY,
                        device_type="access_switch",
                        credentials=_access_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                task_id = _seed_task(
                    rig.factory,
                    device_id=uuid.UUID(onboarded["id"]),
                    capability_key="poe.port.set",
                    parameters={
                        "interface_id": "GigabitEthernet0/0/6",
                        "mode": "cycle",
                        "off_seconds": 5,
                    },
                    timeout_seconds=120,
                )
                row = _run_pool_task(rig.rig, task_id, states=("succeeded",))
                assert row.state == "succeeded"
                evidence = row.evidence or {}
                transitions = evidence["execution"]["poe_transitions"]
                assert [t["readback"] for t in transitions] == ["off", "on"]
                assert evidence["verification"]["poe_state_readback"] == "on"
                with rig.factory() as session:
                    assert _finish_audit(session, row.id) == "succeeded"
                assert vrp_handle.device.poe_state("GigabitEthernet0/0/6") is True
            finally:
                rig.close()


class TestDiagnosticsSlice:
    def test_diagnostics_collect_encrypted_artifact_through_worker(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "core_s5732") as (snmp_handle, vrp_handle):
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-core-diag",
                        adapter_key=CORE_ADAPTER_KEY,
                        device_type="core_switch",
                        credentials=_core_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                task_id = _seed_task(
                    rig.factory,
                    device_id=uuid.UUID(onboarded["id"]),
                    capability_key="logs.diagnostic.collect",
                    parameters={},
                )
                row = _run_pool_task(rig.rig, task_id, states=("succeeded",))
                assert row.state == "succeeded"
                evidence = row.evidence or {}
                assert evidence["verification"]["completion_marker"] == "prompt_returned"
                execution = evidence["execution"]
                stored_sha = execution["artifact_stored"]["sha256"]
                with rig.factory() as session:
                    file_row = session.execute(
                        text(
                            "SELECT f.file_type, f.encrypted, f.sha256, f.metadata->>'source' AS source "
                            "FROM files f JOIN file_links fl ON fl.file_id = f.id "
                            "WHERE fl.task_id = :id",
                        ),
                        {"id": row.id},
                    ).mappings().all()
                    assert len(file_row) == 1
                    entry = dict(file_row[0])
                    assert entry["file_type"] == "operation_log"
                    assert entry["encrypted"] is True
                    assert entry["sha256"] == stored_sha
                    assert entry["source"] == "display.diagnostic_information"
                    assert _finish_audit(session, row.id) == "succeeded"
            finally:
                rig.close()


class TestConfigBackupRestoreSlice:
    def test_backup_then_restore_round_trip_through_worker(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "core_s5732") as (snmp_handle, vrp_handle):
            vrp_handle.device.knobs.restart_blip_seconds = 0.8
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-core-config",
                        adapter_key=CORE_ADAPTER_KEY,
                        device_type="core_switch",
                        credentials=_core_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                device_id = uuid.UUID(onboarded["id"])
                backup_task = _seed_task(
                    rig.factory,
                    device_id=device_id,
                    capability_key="config.backup",
                    parameters={},
                )
                row = _run_pool_task(rig.rig, backup_task, states=("succeeded",))
                evidence = row.evidence or {}
                assert evidence["execution"]["parse_ok"] is True
                with rig.factory() as session:
                    meta = session.execute(
                        text(
                            "SELECT f.id, f.sha256, f.metadata->>'model' AS model, "
                            "f.metadata->>'vrp_version' AS vrp FROM files f "
                            "JOIN file_links fl ON fl.file_id = f.id WHERE fl.task_id = :id"
                        ),
                        {"id": row.id},
                    ).mappings().one()
                    assert meta["model"] == "S5732-H48XUM2CC"
                    assert meta["vrp"] == "V200R021C10SPC600"
                    backup_file_id = str(meta["id"])
                    backup_fingerprint = meta["sha256"]
                # Restore the very backup we just made (full round trip).
                restore_task = _seed_task(
                    rig.factory,
                    device_id=device_id,
                    capability_key="config.restore",
                    parameters={"file_id": backup_file_id},
                    timeout_seconds=300,
                )
                row = _run_pool_task(rig.rig, restore_task, states=("succeeded",))
                evidence = row.evidence or {}
                execution = evidence["execution"]
                assert execution["certified_strategy"] == "full_replace_via_startup_config_and_reboot"
                verification = evidence["verification"]
                assert verification["config_fingerprint"] == backup_fingerprint
                with rig.factory() as session:
                    assert _finish_audit(session, row.id) == "succeeded"
            finally:
                rig.close()


class TestFirmwareSlice:
    def test_firmware_update_through_worker_without_ticket(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _switch_and_vrp(switch_agent, "access_s5735") as (snmp_handle, vrp_handle):
            vrp_handle.device.knobs.restart_blip_seconds = 0.8
            rig = VrpSliceRig(fresh_test_db_dsn, tmp_path, monkeypatch, snmp_handle.port, vrp_handle.port)
            try:
                with TestClient(rig.app) as http:
                    onboarded = _onboard(
                        http,
                        snmp_handle.port,
                        vrp_handle.port,
                        name="slice-access-fw",
                        adapter_key=ACCESS_ADAPTER_KEY,
                        device_type="access_switch",
                        credentials=_access_credentials(),
                        vrp_fingerprint=vrp_handle.host_fingerprint,
                    )
                    response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
                    assert response.status_code == 200
                    image = (
                        "WARDEN-SIM-FW "
                        + json.dumps({"model": "S5735-L48P4S-A1", "version": "V200R019C10SPC610"})
                        + "\npadding-bytes\n"
                    ).encode("utf-8")
                    file_id = _upload_file(
                        http, csrf, file_type="firmware", filename="access-upgrade.bin", content=image
                    )
                task_id = _seed_task(
                    rig.factory,
                    device_id=uuid.UUID(onboarded["id"]),
                    capability_key="firmware.update",
                    parameters={"file_id": file_id},
                    timeout_seconds=300,
                )
                row = _run_pool_task(rig.rig, task_id, states=("succeeded",))
                evidence = row.evidence or {}
                verification = evidence["verification"]
                assert verification["version_readback"] == "V200R019C10SPC610"
                assert verification["boot_image_readback"] == "firmware-V200R019C10SPC610.bin"
                assert vrp_handle.device.version == "V200R019C10SPC610"
                with rig.factory() as session:
                    # SFTP push path: no device-pull ticket is ever issued.
                    tickets = session.execute(
                        text("SELECT count(*) FROM device_file_tickets WHERE created_by_task_id = :id"),
                        {"id": row.id},
                    ).scalar_one()
                    assert tickets == 0
                    assert _finish_audit(session, row.id) == "succeeded"
            finally:
                rig.close()
