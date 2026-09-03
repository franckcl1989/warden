"""M4T3 platform slices: the real worker runs the Synology DSM operations
(NAS-ACT-01..06) against the TEST-DEVICE DSM simulator (integration, real
PostgreSQL, real HTTP).

Slices (per the M4T3 brief) run the FULL platform boundary — API confirm
chains, the dispatch fence, device_job persistence, encrypted artifact
storage + file_links + download, PAT device-pull tickets (the simulator
FETCHES the platform ticket URL) with revocation, launch tickets with audit:

1. power.restart via the high-risk API chain (reauth required -> preview ->
   confirm) -> pool -> succeeded with reconnect-identity evidence; the sim
   observed the restart blip;
2. disk.smart_test.quick via the MEDIUM-risk API chain (no reauth) -> pool
   -> device_job persisted -> succeeded; a never-completing quick test
   parks the task in verification_required (admin verify path keeps it);
3. logs.support_bundle.collect -> encrypted support_bundle file row +
   file_link, sha256 matches the evidence, API download works;
4. firmware.update with a PAT upload -> the DSM simulator FETCHES the
   platform ticket URL -> version readback == PAT target -> succeeded with
   the ticket revoked; a WRONG-MODEL PAT fails before the fence
   (validation_failed, no dispatch);
5. snmp.configure: enabled=true -> readback evidence succeeded (sim records
   its test-trap emission state); enabled=false -> readback succeeded; a
   platform WITHOUT a configured receiver -> not_configured before fence;
6. backup.status.refresh -> succeeded with the jobs inventory persisted in
   the task evidence;
7. console.dsm.open via POST /devices/{id}/launches -> protocol=web
   descriptor URL = the DSM origin, consumed once, launch audit rows.

The Warden API runs on a real localhost socket (uvicorn) so the SIMULATOR
(acting as the DSM) can pull ticket URLs; the SSRF policy is gated in via
the same loopback monkeypatch pattern as the M3T3/M4T2 slices. The simulator
is a TEST device simulator, never hardware evidence.
"""

from __future__ import annotations

import datetime
import gc
import io
import ipaddress
import json
import threading
import time
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from app.config import WardenSettings
from app.domain.operation_plan import OperationRequest, plan_operation
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.time import utcnow
from app.main import create_app
from app.models.operation import OperationTask
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin
from tests.e2e.test_worker_execution import WorkerRig

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "nas.synology_dsm"
SNMP_RECEIVER = "192.0.2.10:1162"
PAT_VERSION = "7.2.1-69057-update6 (simulated)"
DS224PLUS_MODEL = "DS224+ (simulated)"
DS225PLUS_MODEL = "DS225+ (simulated)"
OPERATOR_PASSWORD = "Op!pass-2026-Strong"

TERMINAL_STATES = ("succeeded", "failed", "timed_out", "verification_required")


@pytest.fixture()
def sim_url() -> Iterator[str]:
    from tests.simulators.dsm.app import SimulatorConfig
    from tests.simulators.dsm.serving import serve_simulator

    with serve_simulator(SimulatorConfig(profile="ds224plus")) as url:
        yield url


@contextmanager
def serve_app(app) -> Iterator[str]:
    """Run the Warden API on 127.0.0.1 with an OS-assigned port."""
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            log_level="warning",
            access_log=False,
            timeout_keep_alive=1,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15.0
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        time.sleep(0.02)
    sockets = server.servers[0].sockets if server.servers else []
    port = sockets[0].getsockname()[1] if sockets else None
    assert port is not None
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=15.0)
        gc.collect()


def _allow_simulator_resolution(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, host, requested_port, allowed_ports
        return ipaddress.ip_address(SIM_HOST), port

    monkeypatch.setattr(DeviceEndpointPolicy, "resolve_endpoint", resolve)


def _keyring_from_file(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


def _control(sim_url: str, **knobs: object) -> dict[str, object]:
    with httpx.Client(base_url=sim_url, timeout=10.0) as client:
        response = client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text
        body = response.json()
        assert isinstance(body, dict)
        return body


def _sim_snapshot(sim_url: str) -> dict[str, object]:
    with httpx.Client(base_url=sim_url, timeout=10.0) as client:
        response = client.get("/warden-sim/control")
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, dict)
        return body


class PlatformRig:
    """One slice environment: real API server + worker rig over one database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        sim_url: str,
        *,
        owner: str = "m4t3-slice-worker",
        snmp_receiver: str = "",
    ) -> None:
        port = int(urlsplit(sim_url).port or 0)
        _allow_simulator_resolution(monkeypatch, port)
        key_file = tmp_path / "credential_master.key"
        key_file.write_text("K" * 64, encoding="utf-8")
        file_key_file = tmp_path / "file_master.key"
        file_key_file.write_text("F" * 64, encoding="utf-8")
        session_file = tmp_path / "session_secret.txt"
        session_file.write_text("S" * 64, encoding="utf-8")
        self.settings = WardenSettings(
            postgres_dsn=fresh_test_db_dsn,
            app_env="development",
            public_url="http://localhost",
            device_access_base_url="http://localhost",
            _env_file=None,
            allowed_device_cidrs=f"{SIM_HOST}/32",
            credential_master_key_file=key_file,
            file_master_key_file=file_key_file,
            session_secret_file=session_file,
            file_store_root=tmp_path / "files",
            operation_job_poll_interval_seconds=0.05,
            snmp_trap_receiver_address=snmp_receiver,
        )
        self.app = create_app(self.settings)
        self.factory = create_session_factory(
            create_engine(dsn_with_psycopg_dialect(fresh_test_db_dsn), pool_pre_ping=True)
        )
        self.keyring = _keyring_from_file(self.settings)
        self.rig = WorkerRig(
            fresh_test_db_dsn,
            self.settings,
            owner=owner,
            keyring=self.keyring,
        )
        with self.factory() as session:
            create_admin(session)

    @contextmanager
    def serving(self) -> Iterator[str]:
        with serve_app(self.app) as url:
            self.http_url = url
            # The ticket URLs the devices pull must point at THIS server.
            self.settings.public_url = url
            self.settings.device_access_base_url = url
            yield url

    def close(self) -> None:
        self.rig.close()
        engine = self.app.state.engine
        if engine is not None:
            engine.dispose()


def _login(client: httpx.Client, username: str, password: str) -> str:
    response = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json().get("csrf_token", ""))


def _onboard(client: httpx.Client, csrf: str, sim_url: str, name: str) -> dict[str, object]:
    probe = client.post(
        f"{API}/device-probes",
        json={
            "device_type": "synology_nas",
            "adapter_key": ADAPTER_KEY,
            "management_endpoint": SIM_HOST,
            "port": int(urlsplit(sim_url).port or 0),
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, probe.text
    created = client.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": "synology_nas",
            "adapter_key": ADAPTER_KEY,
            "management_endpoint": SIM_HOST,
            "port": int(urlsplit(sim_url).port or 0),
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
            "enabled": True,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _confirm_operation(
    client: httpx.Client,
    csrf: str,
    device_id: str,
    *,
    capability_key: str,
    parameters: dict[str, object],
    confirmation_text: str,
    idempotency_key: str,
) -> str:
    preview = client.post(
        f"{API}/devices/{device_id}/operation-previews",
        json={"capability_key": capability_key, "parameters": parameters},
        headers={"X-CSRF-Token": csrf},
    )
    assert preview.status_code == 200, preview.text
    token = str(preview.json()["preview_token"])
    confirmed = client.post(
        f"{API}/devices/{device_id}/operations",
        json={"preview_token": token, "confirmation_text": confirmation_text},
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": idempotency_key},
    )
    assert confirmed.status_code == 202, confirmed.text
    return str(confirmed.json()["id"])


def _upload_file(client: httpx.Client, csrf: str, *, file_type: str, filename: str, content: bytes) -> str:
    created = client.post(
        f"{API}/files/uploads",
        json={"file_type": file_type, "size_bytes": len(content), "original_filename": filename},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    upload_id = str(created.json()["id"])
    put = client.put(
        f"{API}/files/uploads/{upload_id}/content",
        content=content,
        headers={"X-CSRF-Token": csrf},
    )
    assert put.status_code == 200, put.text
    completed = client.post(f"{API}/files/uploads/{upload_id}/complete", headers={"X-CSRF-Token": csrf})
    assert completed.status_code == 200, completed.text
    return upload_id


def _pat_bytes(model: str = DS224PLUS_MODEL, version: str = PAT_VERSION) -> bytes:
    """The warden-sim PAT fixture (first-line header; DSL shape only)."""
    header = f"WARDEN-SIM-PAT {json.dumps({'model': model, 'version': version}, ensure_ascii=False)}"
    return (header + "\npadding-bytes-for-a-package\n").encode("utf-8")


def _seed_task(
    db: Session,
    *,
    device_id: uuid.UUID,
    requested_by: uuid.UUID,
    capability_key: str,
    parameters: dict[str, object],
    timeout_seconds: int | None = None,
) -> uuid.UUID:
    from app.models.devices import Device

    device = db.get(Device, device_id)
    assert device is not None
    snapshot = __import__("app.application.operations", fromlist=["build_snapshot"]).build_snapshot(db, device)
    plan = plan_operation(snapshot, OperationRequest(capability_key=capability_key, parameters=parameters))
    task = OperationTask(
        requirement_id=plan.requirement_id,
        capability_key=capability_key,
        device_id=device_id,
        requested_by=requested_by,
        risk_level=plan.risk_level,
        parameters=parameters,
        idempotency_key=f"m4t3-slice-{uuid.uuid4().hex[:16]}",
        conflict_scope=plan.conflict_scope,
        state="queued",
        plan_hash=plan.plan_hash,
        parameter_hash=plan.parameter_hash,
        adapter_version=plan.adapter_version,
        timeout_at=utcnow() + datetime.timedelta(seconds=timeout_seconds or plan.timeout_seconds),
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return str(task.id)


def _pat_upload_and_task_id(
    rig: PlatformRig,
    base_url: str,
    device_id: str,
    *,
    content: bytes,
    idempotency: str,
    timeout_seconds: int | None = None,
) -> tuple[str, str]:
    del idempotency, timeout_seconds
    with httpx.Client(base_url=base_url, timeout=20.0) as client:
        csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        file_id = _upload_file(
            client, csrf, file_type="firmware", filename="dsm-update.pat", content=content
        )
    with rig.factory() as session:
        user = session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
        task_id = _seed_task(
            session,
            device_id=uuid.UUID(device_id),
            requested_by=user,
            capability_key="firmware.update",
            parameters={"file_id": file_id},
        )
    return str(task_id), file_id


def _dump_row(db: Session, task: OperationTask) -> None:
    evidence = task.evidence or {}
    verification = evidence.get("verification") or {}
    print(
        json.dumps(
            {
                "task": str(task.id),
                "capability": task.capability_key,
                "state": task.state,
                "verification_state": task.verification_state,
                "dispatch_started_at": task.dispatch_started_at.isoformat()
                if task.dispatch_started_at
                else None,
                "device_job_id": task.device_job_id,
                "error_code": task.error_code,
                "verification": {k: v for k, v in verification.items() if k != "artifact_manifest"},
            },
            ensure_ascii=False,
        )
    )


class TestDsmRestartSlice:
    def test_high_risk_restart_runs_through_the_worker(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, restart_blip_seconds=0.6)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-restart-nas")
                    device_id = onboarded["id"]
                    assert onboarded["adapter_key"] == ADAPTER_KEY
                    # High-risk previews require a fresh reauth (M2 flow):
                    # 401 reauthentication_required until the reauth.
                    blocked = client.post(
                        f"{API}/devices/{device_id}/operation-previews",
                        json={"capability_key": "power.restart", "parameters": {}},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert blocked.status_code == 401
                    assert blocked.json()["error"]["code"] == "reauthentication_required"
                    assert (
                        client.post(
                            f"{API}/auth/reauth",
                            json={"password": ADMIN_PASSWORD},
                            headers={"X-CSRF-Token": csrf},
                        ).status_code
                        == 200
                    )
                    task_id = _confirm_operation(
                        client,
                        csrf,
                        device_id,
                        capability_key="power.restart",
                        parameters={},
                        confirmation_text="slice-restart-nas",
                        idempotency_key="slice-nas-restart-0001",
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
                evidence = row.evidence or {}
                execution = evidence.get("execution") or {}
                verification = evidence.get("verification") or {}
                assert execution.get("action") == "restart"
                assert execution.get("api") == "SYNO.Core.System"
                assert verification.get("disconnect_observed") is True
                identity = verification.get("identity_verified") or {}
                assert identity.get("serial") == "SIM-DS224P-0001"
                with rig.factory() as session:
                    finish = session.execute(
                        text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                        {"id": row.id},
                    ).scalar_one()
                    assert finish == "succeeded"
                    _dump_row(session, row)
                snapshot = _sim_snapshot(sim_url)
                assert snapshot["power"] == "on"
                assert snapshot["firmware"] == "7.2.1-69057-update5 (simulated)"
        finally:
            rig.close()


class TestDsmSmartSlices:
    def test_quick_test_via_medium_risk_api_chain_tracks_device_job(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, smart_quick_duration_seconds=0.8)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-smart-nas")
                    device_id = onboarded["id"]
                    # Medium-risk preview works WITHOUT a fresh reauth.
                    preview = client.post(
                        f"{API}/devices/{device_id}/operation-previews",
                        json={"capability_key": "disk.smart_test.quick", "parameters": {"disk_id": "sata1"}},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert preview.status_code == 200, preview.text
                    task_id = _confirm_operation(
                        client,
                        csrf,
                        device_id,
                        capability_key="disk.smart_test.quick",
                        parameters={"disk_id": "sata1"},
                        confirmation_text="slice-smart-nas",
                        idempotency_key="slice-nas-smart-0001",
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                assert row.device_job_id is not None
                assert row.verification_state == "passed"
                evidence = row.evidence or {}
                verification = evidence.get("verification") or {}
                assert verification.get("job_state") == "success"
                with rig.factory() as session:
                    states = [
                        item[0]
                        for item in session.execute(
                            text(
                                "SELECT DISTINCT state FROM operation_task_events "
                                "WHERE task_id = :id ORDER BY state"
                            ),
                            {"id": row.id},
                        ).all()
                    ]
                    assert "waiting_device" in states
                    _dump_row(session, row)
        finally:
            rig.close()

    def test_never_completing_quick_test_parks_verification_required(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, smart_quick_duration_seconds=0.2, failures={"smart_test_never_completes": True})
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-smart-stuck")
                    device_id = onboarded["id"]
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    task_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="disk.smart_test.quick",
                        parameters={"disk_id": "sata1"},
                        timeout_seconds=8,
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("verification_required",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "verification_required"
                assert row.error_code == "ambiguous_result"
                # The admin verify path re-polls the SAME persisted job and
                # keeps the task parked (never a replay, never auto-success).
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    verify = client.post(
                        f"{API}/operations/{row.id}/verify", headers={"X-CSRF-Token": csrf}
                    )
                    assert verify.status_code == 200, verify.text
                with rig.factory() as session:
                    after = session.get(OperationTask, row.id)
                    assert after is not None
                    assert after.state == "verification_required"
                    _dump_row(session, after)
        finally:
            rig.close()


class TestDsmSupportBundleSlice:
    def test_support_bundle_artifact_encrypted_linked_and_downloadable(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-bundle-nas")
                    device_id = onboarded["id"]
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    task_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="logs.support_bundle.collect",
                        parameters={},
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                evidence = row.evidence or {}
                execution = evidence.get("execution") or {}
                stored = execution.get("artifact_stored") or {}
                assert stored.get("status") == "ready"
                assert stored.get("encrypted") is True
                assert stored.get("file_type") == "support_bundle"
                with rig.factory() as session:
                    file_row = session.execute(
                        text(
                            "SELECT f.id, f.sha256 FROM files f "
                            "JOIN file_links fl ON fl.file_id = f.id "
                            "WHERE fl.task_id = :id AND fl.purpose = 'output_support_bundle'"
                        ),
                        {"id": row.id},
                    ).one()
                    assert file_row[1] == stored.get("sha256")
                    _dump_row(session, row)
                # The encrypted artifact downloads and decrypts back to the zip.
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    download = client.get(f"{API}/files/{file_row[0]}/download", headers={"X-CSRF-Token": csrf})
                    assert download.status_code == 200
                    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
                        assert "manifest.json" in archive.namelist()
        finally:
            rig.close()


class TestDsmFirmwareSlices:
    def test_firmware_update_pat_fetch_version_readback_and_ticket_revoked(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(
            sim_url,
            upgrade_duration_seconds=0.4,
            upgrade_offline_seconds=0.6,
            upgrade_fetch_required=True,
        )
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-fw-nas")
                    device_id = onboarded["id"]
                task_id, file_id = _pat_upload_and_task_id(
                    rig, base_url, device_id, content=_pat_bytes(), idempotency="slice-nas-fw"
                )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",), timeout=90.0)
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                assert row.device_job_id is not None
                evidence = row.evidence or {}
                execution = evidence.get("execution") or {}
                verification = evidence.get("verification") or {}
                assert verification.get("readback_version") == PAT_VERSION
                # The ticket URL never lands in the plaintext task evidence.
                assert "device-file-access" not in json.dumps(evidence)
                assert "ticket_id" in execution
                assert execution.get("expected_version") == PAT_VERSION
                with rig.factory() as session:
                    revoked = session.execute(
                        text(
                            "SELECT revoked_at FROM device_file_tickets "
                            "WHERE created_by_task_id = :id AND purpose = 'firmware'"
                        ),
                        {"id": row.id},
                    ).scalar_one()
                    assert revoked is not None
                    _dump_row(session, row)
                snapshot = _sim_snapshot(sim_url)
                # The DSM "device" fetched the platform ticket URL and bumped.
                assert snapshot["firmware"] == PAT_VERSION
                assert len(snapshot["device_fetches"]) == 1
                assert "device-file-access" in str(snapshot["device_fetches"][0])
        finally:
            rig.close()

    def test_wrong_model_pat_fails_before_the_dispatch_fence(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-fw-wrong")
                    device_id = onboarded["id"]
                    file_id = _upload_file(
                        client,
                        csrf,
                        file_type="firmware",
                        filename="wrong-model.pat",
                        content=_pat_bytes(model=DS225PLUS_MODEL),
                    )
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    task_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="firmware.update",
                        parameters={"file_id": file_id},
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("failed",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "failed"
                assert row.error_code == "validation_failed"
                # Fails BEFORE the dispatch fence: the device was never called.
                assert row.dispatch_started_at is None
                with rig.factory() as session:
                    _dump_row(session, row)
        finally:
            rig.close()


class TestDsmSnmpSlices:
    def test_snmp_enable_and_disable_with_receiver_config(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(
            fresh_test_db_dsn, tmp_path, monkeypatch, sim_url, snmp_receiver=SNMP_RECEIVER
        )
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-snmp-nas")
                    device_id = onboarded["id"]
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    enable_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="snmp.configure",
                        parameters={"enabled": True},
                    )
                rig.rig.start_pool()
                try:
                    enable_row = rig.rig.wait_terminal(uuid.UUID(enable_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert enable_row.state == "succeeded"
                evidence = enable_row.evidence or {}
                verification = evidence.get("verification") or {}
                assert verification.get("readback_matches") is True
                assert verification.get("enabled") is True
                assert verification.get("receiver_address") == SNMP_RECEIVER
                snapshot = _sim_snapshot(sim_url)
                assert snapshot["snmp"] == {"enabled": True, "receiver_address": SNMP_RECEIVER}
                assert snapshot["traps"]  # the DSL test-trap emission record
                with rig.factory() as session:
                    _dump_row(session, enable_row)
                # Disable through a second task on the same device.
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    disable_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="snmp.configure",
                        parameters={"enabled": False},
                    )
                rig.rig.start_pool()
                try:
                    disable_row = rig.rig.wait_terminal(uuid.UUID(disable_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert disable_row.state == "succeeded"
                snapshot = _sim_snapshot(sim_url)
                assert snapshot["snmp"] == {"enabled": False, "receiver_address": ""}
                with rig.factory() as session:
                    _dump_row(session, disable_row)
        finally:
            rig.close()

    def test_snmp_without_platform_receiver_is_not_configured(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        # No snmp_trap_receiver_address in the deployment settings.
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-snmp-nocfg")
                    device_id = onboarded["id"]
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    task_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="snmp.configure",
                        parameters={"enabled": True},
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("failed",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "failed"
                assert row.error_code == "not_configured"
                assert row.dispatch_started_at is None  # pre-fence failure
                with rig.factory() as session:
                    _dump_row(session, row)
        finally:
            rig.close()


class TestDsmBackupSlice:
    def test_backup_status_refresh_persists_jobs_in_task_evidence(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-backup-nas")
                    device_id = onboarded["id"]
                with rig.factory() as session:
                    user = (
                        session.execute(text("SELECT id FROM users WHERE username = 'admin'")).scalar_one()
                    )
                    task_id = _seed_task(
                        session,
                        device_id=uuid.UUID(device_id),
                        requested_by=user,
                        capability_key="backup.status.refresh",
                        parameters={},
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                evidence = row.evidence or {}
                execution = evidence.get("execution") or {}
                jobs = execution.get("jobs")
                assert isinstance(jobs, list) and len(jobs) == 2
                assert {job["name"] for job in jobs} == {"Daily Backup", "Weekly Backup"}
                packages = execution.get("packages")
                assert isinstance(packages, list)
                unavailable = [p for p in packages if p.get("available") is False]
                assert unavailable and unavailable[0]["reason"] == "not_installed"
                with rig.factory() as session:
                    _dump_row(session, row)
        finally:
            rig.close()


class TestDsmLaunchSlice:
    def test_console_dsm_open_launch_descriptor_and_audit(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-launch-nas")
                    device_id = onboarded["id"]
                    created = client.post(
                        f"{API}/devices/{device_id}/launches",
                        json={"capability_key": "console.dsm.open"},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert created.status_code == 201, created.text
                    body = created.json()
                    launch_id = body["launch_id"]
                    consume_url = body["url"]
                    assert consume_url.endswith(f"/api/v1/launches/{launch_id}")
                    # JSON consume (browser GETs get the auto-redirect page):
                    # the descriptor targets the DSM origin and never carries
                    # credentials/platform tokens.
                    consumed = client.get(
                        f"{API}/launches/{launch_id}",
                        headers={"X-CSRF-Token": csrf, "Accept": "application/json"},
                    )
                    assert consumed.status_code == 200, consumed.text
                    descriptor = consumed.json()["descriptor"]
                    assert descriptor["kind"] == "url"
                    assert descriptor["url"] == f"http://127.0.0.1:{int(urlsplit(sim_url).port or 0)}"
                    assert "pass" not in descriptor["url"]
                    assert "token" not in descriptor["url"]
                    # Single-use: the second read is a uniform 404.
                    again = client.get(
                        f"{API}/launches/{launch_id}", headers={"X-CSRF-Token": csrf}
                    )
                    assert again.status_code == 404
                with rig.factory() as session:
                    protocol = session.execute(
                        text("SELECT protocol FROM launch_sessions WHERE id = :id"),
                        {"id": launch_id},
                    ).scalar_one()
                    assert protocol == "web"
                    actions = [
                        item[0]
                        for item in session.execute(
                            text("SELECT action FROM audit_logs WHERE resource_id = :id ORDER BY action"),
                            {"id": launch_id},
                        ).all()
                    ]
                    assert "launch.create" in actions
                    assert "launch.consume" in actions
        finally:
            rig.close()
