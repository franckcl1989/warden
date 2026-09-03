"""M3T3 platform slices: the real worker runs common Redfish operations
(SRV-ACT-01/02/04/05/06/07) against the test-device simulator (integration,
real PostgreSQL, real HTTP).

Four slices (per the M3T3 brief) run the FULL M3T3 boundary: the adapter
yields bytes/descriptors, the worker stores/encrypts/links artifacts, issues
device-pull tickets bound to device+file+purpose+expiry, persists inventory,
and revokes tickets on completion:

1. power.cycle via the high-risk API confirm chain (reauth -> preview ->
   confirm) -> pool executes -> succeeded with power read-back evidence;
2. virtual media: files-API ISO upload -> mount task (the simulator FETCHES
   the platform ticket URL) -> read-back verified -> unmount -> slot empty +
   ticket revoked;
3. support bundle: collect task -> encrypted artifact file row + file_link,
   hash verified, API download works;
4. firmware update (version read-back through the fetched image header) and
   asset.refresh (device serial/model/firmware + fru components).

The Warden API runs on a real localhost socket (uvicorn) so the SIMULATOR
(acting as the device) can pull ticket URLs; the SSRF policy is gated in via
the same loopback monkeypatch pattern as the M3T2 slice (production loopback
denial is covered by its own unit tests). The simulator is a TEST device
simulator, never hardware evidence.
"""

from __future__ import annotations

import datetime
import gc
import ipaddress
import json
import threading
import time
import uuid
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
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin
from tests.e2e.test_worker_execution import WorkerRig
from tests.task_factories import make_user

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "server.redfish"
OPERATOR_PASSWORD = "Op!pass-2026-Strong"


@pytest.fixture()
def sim_url() -> Iterator[str]:
    from tests.simulators.redfish.app import SimulatorConfig
    from tests.simulators.redfish.serving import serve_simulator

    with serve_simulator(SimulatorConfig(profile="healthy")) as url:
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


def _control(sim_url: str, **knobs: object) -> None:
    with httpx.Client(base_url=sim_url, timeout=10.0) as client:
        response = client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text


class PlatformRig:
    """One slice environment: real API server + worker rig over one database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        sim_url: str,
        *,
        owner: str = "m3t3-slice-worker",
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

    def sim_control(self, sim_url: str) -> dict[str, object]:
        with httpx.Client(base_url=sim_url, timeout=10.0) as client:
            response = client.get("/warden-sim/control")
            assert response.status_code == 200
            return response.json()

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
            "device_type": "server",
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
            "device_type": "server",
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


def _seed_task(
    db: Session,
    *,
    device_id: uuid.UUID,
    requested_by: uuid.UUID,
    capability_key: str,
    parameters: dict[str, object],
) -> uuid.UUID:
    from app.models.devices import Device
    from app.models.operation import OperationTask

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
        idempotency_key=f"m3t3-slice-{uuid.uuid4().hex[:16]}",
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
    return task.id


def _simulator_slot(sim_url: str, slot_id: str) -> dict[str, object]:
    with httpx.Client(base_url=sim_url, timeout=10.0) as client:
        login = client.post(
            "/redfish/v1/SessionService/Sessions",
            json={"UserName": SIM_USERNAME, "Password": SIM_PASSWORD},
        )
        assert login.status_code == 201
        token = login.headers["x-auth-token"]
        slot = client.get(f"/redfish/v1/Managers/1/VirtualMedia/{slot_id}", headers={"X-Auth-Token": token})
        assert slot.status_code == 200
        return slot.json()


class TestPowerCycleSlice:
    def test_high_risk_power_cycle_runs_through_the_worker(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, task_duration_seconds=0.05, power_blip_seconds=0.4)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url:
                with httpx.Client(base_url=base_url, timeout=20.0) as client:
                    csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    onboarded = _onboard(client, csrf, sim_url, "slice-power-srv")
                    device_id = onboarded["id"]
                    assert onboarded["adapter_key"] == ADAPTER_KEY
                    # Reauth is mandatory for high-risk confirms.
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
                        capability_key="power.cycle",
                        parameters={},
                        confirmation_text="slice-power-srv",
                        idempotency_key="slice-power-cycle-0001",
                    )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                assert row.dispatch_started_at is not None
                assert row.verification_state == "passed"
                evidence = row.evidence or {}
                execution = evidence.get("execution") or {}
                verification = evidence.get("verification") or {}
                assert execution.get("reset_type") == "ForceRestart"
                assert verification.get("succeeded") is True
                assert verification.get("transition_observed") is True
                with rig.factory() as session:
                    finish = session.execute(
                        text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                        {"id": row.id},
                    ).scalar_one()
                    assert finish == "succeeded"
                snapshot = rig.sim_control(sim_url)
                assert snapshot["system_power"] == "On"
        finally:
            rig.close()


class TestVirtualMediaSlice:
    def test_iso_upload_mount_verify_unmount_and_ticket_revoked(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, media_fetch_required=True)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            iso = b"\x00" * 4096 + b"WARDEN-BOOT-ISO-PAYLOAD"  # plain ISO-ish content
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=20.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                onboarded = _onboard(client, csrf, sim_url, "slice-media-srv")
                device_id = uuid.UUID(onboarded["id"])
                file_id = _upload_file(client, csrf, file_type="virtual_media", filename="boot.iso", content=iso)
                with rig.factory() as session:
                    user = make_user(session, index=1)
                    mount_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="virtual_media.mount",
                        parameters={"file_id": file_id, "media_kind": "iso"},
                    )
                    rig.rig.start_pool()
                    try:
                        mount_row = rig.rig.wait_terminal(
                            mount_task, states=("succeeded", "failed", "verification_required", "timed_out")
                        )
                    finally:
                        rig.rig.stop_pool()
                    assert mount_row.state == "succeeded", (
                        mount_row.state,
                        mount_row.error_code,
                        mount_row.error_detail,
                        mount_row.evidence,
                        rig.sim_control(sim_url),
                    )
                mount_evidence = mount_row.evidence or {}
                slot_id = str((mount_evidence.get("execution") or {}).get("slot_id"))
                assert slot_id in ("1", "2")

                with rig.factory() as session:
                    link = session.execute(
                        text("SELECT purpose FROM file_links WHERE task_id = :id AND device_id = :dev"),
                        {"id": mount_row.id, "dev": device_id},
                    ).all()
                    assert {row[0] for row in link} == {"input_virtual_media"}
                    ticket = session.execute(
                        text(
                            "SELECT id, purpose, revoked_at FROM device_file_tickets "
                            "WHERE created_by_task_id = :id AND device_id = :dev"
                        ),
                        {"id": mount_row.id, "dev": device_id},
                    ).one()
                    assert ticket[1] == "virtual_media"
                    assert ticket[2] is None
                    ticket_id = ticket[0]
                fetched = rig.sim_control(sim_url).get("device_fetches") or []
                assert any(str(ticket_id) in str(url) for url in fetched), "simulator never fetched the ticket URL"

                slot = _simulator_slot(sim_url, slot_id)
                assert slot["Inserted"] is True
                assert str(ticket_id) in str(slot["Image"])

                with rig.factory() as session:
                    unmount_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="virtual_media.unmount",
                        parameters={"slot_id": slot_id},
                    )
                rig.rig.start_pool()
                try:
                    unmount_row = rig.rig.wait_terminal(unmount_task, states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert unmount_row.state == "succeeded"
                slot = _simulator_slot(sim_url, slot_id)
                assert slot["Inserted"] is False
                with rig.factory() as session:
                    ticket = session.execute(
                        text("SELECT revoked_at FROM device_file_tickets WHERE id = :id"),
                        {"id": ticket_id},
                    ).one()
                    assert ticket[0] is not None
        finally:
            rig.close()


class TestSupportBundleSlice:
    def test_support_bundle_artifact_encrypted_linked_and_downloadable(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=20.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                onboarded = _onboard(client, csrf, sim_url, "slice-bundle-srv")
                device_id = uuid.UUID(onboarded["id"])
                with rig.factory() as session:
                    user = make_user(session, index=2)
                    bundle_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="logs.support_bundle.collect",
                        parameters={},
                    )
                rig.rig.start_pool()
                try:
                    bundle_row = rig.rig.wait_terminal(bundle_task, states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert bundle_row.state == "succeeded"
                with rig.factory() as session:
                    file_row = session.execute(
                        text(
                            "SELECT f.id, f.file_type, f.sha256, f.encrypted, f.status, "
                            "f.mime_type, f.size_bytes "
                            "FROM files f JOIN file_links fl ON fl.file_id = f.id "
                            "WHERE fl.task_id = :id AND fl.purpose = 'output_support_bundle'"
                        ),
                        {"id": bundle_row.id},
                    ).one()
                    assert file_row[1] == "support_bundle"
                    assert file_row[2] is not None and len(file_row[2]) == 64
                    assert file_row[3] is True  # encrypted at rest
                    assert file_row[4] == "ready"
                    assert file_row[6] > 0
                    artifact_file_id = file_row[0]
                    evidence = bundle_row.evidence or {}
                    stored = (evidence.get("execution") or {}).get("artifact_stored") or {}
                    assert stored.get("sha256") == file_row[2]
                    assert stored.get("encrypted") is True
                download = client.get(f"{API}/files/{artifact_file_id}/download")
                assert download.status_code == 200
                assert download.content.startswith(b"PK")
        finally:
            rig.close()


class TestFirmwareAndAssetSlices:
    def test_firmware_update_version_readback(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        _control(sim_url, task_duration_seconds=0.05, update_fetch_required=True)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=20.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                onboarded = _onboard(client, csrf, sim_url, "slice-fw-srv")
                device_id = uuid.UUID(onboarded["id"])
                model = onboarded["model"]
                header = (
                    b"WARDEN-SIM-FW "
                    + json.dumps({"model": model, "target": "BMC", "version": "SIM-BMC-1.1.0"}).encode("utf-8")
                    + b"\n"
                )
                file_id = _upload_file(
                    client,
                    csrf,
                    file_type="firmware",
                    filename="sim-bmc-1.1.0.fw",
                    content=header + b"\x00" * 2048,
                )
                with rig.factory() as session:
                    user = make_user(session, index=3)
                    update_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="firmware.update",
                        parameters={"file_id": file_id, "target_id": "BMC"},
                    )
                rig.rig.start_pool()
                try:
                    update_row = rig.rig.wait_terminal(
                        update_task, states=("succeeded", "failed", "verification_required", "timed_out")
                    )
                finally:
                    rig.rig.stop_pool()
                assert update_row.state == "succeeded", (
                    update_row.state,
                    update_row.error_code,
                    update_row.error_detail,
                    update_row.evidence,
                )
                verification = (update_row.evidence or {}).get("verification") or {}
                assert verification.get("readback_version") == "SIM-BMC-1.1.0"
                snapshot = rig.sim_control(sim_url)
                assert snapshot["versions"]["BMC"] == "SIM-BMC-1.1.0"
                with rig.factory() as session:
                    # The update ticket was revoked at the terminal transition.
                    ticket = session.execute(
                        text("SELECT revoked_at FROM device_file_tickets WHERE created_by_task_id = :id"),
                        {"id": update_row.id},
                    ).one()
                    assert ticket[0] is not None
                # firmware.query refreshes the persisted device row with
                # the bumped version and records the inventory items.
                with rig.factory() as session:
                    query_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="firmware.query",
                        parameters={},
                    )
                rig.rig.start_pool()
                try:
                    query_row = rig.rig.wait_terminal(query_task, states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert query_row.state == "succeeded"
                with rig.factory() as session:
                    device = session.execute(
                        text("SELECT firmware_version FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert device[0] == "SIM-BMC-1.1.0"
                    firmware_rows = session.execute(
                        text(
                            "SELECT native_id, properties FROM components "
                            "WHERE device_id = :id AND kind = 'firmware' AND retired_at IS NULL "
                            "ORDER BY native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    assert {row[0]: row[1] for row in firmware_rows} == {
                        "BMC": {"version": "SIM-BMC-1.1.0"},
                        "BIOS": {"version": "SIM-BIOS-2.0"},
                    }
        finally:
            rig.close()

    def test_asset_refresh_updates_device_and_fru_components(
        self, sim_url: str, fresh_test_db_dsn: str, tmp_path, monkeypatch
    ) -> None:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=20.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                onboarded = _onboard(client, csrf, sim_url, "slice-asset-srv")
                device_id = uuid.UUID(onboarded["id"])
                with rig.factory() as session:
                    # Wipe the identity rows: asset.refresh must restore them.
                    session.execute(
                        text("UPDATE devices SET serial_number = NULL, model = NULL WHERE id = :id"),
                        {"id": device_id},
                    )
                    session.commit()
                    user = make_user(session, index=4)
                    asset_task = _seed_task(
                        session,
                        device_id=device_id,
                        requested_by=user.id,
                        capability_key="asset.refresh",
                        parameters={},
                    )
                rig.rig.start_pool()
                try:
                    asset_row = rig.rig.wait_terminal(asset_task, states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert asset_row.state == "succeeded"
                with rig.factory() as session:
                    device = session.execute(
                        text("SELECT serial_number, model, firmware_version FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert device[0] == "WARDEN-SIM-0001"
                    assert device[1] == "Warden SimServer 1U (simulated)"
                    assert device[2] == "SIM-BMC-1.0.0"
                    fru = session.execute(
                        text(
                            "SELECT kind, native_id, name, properties FROM components "
                            "WHERE device_id = :id AND kind = 'fru' AND retired_at IS NULL "
                            "ORDER BY native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    assert [row[1] for row in fru] == ["chassis-1", "manager-1"]
                    assert fru[0][3].get("part_number") == "SIM-CH-1U-A"
                    assert fru[1][3].get("firmware_version") == "SIM-BMC-1.0.0"
        finally:
            rig.close()


def _port_of(url: str) -> int:
    return int(urlsplit(url).port or 0)
