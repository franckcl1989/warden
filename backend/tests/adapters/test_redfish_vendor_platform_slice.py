"""M3T5 Dell platform slice: a server.dell_idrac device over the real
platform (integration, real PostgreSQL, real HTTP).

End-to-end with the Dell iDRAC overlay against the TEST-DEVICE simulator's
``dell`` vendor profile: probe identity gate accept -> save ready (device row
carries the Dell self-reported identity) -> a real collection run produces
metric_latest rows (vendor-namespaced OEM members) -> a power.cycle task runs
through the API confirm chain + worker pool with the Dell certified ResetType
pin (ForceRestart) 鈥?the simulator RECORDS the ResetType device-side
(control snapshot ``last_system_resets``) and the task succeeds with
verification passed.

The simulator is a TEST DEVICE SIMULATOR, never 鐪熸満 evidence
(HARDWARE_CERTIFICATION.md 搂3): the certification matrix stays
``not_started`` 鈥?this slice only proves the overlay plumbing.
"""

from __future__ import annotations

import gc
import ipaddress
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from app.application.collection import run_collection
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.observation_store import claim_collection_run
from app.infrastructure.time import utcnow
from app.main import create_app
from sqlalchemy import create_engine, text

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin
from tests.e2e.test_worker_execution import WorkerRig
from tests.simulators.redfish.app import SimulatorConfig
from tests.simulators.redfish.serving import serve_simulator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "server.dell_idrac"
OPERATOR_PASSWORD = "Op!pass-2026-Strong"


@pytest.fixture()
def sim_url() -> Iterator[str]:
    with serve_simulator(SimulatorConfig(profile="healthy", vendor="dell")) as url:
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
        return response.json()


class PlatformRig:
    """One slice environment: real API server + worker rig over one database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        sim_url: str,
    ) -> None:
        port = int(urlsplit(sim_url).port or 0)
        _allow_simulator_resolution(monkeypatch, port)
        key_file = tmp_path / "credential_master.key"
        key_file.write_text("K" * 64, encoding="utf-8")
        session_file = tmp_path / "session_secret.txt"
        session_file.write_text("S" * 64, encoding="utf-8")
        self.settings = WardenSettings(
            postgres_dsn=fresh_test_db_dsn,
            app_env="development",
            public_url="http://localhost",
            _env_file=None,
            allowed_device_cidrs=f"{SIM_HOST}/32",
            credential_master_key_file=key_file,
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
            owner="m3t5-dell-slice-worker",
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
    discovery = body["discovery"]
    assert discovery["vendor"] == "Dell Inc."
    assert discovery["model"] == "PowerEdge R760"
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
    confirmation_text: str,
    idempotency_key: str,
) -> str:
    preview = client.post(
        f"{API}/devices/{device_id}/operation-previews",
        json={"capability_key": "power.cycle", "parameters": {}},
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


def _print_evidence(label: str, evidence: dict[str, object]) -> None:
    import json

    print(f"\n=== M3T5-DELL-E2E evidence: {label} ===")
    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))



class TestDellPlatformSlice:
    def test_onboard_collect_and_dell_power_cycle_mapping(
        self,
        sim_url: str,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch,
    ) -> None:
        _control(sim_url, task_duration_seconds=0.05, power_blip_seconds=0.4)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=20.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                onboarded = _onboard(client, csrf, sim_url, "slice-dell-idrac")
                device_id = uuid.UUID(onboarded["id"])
                assert onboarded["adapter_key"] == ADAPTER_KEY
                assert onboarded["readiness"] == "ready"
                assert onboarded["enabled"] is True
                caps = client.get(f"{API}/devices/{device_id}/capabilities")
                assert caps.status_code == 200
                cap_items = caps.json()["items"]
                assert len(cap_items) == 31
                assert all(item["support_state"] == "supported" for item in cap_items)
                assert all(item["discovery_method"] == ADAPTER_KEY for item in cap_items)

                with rig.factory() as session:
                    device = session.execute(
                        text("SELECT vendor, model, serial_number, firmware_version FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    identity = dict(device._mapping)
                    _print_evidence("onboarded-identity", identity)
                    assert identity["vendor"] == "Dell Inc."
                    assert identity["model"] == "PowerEdge R760"

                # Real collection run -> metric_latest rows (Oem.Dell members).
                with rig.factory() as session:
                    from app.models.observation import CollectionRun

                    run = CollectionRun(
                        device_id=device_id,
                        collection_type="metrics",
                        scheduled_at=utcnow(),
                        state="scheduled",
                        attempt_count=0,
                    )
                    session.add(run)
                    session.commit()
                    run_id = run.id
                with rig.factory() as session:
                    claimed = claim_collection_run(
                        session, lease_owner="m3t5-dell-slice-worker", lease_seconds=300
                    )
                    assert claimed is not None and claimed.id == run_id
                    session.commit()
                with rig.factory() as session:
                    run_collection(session, run_id, settings=rig.settings, keyring=rig.keyring, now=utcnow())
                    session.commit()

                with rig.factory() as session:
                    run = session.execute(
                        text("SELECT state, success_count, failure_count FROM collection_runs WHERE id = :id"),
                        {"id": run_id},
                    ).one()
                    assert dict(run._mapping)["state"] == "succeeded"
                    latest = session.execute(
                        text(
                            "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, "
                            "c.kind, c.native_id "
                            "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                            "WHERE ml.device_id = :id AND ml.metric_key IN "
                            "('health.overall','memory.ecc_errors','drive.smart','raid.status',"
                            "'indicator.led') ORDER BY ml.metric_key, c.kind, c.native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    evidence_rows = [dict(row._mapping) for row in latest]
                    _print_evidence("metrics-after-collect", {"rows": evidence_rows})
                    by_key: dict[tuple[str, str | None, str | None], dict[str, object]] = {}
                    for row in latest:
                        mapped = dict(row._mapping)
                        by_key[
                            (
                                str(mapped["metric_key"]),
                                mapped["kind"] if isinstance(mapped["kind"], str) else None,
                                mapped["native_id"] if isinstance(mapped["native_id"], str) else None,
                            )
                        ] = mapped
                    assert by_key[("health.overall", None, None)]["value_text"] == "healthy"
                    assert by_key[("memory.ecc_errors", "memory", "DIMM0")]["value_double"] == 3
                    assert by_key[("memory.ecc_errors", "memory", "DIMM0")]["unit"] == "1"
                    assert by_key[("drive.smart", "drive", "sda")]["value_text"] == "passed"
                    assert by_key[("raid.status", "raid", "RAID6_1")]["value_text"] == "optimal"

                # High-risk power.cycle through the real confirm chain + pool.
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
                    str(device_id),
                    confirmation_text="slice-dell-idrac",
                    idempotency_key="slice-dell-cycle-0001",
                )
            rig.rig.start_pool()
            try:
                row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
            finally:
                rig.rig.stop_pool()
            assert row.state == "succeeded"
            assert row.verification_state == "passed"
            execution = (row.evidence or {}).get("execution") or {}
            assert execution.get("reset_type") == "ForceRestart"
            assert "iDRAC" in str(execution.get("mapping"))
            verification = (row.evidence or {}).get("verification") or {}
            assert verification.get("succeeded") is True
            snapshot = rig.sim_control(sim_url)
            assert snapshot["last_system_resets"] == ["ForceRestart"]
            assert snapshot["system_power"] == "On"
            with rig.factory() as session:
                audit = session.execute(
                    text(
                        "SELECT action, count(*) AS n FROM audit_logs WHERE task_id = :id GROUP BY action"
                    ),
                    {"id": row.id},
                ).all()
                _print_evidence("task-audit", {"audit": [dict(r._mapping) for r in audit]})
                assert {str(r._mapping["action"]) for r in audit} >= {
                    "operation.create",
                    "operation.start",
                    "operation.finish",
                }
        finally:
            rig.close()
