"""M4T5 M4 gate: NAS journey E2E over both certified model profiles (integration).

One comprehensive flow proving the WHOLE M4 NAS surface works through the
real platform (real API server + real PostgreSQL + real worker executor)
against the TEST-DEVICE DSM simulator on BOTH certified consumer profiles:

1. onboard a ``ds224plus``-profile journey device AND a ``ds225plus``-profile
   identity device (``nas.synology_dsm``); the saved device rows carry each
   profile's self-reported model/serial identity (DS224+ (simulated)/
   SIM-DS224P-0001 vs DS225+ (simulated)/SIM-DS225P-0001) — model-profile
   identity differences are honored end to end;
2. run health/metrics/logs collections on both profiles through the real
   claim/run path -> collection_runs succeeded; the metrics surface carries
   the NAS-MON-01..06 members with contract units; logs land as device
   events (NAS-MON-06); the ds225plus device rows stay on its own identity;
3. degrade the journey device with the crashed-disk knob
   (``storage_degraded``) -> a metrics run opens ``status.problem`` alerts
   (disk.status/disk.smart critical, storage_pool.status warning) while
   numeric bad_sectors/usage_percent stay data (ADR-025);
4. the full NAS-ACT-01 power.restart slice through the high-risk API chain
   (401 reauthentication_required until the reauth -> preview -> confirm ->
   worker) -> succeeded with reconnect-identity evidence (the DSM reconnects
   as the SAME device); the degraded alerts stay open (a reboot does not
   erase device state);
5. NAS-ACT-04 disk.smart_test.quick on a discovered disk through the
   medium-risk API chain -> succeeded with the device job tracked
   (device_job_id + waiting_device event);
6. NAS-ACT-05 backup.status.refresh -> succeeded with the jobs inventory
   persisted in the task evidence (unavailable packages explicit);
7. NAS-ACT-02 console.dsm.open via POST /devices/{id}/launches -> protocol
   ``web`` descriptor targeting the DSM origin, consumed exactly once
   (the second read is a uniform 404) with launch audit rows;
8. restore the health knobs -> two healthy metrics runs resolve the alerts
   (status.problem rows -> resolved, zero active).

Every step asserts its audit rows, task/collection evidence and psql rows.

Honest label: this module proves SIMULATOR-VERIFIED mechanics only. The DSM
simulator is a TEST DEVICE SIMULATOR (tests/simulators/dsm) and never 真机
evidence (HARDWARE_CERTIFICATION.md §3, ADR-018); the certification matrix
stays ``not_started`` and no hardware-support claim is made anywhere in this
file. DSM version/package differences between DS224+ and DS225+ require
target-model certification on real devices.
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
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.time import utcnow
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, login_csrf
from tests.e2e.test_worker_execution import WorkerRig
from tests.simulators.dsm.app import SimulatorConfig, create_simulator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "nas.synology_dsm"

# Simulator-authored identity strings (profile, model, serial, DSM version) —
# never real-device evidence; the module docstring says so.
DS224PLUS_PROFILE = "ds224plus"
DS224PLUS_MODEL = "DS224+ (simulated)"
DS224PLUS_SERIAL = "SIM-DS224P-0001"
DS225PLUS_PROFILE = "ds225plus"
DS225PLUS_MODEL = "DS225+ (simulated)"
DS225PLUS_SERIAL = "SIM-DS225P-0001"

JOURNEY_DEVICE_NAME = "journey-ds224plus"
IDENTITY_DEVICE_NAME = "identity-ds225plus"
OWNER = "m4t5-journey-worker"
# The devices endpoint uniqueness key is host-only
# (uq_devices_type_endpoint_adapter), so the two journey simulators boot on
# two distinct loopback hosts of the 127.0.0.0/8 range.
IDENTITY_SIM_HOST = "127.0.0.2"


def _port_of(url: str) -> int:
    parsed = urlsplit(url)
    assert parsed.port is not None
    return parsed.port


def hostname_of(url: str) -> str:
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    return parsed.hostname


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


@contextmanager
def _serve_simulator_on(host: str, config: SimulatorConfig | None = None) -> Iterator[str]:
    """Run the DSM simulator on ``host`` with an OS-assigned port.

    Two journey devices need two DISTINCT management endpoints: the devices
    table enforces ``(device_type, management_endpoint, adapter_key)``
    uniqueness and the endpoint key is host-only, so the second simulator
    boots on another loopback address (127.0.0.0/8 is loopback; the SSRF
    resolver monkeypatch below gates both into the probe resolution step).
    """
    server = uvicorn.Server(
        uvicorn.Config(
            create_simulator(config if config is not None else SimulatorConfig()),
            host=host,
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
        if not thread.is_alive():
            msg = "simulator server thread exited before startup"
            raise RuntimeError(msg)
        time.sleep(0.02)
    if not getattr(server, "started", False):
        msg = "simulator server did not start in time"
        raise RuntimeError(msg)
    sockets = server.servers[0].sockets if server.servers else []
    if not sockets:
        msg = "simulator server has no bound socket"
        raise RuntimeError(msg)
    port = sockets[0].getsockname()[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=15.0)
        gc.collect()


@contextmanager
def serve_journey_simulators() -> Iterator[tuple[str, str]]:
    """Two simulators on distinct loopback hosts (both TEST device simulators):
    the ds224plus journey device and the ds225plus identity device."""
    journey_cfg = SimulatorConfig(
        profile=DS224PLUS_PROFILE,
        restart_blip_seconds=0.6,
        smart_quick_duration_seconds=0.6,
    )
    identity_cfg = SimulatorConfig(profile=DS225PLUS_PROFILE)
    with (
        _serve_simulator_on(SIM_HOST, journey_cfg) as url_a,
        _serve_simulator_on(IDENTITY_SIM_HOST, identity_cfg) as url_b,
    ):
        yield url_a, url_b


def _allow_simulator_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gate ONLY the two loopback simulators into the probe resolution step.

    Each device row keeps its own simulator's host+port; the resolver maps
    every permitted device endpoint to that device's own simulator instance.
    """

    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, allowed_ports
        assert host in {SIM_HOST, IDENTITY_SIM_HOST}
        return ipaddress.ip_address(host), requested_port

    monkeypatch.setattr(DeviceEndpointPolicy, "resolve_endpoint", resolve)


def _keyring_from_file(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


def _print_evidence(label: str, evidence: object) -> None:
    print(f"\n=== M4T5-JOURNEY evidence: {label} ===")
    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))


class JourneyRig:
    """One journey environment: API app + worker rig over one fresh database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        sim_urls: tuple[str, str],
    ) -> None:
        del sim_urls
        _allow_simulator_resolution(monkeypatch)
        key_file = tmp_path / "credential_master.key"
        key_file.write_text("K" * 64, encoding="utf-8")
        session_file = tmp_path / "session_secret.txt"
        session_file.write_text("S" * 64, encoding="utf-8")
        self.settings = WardenSettings(
            postgres_dsn=fresh_test_db_dsn,
            app_env="development",
            public_url="http://localhost",
            _env_file=None,
            allowed_device_cidrs="127.0.0.0/8",
            credential_master_key_file=key_file,
            session_secret_file=session_file,
            operation_job_poll_interval_seconds=0.05,
        )
        self.app = create_app(self.settings)
        self.keyring = _keyring_from_file(self.settings)
        self.rig = WorkerRig(
            fresh_test_db_dsn,
            self.settings,
            owner=OWNER,
            keyring=self.keyring,
        )
        with self.rig.factory() as session:
            create_admin(session)

    def close(self) -> None:
        self.rig.close()
        engine = self.app.state.engine
        if engine is not None:
            engine.dispose()


def _onboard(
    client: TestClient,
    csrf: str,
    sim_url: str,
    *,
    name: str,
    expected_model: str,
    expected_serial: str,
) -> tuple[uuid.UUID, dict[str, object]]:
    probe = client.post(
        f"{API}/device-probes",
        json={
            "device_type": "synology_nas",
            "adapter_key": ADAPTER_KEY,
            "management_endpoint": hostname_of(sim_url),
            "port": _port_of(sim_url),
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, probe.text
    assert {stage["stage"] for stage in body["stages"]} == {
        "network",
        "tls",
        "auth",
        "identity",
        "capabilities",
    }
    discovery = body["discovery"]
    assert discovery["vendor"] == "Synology"
    assert discovery["model"] == expected_model
    assert discovery["serial_number"] == expected_serial
    created = client.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": "synology_nas",
            "adapter_key": ADAPTER_KEY,
            "management_endpoint": hostname_of(sim_url),
            "port": _port_of(sim_url),
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
            "enabled": True,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    view = created.json()
    assert view["readiness"] == "ready"
    assert view["enabled"] is True
    assert view["adapter_key"] == ADAPTER_KEY
    return uuid.UUID(view["id"]), discovery


def _run_collection(
    rig: JourneyRig,
    device_id: uuid.UUID,
    collection_type: str,
    scheduled_at: datetime.datetime,
) -> dict[str, object]:
    """One run through the real pipeline: insert scheduled row -> claim ->
    run_collection (claim and execute in separate sessions like the worker)."""
    from app.application.collection import run_collection
    from app.infrastructure.observation_store import claim_collection_run
    from app.models.observation import CollectionRun

    run_id: uuid.UUID | None = None
    with rig.rig.factory() as session:
        run = CollectionRun(
            device_id=device_id,
            collection_type=collection_type,
            scheduled_at=scheduled_at,
            state="scheduled",
            attempt_count=0,
        )
        session.add(run)
        session.commit()
        run_id = run.id
    assert run_id is not None
    with rig.rig.factory() as session:
        claimed = claim_collection_run(session, lease_owner=OWNER, lease_seconds=300)
        assert claimed is not None and claimed.id == run_id
        session.commit()
    with rig.rig.factory() as session:
        run_collection(session, run_id, settings=rig.settings, keyring=rig.keyring, now=utcnow())
        session.commit()
    with rig.rig.factory() as session:
        row = session.get(CollectionRun, run_id)
        assert row is not None
        result: dict[str, object] = {
            "run_id": str(row.id),
            "collection_type": row.collection_type,
            "state": row.state,
            "success_count": row.success_count,
            "failure_count": row.failure_count,
            "error_code": row.error_code,
        }
    assert result["state"] == "succeeded", result
    assert result["failure_count"] == 0, result
    return result


def _confirm_operation(
    client: TestClient,
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


def _device_row(rig: JourneyRig, device_id: uuid.UUID) -> dict[str, object]:
    with rig.rig.factory() as session:
        row = session.execute(
            text(
                "SELECT vendor, model, serial_number, readiness, enabled, reachability, health "
                "FROM devices WHERE id = :id"
            ),
            {"id": device_id},
        ).one()
        return dict(row._mapping)


def _metric_rows_by_key(
    rig: JourneyRig, device_id: uuid.UUID
) -> dict[tuple[str, str | None, str | None], dict[str, object]]:
    with rig.rig.factory() as session:
        rows = session.execute(
            text(
                "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, ml.quality, "
                "c.kind, c.native_id "
                "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                "WHERE ml.device_id = :id ORDER BY ml.metric_key, c.kind, c.native_id"
            ),
            {"id": device_id},
        ).all()
    by_key: dict[tuple[str, str | None, str | None], dict[str, object]] = {}
    for row in rows:
        mapped = dict(row._mapping)
        kind = mapped["kind"] if isinstance(mapped["kind"], str) else None
        native = mapped["native_id"] if isinstance(mapped["native_id"], str) else None
        by_key[(str(mapped["metric_key"]), kind, native)] = mapped
    return by_key


def _active_problem_rows(rig: JourneyRig, device_id: uuid.UUID) -> list[dict[str, object]]:
    with rig.rig.factory() as session:
        rows = session.execute(
            text(
                "SELECT rule_key, severity, evidence FROM alerts "
                "WHERE device_id = :id AND status = 'active' AND rule_key = 'status.problem' "
                "ORDER BY severity, rule_key"
            ),
            {"id": device_id},
        ).all()
        return [dict(row._mapping) for row in rows]


def _audit_actions(rig: JourneyRig, task_id: uuid.UUID) -> set[str]:
    with rig.rig.factory() as session:
        rows = session.execute(
            text("SELECT action FROM audit_logs WHERE task_id = :id"),
            {"id": task_id},
        ).all()
    return {str(row._mapping["action"]) for row in rows}


class TestNasJourneyE2E:
    def test_journey_ds224plus_and_ds225plus_profiles_through_the_platform(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with serve_journey_simulators() as (journey_sim_url, identity_sim_url):
            rig = JourneyRig(fresh_test_db_dsn, tmp_path, monkeypatch, (journey_sim_url, identity_sim_url))
            try:
                with TestClient(rig.app) as client:
                    response, csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    assert response.status_code == 200

                    # -- step 1: onboard BOTH certified model profiles --------
                    journey_id, journey_discovery = _onboard(
                        client,
                        csrf,
                        journey_sim_url,
                        name=JOURNEY_DEVICE_NAME,
                        expected_model=DS224PLUS_MODEL,
                        expected_serial=DS224PLUS_SERIAL,
                    )
                    identity_id, identity_discovery = _onboard(
                        client,
                        csrf,
                        identity_sim_url,
                        name=IDENTITY_DEVICE_NAME,
                        expected_model=DS225PLUS_MODEL,
                        expected_serial=DS225PLUS_SERIAL,
                    )
                    # The ds225plus profile records its own model/serial/DSM
                    # version, never the ds224plus identity.
                    row_journey = _device_row(rig, journey_id)
                    row_identity = _device_row(rig, identity_id)
                    assert row_journey["vendor"] == "Synology"
                    assert row_journey["model"] == DS224PLUS_MODEL
                    assert row_journey["serial_number"] == DS224PLUS_SERIAL
                    assert row_identity["vendor"] == "Synology"
                    assert row_identity["model"] == DS225PLUS_MODEL
                    assert row_identity["serial_number"] == DS225PLUS_SERIAL
                    assert row_identity["serial_number"] != row_journey["serial_number"]
                    assert row_journey["readiness"] == "ready" and row_journey["enabled"] is True
                    assert row_identity["readiness"] == "ready" and row_identity["enabled"] is True
                    assert journey_discovery["model"] == DS224PLUS_MODEL
                    assert identity_discovery["model"] == DS225PLUS_MODEL
                    _print_evidence(
                        "onboarded-both-profiles",
                        {
                            "ds224plus": {"device_id": str(journey_id), **row_journey},
                            "ds225plus": {"device_id": str(identity_id), **row_identity},
                        },
                    )
                    caps = client.get(f"{API}/devices/{journey_id}/capabilities")
                    assert caps.status_code == 200
                    cap_items = caps.json()["items"]
                    supported = {item["capability_key"] for item in cap_items if item["support_state"] == "supported"}
                    for key in (
                        "disk.status",
                        "disk.smart",
                        "storage_pool.status",
                        "temperature.system",
                        "fan.rpm",
                        "ups.status",
                        "connectivity.management",
                        "power.restart",
                        "console.dsm.open",
                        "disk.smart_test.quick",
                        "backup.status.refresh",
                    ):
                        assert key in supported

                    now = utcnow()

                    # -- step 2: health/metrics/logs collections, both models --
                    # Health runs are connectivity-only for NAS (never health
                    # evidence); the seeded devices.health stays unknown.
                    journey_health = _run_collection(rig, journey_id, "health", scheduled_at=now)
                    assert _device_row(rig, journey_id)["health"] == "unknown"
                    journey_metrics = _run_collection(
                        rig, journey_id, "metrics", scheduled_at=now + datetime.timedelta(seconds=1)
                    )
                    journey_logs = _run_collection(
                        rig, journey_id, "logs", scheduled_at=now + datetime.timedelta(seconds=2)
                    )
                    identity_health = _run_collection(
                        rig, identity_id, "health", scheduled_at=now + datetime.timedelta(seconds=3)
                    )
                    identity_metrics = _run_collection(
                        rig, identity_id, "metrics", scheduled_at=now + datetime.timedelta(seconds=4)
                    )
                    identity_logs = _run_collection(
                        rig, identity_id, "logs", scheduled_at=now + datetime.timedelta(seconds=5)
                    )
                    _print_evidence(
                        "collections-both-profiles",
                        {
                            "ds224plus": [
                                journey_health,
                                journey_metrics,
                                journey_logs,
                            ],
                            "ds225plus": [
                                identity_health,
                                identity_metrics,
                                identity_logs,
                            ],
                        },
                    )
                    assert _device_row(rig, journey_id)["reachability"] == "online"
                    assert _device_row(rig, journey_id)["health"] == "healthy"
                    assert _device_row(rig, identity_id)["reachability"] == "online"
                    assert _device_row(rig, identity_id)["health"] == "healthy"
                    by_key = _metric_rows_by_key(rig, journey_id)
                    assert by_key[("temperature.system", "sensor", "system")]["value_double"] == 41.0
                    assert by_key[("temperature.system", "sensor", "system")]["unit"] == "Cel"
                    assert by_key[("disk.status", "disk", "sata1")]["value_text"] == "ok"
                    assert by_key[("disk.smart", "disk", "sata1")]["value_text"] == "passed"
                    assert by_key[("storage_pool.status", "storage_pool", "pool1")]["value_text"] == "optimal"
                    assert by_key[("volume.usage_percent", "volume", "vol1")]["value_double"] == 37.5
                    assert by_key[("volume.usage_percent", "volume", "vol1")]["unit"] == "%"
                    assert by_key[("shared_folder.usage_percent", "shared_folder", "homes")]["value_double"] == 50.0
                    assert by_key[("fan.rpm", "fan", "1")]["value_double"] == 2100.0
                    assert by_key[("fan.rpm", "fan", "1")]["unit"] == "r/min"
                    assert by_key[("ups.status", None, None)]["value_text"] == "normal"
                    assert by_key[("connectivity.management", None, None)]["value_text"] == "true"
                    with rig.rig.factory() as session:
                        for device_id in (journey_id, identity_id):
                            events = session.execute(
                                text(
                                    "SELECT count(*), count(DISTINCT native_event_id) FROM device_events "
                                    "WHERE device_id = :id"
                                ),
                                {"id": device_id},
                            ).one()
                            assert tuple(events) == (24, 24)
                            errors = session.execute(
                                text("SELECT count(*) FROM collection_observation_errors WHERE device_id = :id"),
                                {"id": device_id},
                            ).scalar_one()
                            assert errors == 0
                    _print_evidence(
                        "metrics-healthy-ds224plus",
                        {"rows": sorted((str(k), v) for k, v in by_key.items())},
                    )

                    # -- step 3: degrade the journey device (crashed-disk knob)
                    _control(journey_sim_url, storage_degraded=True)
                    degraded = _run_collection(
                        rig, journey_id, "metrics", scheduled_at=now + datetime.timedelta(seconds=6)
                    )
                    assert _device_row(rig, journey_id)["health"] == "critical"
                    problem_rows = _active_problem_rows(rig, journey_id)
                    severities = {str(row["severity"]) for row in problem_rows}
                    assert severities == {"critical", "warning"}
                    evidence_keys = {
                        str(row["evidence"].get("metric_key"))
                        for row in problem_rows
                        if isinstance(row["evidence"], dict)
                    }
                    assert {"disk.status", "disk.smart", "storage_pool.status"} <= evidence_keys
                    # Numeric device data (bad sectors, usage) is NOT an alert
                    # (ADR-025); the 0-rpm/fan rows do not exist on this knob.
                    assert not (evidence_keys & {"disk.bad_sectors", "volume.usage_percent"})
                    degraded_rows = _metric_rows_by_key(rig, journey_id)
                    assert degraded_rows[("disk.bad_sectors", "disk", "sata2")]["value_double"] == 512
                    assert degraded_rows[("disk.bad_sectors", "disk", "sata2")]["quality"] == "good"
                    _print_evidence(
                        "alerts-opened-degraded",
                        {"problem_rows": problem_rows, "run": degraded},
                    )

                    # -- step 4: full power.restart slice (NAS-ACT-01) --------
                    blocked = client.post(
                        f"{API}/devices/{journey_id}/operation-previews",
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
                    restart_id = _confirm_operation(
                        client,
                        csrf,
                        str(journey_id),
                        capability_key="power.restart",
                        parameters={},
                        confirmation_text=JOURNEY_DEVICE_NAME,
                        idempotency_key="m4t5-journey-restart-0001",
                    )
                    rig.rig.start_pool()
                    try:
                        restart_row = rig.rig.wait_terminal(uuid.UUID(restart_id), states=("succeeded",))
                    finally:
                        rig.rig.stop_pool()
                    assert restart_row.state == "succeeded"
                    assert restart_row.verification_state == "passed"
                    assert restart_row.requirement_id == "NAS-ACT-01"
                    evidence = restart_row.evidence or {}
                    execution = evidence.get("execution") or {}
                    verification = evidence.get("verification") or {}
                    assert execution.get("action") == "restart"
                    assert execution.get("api") == "SYNO.Core.System"
                    assert verification.get("disconnect_observed") is True
                    identity_verified = verification.get("identity_verified") or {}
                    assert identity_verified.get("serial") == DS224PLUS_SERIAL
                    audit = _audit_actions(rig, uuid.UUID(restart_id))
                    assert audit >= {"operation.create", "operation.start", "operation.finish"}
                    with rig.rig.factory() as session:
                        finish = session.execute(
                            text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                            {"id": restart_row.id},
                        ).scalar_one()
                        assert finish == "succeeded"
                    snapshot = _sim_snapshot(journey_sim_url)
                    assert snapshot["power"] == "on"
                    assert snapshot["serial"] == DS224PLUS_SERIAL
                    _print_evidence(
                        "power-restart-succeeded",
                        {
                            "task_id": restart_id,
                            "state": restart_row.state,
                            "verification_state": restart_row.verification_state,
                            "execution": execution,
                            "verification": verification,
                            "audit_actions": sorted(audit),
                        },
                    )
                    # A reboot does not erase the degraded device state: the
                    # status.problem alerts stay open (same rows).
                    after_restart_rows = _active_problem_rows(rig, journey_id)
                    assert len(after_restart_rows) == len(problem_rows)
                    assert _device_row(rig, journey_id)["health"] == "critical"

                    # -- step 5: disk.smart_test.quick (NAS-ACT-04) -----------
                    smart_id = _confirm_operation(
                        client,
                        csrf,
                        str(journey_id),
                        capability_key="disk.smart_test.quick",
                        parameters={"disk_id": "sata1"},
                        confirmation_text=JOURNEY_DEVICE_NAME,
                        idempotency_key="m4t5-journey-smart-0001",
                    )
                    rig.rig.start_pool()
                    try:
                        smart_row = rig.rig.wait_terminal(uuid.UUID(smart_id), states=("succeeded",))
                    finally:
                        rig.rig.stop_pool()
                    assert smart_row.state == "succeeded"
                    assert smart_row.verification_state == "passed"
                    assert smart_row.requirement_id == "NAS-ACT-04"
                    assert smart_row.device_job_id is not None
                    smart_evidence = smart_row.evidence or {}
                    smart_verification = smart_evidence.get("verification") or {}
                    assert smart_verification.get("job_state") == "success"
                    with rig.rig.factory() as session:
                        states = [
                            item[0]
                            for item in session.execute(
                                text(
                                    "SELECT DISTINCT state FROM operation_task_events "
                                    "WHERE task_id = :id ORDER BY state"
                                ),
                                {"id": smart_row.id},
                            ).all()
                        ]
                        assert "waiting_device" in states
                        finish = session.execute(
                            text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                            {"id": smart_row.id},
                        ).scalar_one()
                        assert finish == "succeeded"
                    _print_evidence(
                        "smart-test-quick-succeeded",
                        {
                            "task_id": smart_id,
                            "state": smart_row.state,
                            "device_job_id": smart_row.device_job_id,
                            "verification": smart_verification,
                            "event_states": states,
                        },
                    )

                    # -- step 6: backup.status.refresh (NAS-ACT-05) ------------
                    backup_id = _confirm_operation(
                        client,
                        csrf,
                        str(journey_id),
                        capability_key="backup.status.refresh",
                        parameters={},
                        confirmation_text=JOURNEY_DEVICE_NAME,
                        idempotency_key="m4t5-journey-backup-0001",
                    )
                    rig.rig.start_pool()
                    try:
                        backup_row = rig.rig.wait_terminal(uuid.UUID(backup_id), states=("succeeded",))
                    finally:
                        rig.rig.stop_pool()
                    assert backup_row.state == "succeeded"
                    assert backup_row.verification_state == "passed"
                    assert backup_row.requirement_id == "NAS-ACT-05"
                    backup_evidence = backup_row.evidence or {}
                    backup_execution = backup_evidence.get("execution") or {}
                    jobs = backup_execution.get("jobs")
                    assert isinstance(jobs, list) and len(jobs) == 2
                    assert {job["name"] for job in jobs} == {"Daily Backup", "Weekly Backup"}
                    packages = backup_execution.get("packages")
                    assert isinstance(packages, list)
                    unavailable = [p for p in packages if p.get("available") is False]
                    assert unavailable and unavailable[0]["reason"] == "not_installed"
                    with rig.rig.factory() as session:
                        finish = session.execute(
                            text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                            {"id": backup_row.id},
                        ).scalar_one()
                        assert finish == "succeeded"
                    _print_evidence(
                        "backup-refresh-succeeded",
                        {
                            "task_id": backup_id,
                            "state": backup_row.state,
                            "jobs": jobs,
                            "packages": packages,
                        },
                    )

                    # -- step 7: console.dsm.open launch (NAS-ACT-02) ----------
                    created = client.post(
                        f"{API}/devices/{journey_id}/launches",
                        json={"capability_key": "console.dsm.open"},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert created.status_code == 201, created.text
                    launch_body = created.json()
                    launch_id = launch_body["launch_id"]
                    consume_url = launch_body["url"]
                    assert consume_url.endswith(f"/api/v1/launches/{launch_id}")
                    consumed = client.get(
                        f"{API}/launches/{launch_id}",
                        headers={"X-CSRF-Token": csrf, "Accept": "application/json"},
                    )
                    assert consumed.status_code == 200, consumed.text
                    descriptor = consumed.json()["descriptor"]
                    assert descriptor["kind"] == "url"
                    assert descriptor["url"] == (f"http://{hostname_of(journey_sim_url)}:{_port_of(journey_sim_url)}")
                    assert "pass" not in descriptor["url"]
                    assert "token" not in descriptor["url"]
                    again = client.get(f"{API}/launches/{launch_id}", headers={"X-CSRF-Token": csrf})
                    assert again.status_code == 404
                    with rig.rig.factory() as session:
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
                    _print_evidence(
                        "console-dsm-open-launch",
                        {
                            "launch_id": launch_id,
                            "protocol": protocol,
                            "descriptor": descriptor,
                            "audit_actions": actions,
                        },
                    )

                    # -- step 8: restore the health knobs -> alerts resolve ----
                    _control(journey_sim_url, storage_degraded=False)
                    for index in range(2):
                        _run_collection(
                            rig,
                            journey_id,
                            "metrics",
                            scheduled_at=now + datetime.timedelta(seconds=7 + index),
                        )
                    assert _device_row(rig, journey_id)["health"] == "healthy"
                    with rig.rig.factory() as session:
                        active = session.execute(
                            text("SELECT count(*) FROM alerts WHERE device_id = :id AND status = 'active'"),
                            {"id": journey_id},
                        ).scalar_one()
                        assert active == 0
                        resolved = session.execute(
                            text(
                                "SELECT count(*) FROM alerts "
                                "WHERE device_id = :id AND rule_key = 'status.problem' "
                                "AND status = 'resolved'"
                            ),
                            {"id": journey_id},
                        ).scalar_one()
                        assert resolved >= len(problem_rows)
                        runs = session.execute(
                            text(
                                "SELECT collection_type, state, count(*) AS n FROM collection_runs "
                                "WHERE device_id = :id GROUP BY collection_type, state "
                                "ORDER BY collection_type"
                            ),
                            {"id": journey_id},
                        ).all()
                        runs_map = {
                            f"{row._mapping['collection_type']}:{row._mapping['state']}": int(row._mapping["n"])
                            for row in runs
                        }
                        assert runs_map["health:succeeded"] == 1
                        assert runs_map["logs:succeeded"] == 1
                        assert runs_map["metrics:succeeded"] == 4
                    _print_evidence(
                        "restored-and-resolved",
                        {
                            "device": _device_row(rig, journey_id),
                            "resolved_problem_rows": resolved,
                            "collection_runs": runs_map,
                        },
                    )
                    # Both devices ended healthy; the ds225plus identity row
                    # still records its own model/serial (never the journey
                    # device's identity).
                    assert _device_row(rig, identity_id)["health"] == "healthy"
                    assert _device_row(rig, identity_id)["model"] == DS225PLUS_MODEL
                    assert _device_row(rig, identity_id)["serial_number"] == DS225PLUS_SERIAL
            finally:
                time.sleep(0.2)
                rig.close()


class TestNasJourneyDefinition:
    def test_journey_definitions_pin_the_two_model_profiles(self) -> None:
        """The module's profile rows stay the two certified certification
        units; the simulator identities never drift from what the journey
        asserts (a change here is a change to the M4T5 journey contract)."""
        from app.adapters.registry import ADAPTERS

        from tests.simulators.dsm.payloads import identity_of, profile_config

        assert ADAPTER_KEY in ADAPTERS
        ds224 = identity_of(profile_config(DS224PLUS_PROFILE))
        assert ds224["model"] == DS224PLUS_MODEL
        assert ds224["serial"] == DS224PLUS_SERIAL
        ds225 = identity_of(profile_config(DS225PLUS_PROFILE))
        assert ds225["model"] == DS225PLUS_MODEL
        assert ds225["serial"] == DS225PLUS_SERIAL
        assert ds225["firmware"] != ds224["firmware"]
