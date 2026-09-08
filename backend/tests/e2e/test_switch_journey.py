"""M5T6 M5 gate: switch journey E2E over core + access simulator profiles (integration).

One comprehensive flow proving the WHOLE M5 Huawei-switch surface works through
the real platform (real API server + real PostgreSQL + real worker executor +
the real ingest receivers) against the TEST-DEVICE switch simulators (SNMP
agent + VRP SSH server) on BOTH certified-profile kinds:

1. onboard a core-profile (S5732-H48XUM2CC, ``switch.huawei_vrp_core``) AND an
   access-profile (S5735-L48P4S-A1, ``switch.huawei_vrp_access``) device with
   SNMPv3 + SSH credentials; the SSH host-key fingerprint is CAPTURED at the
   probe (first-connect capture mode reports the actual device key) and then
   pinned into the saved device config — automation never first-connects;
2. run metrics collections on both profiles through the real claim/run path:
   the FIRST run carries honest per-port ObservationErrors for the bps rates
   (cache miss — never fabricated), the SECOND run produces in_bps/out_bps
   rows with the exact derived rate (quality good) for every port;
3. degrade the core device with the fan-fault knob -> one metrics run opens a
   ``status.problem`` critical alert (fan.status) and flips devices.health;
4. send a syslog port-flap sequence to the real ingest receiver from a
   declared event-source IP -> attributed ``event.port_flap`` device_events
   rows for the core switch (CORE-MON-06), duplicate line deduplicated;
5. CORE-ACT-02 ``interface.admin.set`` on a discovered port through the
   high-risk API chain (401 reauthentication_required until the reauth ->
   preview -> confirm -> worker) -> succeeded with the admin-state readback;
   a follow-up metrics run mirrors the CLI change in the monitored data;
6. ACCESS-ACT-03 ``poe.port.set`` cycle (off_seconds 5) -> succeeded with
   the off -> on transition proof; the follow-up metrics runs mirror the
   operated state in the monitored PoE data;
7. CORE-ACT-05 config.backup -> encrypted artifact row, then config.restore
   of that very backup (high-risk chain) -> succeeded with the normalized
   config-fingerprint round trip; CORE-ACT-04 logs.diagnostic.collect ->
   encrypted artifact with the CLI completion marker;
8. CORE-ACT-03 console.ssh.open -> one-time terminal ticket, the WebSocket
   session opens (protocol ssh), a ``display version`` round trip returns the
   device banner, POST /terminal/sessions/{id}/close closes the session
   (user_closed) with audit rows; terminal content never leaves the WS;
9. restore the fan knob -> two healthy metrics runs resolve the alerts
   (status.problem rows -> resolved, zero active on the core device).

Every step asserts its audit rows, task/collection evidence and psql rows.

Honest label: this module proves SIMULATOR-VERIFIED mechanics only. The switch
simulators are TEST DEVICE SIMULATORS (tests/simulators/switch,
tests/simulators/vrp) and never 真机 evidence (HARDWARE_CERTIFICATION.md §3,
ADR-018); all Huawei OIDs/CLI templates are [sim] DSL until vendor MIB/command
references are reachable at certification time. The certification matrix stays
``not_started`` and no hardware-support claim is made anywhere in this file.
The S5731S-S48P4X-A second core target needs its own real-device certification
like every other target; this journey exercises the S5732-H48XUM2CC and
S5735-L48P4S-A1 profiles only.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import gc
import ipaddress
import json
import re
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.time import utcnow
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.websockets import WebSocketDisconnect

from tests.adapters.huawei.conftest import SIM_HOST, V3_AUTH_KEY, V3_PRIV_KEY, V3_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, login_csrf
from tests.e2e.test_worker_execution import WorkerRig
from tests.simulators.switch.agent import AgentConfig, AgentCredential, SwitchAgent
from tests.simulators.switch.emitters import vrp_link_state_line
from tests.simulators.switch.hosting import running_agent
from tests.simulators.switch.profiles import profile_by_key
from tests.simulators.vrp.device import SSH_PASSWORD, SSH_USERNAME
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
WS_ORIGIN = "http://localhost"
UTC = datetime.UTC

# Switch-agent counter step (octets per read): one 64-bit HC read per port per
# metrics pass -> the M5T2 platform slice proves the exact derived rate
# STEP * 8 / 60 bit/s for two runs 60 s apart in request time.
STEP = 125_000

# Simulator-authored identity rows (profiles in tests/simulators/switch) —
# never real-device evidence; the module docstring says so.
CORE_PROFILE_KEY = "core_s5732"
CORE_MODEL = "S5732-H48XUM2CC"
CORE_FW = "V200R021C10SPC600"
ACCESS_PROFILE_KEY = "access_s5735"
ACCESS_MODEL = "S5735-L48P4S-A1"
ACCESS_FW = "V200R019C10SPC600"

CORE_ADAPTER_KEY = "switch.huawei_vrp_core"
ACCESS_ADAPTER_KEY = "switch.huawei_vrp_access"

CORE_DEVICE_NAME = "journey-core-s5732"
ACCESS_DEVICE_NAME = "journey-access-s5735"
OWNER = "m5t6-journey-worker"

# Both journey simulators run on the loopback host (device endpoint uniqueness
# key is (device_type, management_endpoint, adapter_key) — the two profiles
# differ in both, so 127.0.0.1 is fine). The core device additionally declares
# ``event_source_ips`` so the syslog flap datagrams can be attributed UNIQUELY
# (a sender bound to 127.0.0.9; the 127.0.0.1 peer would be ambiguous between
# the two onboarded switches).
FLAP_SOURCE_IP = "127.0.0.9"

_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}={0,2}")


@dataclass(frozen=True)
class SimPair:
    """One journey device's two protocol faces (SNMP agent + VRP SSH sim)."""

    profile_key: str
    model: str
    firmware: str
    snmp_port: int
    ssh_port: int
    agent: SwitchAgent
    vrp_fingerprint: str
    vrp_device: object


@contextmanager
def _boot_snmp_agent(profile_key: str) -> Iterator[tuple[SwitchAgent, int]]:
    """Boot one switch SNMP agent (real UDP, OS-assigned port)."""
    config = AgentConfig(
        profile=profile_by_key(profile_key),
        v3_user=AgentCredential(username=V3_USERNAME, auth_key=V3_AUTH_KEY, privacy_key=V3_PRIV_KEY),
    )
    agent = SwitchAgent(config)
    with running_agent(agent) as started:
        assert started.port is not None and started.port > 0
        yield started, int(started.port)


@contextmanager
def serve_journey_sims() -> Iterator[tuple[SimPair, SimPair]]:
    """Boot both journey devices: core S5732 + access S5735 on 127.0.0.1.

    Each device = one SNMP agent (UDP) + one VRP SSH server with its own
    per-boot host key; all four listeners sit on distinct OS-assigned ports
    (the two TEST DEVICE SIMULATOR faces of each virtual switch never share
    state — the journey mirrors CLI-side changes into the SNMP agent where a
    follow-up collect must prove the monitored data follows the operation).
    """
    with (
        _boot_snmp_agent(CORE_PROFILE_KEY) as (core_agent, core_snmp_port),
        running_vrp_server(CORE_PROFILE_KEY) as core_vrp,
    ):
        core_vrp.device.knobs.restart_blip_seconds = 0.8
        with (
            _boot_snmp_agent(ACCESS_PROFILE_KEY) as (access_agent, access_snmp_port),
            running_vrp_server(ACCESS_PROFILE_KEY) as access_vrp,
        ):
            core = SimPair(
                profile_key=CORE_PROFILE_KEY,
                model=CORE_MODEL,
                firmware=CORE_FW,
                snmp_port=core_snmp_port,
                ssh_port=int(core_vrp.port),
                agent=core_agent,
                vrp_fingerprint=core_vrp.host_fingerprint,
                vrp_device=core_vrp.device,
            )
            access = SimPair(
                profile_key=ACCESS_PROFILE_KEY,
                model=ACCESS_MODEL,
                firmware=ACCESS_FW,
                snmp_port=access_snmp_port,
                ssh_port=int(access_vrp.port),
                agent=access_agent,
                vrp_fingerprint=access_vrp.host_fingerprint,
                vrp_device=access_vrp.device,
            )
            yield core, access


def _allow_simulator_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gate the loopback simulator hosts into the probe resolution step.

    The SSRF policy itself denies loopback; the monkeypatch maps the literal
    management host back to itself with the requested port (identical
    technique to the M2/M3/M4/M5 platform slices).
    """

    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, allowed_ports
        assert host == SIM_HOST
        return ipaddress.ip_address(host), requested_port

    monkeypatch.setattr(DeviceEndpointPolicy, "resolve_endpoint", resolve)


def _keyring_from_file(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


def _print_evidence(label: str, evidence: object) -> None:
    print(f"\n=== M5T6-JOURNEY evidence: {label} ===")
    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))


class JourneyRig:
    """One journey environment: API app + worker rig over one fresh database."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _allow_simulator_resolution(monkeypatch)
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
            _env_file=None,
            allowed_device_cidrs="127.0.0.0/8",
            credential_master_key_file=key_file,
            file_master_key_file=file_key_file,
            session_secret_file=session_file,
            file_store_root=tmp_path / "files",
            operation_job_poll_interval_seconds=0.05,
            ingest_bind_host="127.0.0.1",
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


def _snmp_credentials() -> dict[str, object]:
    return {
        "snmp": {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY},
        "ssh": {"username": SSH_USERNAME, "password": SSH_PASSWORD},
    }


def _probe_and_onboard(
    client: TestClient,
    csrf: str,
    *,
    name: str,
    device_type: str,
    adapter_key: str,
    sim: SimPair,
    event_source_ips: list[str] | None = None,
) -> tuple[uuid.UUID, str]:
    """Probe (SSH fingerprint CAPTURE, then pinned) and save one switch.

    Returns ``(device_id, captured_fingerprint)``. The first probe runs in
    first-connect capture mode (no pinned key): the ssh stage reports the
    ACTUAL device key the operator must pin — automation never first-connects
    (SECURITY.md §8). The second probe pins exactly that key and its token is
    the one the device save consumes (the token binds the full config
    fingerprint incl. the pinned key).
    """
    base_config: dict[str, object] = {
        "snmp_version": "v3",
        "port": sim.snmp_port,
        "ssh_port": sim.ssh_port,
    }
    if event_source_ips:
        base_config["event_source_ips"] = event_source_ips

    def probe(config: dict[str, object]) -> object:
        response = client.post(
            f"{API}/device-probes",
            json={
                "device_type": device_type,
                "adapter_key": adapter_key,
                "management_endpoint": SIM_HOST,
                "connection_config": config,
                "credentials": _snmp_credentials(),
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True, body
        return body

    captured = probe(dict(base_config))
    stage_detail = {
        stage["stage"]: stage.get("detail") or ""
        for stage in captured["stages"]
        if stage["stage"] in ("ssh", "identity")
    }
    ssh_detail = stage_detail.get("ssh", "")
    assert "首次连接" in ssh_detail, ssh_detail
    match = _FINGERPRINT_RE.search(ssh_detail)
    assert match is not None, f"ssh stage did not report the actual key: {ssh_detail}"
    captured_fingerprint = match.group(0)
    assert captured_fingerprint == sim.vrp_fingerprint
    discovery = captured["discovery"]
    assert discovery["vendor"] == "Huawei"
    assert discovery["model"] == sim.model
    assert discovery["firmware_version"] == sim.firmware

    pinned_config = dict(base_config)
    pinned_config["ssh_host_fingerprint"] = captured_fingerprint
    pinned = probe(pinned_config)
    pinned_ssh = {stage["stage"]: stage for stage in pinned["stages"] if stage["stage"] == "ssh"}["ssh"]
    assert pinned_ssh["ok"] is True
    assert captured_fingerprint in str(pinned_ssh.get("detail") or "")

    created = client.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": device_type,
            "adapter_key": adapter_key,
            "management_endpoint": SIM_HOST,
            "connection_config": pinned_config,
            "credentials": _snmp_credentials(),
            "enabled": True,
            "probe_token": pinned["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    view = created.json()
    assert view["readiness"] == "ready"
    assert view["enabled"] is True
    assert view["adapter_key"] == adapter_key
    assert view["model"] == sim.model
    assert view["firmware_version"] == sim.firmware
    return uuid.UUID(view["id"]), captured_fingerprint


def _capability_states(client: TestClient, device_id: uuid.UUID) -> dict[str, str]:
    response = client.get(f"{API}/devices/{device_id}/capabilities")
    assert response.status_code == 200
    items = response.json()["items"]
    return {item["capability_key"]: item["support_state"] for item in items}


def _run_collection(
    rig: JourneyRig,
    device_id: uuid.UUID,
    collection_type: str,
    scheduled_at: datetime.datetime,
    *,
    request_now: datetime.datetime,
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
        run_collection(session, run_id, settings=rig.settings, keyring=rig.keyring, now=request_now)
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
    return result


def _reauthenticate(client: TestClient, csrf: str) -> None:
    response = client.post(
        f"{API}/auth/reauth",
        json={"password": ADMIN_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.text


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


def _run_task(
    rig: JourneyRig,
    task_id: uuid.UUID,
    states: tuple[str, ...] = ("succeeded",),
    timeout: float = 150.0,
) -> object:
    rig.rig.start_pool()
    try:
        return rig.rig.wait_terminal(task_id, states=states, timeout=timeout)
    finally:
        rig.rig.stop_pool()


def _device_row(rig: JourneyRig, device_id: uuid.UUID) -> dict[str, object]:
    with rig.rig.factory() as session:
        row = session.execute(
            text(
                "SELECT vendor, model, serial_number, firmware_version, readiness, enabled, "
                "reachability, health FROM devices WHERE id = :id"
            ),
            {"id": device_id},
        ).one()
        return dict(row._mapping)


def _latest_by_native(
    rig: JourneyRig, device_id: uuid.UUID, metric_key: str, native: str | None
) -> dict[str, object] | None:
    with rig.rig.factory() as session:
        if native is None:
            row = session.execute(
                text(
                    "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, ml.quality, "
                    "c.kind, c.native_id "
                    "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                    "WHERE ml.device_id = :id AND ml.metric_key = :key AND ml.component_id IS NULL"
                ),
                {"id": device_id, "key": metric_key},
            ).one_or_none()
        else:
            row = session.execute(
                text(
                    "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, ml.quality, "
                    "c.kind, c.native_id "
                    "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                    "WHERE ml.device_id = :id AND ml.metric_key = :key AND c.native_id = :native"
                ),
                {"id": device_id, "key": metric_key, "native": native},
            ).one_or_none()
    return dict(row._mapping) if row is not None else None


def _active_alerts(rig: JourneyRig, device_id: uuid.UUID) -> list[dict[str, object]]:
    with rig.rig.factory() as session:
        rows = session.execute(
            text(
                "SELECT rule_key, severity, evidence FROM alerts "
                "WHERE device_id = :id AND status = 'active' ORDER BY severity, rule_key"
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


def _finish_audit_result(rig: JourneyRig, task_id: uuid.UUID) -> str:
    with rig.rig.factory() as session:
        return str(
            session.execute(
                text("SELECT result FROM audit_logs WHERE task_id = :id AND action = 'operation.finish'"),
                {"id": task_id},
            ).scalar_one()
        )


def _wait_for(predicate: object, timeout: float = 20.0, interval: float = 0.2) -> None:
    """Poll ``predicate`` (callable -> truthy) until it passes or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s")


class IngestHost:
    """The real IngestService on a private thread with its own event loop.

    Syslog UDP/TCP + trap receivers bind ephemeral ports; the service routes
    through the same platform layer the deployment runs (app/workers/ingest).
    """

    def __init__(self, settings: WardenSettings) -> None:
        from app.workers.ingest import IngestService, PortOverrides

        self._engine = create_db_engine(settings.postgres_dsn)
        self._factory = create_session_factory(self._engine)
        self.service = IngestService(
            settings=settings,
            session_factory=self._factory,
            keyring=_keyring_from_file(settings),
            refresh_seconds=3600,
            port_overrides=PortOverrides(syslog_udp=0, syslog_tcp=0, snmp_trap=0),
        )
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._failures: list[BaseException] = []

    def start(self) -> None:
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            self._stop_event = asyncio.Event()

            async def serve() -> None:
                await self.service.start()
                ready.set()
                await self._stop_event.wait()
                await self.service.stop()

            try:
                loop.run_until_complete(serve())
            except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
                self._failures.append(exc)
                ready.set()
            finally:
                with contextlib.suppress(BaseException):  # noqa: S110 - best-effort teardown
                    loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
                self._engine.dispose()

        self._thread = threading.Thread(target=run, name="m5t6-ingest", daemon=True)
        self._thread.start()
        if not ready.wait(20.0):
            raise AssertionError(f"ingest service failed to start: {self._failures[:1]}")

    def stop(self) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None
        gc.collect()


def _send_syslog_udp(port: int, payload: str, *, source_ip: str = SIM_HOST) -> None:
    """One real UDP syslog datagram bound to ``source_ip`` (RFC 3164)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind((source_ip, 0))
        sender.sendto(payload.encode("utf-8"), (SIM_HOST, port))


class TestSwitchJourneyE2E:
    def test_journey_core_and_access_profiles_through_the_platform(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        isolated_snmp_boots: None,
    ) -> None:
        del isolated_snmp_boots
        with serve_journey_sims() as (core_sim, access_sim):
            rig = JourneyRig(fresh_test_db_dsn, tmp_path, monkeypatch)
            try:
                with TestClient(rig.app) as client:
                    response, csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                    assert response.status_code == 200

                    # -- step 1: onboard BOTH profiles -----------------------
                    core_id, core_fingerprint = _probe_and_onboard(
                        client,
                        csrf,
                        name=CORE_DEVICE_NAME,
                        device_type="core_switch",
                        adapter_key=CORE_ADAPTER_KEY,
                        sim=core_sim,
                        event_source_ips=[FLAP_SOURCE_IP],
                    )
                    access_id, access_fingerprint = _probe_and_onboard(
                        client,
                        csrf,
                        name=ACCESS_DEVICE_NAME,
                        device_type="access_switch",
                        adapter_key=ACCESS_ADAPTER_KEY,
                        sim=access_sim,
                    )
                    # The captured probe fingerprints equal the sims' actual
                    # per-boot host keys; the access device pins its own.
                    assert core_fingerprint == core_sim.vrp_fingerprint
                    assert access_fingerprint == access_sim.vrp_fingerprint
                    assert core_fingerprint != access_fingerprint
                    core_row = _device_row(rig, core_id)
                    access_row = _device_row(rig, access_id)
                    assert core_row["vendor"] == "Huawei"
                    assert core_row["model"] == CORE_MODEL
                    assert core_row["firmware_version"] == CORE_FW
                    assert core_row["serial_number"] is None  # no SNMP serial read: honest
                    assert access_row["model"] == ACCESS_MODEL
                    assert access_row["firmware_version"] == ACCESS_FW
                    assert core_row["readiness"] == "ready" and core_row["enabled"] is True
                    assert access_row["readiness"] == "ready" and access_row["enabled"] is True
                    core_caps = _capability_states(client, core_id)
                    access_caps = _capability_states(client, access_id)
                    core_supported = {
                        "system.cpu_percent",
                        "interface.admin_status",
                        "interface.in_bps",
                        "transceiver.rx_dbm",
                        "fan.status",
                        "stp.port_state",
                        "event.port_flap",
                        "event.device_restart",
                        "event.auth_failure",
                        "device.restart",
                        "interface.admin.set",
                        "config.backup",
                        "config.restore",
                        "logs.diagnostic.collect",
                        "console.ssh.open",
                    }
                    for key in core_supported:
                        assert core_caps.get(key) == "supported", key
                    # No declared Web origin: console.web.open is honest
                    # not_configured, never a guessed launch URL (M5T5).
                    assert core_caps["console.web.open"] == "not_configured"
                    access_supported = {
                        "system.cpu_percent",
                        "interface.errors",
                        "poe.port.status",
                        "poe.total_power_alarm",
                        "poe.port.set",
                        "config.backup",
                        "logs.collect",
                        "console.ssh.open",
                    }
                    for key in access_supported:
                        assert access_caps.get(key) == "supported", key
                    assert access_caps["console.web.open"] == "not_configured"
                    _print_evidence(
                        "onboarded-both-profiles",
                        {
                            "core": {
                                "device_id": str(core_id),
                                **core_row,
                                "captured_fingerprint": core_fingerprint,
                                "capability_rows": len(core_caps),
                            },
                            "access": {
                                "device_id": str(access_id),
                                **access_row,
                                "captured_fingerprint": access_fingerprint,
                                "capability_rows": len(access_caps),
                            },
                        },
                    )

                    now = utcnow()

                    # -- step 2: two metric runs -> rates on the SECOND ------
                    # Request-time nows are spaced 60 s apart: the derived rate
                    # is deterministic (STEP * 8 / 60 bit/s per port).
                    core_r1 = _run_collection(
                        rig,
                        core_id,
                        "metrics",
                        scheduled_at=now,
                        request_now=now,
                    )
                    assert core_r1["state"] == "partial", core_r1
                    assert core_r1["success_count"] > 0 and core_r1["failure_count"] > 0
                    core_r2 = _run_collection(
                        rig,
                        core_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=1),
                        request_now=now + datetime.timedelta(seconds=60),
                    )
                    assert core_r2["state"] == "succeeded", core_r2
                    assert core_r2["failure_count"] == 0, core_r2
                    in_bps = _latest_by_native(rig, core_id, "interface.in_bps", "GigabitEthernet0/0/1")
                    out_bps = _latest_by_native(rig, core_id, "interface.out_bps", "GigabitEthernet0/0/1")
                    assert in_bps is not None and out_bps is not None
                    assert in_bps["quality"] == "good"
                    assert in_bps["unit"] == "bit/s"
                    assert in_bps["value_double"] == pytest.approx(STEP * 8.0 / 60.0)
                    assert out_bps["quality"] == "good"
                    # Every port carries rates after the second collect.
                    with rig.rig.factory() as session:
                        port_bps = session.execute(
                            text(
                                "SELECT count(*) FROM metric_latest ml "
                                "JOIN components c ON c.id = ml.component_id "
                                "WHERE ml.device_id = :id AND ml.metric_key = 'interface.in_bps' "
                                "AND ml.quality = 'good' AND c.kind = 'interface'"
                            ),
                            {"id": core_id},
                        ).scalar_one()
                        assert port_bps == 52
                    assert _device_row(rig, core_id)["reachability"] == "online"
                    assert _device_row(rig, core_id)["health"] == "healthy"
                    _print_evidence(
                        "rates-after-second-collect",
                        {
                            "run_1": core_r1,
                            "run_2": core_r2,
                            "interface.in_bps_GE0/0/1": in_bps,
                            "ports_with_good_bps": port_bps,
                        },
                    )

                    # -- step 3: degrade the core (fan-fault knob) ------------
                    core_sim.agent.set_fan_fault(3, fault=True)
                    core_r3 = _run_collection(
                        rig,
                        core_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=2),
                        request_now=now + datetime.timedelta(seconds=120),
                    )
                    assert core_r3["state"] == "succeeded", core_r3
                    assert _device_row(rig, core_id)["health"] == "critical"
                    core_alerts = _active_alerts(rig, core_id)
                    fan_rows = [
                        row
                        for row in core_alerts
                        if isinstance(row["evidence"], dict) and row["evidence"].get("metric_key") == "fan.status"
                    ]
                    assert fan_rows, core_alerts
                    assert fan_rows[0]["severity"] == "critical"
                    assert fan_rows[0]["rule_key"] == "status.problem"
                    _print_evidence(
                        "alerts-opened-degraded",
                        {"run": core_r3, "problem_rows": core_alerts},
                    )

                    # -- step 4: syslog port-flap sequence -> ingest ----------
                    flap_events: list[dict[str, object]] = []
                    hosted = IngestHost(rig.settings)
                    hosted.start()
                    try:
                        udp_port = hosted.service.syslog.udp_port
                        assert udp_port and udp_port > 0
                        t_flap = datetime.datetime(2026, 9, 4, 7, 0, 0, tzinfo=UTC)
                        down_line = vrp_link_state_line(
                            hostname="sim-s5732-h48xum2cc-1",
                            interface="GigabitEthernet0/0/9",
                            direction="down",
                            when=t_flap,
                        )
                        up_line = vrp_link_state_line(
                            hostname="sim-s5732-h48xum2cc-1",
                            interface="GigabitEthernet0/0/9",
                            direction="up",
                            when=t_flap + datetime.timedelta(seconds=3),
                        )
                        # down (unique) + up (unique) + down AGAIN (dedupe).
                        _send_syslog_udp(int(udp_port), down_line, source_ip=FLAP_SOURCE_IP)
                        time.sleep(0.2)
                        _send_syslog_udp(int(udp_port), up_line, source_ip=FLAP_SOURCE_IP)
                        time.sleep(0.2)
                        _send_syslog_udp(int(udp_port), down_line, source_ip=FLAP_SOURCE_IP)

                        def _find_flaps() -> list[dict[str, object]]:
                            with rig.rig.factory() as session:
                                rows = session.execute(
                                    text(
                                        "SELECT event_type, severity, source, message, "
                                        "detail->>'component_native_id' AS component_native_id "
                                        "FROM device_events WHERE device_id = :id "
                                        "ORDER BY message"
                                    ),
                                    {"id": core_id},
                                ).all()
                                return [dict(row._mapping) for row in rows]

                        _wait_for(lambda: len(_find_flaps()) == 2, timeout=20.0)
                        _wait_for(lambda: hosted.service.counters.deduped_events >= 1, timeout=20.0)
                        flap_events = _find_flaps()
                        assert {str(row["message"]) for row in flap_events} == {
                            "interface GigabitEthernet0/0/9 link down",
                            "interface GigabitEthernet0/0/9 link up",
                        }
                        assert all(str(row["event_type"]) == "event.port_flap" for row in flap_events)
                        assert all(str(row["source"]) == "syslog" for row in flap_events)
                        by_message = {str(row["message"]): row for row in flap_events}
                        # [sim] flap classification: down = warning, up = info.
                        assert by_message["interface GigabitEthernet0/0/9 link down"]["severity"] == "warning"
                        assert by_message["interface GigabitEthernet0/0/9 link up"]["severity"] == "info"
                        assert all(str(row["component_native_id"]) == "GigabitEthernet0/0/9" for row in flap_events)
                        assert hosted.service.counters.stored_events >= 2
                    finally:
                        hosted.stop()
                    # Log events are history: no current-problem alert opened
                    # and the fan alert is untouched (contracts/alert-rules.json).
                    after_flap_alerts = _active_alerts(rig, core_id)
                    assert after_flap_alerts == core_alerts
                    _print_evidence(
                        "ingest-port-flap-attributed",
                        {
                            "device_events": flap_events,
                            "counters": hosted.service.counters.snapshot(),
                            "alerts_unchanged": True,
                        },
                    )

                    # -- step 5: interface.admin.set (CORE-ACT-02) ------------
                    blocked = client.post(
                        f"{API}/devices/{core_id}/operation-previews",
                        json={
                            "capability_key": "interface.admin.set",
                            "parameters": {
                                "interface_id": "GigabitEthernet0/0/2",
                                "enabled": False,
                            },
                        },
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert blocked.status_code == 401
                    assert blocked.json()["error"]["code"] == "reauthentication_required"
                    _reauthenticate(client, csrf)
                    admin_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(core_id),
                        capability_key="interface.admin.set",
                        parameters={
                            "interface_id": "GigabitEthernet0/0/2",
                            "enabled": False,
                        },
                        confirmation_text=CORE_DEVICE_NAME,
                        idempotency_key="m5t6-journey-admin-set-0001",
                    )
                    admin_row = _run_task(rig, uuid.UUID(admin_task_id))
                    assert admin_row.state == "succeeded"
                    assert admin_row.requirement_id == "CORE-ACT-02"
                    assert admin_row.verification_state == "passed"
                    evidence = admin_row.evidence or {}
                    assert evidence["verification"]["admin_state_readback"] == "down"
                    assert _finish_audit_result(rig, admin_row.id) == "succeeded"
                    assert _audit_actions(rig, admin_row.id) >= {
                        "operation.create",
                        "operation.start",
                        "operation.finish",
                    }
                    snapshot = core_sim.vrp_device.snapshot()
                    assert "GigabitEthernet0/0/2" in snapshot["admin_down"]
                    # Mirror the CLI-side admin change into the SNMP face so
                    # the monitored data follows the operation, then collect:
                    # the platform reads admin_status down for that port.
                    core_sim.agent.set_admin_state(2, up=False)
                    core_r4 = _run_collection(
                        rig,
                        core_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=3),
                        request_now=now + datetime.timedelta(seconds=180),
                    )
                    assert core_r4["state"] == "succeeded", core_r4
                    admin_latest = _latest_by_native(rig, core_id, "interface.admin_status", "GigabitEthernet0/0/2")
                    assert admin_latest is not None and admin_latest["value_text"] == "down"
                    _print_evidence(
                        "interface-admin-set-succeeded",
                        {
                            "task_id": admin_task_id,
                            "state": admin_row.state,
                            "verification": evidence["verification"],
                            "audit_actions": sorted(_audit_actions(rig, admin_row.id)),
                            "admin_status_metric_after_collect": admin_latest,
                        },
                    )

                    # -- step 6: access profile collects + PoE surface --------
                    access_r1 = _run_collection(
                        rig,
                        access_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=4),
                        request_now=now,
                    )
                    assert access_r1["state"] == "partial", access_r1
                    access_r2 = _run_collection(
                        rig,
                        access_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=5),
                        request_now=now + datetime.timedelta(seconds=60),
                    )
                    assert access_r2["state"] == "succeeded", access_r2
                    poe_on = _latest_by_native(rig, access_id, "poe.port.status", "GigabitEthernet0/0/6")
                    poe_power = _latest_by_native(rig, access_id, "poe.port.power_w", "GigabitEthernet0/0/6")
                    assert poe_on is not None and poe_on["value_text"] == "on"
                    assert poe_power is not None and poe_power["value_double"] == 5.0
                    with rig.rig.factory() as session:
                        totals = session.execute(
                            text(
                                "SELECT metric_key, value_double, unit FROM metric_latest "
                                "WHERE device_id = :id AND metric_key IN "
                                "('poe.total_power_w','poe.power_budget_w','poe.total_power_percent') "
                                "AND component_id IS NULL ORDER BY metric_key"
                            ),
                            {"id": access_id},
                        ).all()
                        total_map = {str(row._mapping["metric_key"]): dict(row._mapping) for row in totals}
                    assert total_map["poe.total_power_w"]["value_double"] == 80.0
                    assert total_map["poe.power_budget_w"]["value_double"] == 400.0
                    assert total_map["poe.total_power_percent"]["value_double"] == 20.0
                    alarm = _latest_by_native(rig, access_id, "poe.total_power_alarm", None)
                    # The access simulator ships two degraded PoE ports by
                    # design (17 denied / 18 fault): the platform surfaces
                    # their status.problem rows honestly — warning + critical.
                    access_alerts = _active_alerts(rig, access_id)
                    assert {str(row["severity"]) for row in access_alerts} == {"warning", "critical"}
                    assert all(
                        isinstance(row["evidence"], dict) and row["evidence"].get("metric_key") == "poe.port.status"
                        for row in access_alerts
                    )
                    assert _device_row(rig, access_id)["reachability"] == "online"
                    assert _device_row(rig, access_id)["health"] == "critical"
                    _print_evidence(
                        "access-poe-surface-and-alerts",
                        {
                            "poe.port.status_GE0/0/6": poe_on,
                            "poe.port.power_w_GE0/0/6": poe_power,
                            "totals": total_map,
                            "alarm_state": alarm,
                            "problem_rows": access_alerts,
                        },
                    )

                    # -- step 7: poe.port.set cycle (ACCESS-ACT-03) ----------
                    _reauthenticate(client, csrf)
                    poe_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(access_id),
                        capability_key="poe.port.set",
                        parameters={
                            "interface_id": "GigabitEthernet0/0/6",
                            "mode": "cycle",
                            "off_seconds": 5,
                        },
                        confirmation_text=ACCESS_DEVICE_NAME,
                        idempotency_key="m5t6-journey-poe-cycle-0001",
                    )
                    poe_row = _run_task(rig, uuid.UUID(poe_task_id), timeout=180.0)
                    assert poe_row.state == "succeeded"
                    assert poe_row.requirement_id == "ACCESS-ACT-03"
                    assert poe_row.verification_state == "passed"
                    poe_evidence = poe_row.evidence or {}
                    transitions = poe_evidence["execution"]["poe_transitions"]
                    assert [t["readback"] for t in transitions] == ["off", "on"]
                    assert poe_evidence["verification"]["poe_state_readback"] == "on"
                    assert _finish_audit_result(rig, poe_row.id) == "succeeded"
                    assert access_sim.vrp_device.poe_state("GigabitEthernet0/0/6") is True
                    # Mirror the operated state into the SNMP face and prove
                    # the monitored data follows (off then back on with 5 W).
                    access_sim.agent.set_poe_port_state(6, 2)
                    access_sim.agent.set_poe_port_power_mw(6, 0)
                    access_r3 = _run_collection(
                        rig,
                        access_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=6),
                        request_now=now + datetime.timedelta(seconds=120),
                    )
                    assert access_r3["state"] == "succeeded", access_r3
                    assert (
                        _latest_by_native(rig, access_id, "poe.port.status", "GigabitEthernet0/0/6")["value_text"]
                        == "off"
                    )
                    access_sim.agent.set_poe_port_state(6, 1)
                    access_sim.agent.set_poe_port_power_mw(6, 5000)
                    access_r4 = _run_collection(
                        rig,
                        access_id,
                        "metrics",
                        scheduled_at=now + datetime.timedelta(seconds=7),
                        request_now=now + datetime.timedelta(seconds=180),
                    )
                    assert access_r4["state"] == "succeeded", access_r4
                    poe_back = _latest_by_native(rig, access_id, "poe.port.status", "GigabitEthernet0/0/6")
                    power_back = _latest_by_native(rig, access_id, "poe.port.power_w", "GigabitEthernet0/0/6")
                    assert poe_back is not None and poe_back["value_text"] == "on"
                    assert power_back is not None and power_back["value_double"] == 5.0
                    _print_evidence(
                        "poe-cycle-succeeded",
                        {
                            "task_id": poe_task_id,
                            "state": poe_row.state,
                            "execution": poe_evidence["execution"],
                            "verification": poe_evidence["verification"],
                            "monitored_after_cycle": {"status": poe_back, "power_w": power_back},
                        },
                    )

                    # -- step 8: config.backup -> restore round trip ----------
                    backup_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(core_id),
                        capability_key="config.backup",
                        parameters={},
                        confirmation_text=CORE_DEVICE_NAME,
                        idempotency_key="m5t6-journey-backup-0001",
                    )
                    backup_row = _run_task(rig, uuid.UUID(backup_task_id))
                    assert backup_row.state == "succeeded"
                    assert backup_row.requirement_id == "CORE-ACT-05"
                    backup_evidence = backup_row.evidence or {}
                    assert backup_evidence["execution"]["parse_ok"] is True
                    with rig.rig.factory() as session:
                        meta = (
                            session.execute(
                                text(
                                    "SELECT f.id, f.file_type, f.encrypted, f.sha256, "
                                    "f.metadata->>'model' AS model, f.metadata->>'vrp_version' AS vrp "
                                    "FROM files f JOIN file_links fl ON fl.file_id = f.id "
                                    "WHERE fl.task_id = :id"
                                ),
                                {"id": backup_row.id},
                            )
                            .mappings()
                            .one()
                        )
                        meta_map = dict(meta)
                    assert meta_map["file_type"] == "config_backup"
                    assert meta_map["encrypted"] is True
                    assert meta_map["model"] == CORE_MODEL
                    assert meta_map["vrp"] == CORE_FW
                    backup_file_id = str(meta_map["id"])
                    backup_sha = str(meta_map["sha256"])
                    assert _finish_audit_result(rig, backup_row.id) == "succeeded"
                    _print_evidence(
                        "config-backup-succeeded",
                        {
                            "task_id": backup_task_id,
                            "state": backup_row.state,
                            "artifact": meta_map,
                        },
                    )
                    _reauthenticate(client, csrf)
                    restore_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(core_id),
                        capability_key="config.restore",
                        parameters={"file_id": backup_file_id},
                        confirmation_text=CORE_DEVICE_NAME,
                        idempotency_key="m5t6-journey-restore-0001",
                    )
                    restore_row = _run_task(rig, uuid.UUID(restore_task_id), timeout=240.0)
                    assert restore_row.state == "succeeded"
                    assert restore_row.requirement_id == "CORE-ACT-05"
                    assert restore_row.verification_state == "passed"
                    restore_evidence = restore_row.evidence or {}
                    assert (
                        restore_evidence["execution"]["certified_strategy"]
                        == "full_replace_via_startup_config_and_reboot"
                    )
                    assert restore_evidence["verification"]["config_fingerprint"] == backup_sha
                    assert _finish_audit_result(rig, restore_row.id) == "succeeded"
                    _print_evidence(
                        "config-restore-succeeded",
                        {
                            "task_id": restore_task_id,
                            "state": restore_row.state,
                            "execution": restore_evidence["execution"],
                            "verification": restore_evidence["verification"],
                        },
                    )

                    # -- step 9: console.ssh.open terminal session ------------
                    launch = client.post(
                        f"{API}/devices/{core_id}/launches",
                        json={"capability_key": "console.ssh.open"},
                        headers={"X-CSRF-Token": csrf},
                    )
                    assert launch.status_code == 201, launch.text
                    launch_body = launch.json()
                    launch_id = str(launch_body["launch_id"])
                    assert launch_body["url"].endswith(f"/api/v1/terminal/sessions/{launch_id}")
                    session_id: str | None = None
                    try:
                        with client.websocket_connect(
                            f"{API}/terminal/sessions/{launch_id}",
                            headers={"Origin": WS_ORIGIN},
                        ) as websocket:
                            ready = json.loads(websocket.receive_text())
                            assert ready["type"] == "ready"
                            assert ready["protocol"] == "ssh"
                            session_id = str(ready["session_id"])
                            websocket.send_bytes(b"display version\r")
                            output = b""
                            deadline = time.monotonic() + 30.0
                            while CORE_FW.encode("utf-8") not in output and time.monotonic() < deadline:
                                output += websocket.receive_bytes()
                            assert CORE_FW.encode("utf-8") in output, output[:500]
                            # Server-side close via the POST endpoint: the
                            # bridge sends the closed frame, then closes the
                            # WebSocket (normal 1000 close).
                            closed = client.post(
                                f"{API}/terminal/sessions/{session_id}/close",
                                headers={"X-CSRF-Token": csrf},
                            )
                            assert closed.status_code == 200, closed.text
                            assert closed.json()["close_reason"] == "user_closed"
                            # Trailing device output may still be in flight as
                            # binary frames after the close request (load
                            # dependent); drain until the closed frame or the
                            # server-side close.
                            closed_frame = None
                            saw_close = False
                            drain_deadline = time.monotonic() + 10.0
                            while time.monotonic() < drain_deadline:
                                message = websocket.receive()
                                if message.get("type") in ("websocket.close", "websocket.disconnect"):
                                    saw_close = True
                                    break
                                frame_text = message.get("text")
                                if frame_text is None:
                                    continue  # trailing device bytes
                                frame = json.loads(frame_text)
                                if frame.get("type") == "closed":
                                    closed_frame = frame
                                    break
                            assert closed_frame is not None or saw_close
                            if closed_frame is not None:
                                assert closed_frame["type"] == "closed"
                                assert closed_frame["reason"] == "user_closed"
                    except WebSocketDisconnect as exc:
                        assert int(exc.code) in (1000, 1001), exc.code
                    assert session_id is not None
                    with rig.rig.factory() as session:
                        row = session.execute(
                            text(
                                "SELECT status, close_reason, protocol, capability_key "
                                "FROM terminal_sessions WHERE id = :id"
                            ),
                            {"id": uuid.UUID(session_id)},
                        ).one()
                        terminal_row = dict(row._mapping)
                        launch_status = session.execute(
                            text("SELECT status FROM launch_sessions WHERE id = :id"),
                            {"id": uuid.UUID(launch_id)},
                        ).scalar_one()
                        terminal_audits = session.execute(
                            text("SELECT action, detail_jsonb FROM audit_logs WHERE resource_id = :id ORDER BY action"),
                            {"id": session_id},
                        ).all()
                        audit_rows = [
                            {
                                "action": str(a._mapping["action"]),
                                "detail_jsonb": a._mapping["detail_jsonb"],
                            }
                            for a in terminal_audits
                        ]
                    assert terminal_row["status"] == "closed"
                    assert terminal_row["close_reason"] == "user_closed"
                    assert terminal_row["protocol"] == "ssh"
                    assert terminal_row["capability_key"] == "console.ssh.open"
                    assert str(launch_status) == "consumed"
                    audit_actions = {row["action"] for row in audit_rows}
                    assert "terminal.handshake_ok" in audit_actions
                    assert "terminal.closed" in audit_actions
                    closed_audit = next(row for row in audit_rows if row["action"] == "terminal.closed")
                    assert closed_audit["detail_jsonb"]["reason"] == "user_closed"
                    _print_evidence(
                        "console-ssh-terminal-session",
                        {
                            "launch_id": launch_id,
                            "session": terminal_row,
                            "launch_status": launch_status,
                            "command_round_trip": "display version -> banner",
                            "audit_actions": sorted(audit_actions),
                        },
                    )

                    # -- step 10: logs.diagnostic.collect (CORE-ACT-04) --------
                    diag_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(core_id),
                        capability_key="logs.diagnostic.collect",
                        parameters={},
                        confirmation_text=CORE_DEVICE_NAME,
                        idempotency_key="m5t6-journey-diag-0001",
                    )
                    diag_row = _run_task(rig, uuid.UUID(diag_task_id), timeout=240.0)
                    assert diag_row.state == "succeeded"
                    assert diag_row.requirement_id == "CORE-ACT-04"
                    diag_evidence = diag_row.evidence or {}
                    assert diag_evidence["verification"]["completion_marker"] == "prompt_returned"
                    stored_sha = diag_evidence["execution"]["artifact_stored"]["sha256"]
                    with rig.rig.factory() as session:
                        file_row = (
                            session.execute(
                                text(
                                    "SELECT f.file_type, f.encrypted, f.sha256, "
                                    "f.metadata->>'source' AS source "
                                    "FROM files f JOIN file_links fl ON fl.file_id = f.id "
                                    "WHERE fl.task_id = :id"
                                ),
                                {"id": diag_row.id},
                            )
                            .mappings()
                            .one()
                        )
                        diag_file = dict(file_row)
                    assert diag_file["file_type"] == "operation_log"
                    assert diag_file["encrypted"] is True
                    assert diag_file["sha256"] == stored_sha
                    assert diag_file["source"] == "display.diagnostic_information"
                    assert _finish_audit_result(rig, diag_row.id) == "succeeded"
                    _print_evidence(
                        "diagnostic-collect-succeeded",
                        {
                            "task_id": diag_task_id,
                            "state": diag_row.state,
                            "completion_marker": diag_evidence["verification"],
                            "artifact": diag_file,
                        },
                    )

                    # -- step 11: restore the fan knob -> alerts resolve -------
                    core_sim.agent.set_fan_fault(3, fault=False)
                    for index in range(2):
                        _run_collection(
                            rig,
                            core_id,
                            "metrics",
                            scheduled_at=now + datetime.timedelta(seconds=8 + index),
                            request_now=now + datetime.timedelta(seconds=240 + 60 * index),
                        )
                    assert _device_row(rig, core_id)["health"] == "healthy"
                    with rig.rig.factory() as session:
                        active = session.execute(
                            text("SELECT count(*) FROM alerts WHERE device_id = :id AND status = 'active'"),
                            {"id": core_id},
                        ).scalar_one()
                        assert active == 0
                        resolved = session.execute(
                            text(
                                "SELECT count(*) FROM alerts WHERE device_id = :id "
                                "AND rule_key = 'status.problem' AND status = 'resolved'"
                            ),
                            {"id": core_id},
                        ).scalar_one()
                        assert resolved >= len(core_alerts)
                        runs = session.execute(
                            text(
                                "SELECT collection_type, state, count(*) AS n FROM collection_runs "
                                "WHERE device_id = :id GROUP BY collection_type, state "
                                "ORDER BY collection_type, state"
                            ),
                            {"id": core_id},
                        ).all()
                        core_runs_map = {
                            f"{row._mapping['collection_type']}:{row._mapping['state']}": int(row._mapping["n"])
                            for row in runs
                        }
                        access_runs = session.execute(
                            text(
                                "SELECT collection_type, state, count(*) AS n FROM collection_runs "
                                "WHERE device_id = :id GROUP BY collection_type, state "
                                "ORDER BY collection_type, state"
                            ),
                            {"id": access_id},
                        ).all()
                        access_runs_map = {
                            f"{row._mapping['collection_type']}:{row._mapping['state']}": int(row._mapping["n"])
                            for row in access_runs
                        }
                        tasks = session.execute(
                            text(
                                "SELECT capability_key, state, verification_state FROM operation_tasks "
                                "WHERE device_id IN (:core, :access) AND state = 'succeeded' "
                                "ORDER BY capability_key"
                            ),
                            {"core": core_id, "access": access_id},
                        ).all()
                        succeeded_tasks = [dict(row._mapping) for row in tasks]
                    # Core: r1 partial (bps cache miss) + 5 succeeded.
                    assert core_runs_map["metrics:partial"] == 1
                    assert core_runs_map["metrics:succeeded"] == 5
                    # Access: r1 partial + 3 succeeded (r2 + poe mirrors).
                    assert access_runs_map["metrics:partial"] == 1
                    assert access_runs_map["metrics:succeeded"] == 3
                    task_keys = {row["capability_key"] for row in succeeded_tasks}
                    assert task_keys == {
                        "interface.admin.set",
                        "poe.port.set",
                        "config.backup",
                        "config.restore",
                        "logs.diagnostic.collect",
                    }
                    assert all(row["state"] == "succeeded" for row in succeeded_tasks)
                    _print_evidence(
                        "restored-and-resolved",
                        {
                            "core_device": _device_row(rig, core_id),
                            "access_device": _device_row(rig, access_id),
                            "core_resolved_problem_rows": resolved,
                            "core_collection_runs": core_runs_map,
                            "access_collection_runs": access_runs_map,
                            "succeeded_tasks": succeeded_tasks,
                        },
                    )
            finally:
                time.sleep(0.2)
                rig.close()


class TestSwitchJourneyDefinition:
    def test_journey_definitions_pin_the_two_profile_rows(self) -> None:
        """The module's profile rows stay the certified certification units;
        the simulator identities never drift from what the journey asserts."""
        from app.adapters.registry import ADAPTERS

        assert CORE_ADAPTER_KEY in ADAPTERS
        assert ACCESS_ADAPTER_KEY in ADAPTERS
        core_adapter = ADAPTERS[CORE_ADAPTER_KEY]
        access_adapter = ADAPTERS[ACCESS_ADAPTER_KEY]
        assert CORE_MODEL in core_adapter.certified_models
        assert ACCESS_MODEL in access_adapter.certified_models
        core_profile = profile_by_key(CORE_PROFILE_KEY)
        access_profile = profile_by_key(ACCESS_PROFILE_KEY)
        assert core_profile.model == CORE_MODEL
        assert core_profile.adapter_key == CORE_ADAPTER_KEY
        assert core_profile.device_type == "core_switch"
        assert core_profile.vrp_version == CORE_FW
        assert access_profile.model == ACCESS_MODEL
        assert access_profile.adapter_key == ACCESS_ADAPTER_KEY
        assert access_profile.device_type == "access_switch"
        assert access_profile.vrp_version == ACCESS_FW
