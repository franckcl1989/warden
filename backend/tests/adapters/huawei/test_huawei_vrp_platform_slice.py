"""M5T2 platform slice: switch.huawei_vrp_core over the real platform.

End-to-end over REAL SNMP (UDP simulator) + real PostgreSQL 18:

- onboarding through the API probe+save flow (identity gate + discovery
  capability rows + components persisted);
- TWO real collection runs through claim + ``run_collection``: the first
  run carries honest ObservationErrors for the bps rates (cache miss —
  never fabricated), the second run produces metric_latest in_bps/out_bps
  rows with the exact derived rate (quality good);
- the M5T1 ingest path attributes a real UDP syslog port-flap to the
  onboarded switch (device_events row) — CORE-MON-06 wiring evidence.

The simulator is a TEST DEVICE SIMULATOR, never hardware evidence
(tests/simulators/switch/README.md).
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from app.application.collection import run_collection
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.observation_store import claim_collection_run
from app.infrastructure.time import utcnow
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.adapters.huawei.conftest import SIM_HOST, V3_AUTH_KEY, V3_PRIV_KEY, V3_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, login_csrf
from tests.simulators.switch.emitters import vrp_link_state_line

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "switch.huawei_vrp_core"
STEP = 125_000
UTC = datetime.UTC

V3_ENGINE_ID = "73353733322d6869642d30303031"  # core_s5732 profile engine id (hex)
CONNECTION_CONFIG = {
    "snmp_version": "v3",
    "snmp_engine_id": V3_ENGINE_ID,
}
CREDENTIALS = {"snmp": {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY}}


@contextmanager
def _allow_simulator_resolution(monkeypatch: pytest.MonkeyPatch, port: int) -> Iterator[None]:
    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, host, requested_port, allowed_ports
        return ipaddress.ip_address(SIM_HOST), port

    monkeypatch.setattr(DeviceEndpointPolicy, "resolve_endpoint", resolve)
    yield


def _settings(fresh_test_db_dsn: str, tmp_path) -> WardenSettings:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs=f"{SIM_HOST}/32",
        credential_master_key_file=key_file,
        session_secret_file=session_file,
        ingest_bind_host="127.0.0.1",
    )


def _keyring(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


class IngestHost:
    """IngestService on a private thread with its own event loop."""

    def __init__(self, settings: WardenSettings) -> None:
        from app.workers.ingest import IngestService, PortOverrides

        self._engine = create_db_engine(settings.postgres_dsn)
        self._factory = create_session_factory(self._engine)
        self.service = IngestService(
            settings=settings,
            session_factory=self._factory,
            keyring=_keyring(settings),
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
                await self._stop_event.wait()  # type: ignore[union-attr]
                await self.service.stop()

            try:
                loop.run_until_complete(serve())
            except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
                self._failures.append(exc)
                ready.set()
            finally:
                self._engine.dispose()

        self._thread = threading.Thread(target=run, name="m5t2-ingest", daemon=True)
        self._thread.start()
        if not ready.wait(20.0):
            raise AssertionError(f"ingest service failed to start: {self._failures[:1]}")

    def stop(self) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None


class TestHuaweiCorePlatformSlice:
    def test_onboard_two_collects_and_ingest_attribution(
        self,
        switch_agent,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch,
        isolated_snmp_boots: None,
    ) -> None:
        del isolated_snmp_boots
        with switch_agent(profile_key="core_s5732") as h:
            settings = _settings(fresh_test_db_dsn, tmp_path)
            keyring = _keyring(settings)
            app = create_app(settings)
            device_id = uuid.UUID(int=0)
            try:
                self._seed_admin(app)
                with _allow_simulator_resolution(monkeypatch, h.port), TestClient(app) as http:
                    device_id = self._onboard(http, h.port)
            finally:
                engine = app.state.engine
                if engine is not None:
                    engine.dispose()
            engine = create_db_engine(fresh_test_db_dsn)
            factory = create_session_factory(engine)
            try:
                self._run_two_metric_collects(factory, device_id, settings, keyring)
                self._assert_psql_evidence(factory, device_id)
                self._ingest_syslog_event(factory, settings, device_id)
            finally:
                engine.dispose()

    # -- onboarding ---------------------------------------------------------

    def _seed_admin(self, app) -> None:
        from app.infrastructure.db import create_session_factory

        engine = app.state.engine
        assert engine is not None
        with create_session_factory(engine)() as session:
            create_admin(session)

    def _onboard(self, http: TestClient, port: int) -> uuid.UUID:
        response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert response.status_code == 200
        connection_config = dict(CONNECTION_CONFIG)
        connection_config["port"] = port
        probe = http.post(
            f"{API}/device-probes",
            json={
                "device_type": "core_switch",
                "adapter_key": ADAPTER_KEY,
                "management_endpoint": SIM_HOST,
                "connection_config": connection_config,
                "credentials": CREDENTIALS,
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert probe.status_code == 200, probe.text
        body = probe.json()
        assert body["ok"] is True, body
        discovery = body["discovery"]
        assert discovery["vendor"] == "Huawei"
        assert discovery["model"] == "S5732-H48XUM2CC"
        created = http.post(
            f"{API}/devices",
            json={
                "name": "slice-core-s5732",
                "device_type": "core_switch",
                "adapter_key": ADAPTER_KEY,
                "management_endpoint": SIM_HOST,
                "connection_config": connection_config,
                "credentials": CREDENTIALS,
                "enabled": True,
                "probe_token": body["probe_token"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201, created.text
        saved = created.json()
        assert saved["readiness"] == "ready"
        capabilities = http.get(f"{API}/devices/{saved['id']}/capabilities")
        assert capabilities.status_code == 200
        items = capabilities.json()["items"]
        by_key = {item["capability_key"]: item for item in items}
        assert len(items) == 35  # 22 metrics + 3 events + 10 operations
        for key in (
            "system.cpu_percent",
            "interface.in_bps",
            "transceiver.rx_dbm",
            "fan.rpm",
            "stp.port_state",
            "event.port_flap",
            "event.device_restart",
            "event.auth_failure",
        ):
            assert by_key[key]["support_state"] == "supported", key
        assert by_key["device.restart"]["support_state"] == "not_configured"
        assert by_key["device.restart"]["reason_code"] == "ssh_unconfigured"
        return uuid.UUID(saved["id"])

    # -- collection runs ----------------------------------------------------

    def _run_two_metric_collects(
        self,
        factory,
        device_id: uuid.UUID,
        settings: WardenSettings,
        keyring: CredentialKeyring,
    ) -> None:
        base = datetime.datetime.now(UTC)
        for index in range(2):
            with factory() as session:
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
            with factory() as session:
                claimed = claim_collection_run(session, lease_owner="m5t2-slice", lease_seconds=300)
                assert claimed is not None and claimed.id == run_id
                session.commit()
            with factory() as session:
                now = base + datetime.timedelta(seconds=60 * index)
                run_collection(session, run_id, settings=settings, keyring=keyring, now=now)
                session.commit()

    # -- psql evidence --------------------------------------------------------

    def _assert_psql_evidence(self, factory, device_id: uuid.UUID) -> None:
        with factory() as session:
            runs = session.execute(
                text(
                    "SELECT state, success_count, failure_count FROM collection_runs "
                    "WHERE device_id = :id ORDER BY scheduled_at"
                ),
                {"id": device_id},
            ).all()
            states = [dict(row._mapping) for row in runs]
            assert len(states) == 2
            # Run 1: everything but bps succeeded; bps cache miss -> errors.
            assert states[0]["state"] == "partial"
            assert states[0]["failure_count"] > 0 and states[0]["success_count"] > 0
            # Run 2: rates derived -> fully succeeded.
            assert states[1]["state"] == "succeeded"
            assert states[1]["failure_count"] == 0

            latest = session.execute(
                text(
                    "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, ml.quality, "
                    "c.kind, c.native_id "
                    "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                    "WHERE ml.device_id = :id ORDER BY ml.metric_key, c.native_id"
                ),
                {"id": device_id},
            ).all()
            rows = [dict(row._mapping) for row in latest]
            by_key: dict[tuple[str, str | None], dict[str, object]] = {}
            for row in rows:
                by_key[(str(row["metric_key"]), row["native_id"])] = row
            bps_row = by_key[("interface.in_bps", "GigabitEthernet0/0/1")]
            assert bps_row["quality"] == "good"
            assert bps_row["unit"] == "bit/s"
            assert bps_row["value_double"] == pytest.approx(STEP * 8.0 / 60.0)
            out_bps = by_key[("interface.out_bps", "GigabitEthernet0/0/1")]
            assert out_bps["quality"] == "good"
            # Rates appeared for every port after the second collect.
            port_bps = [row for row in rows if row["metric_key"] == "interface.in_bps"]
            assert len(port_bps) == 52
            assert all(row["quality"] == "good" for row in port_bps)
            assert by_key[("system.cpu_percent", None)]["value_double"] == 12
            assert by_key[("interface.oper_status", "GigabitEthernet0/0/1")]["value_text"] == "up"
            assert by_key[("transceiver.rx_dbm", "XGigabitEthernet0/0/1")]["value_double"] == pytest.approx(-2.5)

            components = session.execute(
                text("SELECT kind, native_id, status FROM components WHERE device_id = :id"),
                {"id": device_id},
            ).all()
            comp_rows = [dict(row._mapping) for row in components]
            assert any(
                c["kind"] == "interface" and c["native_id"] == "GigabitEthernet0/0/1" for c in comp_rows
            )
            assert any(c["kind"] == "fan" and c["native_id"] == "FAN1" and c["status"] == "ok" for c in comp_rows)

            errors = session.execute(
                text(
                    "SELECT metric_key_or_event_key, error_code FROM collection_observation_errors "
                    "WHERE device_id = :id AND metric_key_or_event_key IN "
                    "('interface.in_bps','interface.out_bps')"
                ),
                {"id": device_id},
            ).all()
            error_rows = [dict(row._mapping) for row in errors]
            assert len(error_rows) == 104  # 52 ports x 2 directions, first run only
            assert all(str(row["error_code"]) == "not_configured" for row in error_rows)

    # -- ingest path (CORE-MON-06) -------------------------------------------

    def _ingest_syslog_event(self, factory, settings: WardenSettings, device_id: uuid.UUID) -> None:
        hosted = IngestHost(settings)
        hosted.start()
        try:
            udp_port = hosted.service.syslog.udp_port
            assert udp_port and udp_port > 0
            line = vrp_link_state_line(
                hostname="sim-s5732",
                interface="GigabitEthernet0/0/1",
                direction="down",
                when=datetime.datetime(2026, 9, 4, 6, 30, 0, tzinfo=UTC),
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(line.encode("utf-8"), (SIM_HOST, int(udp_port)))

            def _find() -> list[dict[str, object]]:
                with factory() as session:
                    rows = session.execute(
                        text(
                            "SELECT e.event_type, e.severity, e.source, "
                            "e.detail->>'component_native_id' AS component_native_id, e.message "
                            "FROM device_events e WHERE e.device_id = :id"
                        ),
                        {"id": device_id},
                    ).all()
                    return [dict(row._mapping) for row in rows]

            deadline = time.monotonic() + 20.0
            events: list[dict[str, object]] = []
            while time.monotonic() < deadline:
                events = _find()
                if events:
                    break
                time.sleep(0.2)
            assert events, "no ingested event rows appeared"
            row = events[0]
            assert row["event_type"] == "event.port_flap"
            assert row["source"] == "syslog"
            assert row["severity"] == "warning"
            assert row["component_native_id"] == "GigabitEthernet0/0/1"
            assert "down" in str(row["message"])
        finally:
            hosted.stop()
