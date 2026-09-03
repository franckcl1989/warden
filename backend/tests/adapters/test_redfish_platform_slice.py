"""Platform E2E slice over the real Redfish path (M3T2, real PostgreSQL).

End-to-end through the M2T2 pipeline (probe -> save -> enable -> collection
run -> metric_latest -> alerts) with the registered ``server.redfish``
adapter talking to the TEST-DEVICE simulator: onboarding via the real device
API, then claim + run_collection through the real collection application
layer, then psql evidence of metric_latest rows (contract units) and alerts.

The simulator runs on 127.0.0.1. The SSRF policy (network_policy.py) HARD-
denies loopback even when the deployment allowlist names it — this test's
settings declare ``allowed_device_cidrs=127.0.0.1/32`` (per the M3T2 brief)
and additionally gate the simulator endpoint in via a resolve_endpoint
monkeypatch scoped to this module: the loopback deny-list itself is
production semantics covered by its own unit tests and stays untouched.
"""

from __future__ import annotations

import datetime
import ipaddress
import time
import uuid
from urllib.parse import urlsplit

import httpx
import pytest
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.observation_store import claim_collection_run
from app.infrastructure.time import utcnow
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin, login_csrf
from tests.simulators.redfish.app import SimulatorConfig
from tests.simulators.redfish.serving import serve_simulator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "server.redfish"


@pytest.fixture()
def sim_url() -> str:
    with serve_simulator(SimulatorConfig(profile="healthy")) as url:
        yield url


def _port_of(url: str) -> int:
    parsed = urlsplit(url)
    assert parsed.port is not None
    return parsed.port


def _control(url: str, **knobs: object) -> None:
    with httpx.Client(base_url=url, timeout=10.0) as client:
        response = client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text


def _allow_simulator_resolution(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    """Gate ONLY the loopback simulator into the probe resolution step."""

    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[ipaddress.IPv4Address, int]:
        del self, host, requested_port, allowed_ports
        return ipaddress.ip_address(SIM_HOST), port

    monkeypatch.setattr(DeviceEndpointPolicy, "resolve_endpoint", resolve)


def _claim_and_run(
    session: Session,
    *,
    run_id: uuid.UUID,
    settings: WardenSettings,
    keyring: CredentialKeyring,
) -> None:
    run = session.get(CollectionRunModel, run_id)
    assert run is not None
    from app.application.collection import run_collection

    run_collection(session, run_id, settings=settings, keyring=keyring, now=utcnow())
    session.commit()


def _create_and_run(
    factory: sessionmaker[Session],
    *,
    device_id: uuid.UUID,
    collection_type: str,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    scheduled_at: datetime.datetime,
    owner: str = "m3t2-e2e-worker",
) -> dict[str, object]:
    """One run through the real pipeline: insert scheduled row -> claim ->
    run_collection (claim and execute in separate sessions like the worker)."""
    from app.models.observation import CollectionRun

    run_id: uuid.UUID | None = None
    with factory() as session:
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
    with factory() as session_a:
        claimed = claim_collection_run(session_a, lease_owner=owner, lease_seconds=300)
        assert claimed is not None and claimed.id == run_id
        session_a.commit()
    with factory() as session_b:
        from app.application.collection import run_collection

        run_collection(session_b, run_id, settings=settings, keyring=keyring, now=utcnow())
        session_b.commit()
    with factory() as session_c:
        row = session_c.get(CollectionRun, run_id)
        assert row is not None
        return {
            "id": row.id,
            "state": row.state,
            "success_count": row.success_count,
            "failure_count": row.failure_count,
            "error_code": row.error_code,
        }


def _keyring_from_file(settings: WardenSettings) -> CredentialKeyring:
    material = settings.credential_master_key.get_secret_value().encode("utf-8")
    return CredentialKeyring.from_current(CredentialCipher(material))


def _evidence(session: Session, device_id: uuid.UUID) -> dict[str, object]:
    """psql evidence for the M3T2 report (recorded verbatim)."""
    device = session.execute(
        text(
            "SELECT name, adapter_key, vendor, model, readiness, enabled, reachability, health "
            "FROM devices WHERE id = :id"
        ),
        {"id": device_id},
    ).one()
    latest = session.execute(
        text(
            "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, ml.quality, "
            "c.kind, c.native_id "
            "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
            "WHERE ml.device_id = :id ORDER BY ml.metric_key, c.kind, c.native_id"
        ),
        {"id": device_id},
    ).all()
    alerts = session.execute(
        text(
            "SELECT rule_key, severity, status, count(*) AS n "
            "FROM alerts WHERE device_id = :id GROUP BY rule_key, severity, status ORDER BY rule_key"
        ),
        {"id": device_id},
    ).all()
    events = session.execute(
        text(
            "SELECT severity, count(*) AS n, count(DISTINCT native_event_id) AS distinct_ids "
            "FROM device_events WHERE device_id = :id GROUP BY severity ORDER BY severity"
        ),
        {"id": device_id},
    ).all()
    errors = session.execute(
        text(
            "SELECT metric_key_or_event_key, error_code, count(*) AS n "
            "FROM collection_observation_errors WHERE device_id = :id "
            "GROUP BY metric_key_or_event_key, error_code ORDER BY metric_key_or_event_key"
        ),
        {"id": device_id},
    ).all()
    runs = session.execute(
        text(
            "SELECT collection_type, state, success_count, failure_count "
            "FROM collection_runs WHERE device_id = :id ORDER BY scheduled_at"
        ),
        {"id": device_id},
    ).all()
    return {
        "device": dict(device._mapping),
        "metric_latest": [dict(row._mapping) for row in latest],
        "alerts": [dict(row._mapping) for row in alerts],
        "events": [dict(row._mapping) for row in events],
        "errors": [dict(row._mapping) for row in errors],
        "runs": [dict(row._mapping) for row in runs],
    }


def _print_evidence(label: str, evidence: dict[str, object]) -> None:
    print(f"\n=== M3T2-E2E evidence: {label} ===")
    import json

    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))


class TestRedfishPlatformSlice:
    def test_probe_save_enable_collect_alert_and_logs(
        self,
        fresh_test_db_dsn: str,
        sim_url: str,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
    ) -> None:
        port = _port_of(sim_url)
        _allow_simulator_resolution(monkeypatch, port)
        key_file = tmp_path / "credential_master.key"
        key_file.write_text("K" * 64, encoding="utf-8")
        session_file = tmp_path / "session_secret.txt"
        session_file.write_text("S" * 64, encoding="utf-8")
        settings = WardenSettings(
            postgres_dsn=fresh_test_db_dsn,
            app_env="development",
            public_url="http://localhost",
            _env_file=None,
            allowed_device_cidrs=f"{SIM_HOST}/32",
            credential_master_key_file=key_file,
            session_secret_file=session_file,
        )
        app = create_app(settings)
        factory = create_session_factory(create_engine(dsn_with_psycopg_dialect(fresh_test_db_dsn)))
        keyring = _keyring_from_file(settings)

        with factory() as session:
            create_admin(session)
        try:
            with TestClient(app) as client:
                response, csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                assert response.status_code == 200

                # probe (healthy profile) -> save -> enable via the real API
                probe = client.post(
                    f"{API}/device-probes",
                    json={
                        "device_type": "server",
                        "adapter_key": ADAPTER_KEY,
                        "management_endpoint": SIM_HOST,
                        "port": port,
                        "connection_config": {"protocol": "http"},
                        "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                assert probe.status_code == 200, probe.text
                body = probe.json()
                assert body["ok"] is True
                assert {stage["stage"] for stage in body["stages"]} == {
                    "network",
                    "tls",
                    "auth",
                    "identity",
                    "capabilities",
                }
                discovery = body["discovery"]
                assert discovery["vendor"] == "Warden Simulator"
                assert discovery["serial_number"] == "WARDEN-SIM-0001"
                assert len(discovery["capabilities"]) == 31

                created = client.post(
                    f"{API}/devices",
                    json={
                        "name": "sim-redfish-srv",
                        "device_type": "server",
                        "adapter_key": ADAPTER_KEY,
                        "management_endpoint": SIM_HOST,
                        "port": port,
                        "connection_config": {"protocol": "http"},
                        "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
                        "enabled": True,
                        "probe_token": body["probe_token"],
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                assert created.status_code == 201, created.text
                device_view = created.json()
                device_id = uuid.UUID(device_view["id"])
                assert device_view["readiness"] == "ready"
                assert device_view["enabled"] is True
                assert device_view["adapter_key"] == ADAPTER_KEY

                caps = client.get(f"{API}/devices/{device_id}/capabilities")
                assert caps.status_code == 200
                cap_items = caps.json()["items"]
                assert len(cap_items) == 31
                assert all(item["support_state"] == "supported" for item in cap_items)

                with factory() as session:
                    evidence_onboard = _evidence(session, device_id)
                    components = session.execute(
                        text(
                            "SELECT kind, native_id, status FROM components "
                            "WHERE device_id = :id AND retired_at IS NULL "
                            "ORDER BY kind, native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    evidence_onboard["components"] = [dict(r._mapping) for r in components]
                    _print_evidence("onboarded-healthy", evidence_onboard)
                    assert len(components) == 21
                    assert (
                        session.execute(
                            text(
                                "SELECT count(*) FROM device_capabilities "
                                "WHERE device_id = :id AND support_state = 'supported'"
                            ),
                            {"id": device_id},
                        ).scalar()
                        == 31
                    )

                # Switch the simulator to the critical profile.
                _control(sim_url, profile="critical")

                # Metrics run on the CRITICAL profile: latest rows + alerts.
                now = utcnow()
                metrics_run = _create_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="metrics",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now,
                )
                assert metrics_run["state"] == "succeeded", metrics_run
                with factory() as session:
                    device = session.execute(
                        text("SELECT health, reachability FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "critical"
                    latest = session.execute(
                        text(
                            "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, "
                            "c.kind, c.native_id "
                            "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                            "WHERE ml.device_id = :id AND ml.metric_key IN "
                            "('temperature.cpu','psu.load_w','psu.voltage_v','fan.rpm',"
                            "'drive.status','memory.status','indicator.led','health.overall',"
                            "'chassis.intrusion','psu.present','drive.smart','raid.status') "
                            "ORDER BY ml.metric_key, c.kind, c.native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    by_key: dict[tuple[str, str | None, str | None], dict[str, object]] = {}
                    for row in latest:
                        mapped = dict(row._mapping)
                        metric = mapped["metric_key"]
                        kind = mapped["kind"]
                        native = mapped["native_id"]
                        by_key[
                            (
                                str(metric),
                                kind if isinstance(kind, str) else None,
                                native if isinstance(native, str) else None,
                            )
                        ] = mapped
                    assert by_key[("temperature.cpu", "processor", "cpu-1")]["value_double"] == 93
                    assert by_key[("temperature.cpu", "processor", "cpu-1")]["unit"] == "Cel"
                    assert by_key[("psu.load_w", "psu", "PSU1")]["value_double"] == 260
                    assert by_key[("psu.load_w", "psu", "PSU1")]["unit"] == "W"
                    assert by_key[("psu.voltage_v", "psu", "PSU1")]["value_double"] == 12.2
                    assert by_key[("fan.rpm", "fan", "FAN3")]["value_double"] == 800
                    assert by_key[("fan.rpm", "fan", "FAN3")]["unit"] == "r/min"
                    assert by_key[("drive.status", "drive", "sdb")]["value_text"] == "critical"
                    assert by_key[("drive.smart", "drive", "sdb")]["value_text"] == "failed"
                    assert by_key[("memory.status", "memory", "DIMM1")]["value_text"] == "critical"
                    assert by_key[("indicator.led", None, None)]["value_text"] == "critical"
                    assert by_key[("chassis.intrusion", None, None)]["value_text"] == "detected"
                    assert by_key[("psu.present", "psu", "PSU2")]["value_text"] == "absent"
                    assert by_key[("health.overall", None, None)]["value_text"] == "critical"
                    assert by_key[("raid.status", "raid", "RAID6_1")]["value_text"] == "degraded"
                    # No fabricated zero/healthy rows on the critical surface.
                    zero_or_ok = session.execute(
                        text(
                            "SELECT metric_key, value_text FROM metric_latest "
                            "WHERE device_id = :id AND value_double = 0"
                        ),
                        {"id": device_id},
                    ).all()
                    assert zero_or_ok == []

                    active = session.execute(
                        text(
                            "SELECT rule_key, severity FROM alerts "
                            "WHERE device_id = :id AND status = 'active' "
                            "ORDER BY rule_key"
                        ),
                        {"id": device_id},
                    ).all()
                    active_map = {str(r._mapping["rule_key"]): str(r._mapping["severity"]) for r in active}
                    assert active_map.get("device.health") == "critical"
                    assert "status.problem" in active_map
                    assert len(active) >= 3  # device.health + several status problems
                    _print_evidence("metrics-critical", _evidence(session, device_id))

                # Logs run: SEL import; a forced full re-read dedupes by native id.
                logs_run = _create_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="logs",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=1),
                )
                assert logs_run["state"] == "succeeded", logs_run
                with factory() as session:
                    count = session.execute(
                        text(
                            "SELECT count(*), count(DISTINCT native_event_id) FROM device_events "
                            "WHERE device_id = :id"
                        ),
                        {"id": device_id},
                    ).one()
                    assert tuple(count) == (25, 25)
                    # Force the adapter to re-read the whole SEL (last_run_at
                    # cleared) — the platform dedupes on native ids.
                    session.execute(
                        text(
                            "UPDATE devices SET collection_state = collection_state::jsonb - 'logs' "
                            "WHERE id = :id"
                        ),
                        {"id": device_id},
                    )
                    session.commit()
                logs_run2 = _create_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="logs",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=2),
                )
                assert logs_run2["state"] == "succeeded", logs_run2
                with factory() as session:
                    count = session.execute(
                        text(
                            "SELECT count(*), count(DISTINCT native_event_id) FROM device_events "
                            "WHERE device_id = :id"
                        ),
                        {"id": device_id},
                    ).one()
                    assert tuple(count) == (25, 25)

                # Back to healthy: two good signals resolve the health alert.
                _control(sim_url, profile="healthy")
                first_healthy = _create_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="metrics",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=3),
                )
                assert first_healthy["state"] == "succeeded"
                with factory() as session:
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "healthy"
                    health_alerts = session.execute(
                        text(
                            "SELECT status, signal_count FROM alerts "
                            "WHERE device_id = :id AND rule_key = 'device.health' "
                            "ORDER BY version DESC LIMIT 1"
                        ),
                        {"id": device_id},
                    ).one()
                    # resolve_after=2: the first good signal only counts.
                    assert dict(health_alerts._mapping)["status"] == "active"
                    second_healthy = _create_and_run(
                        factory,
                        device_id=device_id,
                        collection_type="metrics",
                        settings=settings,
                        keyring=keyring,
                        scheduled_at=now + datetime.timedelta(seconds=4),
                    )
                    assert second_healthy["state"] == "succeeded"
                    health_alerts = session.execute(
                        text(
                            "SELECT status FROM alerts "
                            "WHERE device_id = :id AND rule_key = 'device.health' "
                            "ORDER BY version DESC LIMIT 1"
                        ),
                        {"id": device_id},
                    ).one()
                    assert dict(health_alerts._mapping)["status"] == "resolved"
                    _print_evidence("resolved-healthy", _evidence(session, device_id))
        finally:
            time.sleep(0.1)
            engine = app.state.engine
            if engine is not None:
                engine.dispose()


from app.models.observation import CollectionRun as CollectionRunModel  # noqa: E402
