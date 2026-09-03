"""Platform E2E slice over the real DSM path (M4T2, real PostgreSQL).

End-to-end through the M2T2 pipeline (probe -> save -> enable -> collection
run -> metric_latest -> alerts) with the registered ``nas.synology_dsm``
adapter talking to the TEST-DEVICE DSM simulator (ds224plus profile): psql
evidence of metric_latest rows with contract units/enums, the degraded
knob's status.problem alerts, and the honest fan-rpm-0 rule (device-reported
0 rpm is data; it never opens an alert — fan.rpm alert_policy=none). NAS
reachability/health and logs runs emit ONLY connectivity observations:
the slice asserts such runs never regress the devices.health column
(connectivity is reachability evidence, not health evidence —
PRODUCT_DESIGN.md §6.2, M4T2 controller ruling).

The simulator runs on 127.0.0.1. The SSRF policy HARD-denies loopback —
this test's settings declare ``allowed_device_cidrs=127.0.0.1/32`` and
gate the simulator endpoint in via a resolve_endpoint monkeypatch scoped
to this module (same approach as the M3T2/M3T5 platform slices; the
loopback deny-list itself stays untouched).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
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
from tests.simulators.dsm.serving import serve_simulator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
ADAPTER_KEY = "nas.synology_dsm"


@pytest.fixture()
def sim_url() -> str:
    with serve_simulator() as url:
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
    factory: sessionmaker[Session],
    *,
    device_id: uuid.UUID,
    collection_type: str,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    scheduled_at: datetime.datetime,
    owner: str = "m4t2-e2e-worker",
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
    """psql evidence for the M4T2 report (recorded verbatim)."""
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
    print(f"\n=== M4T2-E2E evidence: {label} ===")
    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))


def _onboard(
    client: TestClient,
    *,
    port: int,
    csrf: str,
    name: str,
) -> tuple[dict[str, object], uuid.UUID]:
    """Probe the ds224plus-profile simulator and save+enable the device."""
    probe = client.post(
        f"{API}/device-probes",
        json={
            "device_type": "synology_nas",
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
    assert body["ok"] is True, body
    assert {stage["stage"] for stage in body["stages"]} == {
        "network",
        "tls",
        "auth",
        "identity",
        "capabilities",
    }
    discovery = body["discovery"]
    assert discovery["vendor"] == "Synology"
    assert discovery["model"] == "DS224+ (simulated)"
    assert discovery["serial_number"] == "SIM-DS224P-0001"
    assert len(discovery["capabilities"]) == 24
    supported = {item["capability_key"] for item in discovery["capabilities"] if item["support_state"] == "supported"}
    assert supported == {
        "disk.status",
        "disk.smart",
        "disk.bad_sectors",
        "storage_pool.status",
        "raid.status",
        "raid.rebuild_progress",
        "temperature.system",
        "fan.rpm",
        "fan.status",
        "volume.usage_percent",
        "shared_folder.usage_percent",
        "ups.status",
        "connectivity.management",
        # NAS-ACT operation rows (M4T3): supported when the certified source
        # API is callable on the discovered device.
        "power.restart",
        "power.shutdown",
        "console.dsm.open",
        "logs.support_bundle.collect",
        "disk.smart_test.quick",
        "disk.smart_test.full",
        "backup.status.refresh",
        "firmware.update",
        "snmp.configure",
        "event.system_log",
    }
    psu = next(item for item in discovery["capabilities"] if item["capability_key"] == "psu.status")
    assert psu["support_state"] == "unsupported"
    assert psu["reason_code"] == "no_webapi_source"

    created = client.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": "synology_nas",
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
    return body, device_id


class TestDsmPlatformSlice:
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

                _body, device_id = _onboard(client, port=port, csrf=csrf, name="sim-dsm-nas")

                caps = client.get(f"{API}/devices/{device_id}/capabilities")
                assert caps.status_code == 200
                cap_items = caps.json()["items"]
                assert len(cap_items) == 24

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
                    _print_evidence("onboarded-ds224plus", evidence_onboard)
                    assert len(components) == 9
                    assert (
                        session.execute(
                            text(
                                "SELECT count(*) FROM device_capabilities "
                                "WHERE device_id = :id AND support_state = 'supported'"
                            ),
                            {"id": device_id},
                        ).scalar()
                        # 14 monitoring rows + 9 NAS-ACT operation rows (M4T3).
                        == 23
                    )

                # Connectivity-only health run FIRST (the real 30 s cadence):
                # NAS health runs emit ONLY connectivity.management, which is
                # reachability evidence — never health evidence. The seeded
                # health stays untouched (no healthy-from-connectivity,
                # PRODUCT_DESIGN.md §6.2 health evidence gate).
                now = utcnow()
                connectivity_run = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="health",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now,
                )
                assert connectivity_run["state"] == "succeeded", connectivity_run
                with factory() as session:
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "unknown"
                    _print_evidence("connectivity-only-health-run", _evidence(session, device_id))

                # Metrics run on the ds224plus HEALTHY surface: latest rows
                # with contract units + connectivity true, no errors.
                healthy_run = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="metrics",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=1),
                )
                assert healthy_run["state"] == "succeeded", healthy_run
                with factory() as session:
                    device = session.execute(
                        text("SELECT health, reachability FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    device_map = dict(device._mapping)
                    assert device_map["reachability"] == "online"
                    assert device_map["health"] == "healthy"
                    rows = session.execute(
                        text(
                            "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, "
                            "c.kind, c.native_id "
                            "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                            "WHERE ml.device_id = :id ORDER BY ml.metric_key, c.kind, c.native_id"
                        ),
                        {"id": device_id},
                    ).all()
                    by_key: dict[tuple[str, str | None, str | None], dict[str, object]] = {}
                    for row in rows:
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
                    assert by_key[("temperature.system", "sensor", "system")]["value_double"] == 41.0
                    assert by_key[("temperature.system", "sensor", "system")]["unit"] == "Cel"
                    assert by_key[("disk.status", "disk", "sata1")]["value_text"] == "ok"
                    assert by_key[("disk.smart", "disk", "sata1")]["value_text"] == "passed"
                    assert by_key[("disk.bad_sectors", "disk", "sata1")]["value_double"] == 0
                    assert by_key[("storage_pool.status", "storage_pool", "pool1")]["value_text"] == "optimal"
                    assert by_key[("volume.usage_percent", "volume", "vol1")]["value_double"] == 37.5
                    assert by_key[("volume.usage_percent", "volume", "vol1")]["unit"] == "%"
                    assert by_key[("shared_folder.usage_percent", "shared_folder", "homes")]["value_double"] == 50.0
                    assert by_key[("fan.rpm", "fan", "1")]["value_double"] == 2100.0
                    assert by_key[("fan.rpm", "fan", "1")]["unit"] == "r/min"
                    assert by_key[("fan.status", "fan", "1")]["value_text"] == "ok"
                    assert by_key[("ups.status", None, None)]["value_text"] == "normal"
                    assert by_key[("connectivity.management", None, None)]["value_text"] == "true"
                    # psu.status never becomes a metric row (no source).
                    psu_rows = session.execute(
                        text("SELECT count(*) FROM metric_latest WHERE device_id = :id AND metric_key = 'psu.status'"),
                        {"id": device_id},
                    ).scalar()
                    assert psu_rows == 0

                # Degraded knob: disk critical + pool degraded + fan broken
                # (0 rpm device data) + UPS on battery -> status.problem rows.
                _control(sim_url, profile="degraded")
                degraded_run = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="metrics",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=2),
                )
                assert degraded_run["state"] == "succeeded", degraded_run
                with factory() as session:
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "critical"
                    active = session.execute(
                        text(
                            "SELECT rule_key, severity, evidence FROM alerts "
                            "WHERE device_id = :id AND status = 'active' ORDER BY rule_key, severity"
                        ),
                        {"id": device_id},
                    ).all()
                    active_rows = [dict(r._mapping) for r in active]
                    problem_severities = {
                        str(row["severity"]) for row in active_rows if row["rule_key"] == "status.problem"
                    }
                    assert "critical" in problem_severities
                    assert "warning" in problem_severities  # degraded pool / UPS on battery
                    evidence_metric_keys = [
                        str(row["evidence"].get("metric_key"))
                        for row in active_rows
                        if isinstance(row["evidence"], dict)
                    ]
                    assert "disk.status" in evidence_metric_keys
                    assert "disk.smart" in evidence_metric_keys
                    # fan rpm 0 is DEVICE-REPORTED data and is NOT an alert:
                    # no active alert may be attributable to the numeric fan
                    # rpm metric (ADR-025: no invented thresholds).
                    assert "fan.rpm" not in evidence_metric_keys
                    # The broken fan's status alert comes from the device text.
                    assert "fan.status" in evidence_metric_keys
                    # 0 rpm stored as the honest device reading (quality good).
                    zero_rows = session.execute(
                        text(
                            "SELECT ml.metric_key, ml.value_double, ml.quality "
                            "FROM metric_latest ml WHERE ml.device_id = :id AND ml.value_double = 0"
                        ),
                        {"id": device_id},
                    ).all()
                    zero_map = {str(r._mapping["metric_key"]): str(r._mapping["quality"]) for r in zero_rows}
                    assert zero_map == {"fan.rpm": "good", "disk.bad_sectors": "good"}
                    _print_evidence("metrics-degraded", _evidence(session, device_id))

                # Logs run: DSM log import with native ids; a forced full
                # re-read dedupes on the platform side. The logs run also
                # carries ONLY connectivity observations — while the disk is
                # still degraded the health column must NOT regress
                # (health evidence gate, PRODUCT_DESIGN.md §6.2).
                logs_run = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="logs",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=3),
                )
                assert logs_run["state"] == "succeeded", logs_run
                with factory() as session:
                    count = session.execute(
                        text(
                            "SELECT count(*), count(DISTINCT native_event_id) FROM device_events WHERE device_id = :id"
                        ),
                        {"id": device_id},
                    ).one()
                    assert tuple(count) == (24, 24)
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "critical"
                    session.execute(
                        text("UPDATE devices SET collection_state = collection_state::jsonb - 'logs' WHERE id = :id"),
                        {"id": device_id},
                    )
                    session.commit()

                # Connectivity-only health run while STILL degraded: the
                # regression — connectivity must never refresh health to
                # healthy between metrics runs (the M4T2 controller ruling).
                degraded_health_run = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="health",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=4),
                )
                assert degraded_health_run["state"] == "succeeded", degraded_health_run
                with factory() as session:
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "critical"
                    _print_evidence("degraded-health-run-connectivity-only", _evidence(session, device_id))

                logs_run2 = _claim_and_run(
                    factory,
                    device_id=device_id,
                    collection_type="logs",
                    settings=settings,
                    keyring=keyring,
                    scheduled_at=now + datetime.timedelta(seconds=5),
                )
                assert logs_run2["state"] == "succeeded", logs_run2
                with factory() as session:
                    count = session.execute(
                        text("SELECT count(*) FROM device_events WHERE device_id = :id"),
                        {"id": device_id},
                    ).one()
                    assert tuple(count) == (24,)

                # fan_zero_rpm on the healthy surface: 0 rpm stays data and
                # two good signals resolve the status.problem alerts. The
                # degraded knobs are switched off explicitly (profile
                # switches only force profile-owned knobs).
                _control(
                    sim_url,
                    profile="ds224plus",
                    storage_degraded=False,
                    ups_on_battery=False,
                    fan_broken=False,
                    fan_zero_rpm=True,
                )
                for index in range(2):
                    healthy_again = _claim_and_run(
                        factory,
                        device_id=device_id,
                        collection_type="metrics",
                        settings=settings,
                        keyring=keyring,
                        scheduled_at=now + datetime.timedelta(seconds=6 + index),
                    )
                    assert healthy_again["state"] == "succeeded", healthy_again
                with factory() as session:
                    device = session.execute(
                        text("SELECT health FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    assert dict(device._mapping)["health"] == "healthy"
                    active_remaining = session.execute(
                        text("SELECT count(*) FROM alerts WHERE device_id = :id AND status = 'active'"),
                        {"id": device_id},
                    ).scalar()
                    assert int(active_remaining) == 0
                    zero_rows = session.execute(
                        text(
                            "SELECT count(*) FROM metric_latest "
                            "WHERE device_id = :id AND metric_key = 'fan.rpm' AND value_double = 0"
                        ),
                        {"id": device_id},
                    ).scalar()
                    assert int(zero_rows) == 2  # both fans report 0 rpm
                    _print_evidence("resolved-healthy", _evidence(session, device_id))
        finally:
            time.sleep(0.1)
            engine = app.state.engine
            if engine is not None:
                engine.dispose()
