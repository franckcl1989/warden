"""Overview / alerts / components / events API integration tests.

Covers overview_get (real-table stats, per-type summary, attention ordering
离线 > 严重 > 警告 > 数据过期, empty recent operations until M2T4),
alerts_list/alerts_get (engine rows only, filters, detail with evidence and
timeline, 404s), device_components_list and device_events_list (pagination,
kind/status and severity/type/source/time filters) and monitor.read
permissions (viewer ok, unauthenticated 401).
"""

from __future__ import annotations

import datetime
import uuid

from app.models.devices import Component, Device
from app.models.observation import Alert, CollectionRun, DeviceEvent
from app.models.operation import OperationTask
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    create_admin,
    create_user,
    login,
)
from tests.observation_factories import make_collection_device
from tests.task_factories import make_user

API = "/api/v1"
UTC = datetime.UTC


def _login_viewer(client: TestClient, db: Session) -> None:
    create_admin(db)
    create_user(db, username="viewer1", password=ADMIN_PASSWORD, role="viewer")
    response = login(client, "viewer1", ADMIN_PASSWORD)
    assert response.status_code == 200


def _make_device(
    db: Session,
    *,
    index: int,
    device_type: str = "server",
    name: str | None = None,
    reachability: str = "unknown",
    health: str = "unknown",
    vendor: str | None = "Fake",
    model: str | None = None,
) -> Device:
    device = Device(
        name=name or f"overview-dev-{index}",
        device_type=device_type,
        vendor=vendor,
        model=model,
        management_endpoint=f"10.9.{index // 250}.{index % 250 + 1}",
        adapter_key="fake.simple",
        connection_config={},
        enabled=True,
        readiness="ready",
        reachability=reachability,
        health=health,
        last_collected_at=datetime.datetime.now(UTC),
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def _alert(
    db: Session,
    *,
    device: Device,
    rule_key: str,
    severity: str,
    title: str,
    status: str = "active",
    first_occurred_at: datetime.datetime | None = None,
    resolved_at: datetime.datetime | None = None,
    component_id: uuid.UUID | None = None,
) -> Alert:
    stamp = first_occurred_at or datetime.datetime.now(UTC) - datetime.timedelta(hours=1)
    alert = Alert(
        device_id=device.id,
        component_id=component_id,
        rule_key=rule_key,
        severity=severity,
        status=status,
        title=title,
        evidence={"observed": True, "rule_key": rule_key},
        first_occurred_at=stamp,
        last_occurred_at=stamp,
        resolved_at=resolved_at,
        dedupe_key=f"{rule_key}:{device.id}:{title}",
        signal_count=0,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


class TestOverview:
    def test_overview_stats_match_seeded_state(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        online_ok = _make_device(db, index=1, reachability="online", health="healthy")
        offline_critical = _make_device(db, index=2, reachability="offline", health="critical")
        unknown_unknown = _make_device(db, index=3, reachability="unknown", health="unknown")
        warning_nas = _make_device(db, index=4, device_type="synology_nas", reachability="online", health="warning")
        _alert(db, device=offline_critical, rule_key="device.offline", severity="critical", title="设备离线")
        _alert(db, device=offline_critical, rule_key="device.health", severity="critical", title="设备健康异常")
        user = make_user(db, index=4)
        # The device mutex (uq_operation_tasks_active_mutex) allows one active
        # task per (device, conflict_scope): spread the open states across
        # devices.
        targets = [online_ok, warning_nas, unknown_unknown]
        for state, target in zip(
            ("running", "waiting_device", "verification_required"), targets, strict=True
        ):
            db.add(
                OperationTask(
                    requirement_id="SRV-ACT-02",
                    capability_key="power.on",
                    device_id=target.id,
                    requested_by=user.id,
                    risk_level="high",
                    parameters={},
                    idempotency_key=f"overview-task-{state}-4",
                    conflict_scope="device",
                    state=state,
                )
            )
        db.commit()

        response = client.get(f"{API}/overview")

        assert response.status_code == 200
        body = response.json()
        stats = body["stats"]
        assert stats["device_total"] == 4
        assert stats["reachability"] == {"online": 2, "offline": 1, "unknown": 1}
        assert stats["health"] == {"healthy": 1, "warning": 1, "critical": 1, "unknown": 1}
        assert stats["active_critical_alerts"] == 2  # both engine rows are critical
        assert stats["operations_running"] == 2
        assert stats["operations_verification_required"] == 1
        server = body["device_types"]["server"]
        assert server["reachability"] == {"online": 1, "offline": 1, "unknown": 1}
        nas = body["device_types"]["synology_nas"]
        assert nas["reachability"] == {"online": 1, "offline": 0, "unknown": 0}
        assert body["device_types"]["core_switch"]["reachability"] == {
            "online": 0,
            "offline": 0,
            "unknown": 0,
        }
        assert body["recent_operations"] == []  # M2T4 fills this
        assert body["as_of"] is not None

    def test_overview_attention_ordering_offline_then_critical_then_warning_then_expired(
        self, client_env
    ) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        offline = _make_device(db, index=10, reachability="offline", health="critical")
        critical = _make_device(db, index=11, reachability="online", health="critical")
        warning = _make_device(db, index=12, reachability="online", health="warning")
        expired = _make_device(db, index=13, reachability="online", health="healthy")
        healthy = _make_device(db, index=14, reachability="online", health="healthy")
        offline_alert = _alert(
            db,
            device=offline,
            rule_key="device.offline",
            severity="critical",
            title="设备离线",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=4),
        )
        _alert(
            db,
            device=offline,
            rule_key="data.expired",
            severity="warning",
            title="监控数据过期",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=3),
        )
        _alert(
            db,
            device=critical,
            rule_key="device.health",
            severity="critical",
            title="设备健康异常",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=2),
        )
        _alert(
            db,
            device=warning,
            rule_key="status.problem",
            severity="warning",
            title="设备状态异常",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=1),
        )
        _alert(
            db,
            device=expired,
            rule_key="data.expired",
            severity="warning",
            title="监控数据过期",
            first_occurred_at=datetime.datetime.now(UTC),
        )
        db.commit()

        response = client.get(f"{API}/overview")

        assert response.status_code == 200
        attention = response.json()["attention"]
        assert [item["device"]["id"] for item in attention] == [
            str(offline.id),
            str(critical.id),
            str(warning.id),
            str(expired.id),
        ]
        assert healthy.id not in [item["device"]["id"] for item in attention]
        first = attention[0]
        assert first["device"]["name"] == offline.name
        assert first["rank"] == 0
        # An offline device with stale data still ranks as offline, and its
        # problems carry BOTH engine rows.
        assert [problem["rule_key"] for problem in first["problems"]] == [
            "device.offline",
            "data.expired",
        ]
        assert first["problems"][0]["id"] == str(offline_alert.id)
        assert first["problems"][0]["first_occurred_at"] is not None
        assert attention[1]["rank"] == 1
        assert attention[2]["rank"] == 2
        assert attention[3]["rank"] == 3

    def test_overview_ignores_resolved_alerts(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=20, reachability="offline", health="critical")
        _alert(db, device=device, rule_key="device.offline", severity="critical", title="resolved", status="resolved")
        db.commit()

        response = client.get(f"{API}/overview")

        assert response.status_code == 200
        body = response.json()
        assert body["stats"]["device_total"] == 1
        assert body["stats"]["active_critical_alerts"] == 0
        assert body["attention"] == []


class TestAlertsApi:
    def test_alerts_list_defaults_to_active_and_sorts_by_first_occurred(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=30)
        old = _alert(
            db,
            device=device,
            rule_key="device.health",
            severity="warning",
            title="old-warning",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=5),
        )
        fresh = _alert(
            db,
            device=device,
            rule_key="status.problem",
            severity="critical",
            title="fresh-critical",
            first_occurred_at=datetime.datetime.now(UTC) - datetime.timedelta(hours=1),
        )
        _alert(
            db,
            device=device,
            rule_key="device.health",
            severity="warning",
            title="resolved-warning",
            status="resolved",
            resolved_at=datetime.datetime.now(UTC),
        )
        db.commit()

        response = client.get(f"{API}/alerts")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["id"] for item in body["items"]] == [str(fresh.id), str(old.id)]
        first = body["items"][0]
        assert first["device"]["id"] == str(device.id)
        assert first["device"]["name"] == device.name
        assert first["severity"] == "critical"
        assert first["status"] == "active"
        assert "evidence" not in first  # list rows omit evidence

        resolved = client.get(f"{API}/alerts", params={"status": "resolved"})
        assert resolved.status_code == 200
        assert resolved.json()["total"] == 1
        assert resolved.json()["items"][0]["title"] == "resolved-warning"
        assert resolved.json()["items"][0]["resolved_at"] is not None

    def test_alerts_list_filters_device_severity_rule_key(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device_a = _make_device(db, index=31)
        device_b = _make_device(db, index=32)
        _alert(db, device=device_a, rule_key="device.health", severity="critical", title="a-critical")
        _alert(db, device=device_a, rule_key="data.expired", severity="warning", title="a-expired")
        _alert(db, device=device_b, rule_key="device.offline", severity="critical", title="b-offline")
        db.commit()

        by_device = client.get(f"{API}/alerts", params={"device_id": str(device_a.id)})
        assert by_device.json()["total"] == 2
        by_severity = client.get(f"{API}/alerts", params={"severity": "warning"})
        assert by_severity.json()["total"] == 1
        assert by_severity.json()["items"][0]["rule_key"] == "data.expired"
        by_rule = client.get(f"{API}/alerts", params={"rule_key": "device.offline"})
        assert by_rule.json()["total"] == 1
        assert by_rule.json()["items"][0]["device"]["id"] == str(device_b.id)

    def test_alerts_get_returns_evidence_and_timeline(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=33)
        alert = _alert(
            db,
            device=device,
            rule_key="device.offline",
            severity="critical",
            title="设备离线",
        )
        db.commit()

        response = client.get(f"{API}/alerts/{alert.id}")

        assert response.status_code == 200
        body = response.json()
        assert body["evidence"] == {"observed": True, "rule_key": "device.offline"}
        assert body["dedupe_key"] == f"device.offline:{device.id}:设备离线"
        assert body["first_occurred_at"] is not None
        assert body["last_occurred_at"] is not None
        assert body["resolved_at"] is None
        assert body["device"]["id"] == str(device.id)

    def test_alerts_get_unknown_id_404(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        unknown = client.get(f"{API}/alerts/{uuid.uuid4()}")
        assert unknown.status_code == 404
        assert unknown.json()["error"]["code"] == "resource_not_found"
        malformed = client.get(f"{API}/alerts/not-a-uuid")
        assert malformed.status_code == 404

    def test_collection_runs_list_filters_and_omits_lease_internals(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = make_collection_device(db, index=34)
        base = datetime.datetime.now(UTC) - datetime.timedelta(hours=2)
        db.add_all(
            [
                CollectionRun(
                    device_id=device.id,
                    collection_type="metrics",
                    scheduled_at=base,
                    started_at=base,
                    finished_at=base + datetime.timedelta(seconds=5),
                    state="succeeded",
                    success_count=10,
                    failure_count=0,
                ),
                CollectionRun(
                    device_id=device.id,
                    collection_type="reachability",
                    scheduled_at=base + datetime.timedelta(minutes=5),
                    started_at=base + datetime.timedelta(minutes=5),
                    finished_at=base + datetime.timedelta(minutes=5, seconds=30),
                    state="failed",
                    error_code="network_unreachable",
                    error_summary="no route",
                    failure_count=1,
                    lease_owner="hidden-worker",
                    lease_expires_at=base,
                ),
            ]
        )
        db.commit()

        response = client.get(f"{API}/devices/{device.id}/collection-runs")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert body["items"][0]["collection_type"] == "reachability"  # scheduled_at desc
        assert "lease_owner" not in body["items"][0]
        assert "lease_expires_at" not in body["items"][0]
        assert body["items"][0]["state"] == "failed"
        assert body["items"][0]["error_code"] == "network_unreachable"

        filtered = client.get(
            f"{API}/devices/{device.id}/collection-runs",
            params={"collection_type": "metrics", "state": "succeeded"},
        )
        assert filtered.json()["total"] == 1
        assert filtered.json()["items"][0]["success_count"] == 10

        unknown = client.get(f"{API}/devices/{uuid.uuid4()}/collection-runs")
        assert unknown.status_code == 404


class TestComponentsEventsApi:
    def _seed_components(
        self, db: Session, device: Device, now: datetime.datetime
    ) -> list[Component]:
        rows = []
        for index in range(3):
            row = Component(
                device_id=device.id,
                kind="fan",
                native_id=f"FAN{index}",
                name=f"Fan {index}",
                status="ok" if index < 2 else "critical",
                properties={"rpm": 3000 + index},
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(row)
            rows.append(row)
        retired = Component(
            device_id=device.id,
            kind="fan",
            native_id="FAN9",
            name="Fan 9 (retired)",
            status="absent",
            properties={},
            first_seen_at=now,
            last_seen_at=now,
            retired_at=now,
        )
        db.add(retired)
        db.commit()
        return rows

    def test_components_list_pagination_filters_and_retirement(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=40)
        now = datetime.datetime.now(UTC)
        self._seed_components(db, device, now)

        response = client.get(f"{API}/devices/{device.id}/components")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3  # retired component is not current
        kinds = {item["kind"] for item in body["items"]}
        assert kinds == {"fan"}
        assert body["items"][0]["native_id"] == "FAN0"
        assert body["items"][0]["properties"] == {"rpm": 3000}

        by_status = client.get(f"{API}/devices/{device.id}/components", params={"status": "critical"})
        assert by_status.json()["total"] == 1
        by_kind = client.get(f"{API}/devices/{device.id}/components", params={"kind": "psu"})
        assert by_kind.json()["total"] == 0

        paged = client.get(f"{API}/devices/{device.id}/components", params={"page_size": 2})
        assert paged.json()["total"] == 3
        assert len(paged.json()["items"]) == 2

    def test_events_list_filters_and_ordering(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=41)
        now = datetime.datetime.now(UTC)
        db.add_all(
            [
                DeviceEvent(
                    device_id=device.id,
                    event_type="event.sel",
                    severity="info",
                    message="old info",
                    occurred_at=now - datetime.timedelta(hours=5),
                    received_at=now,
                    source="redfish_sel",
                    native_event_id="SEL-1",
                ),
                DeviceEvent(
                    device_id=device.id,
                    event_type="event.sel",
                    severity="critical",
                    message="new critical",
                    occurred_at=now - datetime.timedelta(hours=1),
                    received_at=now,
                    source="redfish_sel",
                    native_event_id="SEL-2",
                ),
                DeviceEvent(
                    device_id=device.id,
                    event_type="event.syslog",
                    severity="warning",
                    message="syslog warning",
                    occurred_at=now - datetime.timedelta(minutes=30),
                    received_at=now,
                    source="syslog",
                    native_event_id=None,
                ),
            ]
        )
        db.commit()

        response = client.get(f"{API}/devices/{device.id}/events")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert body["items"][0]["message"] == "syslog warning"  # occurred_at desc
        assert body["items"][0]["source"] == "syslog"
        assert "detail" not in body["items"][0]

        critical = client.get(f"{API}/devices/{device.id}/events", params={"severity": "critical"})
        assert critical.json()["total"] == 1
        assert critical.json()["items"][0]["native_event_id"] == "SEL-2"

        by_source = client.get(f"{API}/devices/{device.id}/events", params={"source": "redfish_sel"})
        assert by_source.json()["total"] == 2

        ranged = client.get(
            f"{API}/devices/{device.id}/events",
            params={
                "from": (now - datetime.timedelta(hours=2)).isoformat(),
                "to": now.isoformat(),
            },
        )
        assert ranged.json()["total"] == 2

        paged = client.get(f"{API}/devices/{device.id}/events", params={"page_size": 2})
        assert paged.json()["total"] == 3
        assert len(paged.json()["items"]) == 2


class TestMonitorPermissions:
    def test_viewer_can_read_all_monitoring_endpoints(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        device = _make_device(db, index=50)
        _alert(db, device=device, rule_key="device.health", severity="warning", title="warn")
        db.commit()

        assert client.get(f"{API}/overview").status_code == 200
        assert client.get(f"{API}/devices/{device.id}/components").status_code == 200
        assert client.get(f"{API}/devices/{device.id}/events").status_code == 200
        assert client.get(f"{API}/devices/{device.id}/metrics/latest").status_code == 200
        assert client.get(f"{API}/devices/{device.id}/collection-runs").status_code == 200
        assert client.get(f"{API}/alerts").status_code == 200

    def test_unauthenticated_401(self, client_env) -> None:
        client, _db, _settings = client_env
        assert client.get(f"{API}/overview").status_code == 401
        assert client.get(f"{API}/alerts").status_code == 401

    def test_disabled_user_cannot_read_monitoring(self, client_env) -> None:
        client, db, _settings = client_env
        create_admin(db)
        create_user(db, username="disabled1", password=ADMIN_PASSWORD, role="viewer", status="disabled")
        # A disabled account cannot even hold a session: reads stay 401.
        assert client.get(f"{API}/overview").status_code == 401
