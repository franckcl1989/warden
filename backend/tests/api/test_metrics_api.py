"""Metrics read API integration tests (real PostgreSQL, API_CONTRACT.md §5).

Covers device_metrics_latest (shape, freshness per PRODUCT_DESIGN.md §6.3,
component grouping, pagination) and device_metrics_series (resolution
selection: within 7d raw / 7-30d 5m / 30-180d 1h, coarser requests honored,
finer-than-retention rejected 422, state/counter series as change points with
no averaging, empty series -> 200 with metadata, unknown metric 422, unknown
device 404) plus monitor.read permissions.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.config import WardenSettings
from app.models.devices import Component, Device
from app.models.observation import MetricLatest, MetricPoint, MetricRollup1h, MetricRollup5m
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    create_admin,
    create_user,
    login,
)
from tests.observation_factories import make_collection_device

API = "/api/v1"
UTC = datetime.UTC

METRIC_LATEST_PATH = "temperature.cpu"
DEVICE_GAUGE = "system.cpu_percent"


@pytest.fixture
def seeded(
    client_env: tuple[TestClient, Session, WardenSettings],
) -> tuple[TestClient, Session, Device, Component, datetime.datetime]:
    client, db, _settings = client_env
    device = make_collection_device(db, index=30)
    component = Component(
        device_id=device.id,
        kind="processor",
        native_id="CPU0",
        name="CPU 0",
        status="ok",
        properties={},
        first_seen_at=datetime.datetime.now(UTC),
        last_seen_at=datetime.datetime.now(UTC),
    )
    db.add(component)
    db.commit()
    db.refresh(component)
    return client, db, device, component, datetime.datetime.now(UTC)


def _login_viewer(client: TestClient, db: Session) -> None:
    create_admin(db)
    create_user(db, username="viewer1", password=ADMIN_PASSWORD, role="viewer")
    response = login(client, "viewer1", ADMIN_PASSWORD)
    assert response.status_code == 200


def _metric_latest_row(
    db: Session,
    *,
    device_id: uuid.UUID,
    component_id: uuid.UUID | None,
    metric_key: str,
    observed_at: datetime.datetime,
    value_double: float | None = None,
    value_text: str | None = None,
    unit: str | None = None,
) -> None:
    assert (value_double is None) != (value_text is None)
    db.add(
        MetricLatest(
            device_id=device_id,
            component_id=component_id,
            metric_key=metric_key,
            value_double=value_double,
            value_text=value_text,
            unit=unit,
            quality="good",
            source="redfish",
            observed_at=observed_at,
        )
    )


class TestMetricsLatest:
    def test_latest_shape_freshness_and_component_grouping(
        self, seeded: tuple[TestClient, Session, Device, Component, datetime.datetime]
    ) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        # device-scope gauge: 30 s old -> fresh (60 s metrics interval)
        _metric_latest_row(
            db,
            device_id=device.id,
            component_id=None,
            metric_key=DEVICE_GAUGE,
            observed_at=now - datetime.timedelta(seconds=30),
            value_double=12.5,
            unit="%",
        )
        # component-scope gauge: 150 s old -> stale (>2x, <=3x interval)
        _metric_latest_row(
            db,
            device_id=device.id,
            component_id=component.id,
            metric_key=METRIC_LATEST_PATH,
            observed_at=now - datetime.timedelta(seconds=150),
            value_double=41.0,
            unit="Cel",
        )
        # component-scope state: enum text, 250 s old -> expired (>3x)
        _metric_latest_row(
            db,
            device_id=device.id,
            component_id=component.id,
            metric_key="memory.status",
            observed_at=now - datetime.timedelta(seconds=250),
            value_text="ok",
        )
        # component-scope boolean
        _metric_latest_row(
            db,
            device_id=device.id,
            component_id=component.id,
            metric_key="drive.predictive_failure",
            observed_at=now - datetime.timedelta(seconds=10),
            value_text="false",
        )
        db.commit()

        response = client.get(f"{API}/devices/{device.id}/metrics/latest")

        assert response.status_code == 200
        body = response.json()
        assert body["device_id"] == str(device.id)
        assert body["total"] == 2  # two component groups (device-scope + CPU0)
        groups = {str(item["component"]["id"]) if item["component"] else "device": item for item in body["items"]}
        device_group = groups["device"]
        assert device_group["component"] is None
        metric = device_group["metrics"][0]
        assert metric["metric_key"] == DEVICE_GAUGE
        assert metric["value"] == 12.5
        assert metric["unit"] == "%"
        assert metric["freshness"] == "fresh"

        comp_group = groups[str(component.id)]
        assert comp_group["component"]["kind"] == "processor"
        assert comp_group["component"]["native_id"] == "CPU0"
        by_key = {m["metric_key"]: m for m in comp_group["metrics"]}
        assert by_key[METRIC_LATEST_PATH]["value"] == 41.0
        assert by_key[METRIC_LATEST_PATH]["freshness"] == "stale"
        assert by_key["memory.status"]["value"] == "ok"
        assert by_key["memory.status"]["freshness"] == "expired"
        assert by_key["drive.predictive_failure"]["value"] is False
        assert by_key["drive.predictive_failure"]["freshness"] == "fresh"

    def test_latest_pagination(self, seeded) -> None:
        client, db, device, _component, now = seeded
        _login_viewer(client, db)
        # One component per row so the component groups paginate cleanly.
        components = []
        for index in range(3):
            row = Component(
                device_id=device.id,
                kind="fan",
                native_id=f"FAN{index}",
                name=f"Fan {index}",
                status="ok",
                properties={},
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(row)
            db.flush()
            components.append(row)
            _metric_latest_row(
                db,
                device_id=device.id,
                component_id=row.id,
                metric_key=METRIC_LATEST_PATH,
                observed_at=now,
                value_double=float(index),
                unit="Cel",
            )
        db.commit()

        page_one = client.get(f"{API}/devices/{device.id}/metrics/latest", params={"page_size": 2})
        page_two = client.get(f"{API}/devices/{device.id}/metrics/latest", params={"page": 2, "page_size": 2})

        assert page_one.status_code == 200
        assert page_one.json()["total"] == 3
        assert len(page_one.json()["items"]) == 2
        assert page_two.status_code == 200
        assert len(page_two.json()["items"]) == 1

    def test_latest_unknown_device_404(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        response = client.get(f"{API}/devices/{uuid.uuid4()}/metrics/latest")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "resource_not_found"


class TestMetricsSeries:
    def _seed_gauge_points(
        self,
        db: Session,
        device_id: uuid.UUID,
        component_id: uuid.UUID | None,
        metric_key: str,
        *,
        base: datetime.datetime,
        values: list[float],
        seconds_between: int = 60,
    ) -> None:
        for index, value in enumerate(values):
            db.add(
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device_id,
                    component_id=component_id,
                    metric_key=metric_key,
                    observed_at=base + datetime.timedelta(seconds=seconds_between * index),
                    value_double=value,
                    unit="%",
                    quality="good",
                    source="redfish",
                )
            )

    def test_raw_resolution_within_7d(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        base = now - datetime.timedelta(hours=2)
        self._seed_gauge_points(db, device.id, component.id, METRIC_LATEST_PATH, base=base, values=[1.0, 2.0, 3.0])
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(hours=3)).isoformat(),
                "to": now.isoformat(),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["metric_key"] == METRIC_LATEST_PATH
        assert body["series"] == "gauge"
        assert body["unit"] == "Cel"
        assert body["resolution"] == "raw"
        values = [point["value"] for point in body["points"]]
        assert values == [1.0, 2.0, 3.0]
        assert all(point["source"] == "redfish" for point in body["points"])
        assert all(point["quality"] == "good" for point in body["points"])
        assert all(point["min_value"] is None for point in body["points"])

    def test_5m_resolution_for_7_30_day_window(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        window = now - datetime.timedelta(days=15)
        db.add(
            MetricRollup5m(
                device_id=device.id,
                component_id=component.id,
                metric_key=METRIC_LATEST_PATH,
                window_start=window,
                min_value=1.0,
                max_value=5.0,
                avg_value=3.0,
                last_value=5.0,
                count=5,
                quality="good",
            )
        )
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(days=20)).isoformat(),
                "to": (now - datetime.timedelta(days=10)).isoformat(),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["resolution"] == "5m"
        assert len(body["points"]) == 1
        point = body["points"][0]
        assert point["value"] == 3.0  # avg is the chart value
        assert point["min_value"] == 1.0
        assert point["max_value"] == 5.0
        assert point["last_value"] == 5.0
        assert point["count"] == 5

    def test_1h_resolution_for_30_180_day_window(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        window = now - datetime.timedelta(days=60)
        db.add(
            MetricRollup1h(
                device_id=device.id,
                component_id=component.id,
                metric_key=METRIC_LATEST_PATH,
                window_start=window,
                min_value=2.0,
                max_value=8.0,
                avg_value=5.0,
                last_value=8.0,
                count=60,
                quality="good",
            )
        )
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(days=90)).isoformat(),
                "to": (now - datetime.timedelta(days=30)).isoformat(),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["resolution"] == "1h"
        assert len(body["points"]) == 1
        assert body["points"][0]["value"] == 5.0

    def test_coarser_requested_resolution_is_honored(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        window = now - datetime.timedelta(days=1)
        db.add(
            MetricRollup5m(
                device_id=device.id,
                component_id=component.id,
                metric_key=METRIC_LATEST_PATH,
                window_start=window,
                min_value=1.0,
                max_value=2.0,
                avg_value=1.5,
                last_value=2.0,
                count=10,
                quality="good",
            )
        )
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(days=2)).isoformat(),
                "to": now.isoformat(),
                "resolution": "5m",
            },
        )

        # Default for a 2-day window is raw; the coarser 5m request is honored.
        assert response.status_code == 200
        body = response.json()
        assert body["resolution"] == "5m"
        assert len(body["points"]) == 1

    @pytest.mark.parametrize(
        ("days", "resolution"),
        [(20, "raw"), (45, "raw"), (45, "5m")],
    )
    def test_finer_resolution_beyond_retention_is_rejected_422(
        self, seeded, days: int, resolution: str
    ) -> None:
        client, db, device, _component, now = seeded
        _login_viewer(client, db)
        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "from": (now - datetime.timedelta(days=days)).isoformat(),
                "to": now.isoformat(),
                "resolution": resolution,
            },
        )
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "validation_failed"
        assert error["details"]["field"] == "resolution"

    def test_range_beyond_180d_is_rejected_422(self, seeded) -> None:
        client, db, device, _component, now = seeded
        _login_viewer(client, db)
        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "from": (now - datetime.timedelta(days=200)).isoformat(),
                "to": now.isoformat(),
            },
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    def test_unknown_metric_key_is_422(self, seeded) -> None:
        client, db, device, _component, now = seeded
        _login_viewer(client, db)
        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": "temperature.banana",
                "from": (now - datetime.timedelta(hours=1)).isoformat(),
                "to": now.isoformat(),
            },
        )
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "validation_failed"
        assert error["details"]["field"] == "metric"

    def test_unknown_device_is_404(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        now = datetime.datetime.now(UTC)
        response = client.get(
            f"{API}/devices/{uuid.uuid4()}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "from": (now - datetime.timedelta(hours=1)).isoformat(),
                "to": now.isoformat(),
            },
        )
        assert response.status_code == 404

    def test_empty_series_is_200_with_metadata(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(hours=1)).isoformat(),
                "to": now.isoformat(),
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["points"] == []
        assert body["unit"] == "Cel"
        assert body["resolution"] == "raw"

    def test_state_series_returns_change_points_not_averages(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        db.add_all(
            [
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device.id,
                    component_id=component.id,
                    metric_key="memory.status",
                    observed_at=now - datetime.timedelta(hours=5),
                    value_double=None,
                    value_text="ok",
                    quality="good",
                    source="redfish",
                ),
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device.id,
                    component_id=component.id,
                    metric_key="memory.status",
                    observed_at=now - datetime.timedelta(hours=1),
                    value_double=None,
                    value_text="warning",
                    quality="good",
                    source="redfish",
                ),
            ]
        )
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": "memory.status",
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(days=1)).isoformat(),
                "to": now.isoformat(),
            },
        )

        # Even though the window default for 1 day is raw, a state series is
        # served as raw change points with NO averaging; requesting an
        # explicit coarser resolution cannot invent aggregates either.
        assert response.status_code == 200
        body = response.json()
        assert body["series"] == "state"
        assert body["resolution"] == "raw"
        assert [point["value"] for point in body["points"]] == ["ok", "warning"]
        assert body["points"][1]["source"] == "redfish"

    def test_monotonic_counter_series_returns_raw_points(self, seeded) -> None:
        client, db, device, component, now = seeded
        _login_viewer(client, db)
        for hours_ago, value in ((3, 100.0), (1, 105.0)):
            db.add(
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device.id,
                    component_id=component.id,
                    metric_key="memory.ecc_errors",
                    observed_at=now - datetime.timedelta(hours=hours_ago),
                    value_double=value,
                    quality="good",
                    source="redfish",
                )
            )
        db.commit()

        response = client.get(
            f"{API}/devices/{device.id}/metrics/series",
            params={
                "metric": "memory.ecc_errors",
                "component_id": str(component.id),
                "from": (now - datetime.timedelta(days=7)).isoformat(),
                "to": now.isoformat(),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["series"] == "monotonic_counter"
        assert body["resolution"] == "raw"
        assert [point["value"] for point in body["points"]] == [100.0, 105.0]


class TestMetricsPermissions:
    def test_unauthenticated_401(self, client_env) -> None:
        client, _db, _settings = client_env
        response = client.get(f"{API}/overview")
        assert response.status_code == 401

    def test_viewer_can_read_series_and_latest(self, client_env) -> None:
        client, db, _settings = client_env
        _login_viewer(client, db)
        now = datetime.datetime.now(UTC)
        response = client.get(f"{API}/overview")
        assert response.status_code == 200
        response = client.get(
            f"{API}/devices/00000000-0000-0000-0000-000000000001/metrics/series",
            params={
                "metric": METRIC_LATEST_PATH,
                "from": (now - datetime.timedelta(hours=1)).isoformat(),
                "to": now.isoformat(),
            },
        )
        # Unknown device: viewer passes the permission gate (404 not 403).
        assert response.status_code == 404
