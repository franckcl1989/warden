"""Health endpoint tests: /health/live and /health/ready.

Unit tests never touch the database: they replace ``app.state.readiness`` with
a registry that contains only fake probes. The real database probe is covered
by the integration test at the bottom against PostgreSQL 18.
"""

from __future__ import annotations

import os

import pytest
from app.config import WardenSettings
from app.infrastructure.readiness import ProbeResult, ReadinessRegistry
from app.main import create_app
from fastapi.testclient import TestClient

TEST_DSN_FALLBACK = "postgresql://warden@127.0.0.1:55433/warden_test"


class _FakeProbe:
    def __init__(self, name: str, ok: bool) -> None:
        self.name = name
        self._ok = ok

    async def check(self) -> ProbeResult:
        return ProbeResult(name=self.name, ok=self._ok)


@pytest.mark.unit
def test_health_live_returns_ok(client: TestClient) -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.unit
def test_health_ready_empty_registry_returns_ok() -> None:
    app = create_app()
    app.state.readiness = ReadinessRegistry()
    with TestClient(app) as test_client:
        response = test_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["probes"] == []


@pytest.mark.unit
def test_health_ready_reports_ok_when_all_probes_pass() -> None:
    app = create_app()
    registry = ReadinessRegistry()
    registry.register(_FakeProbe("postgres", ok=True))
    app.state.readiness = registry
    with TestClient(app) as test_client:
        response = test_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["probes"] == [{"name": "postgres", "ok": True, "detail": ""}]


@pytest.mark.unit
def test_health_ready_reports_degraded_when_a_probe_fails() -> None:
    app = create_app()
    registry = ReadinessRegistry()
    registry.register(_FakeProbe("ok-probe", ok=True))
    registry.register(_FakeProbe("postgres", ok=False))
    app.state.readiness = registry
    with TestClient(app) as test_client:
        response = test_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["probes"] == [
        {"name": "ok-probe", "ok": True, "detail": ""},
        {"name": "postgres", "ok": False, "detail": ""},
    ]


@pytest.mark.integration
def test_health_ready_reflects_real_database_probe() -> None:
    dsn = os.environ.get("WARDEN_TEST_POSTGRES_DSN") or TEST_DSN_FALLBACK
    app = create_app(WardenSettings(postgres_dsn=dsn, _env_file=None))
    try:
        with TestClient(app) as test_client:
            response = test_client.get("/health/ready")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["probes"] == [{"name": "postgres", "ok": True, "detail": ""}]
    finally:
        for probe in app.state.readiness.probes:
            engine = getattr(probe, "engine", None)
            if engine is not None:
                engine.dispose()
