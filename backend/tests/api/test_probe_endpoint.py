"""POST /device-probes integration tests (real PostgreSQL, docs/API_CONTRACT §4).

Covers the fake adapter success path, the fail_credentials / fail_tls modes
(stage-level failures with a failure token), the SSRF policy violation
(loopback -> 422 network_unreachable stage=endpoint_policy), schema rejection,
the 10/min per-user rate limit and the admin-only permission (device.manage).
Credentials never appear in the response body.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login_csrf,
)

API = "/api/v1"
PROBE_PATH = f"{API}/device-probes"
ENDPOINT = "192.0.2.10"
PASSWORD = "device-pass-123"


def base_probe(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "device_type": "server",
        "adapter_key": "fake.simple",
        "management_endpoint": ENDPOINT,
        "connection_config": {},
        "credentials": {"username": "admin", "password": PASSWORD},
    }
    payload.update(overrides)
    return payload


def admin_csrf(device_client: TestClient) -> str:
    response, csrf = login_csrf(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    return csrf


@pytest.mark.integration
def test_probe_success_all_stages_and_discovery(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(PROBE_PATH, json=base_probe(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    stages = {item["stage"]: item for item in body["stages"]}
    assert set(stages) == {"network", "tls", "auth", "identity", "capabilities"}
    assert all(stages[stage]["ok"] is True for stage in stages)
    discovery = body["discovery"]
    assert discovery["vendor"] == "Fake"
    assert discovery["model"] == "FakeServer-1"
    assert discovery["serial_number"] == "FAKE-SN-0001"
    assert discovery["firmware_version"] == "1.0.0"
    assert len(discovery["capabilities"]) >= 20
    assert {component["kind"] for component in discovery["components"]} >= {
        "processor",
        "memory",
        "drive",
        "fan",
        "psu",
    }
    assert body["probe_token"]
    assert body["expires_at"]
    assert PASSWORD not in response.text
    assert "password" not in response.text


@pytest.mark.integration
def test_probe_credentials_fail_mode_issues_failure_token(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(connection_config={"fail_credentials": True}),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    auth_stage = next(stage for stage in body["stages"] if stage["stage"] == "auth")
    assert auth_stage["error_code"] == "authentication_failed"
    # A failure token is still issued: it may only save as not_ready.
    assert body["probe_token"]
    assert body["discovery"] is None
    assert PASSWORD not in response.text


@pytest.mark.integration
def test_probe_tls_fail_mode(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(connection_config={"fail_tls": True}),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    tls_stage = next(stage for stage in body["stages"] if stage["stage"] == "tls")
    assert tls_stage["error_code"] == "tls_validation_failed"
    assert body["probe_token"]
    assert PASSWORD not in response.text


@pytest.mark.integration
def test_probe_loopback_is_rejected_by_policy(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(management_endpoint="127.0.0.1"),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "network_unreachable"
    assert error["details"]["stage"] == "endpoint_policy"
    assert PASSWORD not in response.text


@pytest.mark.integration
def test_probe_unknown_adapter_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(adapter_key="server.dell_idrac"),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "adapter_key"


@pytest.mark.integration
def test_probe_adapter_device_type_mismatch_rejected(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(device_type="synology_nas"),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "adapter_key"


@pytest.mark.integration
def test_probe_rejects_bad_credentials_schema(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(credentials={"username": "admin"}),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "credentials"


@pytest.mark.integration
def test_probe_rejects_bad_connection_config(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(connection_config={"protocol": "http"}),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "connection_config"


@pytest.mark.integration
def test_probe_endpoint_with_credentials_in_url_rejected(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(management_endpoint="https://10.0.0.1/redfish"),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "invalid_request"
    assert error["details"]["field"] == "management_endpoint"


@pytest.mark.integration
def test_probe_rate_limited_after_10_per_minute(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    headers = {"X-CSRF-Token": csrf}
    for _ in range(10):
        response = device_client.post(PROBE_PATH, json=base_probe(), headers=headers)
        assert response.status_code == 200
    eleventh = device_client.post(PROBE_PATH, json=base_probe(), headers=headers)
    assert eleventh.status_code == 429
    error = eleventh.json()["error"]
    assert error["code"] == "rate_limited"
    assert error["details"]["scope"] == "probe"
    assert PASSWORD not in eleventh.text


@pytest.mark.integration
def test_probe_requires_device_manage(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="operator.1", password="Oper!ator-2026-Pass", role="operator")
    create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")
    for username, password in (("operator.1", "Oper!ator-2026-Pass"), ("viewer.1", "View!er-2026-Pass")):
        response, csrf = login_csrf(device_client, username, password)
        assert response.status_code == 200
        denied = device_client.post(PROBE_PATH, json=base_probe(), headers={"X-CSRF-Token": csrf})
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "permission_denied"
