"""OpenAPI export tests: operationIds vs contracts/http-api.json, error envelope."""

from __future__ import annotations

import json

import pytest
from app.generated.http_api import HTTP_ENDPOINTS
from app.tools.openapi_export import OPENAPI_PATH, run


def exported_schema() -> dict[str, object]:
    run()
    return json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))


@pytest.mark.unit
def test_exported_openapi_contains_health_operation_ids() -> None:
    schema = exported_schema()
    paths = schema["paths"]
    assert isinstance(paths, dict)
    assert "/health/live" in paths
    assert "/health/ready" in paths
    assert paths["/health/live"]["get"]["operationId"] == "health_live"
    assert paths["/health/ready"]["get"]["operationId"] == "health_ready"


@pytest.mark.unit
def test_exported_openapi_contains_error_envelope_schema() -> None:
    schema = exported_schema()
    components = schema["components"]
    assert isinstance(components, dict)
    schemas = components["schemas"]
    assert isinstance(schemas, dict)
    assert "ErrorEnvelope" in schemas
    assert "ErrorBody" in schemas


@pytest.mark.unit
def test_exported_openapi_operation_ids_are_unique() -> None:
    schema = exported_schema()
    paths = schema["paths"]
    assert isinstance(paths, dict)
    operation_ids = [operation["operationId"] for path in paths.values() for operation in path.values()]
    assert operation_ids
    assert len(operation_ids) == len(set(operation_ids))


AUTH_USERS_ROLES_ENDPOINTS = {
    "auth_login": ("POST", "/auth/login"),
    "auth_logout": ("POST", "/auth/logout"),
    "auth_get_me": ("GET", "/auth/me"),
    "auth_change_password": ("POST", "/auth/password"),
    "auth_reauthenticate": ("POST", "/auth/reauth"),
    "users_list": ("GET", "/users"),
    "users_create": ("POST", "/users"),
    "users_get": ("GET", "/users/{id}"),
    "users_update": ("PATCH", "/users/{id}"),
    "roles_list": ("GET", "/roles"),
}

DEVICE_ENDPOINTS = {
    "device_probes_create": ("POST", "/device-probes"),
    "devices_create": ("POST", "/devices"),
    "devices_list": ("GET", "/devices"),
    "devices_get": ("GET", "/devices/{id}"),
    "devices_update": ("PATCH", "/devices/{id}"),
    "devices_probe": ("POST", "/devices/{id}/probe"),
    "device_capabilities_list": ("GET", "/devices/{id}/capabilities"),
}


def _assert_operation_ids(
    schema: dict[str, object],
    expected: dict[str, tuple[str, str]],
) -> None:
    paths = schema["paths"]
    assert isinstance(paths, dict)
    observed: dict[str, tuple[str, str]] = {}
    for path, methods in paths.items():
        for method, operation in methods.items():
            if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
                observed[operation["operationId"]] = (method.upper(), path)
    for operation_id, (method, path) in expected.items():
        assert observed.get(operation_id) == (method, f"/api/v1{path}"), operation_id
        contract_endpoint = HTTP_ENDPOINTS[operation_id]
        assert contract_endpoint.path == path
        assert contract_endpoint.operation_id == operation_id
        assert contract_endpoint.method == method


@pytest.mark.unit
def test_exported_openapi_auth_users_roles_operation_ids_match_contract() -> None:
    """The implemented endpoints carry the EXACT operationIds of http-api.json."""
    _assert_operation_ids(exported_schema(), AUTH_USERS_ROLES_ENDPOINTS)


@pytest.mark.unit
def test_exported_openapi_device_operation_ids_match_contract() -> None:
    """M1T3 device endpoints carry the EXACT operationIds of http-api.json."""
    _assert_operation_ids(exported_schema(), DEVICE_ENDPOINTS)
