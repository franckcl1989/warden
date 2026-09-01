"""OpenAPI export tests: health operationIds, error envelope schema, unique ids."""

from __future__ import annotations

import json

import pytest
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
