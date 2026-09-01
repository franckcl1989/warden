"""Unified error envelope tests per contracts/error-codes.json."""

from __future__ import annotations

import re

import pytest
from app.domain.errors import AppError
from app.main import create_app
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")

error_test_router = APIRouter()


class RequiredBody(BaseModel):
    field_a: str


@error_test_router.get("/test/app-error")
async def app_error() -> None:
    raise AppError("authentication_failed", "设备认证失败", details={"stage": "device_probe"})


@error_test_router.get("/test/app-error-disallowed")
async def app_error_disallowed() -> None:
    raise AppError(
        "authentication_failed",
        "设备认证失败",
        details={"stage": "device_probe", "password": "hunter2", "reason": "不应透出"},
    )


@error_test_router.get("/test/unknown-code")
async def unknown_code() -> None:
    raise AppError("not_a_registered_code", "未知错误")


@error_test_router.get("/test/boom")
async def boom() -> None:
    raise ValueError("hunter2 leaked")


@error_test_router.post("/test/echo-json")
async def echo_json(body: RequiredBody) -> None:
    del body


@pytest.fixture
def error_client() -> TestClient:
    app = create_app()
    app.include_router(error_test_router)
    # ServerErrorMiddleware re-raises handled 500s; the test inspects the response.
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.unit
def test_app_error_envelope(error_client: TestClient) -> None:
    response = error_client.get("/test/app-error")
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "authentication_failed"
    assert error["message"] == "设备认证失败"
    assert error["details"] == {"stage": "device_probe"}
    assert REQUEST_ID_RE.fullmatch(error["request_id"]) is not None
    assert response.headers["x-request-id"] == error["request_id"]


@pytest.mark.unit
def test_app_error_details_filtered_to_safe_fields(error_client: TestClient) -> None:
    response = error_client.get("/test/app-error-disallowed")
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "authentication_failed"
    assert error["details"] == {"stage": "device_probe"}
    assert "hunter2" not in response.text


@pytest.mark.unit
def test_unknown_code_becomes_internal_error(error_client: TestClient) -> None:
    response = error_client.get("/test/unknown-code")
    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    assert error["details"] == {}
    assert REQUEST_ID_RE.fullmatch(error["request_id"]) is not None
    assert response.headers["x-request-id"] == error["request_id"]


@pytest.mark.unit
def test_unknown_exception_becomes_internal_error_without_details(error_client: TestClient) -> None:
    response = error_client.get("/test/boom")
    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "internal_error"
    assert error["details"] == {}
    assert "hunter2" not in response.text
    assert REQUEST_ID_RE.fullmatch(error["request_id"]) is not None
    assert response.headers["x-request-id"] == error["request_id"]


@pytest.mark.unit
def test_request_validation_uses_invalid_request_envelope(error_client: TestClient) -> None:
    response = error_client.post("/test/echo-json", json={"nope": 1})
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "invalid_request"
    assert set(error["details"]) <= {"field", "reason"}
    assert error["details"]["field"] == "field_a"
    assert REQUEST_ID_RE.fullmatch(error["request_id"]) is not None
