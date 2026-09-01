"""Structured logging tests: JSON output, redaction and context binding."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator

import pytest
import structlog
from app.infrastructure.logging import REDACTED_VALUE, bind_task_context, configure_logging, redact_sensitive_values
from structlog.contextvars import clear_contextvars


def make_captured_logger() -> tuple[structlog.BoundLogger, io.StringIO]:
    stream = io.StringIO()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=stream),
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_sensitive_values,
            structlog.processors.JSONRenderer(),
        ],
    )
    return logger, stream


@pytest.fixture(autouse=True)
def clear_log_context() -> Iterator[None]:
    clear_contextvars()
    yield
    clear_contextvars()


@pytest.mark.unit
def test_log_renders_as_json() -> None:
    logger, stream = make_captured_logger()
    logger.info("hello", task_id="t-1")
    data = json.loads(stream.getvalue())
    assert data["event"] == "hello"
    assert data["task_id"] == "t-1"


@pytest.mark.unit
def test_sensitive_values_are_redacted() -> None:
    logger, stream = make_captured_logger()
    logger.info("login", password="hunter2", snmp_community="public")
    data = json.loads(stream.getvalue())
    assert data["password"] == REDACTED_VALUE
    assert data["snmp_community"] == REDACTED_VALUE
    assert "hunter2" not in stream.getvalue()
    assert "public" not in stream.getvalue()


@pytest.mark.unit
def test_nested_sensitive_values_are_redacted() -> None:
    logger, stream = make_captured_logger()
    logger.info("device", nested={"username": "admin", "password": "s3cret"}, ok=True)
    data = json.loads(stream.getvalue())
    assert data["nested"]["password"] == REDACTED_VALUE
    assert data["nested"]["username"] == "admin"


@pytest.mark.unit
def test_context_binding_via_helper() -> None:
    logger, stream = make_captured_logger()
    bind_task_context(task_id="t-1", device_id="d-1")
    logger.info("run")
    data = json.loads(stream.getvalue())
    assert data["task_id"] == "t-1"
    assert data["device_id"] == "d-1"


@pytest.mark.unit
def test_missing_context_does_not_raise() -> None:
    logger, stream = make_captured_logger()
    logger.info("plain")
    data = json.loads(stream.getvalue())
    assert data["event"] == "plain"


@pytest.mark.unit
def test_configured_pipeline_emits_json() -> None:
    buffer = io.BytesIO()
    configure_logging(output=buffer)
    structlog.get_logger("warden.test").info("ready")
    line = buffer.getvalue().decode("utf-8")
    data = json.loads(line)
    assert data["event"] == "ready"
    assert "level" in data
    assert "timestamp" in data
