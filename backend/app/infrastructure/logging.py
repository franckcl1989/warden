"""Structured JSON logging with sensitive-key redaction.

Redaction happens at the rendering level: any event key whose name contains a
sensitive fragment (case-insensitive substring) has its value replaced with a
constant marker. The fragment list mirrors docs/SECURITY.md (password, token,
authorization, community, auth_key, privacy_key, cookie, secret) plus the
credential-bearing container names.
"""

from __future__ import annotations

import logging
from typing import BinaryIO

import orjson
import structlog
from structlog.contextvars import bind_contextvars
from structlog.types import EventDict

SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "token",
    "authorization",
    "community",
    "auth_key",
    "privacy_key",
    "cookie",
    "secret",
    "credential",
)

REDACTED_VALUE = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def _redact_mapping(values: dict[str, object]) -> dict[str, object]:
    redacted: dict[str, object] = {}
    for key, value in values.items():
        if is_sensitive_key(key):
            redacted[key] = REDACTED_VALUE
        else:
            redacted[key] = _redact_item(value)
    return redacted


def _redact_item(value: object) -> object:
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, list):
        return [_redact_item(item) for item in value]
    return value


def redact_sensitive_values(logger: object, method_name: str, event_dict: EventDict) -> EventDict:
    """Processor: replace values of sensitive-named keys at rendering time."""
    del logger, method_name
    redacted = _redact_mapping(dict(event_dict))
    return redacted


def configure_logging(*, level: int = logging.INFO, output: BinaryIO | None = None) -> None:
    """Configure structlog with JSON rendering, context merging and redaction."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            redact_sensitive_values,
            structlog.processors.JSONRenderer(serializer=orjson.dumps),
        ],
        logger_factory=structlog.BytesLoggerFactory(file=output),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


def bind_task_context(*, task_id: str | None = None, device_id: str | None = None, **extra: object) -> None:
    """Bind task/device context for subsequent log calls; ``None`` values are skipped."""
    context: dict[str, object] = {}
    if task_id is not None:
        context["task_id"] = task_id
    if device_id is not None:
        context["device_id"] = device_id
    for key, value in extra.items():
        if value is not None:
            context[key] = value
    bind_contextvars(**context)
