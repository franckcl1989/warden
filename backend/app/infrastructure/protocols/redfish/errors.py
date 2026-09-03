"""Stable Redfish error mapping (docs/DEVICE_ADAPTERS.md §7).

Redfish ``base/1.0`` error bodies and their ``@Message.ExtendedInfo`` members
map to a stable subset of ``contracts/error-codes.json`` — the same 12 codes
the device adapters may return. Device-supplied message TEXT is never trusted:
mapped errors carry a sanitized reason built from our own labels, while the raw
parsed body is captured only for audit on ``RedfishHttpError.body`` (never for
logging, never in ``str``/``repr``).

Mapping notes:

- 401 during login/any authenticated call -> ``authentication_failed``; a
  404/405/501 on the SessionService POST means the manager has no session
  service — the session layer treats that as "session auth unsupported"
  (downgrade to HTTP Basic only when the connection config explicitly declared
  ``auth_mode=basic``; the mapping itself yields ``authentication_failed``).
- 403 -> ``permission_denied_by_device``; 429 -> ``rate_limited``; 409 on an
  action -> ``device_busy``.
- 400 on an action with extended members naming the action itself
  (``ActionNotSupported``/``ActionUnknown``/``PropertyUnknown``) is
  ``unsupported_capability`` — matched by MessageId NAME within the Base
  registry family regardless of its version (``Base.1.x``); parameter-shaped
  failures are ``validation_failed``.
- A vanished task (404 while polling) is ``ambiguous_result``: the outcome is
  unprovable and must never be replayed.
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

# DEVICE_ADAPTERS.md §7 table — the only codes protocol code may raise.
ADAPTER_ERROR_CODES: frozenset[str] = frozenset(
    {
        "network_unreachable",
        "tls_validation_failed",
        "authentication_failed",
        "permission_denied_by_device",
        "protocol_error",
        "unsupported_capability",
        "not_configured",
        "device_busy",
        "validation_failed",
        "rate_limited",
        "operation_failed",
        "ambiguous_result",
    }
)

_REQUEST_CONTEXT_CODES = frozenset({"auth", "read", "action", "task"})

# Extended-info MessageIds that mean "the device does not expose this action".
# Matched by NAME inside the Base registry family: an exact version list would
# mis-map a device speaking any other Base.1.x version to validation_failed.
_UNSUPPORTED_ACTION_NAMES = frozenset({"ActionNotSupported", "ActionUnknown", "PropertyUnknown"})


def _is_unsupported_action_message(message_id: str) -> bool:
    """True when a MessageId names an unsupported action in the Base registry.

    ``Base.<any version>.ActionNotSupported`` (e.g. Base.1.5.ActionNotSupported)
    matches; a vendor's own registry or any other message name does not.
    """
    registry, _, name = message_id.partition(".")
    if registry != "Base":
        return False
    return name.rsplit(".", 1)[-1] in _UNSUPPORTED_ACTION_NAMES


def _message_ids_from_error(error: dict[str, Any]) -> tuple[str, ...]:
    info = error.get("@Message.ExtendedInfo")
    if not isinstance(info, list):
        return ()
    ids: list[str] = []
    for member in info:
        if isinstance(member, dict):
            message_id = member.get("MessageId")
            if isinstance(message_id, str):
                ids.append(message_id)
    return tuple(ids)


def extended_message_ids(body: object | None) -> tuple[str, ...]:
    """Extended-error ``MessageId`` values from a Redfish error body."""
    if not isinstance(body, dict):
        return ()
    error = body.get("error")
    if not isinstance(error, dict):
        return ()
    return _message_ids_from_error(error)


def device_code_from_body(body: object | None) -> str | None:
    """Top-level Redfish error code (e.g. ``Base.1.13.GeneralError``)."""
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) else None


class RedfishError(Exception):
    """Protocol error carrying a stable contracts/error-codes.json code.

    ``message`` is sanitized by construction — never device-supplied text.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        stage: str = "request",
        detail_safe: str | None = None,
    ) -> None:
        if code not in ADAPTER_ERROR_CODES:
            msg = f"{code!r} is not an adapter error code (docs/DEVICE_ADAPTERS.md §7)"
            raise ValueError(msg)
        self.code = code
        self.message = message
        self.stage = stage
        self.detail_safe = detail_safe
        super().__init__(f"redfish {stage} {code}: {message}")


class RedfishHttpError(RedfishError):
    """A device HTTP error mapped to a stable code.

    ``status`` and the raw parsed ``body`` are retained for audit/evidence;
    neither is rendered by ``str``/``repr`` (device text must never reach
    logs or API details). ``retry_after_seconds`` carries the device rate
    limit when the response was 429 with a Retry-After header.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status: int,
        body: object | None = None,
        device_code: str | None = None,
        message_ids: tuple[str, ...] = (),
        retry_after_seconds: float | None = None,
        stage: str = "request",
    ) -> None:
        self.status = status
        self.body = body
        self.device_code = device_code
        self.message_ids = message_ids
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code, message, stage=stage)


def _http_mapping(status: int, message_ids: tuple[str, ...], context: str) -> tuple[str, str]:
    """Return (stable code, sanitized reason label) for a status + context."""
    if context not in _REQUEST_CONTEXT_CODES:
        msg = f"unknown mapping context {context!r}"
        raise ValueError(msg)
    if status == 401:
        return "authentication_failed", "device rejected the credentials or session"
    if status == 403:
        if context == "auth":
            return "authentication_failed", "login was refused by the device"
        return "permission_denied_by_device", "device account lacks the required privilege"
    if status == 404:
        if context == "task":
            return "ambiguous_result", "device task disappeared before a terminal state"
        if context == "auth":
            return "authentication_failed", "session service is not available on the device"
        return "unsupported_capability", "device does not expose the requested resource"
    if status in (405, 501) and context == "auth":
        return "authentication_failed", "session service is not available on the device"
    if status == 409 and context == "action":
        return "device_busy", "device reported a conflicting operation"
    if status == 429:
        return "rate_limited", "device rate limited the request"
    if status == 400:
        if context == "action":
            if any(_is_unsupported_action_message(message_id) for message_id in message_ids):
                return "unsupported_capability", "device does not support the requested action"
            return "validation_failed", "device rejected the action parameters"
        return "protocol_error", "device answered a read with an unexpected error"
    if status >= 500:
        return "operation_failed", "device reported a server-side failure"
    return "operation_failed", f"unexpected device HTTP status {status}"


def map_http_error(
    status: int,
    body: object | None,
    *,
    context: str,
    retry_after_seconds: float | None = None,
) -> RedfishHttpError:
    """Map a device HTTP response to a sanitized ``RedfishHttpError``."""
    message_ids = extended_message_ids(body)
    code, message = _http_mapping(status, message_ids, context)
    return RedfishHttpError(
        code=code,
        message=message,
        status=status,
        body=body,
        device_code=device_code_from_body(body),
        message_ids=message_ids,
        retry_after_seconds=retry_after_seconds,
    )


def _is_tls_failure(exc: BaseException) -> bool:
    return any(
        isinstance(cause, ssl.SSLCertVerificationError) for cause in _cause_chain(exc)
    ) or "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _cause_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def classify_transport_error(exc: BaseException) -> RedfishError:
    """Map transport-level failures (no HTTP response) to stable codes."""
    if _is_tls_failure(exc):
        return RedfishError(
            "tls_validation_failed",
            "TLS certificate validation failed",
            stage="tls",
            detail_safe="tls",
        )
    if isinstance(exc, httpx.TimeoutException):
        return RedfishError(
            "network_unreachable",
            "device request timed out",
            stage="request",
            detail_safe="request",
        )
    if isinstance(exc, httpx.TransportError):
        return RedfishError(
            "network_unreachable",
            "device connection failed",
            stage="connect",
            detail_safe="connect",
        )
    return RedfishError(
        "protocol_error",
        "unexpected transport failure",
        stage="connect",
    )
