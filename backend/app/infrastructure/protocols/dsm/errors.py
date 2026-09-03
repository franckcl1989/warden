"""Stable DSM error mapping (docs/DEVICE_ADAPTERS.md §5/§7, ADR-018).

DSM WebAPI answers envelopes: ``{"success": true, "data": {...}}`` or
``{"success": false, "error": {"code": <int>}}``. Every DSM error code maps
to a stable subset of ``contracts/error-codes.json`` — the same 12 codes the
device adapters may return (DEVICE_ADAPTERS.md §7). Device-supplied TEXT is
never trusted: mapped errors carry a sanitized reason built from our own
labels, and the raw DSM code is retained for audit on ``DSMError.dsm_code``
(never rendered by ``str``/``repr``, never logged).

Row basis (every row is explicit about its evidence, ADR-018):

- ``[guide]`` — the Synology DSM Login Web API guide's common error codes
  (100..108): stable semantics across DSM 6/7.
- ``[sim]`` — simulator-DSL rows: fixture-certified against the Warden DSM
  test simulator only. Real-DSM 4xx login semantics and per-API code spaces
  are target-model certification territory (M4T2). Codes NOT listed here are
  NEVER guessed into a stable code: they surface as ``protocol_error`` with
  the original code preserved on ``DSMError.dsm_code``.
"""

from __future__ import annotations

import ssl

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

# --- DSM code catalog -------------------------------------------------------
# The DSM Login Web API guide documents a stable common-error block 100..108
# shared by every API. The simulator serves these exact codes (plus its own
# documented DSL rows for login 4xx), so the client and the simulator agree
# by construction; the simulator README records the per-code basis.
DSM_CODE_INVALID_PARAMETER = 101
DSM_CODE_UNKNOWN_API = 102
DSM_CODE_UNKNOWN_METHOD = 103
DSM_CODE_UNKNOWN_VERSION = 104
DSM_CODE_NO_PERMISSION = 105
DSM_CODE_SESSION_TIMEOUT = 106

# Simulator DSL / DSM 7 login-family codes (fixture-certified only; M4T2
# certifies the real target behavior per ADR-018).
DSM_CODE_BAD_CREDENTIALS = 401
DSM_CODE_TWO_FACTOR_REQUIRED = 403

_DSM_CODE_LABELS: dict[int, str] = {
    100: "unknown_error",
    101: "invalid_parameter",
    102: "unknown_api",
    103: "unknown_method",
    104: "unknown_version",
    105: "no_permission",
    106: "session_timeout",
    107: "session_interrupted",
}

# Base mapping (any API) — (stable code, sanitized reason). Rows marked
# [guide] are the DSM Login Web API guide common error codes; [sim] rows are
# simulator-DSL rows pending real-device certification (M4T2, ADR-018).
_BASE_CODE_ROWS: dict[int, tuple[str, str]] = {
    DSM_CODE_INVALID_PARAMETER: ("validation_failed", "device rejected the request parameters"),  # [guide]
    DSM_CODE_UNKNOWN_API: ("unsupported_capability", "device does not expose the requested API"),  # [guide]
    DSM_CODE_UNKNOWN_METHOD: ("unsupported_capability", "device does not expose the requested method"),  # [guide]
    DSM_CODE_UNKNOWN_VERSION: (
        "unsupported_capability",
        "device does not support the requested API version",
    ),  # [guide]
    DSM_CODE_NO_PERMISSION: ("permission_denied_by_device", "device session lacks the required permission"),  # [guide]
    DSM_CODE_SESSION_TIMEOUT: ("authentication_failed", "device session timed out"),  # [guide]
    DSM_CODE_BAD_CREDENTIALS: ("authentication_failed", "device rejected the credentials or session"),  # [sim]
    400: ("validation_failed", "device rejected the request parameters"),  # [sim]
    403: ("permission_denied_by_device", "device account lacks the required privilege"),  # [sim]
    406: ("authentication_failed", "device blocked the login or session"),  # [sim]
}

# Per-(api_name, code) refinements. Only rows with evidence live here; the
# base table covers everything else. ``SYNO.API.Auth`` login rows refine the
# generic 4xx base rows with login-specific semantics ([sim] until M4T2
# certification pins the real target behavior).
_API_CODE_ROWS: dict[tuple[str, int], tuple[str, str]] = {
    ("SYNO.API.Auth", 400): ("authentication_failed", "device rejected the login credentials"),  # [sim]
    ("SYNO.API.Auth", DSM_CODE_BAD_CREDENTIALS): (
        "authentication_failed",
        "device rejected the login credentials",
    ),  # [sim]
}

# API names the session layer treats as the login surface (2FA rows apply
# there only).
AUTH_API_NAMES = frozenset({"SYNO.API.Auth"})


def dsm_code_label(code: int) -> str:
    """Stable snake_case label for a known DSM code; the raw int for others."""
    return _DSM_CODE_LABELS.get(code, f"dsm_code_{code}")


def _row_for(api_name: str, code: int) -> tuple[str, str]:
    if (api_name, code) in _API_CODE_ROWS:
        return _API_CODE_ROWS[(api_name, code)]
    return _BASE_CODE_ROWS.get(code, ("protocol_error", "device returned an unmapped DSM error code"))


class DSMError(Exception):
    """Protocol error carrying a stable contracts/error-codes.json code.

    ``message`` is sanitized by construction — never device-supplied text.
    ``dsm_code`` preserves the ORIGINAL DSM error code for audit/evidence
    (ADR-018): an unknown code stays visible on the exception instead of
    being mapped to a fake. ``missing`` names the absent configuration item
    when ``code == "not_configured"`` (e.g. ``"otp"`` for a 2FA-blocked
    automation account).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        stage: str = "request",
        detail_safe: str | None = None,
        dsm_code: int | None = None,
        missing: str | None = None,
        api_name: str | None = None,
        method: str | None = None,
    ) -> None:
        if code not in ADAPTER_ERROR_CODES:
            msg = f"{code!r} is not an adapter error code (docs/DEVICE_ADAPTERS.md §7)"
            raise ValueError(msg)
        self.code = code
        self.message = message
        self.stage = stage
        self.detail_safe = detail_safe
        self.dsm_code = dsm_code
        self.missing = missing
        self.api_name = api_name
        self.method = method
        super().__init__(f"dsm {stage} {code}: {message}")


def raise_envelope_error(
    *,
    api_name: str,
    method: str,
    code: int,
    stage: str = "request",
    context: str = "call",
) -> None:
    """Raise the mapped ``DSMError`` for an envelope ``error.code``.

    ``context="login"`` is used for SYNO.API.Auth login responses: the
    DSM 7 login surface's two-step-verification row is a ``not_configured``
    gap (the automation credential is missing its OTP), never a guessed
    authentication failure (brief M4T1 session decision; SECURITY.md §5 —
    the device account should be a dedicated non-2FA automation account).
    """
    if context == "login" and api_name in AUTH_API_NAMES and code == DSM_CODE_TWO_FACTOR_REQUIRED:
        raise DSMError(
            "not_configured",
            "two-factor authentication is enabled on the DSM account; use a dedicated "
            "non-2FA automation account with minimal privileges (SECURITY.md §5)",
            stage=stage,
            detail_safe="dsm_code:403",
            dsm_code=code,
            missing="otp",
            api_name=api_name,
            method=method,
        )
    stable, reason = _row_for(api_name, code)
    label = dsm_code_label(code)
    raise DSMError(
        stable,
        reason,
        stage=stage,
        detail_safe=f"dsm_code:{label}",
        dsm_code=code,
        api_name=api_name,
        method=method,
    )


# --- envelope handling ------------------------------------------------------


def envelope_data(body: object) -> tuple[bool, object | None, int | None]:
    """Split a decoded DSM response body into (success, data, error code).

    A body that is not a DSM envelope at all raises ``protocol_error``
    (stage parse); an envelope with a malformed error member is treated as
    an unmapped device error (``protocol_error`` with the code preserved as
    ``None``). The returned tuple never fabricates success.
    """
    if not isinstance(body, dict):
        raise DSMError("protocol_error", "device returned a non-object response body", stage="parse")
    success = body.get("success")
    if success is True:
        data = body.get("data")
        return True, data if data is not None else {}, None
    if success is False:
        error = body.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if isinstance(code, int):
                return False, None, code
            if isinstance(code, str) and code.isdigit():
                return False, None, int(code)
        return False, None, None
    raise DSMError("protocol_error", "device response is not a DSM success/error envelope", stage="parse")


# --- transport / HTTP mapping -----------------------------------------------


def _cause_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _is_tls_failure(exc: BaseException) -> bool:
    return any(
        isinstance(cause, ssl.SSLCertVerificationError) for cause in _cause_chain(exc)
    ) or "CERTIFICATE_VERIFY_FAILED" in str(exc)


def classify_transport_error(exc: BaseException) -> DSMError:
    """Map transport-level failures (no HTTP response) to stable codes."""
    if _is_tls_failure(exc):
        return DSMError(
            "tls_validation_failed",
            "TLS certificate validation failed",
            stage="tls",
            detail_safe="tls",
        )
    if isinstance(exc, httpx.TimeoutException):
        return DSMError(
            "network_unreachable",
            "device request timed out",
            stage="request",
            detail_safe="request",
        )
    if isinstance(exc, httpx.TransportError):
        return DSMError(
            "network_unreachable",
            "device connection failed",
            stage="connect",
            detail_safe="connect",
        )
    return DSMError(
        "protocol_error",
        "unexpected transport failure",
        stage="connect",
    )


_HTTP_CONTEXT_CODES = frozenset({"auth", "read", "action"})


def raise_http_error(
    status: int,
    *,
    context: str,
    api_name: str,
    method: str,
    retry_after_seconds: float | None = None,
) -> None:
    """Map a non-2xx device HTTP response to a sanitized ``DSMError``.

    DSM normally answers HTTP 200 even for business errors; a non-2xx
    response is a transport/device-level failure. ``retry_after_seconds``
    carries the device rate limit when the response was 429 with a
    Retry-After header (callers may retry idempotent reads once).
    """
    if context not in _HTTP_CONTEXT_CODES:
        msg = f"unknown mapping context {context!r}"
        raise ValueError(msg)
    if status == 401:
        code, reason = "authentication_failed", "device rejected the credentials or session"
    elif status == 403 and context == "auth":
        code, reason = "authentication_failed", "login was refused by the device"
    elif status == 403:
        code, reason = "permission_denied_by_device", "device account lacks the required privilege"
    elif status == 404:
        code, reason = "protocol_error", "device answered a discovered API path with 404"
    elif status == 429:
        code, reason = "rate_limited", "device rate limited the request"
    elif status == 400:
        code, reason = "validation_failed", "device rejected the request parameters"
    elif status >= 500:
        code, reason = "operation_failed", "device reported a server-side failure"
    else:
        code, reason = "operation_failed", f"unexpected device HTTP status {status}"
    detail = f"http:{status}"
    if retry_after_seconds is not None:
        detail = f"{detail},retry_after:{retry_after_seconds:g}"
    raise DSMError(
        code,
        reason,
        stage="request",
        detail_safe=detail,
        api_name=api_name,
        method=method,
    )
