"""Device-domain errors: AppError factories bound to stable contract codes.

docs/API_CONTRACT.md §2: only ``contracts/error-codes.json`` codes leave the
process; messages are Chinese, codes are the stable English contract values.
The device API reuses the generic factories from ``app.domain.auth_errors``
(validation_failed, resource_not_found, version_conflict, rate_limited) and
adds device-specific mappings below.
"""

from __future__ import annotations

from app.domain.adapter import ProbeStage
from app.domain.errors import AppError

MESSAGE_NETWORK_UNREACHABLE = "无法连接设备"
MESSAGE_TLS_VALIDATION_FAILED = "设备 TLS 证书校验失败"
MESSAGE_AUTHENTICATION_FAILED = "设备认证失败"
MESSAGE_PROBE_FAILED = "设备探测失败"

_STAGE_MESSAGES: dict[str, str] = {
    "network_unreachable": MESSAGE_NETWORK_UNREACHABLE,
    "tls_validation_failed": MESSAGE_TLS_VALIDATION_FAILED,
    "authentication_failed": MESSAGE_AUTHENTICATION_FAILED,
}


def probe_policy_violation(endpoint: str, reason: str) -> AppError:
    """SSRF guard rejection: mapped to network_unreachable stage=endpoint_policy."""
    return AppError(
        "network_unreachable",
        "设备地址不在允许的管理网段内",
        details={"stage": "endpoint_policy", "endpoint": endpoint, "reason": reason},
    )


def probe_stage_error(stage: ProbeStage) -> AppError:
    """A failed probe stage surfaced as a stable error (update-time re-probes).

    ``details`` keep only the contract-safe fields for the stage's error code
    (the boundary filters them further before any response leaves).
    """
    code = stage.error_code or "network_unreachable"
    message = _STAGE_MESSAGES.get(code, MESSAGE_PROBE_FAILED)
    return AppError(
        code,
        stage.detail_safe or message,
        details={"stage": stage.stage, "reason": stage.detail_safe},
    )
