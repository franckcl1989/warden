"""Auth-domain errors: AppError factories bound to stable contract codes.

docs/API_CONTRACT.md §2: only ``contracts/error-codes.json`` codes leave the
process; these factories keep the code/message/details mapping in one place.
Messages are Chinese, codes are the stable English contract values.
"""

from __future__ import annotations

import datetime

from app.domain.errors import AppError

MESSAGE_UNAUTHENTICATED = "未登录或会话不存在"
MESSAGE_SESSION_EXPIRED = "会话已过期，请重新登录"
MESSAGE_CSRF_FAILED = "CSRF 校验失败"
MESSAGE_PERMISSION_DENIED = "权限不足"
MESSAGE_RATE_LIMITED = "请求过于频繁，请稍后重试"
MESSAGE_RESOURCE_NOT_FOUND = "资源不存在"
MESSAGE_VERSION_CONFLICT = "版本冲突，请刷新后重试"
MESSAGE_INVALID_CREDENTIALS = "用户名或密码错误"
MESSAGE_ACCOUNT_LOCKED = "账号已锁定，请稍后重试"
MESSAGE_ACCOUNT_DISABLED = "账号已禁用，请联系管理员"
MESSAGE_CURRENT_PASSWORD_WRONG = "当前密码错误"  # noqa: S105 (a message about passwords, not a password)
MESSAGE_REAUTH_REQUIRED = "高风险操作需要重新验证密码"


def unauthenticated() -> AppError:
    return AppError("unauthenticated", MESSAGE_UNAUTHENTICATED)


def session_expired() -> AppError:
    return AppError("session_expired", MESSAGE_SESSION_EXPIRED)


def reauthentication_required(reauthenticated_until: datetime.datetime) -> AppError:
    return AppError(
        "reauthentication_required",
        MESSAGE_REAUTH_REQUIRED,
        details={"reauthenticated_until": reauthenticated_until.isoformat()},
    )


def csrf_failed() -> AppError:
    return AppError("csrf_failed", MESSAGE_CSRF_FAILED)


def permission_denied(permission: str | None = None) -> AppError:
    details: dict[str, object] = {}
    if permission is not None:
        details["permission"] = permission
    return AppError("permission_denied", MESSAGE_PERMISSION_DENIED, details=details)


def rate_limited(retry_after_seconds: float, scope: str) -> AppError:
    return AppError(
        "rate_limited",
        MESSAGE_RATE_LIMITED,
        details={"retry_after_seconds": retry_after_seconds, "scope": scope},
    )


def validation_failed(field: str, reason: str) -> AppError:
    return AppError("validation_failed", reason, details={"field": field, "reason": reason})


def resource_not_found(resource_type: str) -> AppError:
    return AppError("resource_not_found", MESSAGE_RESOURCE_NOT_FOUND, details={"resource_type": resource_type})


def version_conflict(current_version: int) -> AppError:
    return AppError("version_conflict", MESSAGE_VERSION_CONFLICT, details={"current_version": current_version})


def invalid_credentials() -> AppError:
    return validation_failed("credentials", MESSAGE_INVALID_CREDENTIALS)


def account_locked() -> AppError:
    return validation_failed("username", MESSAGE_ACCOUNT_LOCKED)


def account_disabled() -> AppError:
    return validation_failed("username", MESSAGE_ACCOUNT_DISABLED)


def current_password_wrong() -> AppError:
    return validation_failed("current_password", MESSAGE_CURRENT_PASSWORD_WRONG)


def password_policy_violated(reason: str) -> AppError:
    return validation_failed("new_password", reason)


def username_taken() -> AppError:
    return validation_failed("username", "用户名已存在")


def dependency_unavailable(dependency: str = "postgres") -> AppError:
    return AppError("dependency_unavailable", "数据库不可用", details={"dependency": dependency})


def maintenance_mode(*, since: datetime.datetime | None = None, reason: str | None = None) -> AppError:
    """503 maintenance_mode (contracts/error-codes.json: since/reason safe).

    DEPLOYMENT.md §8: 维护模式开启后 API 拒绝新任务和 launch；details 只带
    契约允许的 since/reason。
    """
    details: dict[str, object] = {}
    if since is not None:
        details["since"] = since.isoformat()
    if reason:
        details["reason"] = reason
    return AppError("maintenance_mode", "系统维护中：已暂停新建操作任务与远程连接", details=details)


def internal() -> AppError:
    return AppError("internal_error", "服务器内部错误")
