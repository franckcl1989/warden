"""Roles and the permission matrix (docs/SECURITY.md §3.1).

The matrix is a frozen code constant; there is no roles/permissions table and
no custom roles (docs/DATA_MODEL.md §3.2). ``GET /roles`` only reads this
matrix back.
"""

from __future__ import annotations

import enum
import types
import typing

DEVICE_READ = "device.read"
DEVICE_MANAGE = "device.manage"
MONITOR_READ = "monitor.read"
OPERATION_READ = "operation.read"
OPERATION_EXECUTE_LOW = "operation.execute.low"
OPERATION_EXECUTE_MEDIUM = "operation.execute.medium"
OPERATION_EXECUTE_HIGH = "operation.execute.high"
FILE_METADATA_READ = "file.metadata.read"
FILE_DOWNLOAD_OUTPUT = "file.download.output"
FILE_MANAGE_INPUT = "file.manage.input"
FILE_DELETE = "file.delete"
AUDIT_READ = "audit.read"
USER_MANAGE = "user.manage"
SYSTEM_READ = "system.read"

ALL_PERMISSIONS = frozenset(
    {
        DEVICE_READ,
        DEVICE_MANAGE,
        MONITOR_READ,
        OPERATION_READ,
        OPERATION_EXECUTE_LOW,
        OPERATION_EXECUTE_MEDIUM,
        OPERATION_EXECUTE_HIGH,
        FILE_METADATA_READ,
        FILE_DOWNLOAD_OUTPUT,
        FILE_MANAGE_INPUT,
        FILE_DELETE,
        AUDIT_READ,
        USER_MANAGE,
        SYSTEM_READ,
    }
)


class Role(enum.StrEnum):
    """The three built-in roles (docs/SECURITY.md §3.1)."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# Permission matrix, EXACTLY as designed in docs/SECURITY.md §3.1.
_PERMISSIONS_BY_ROLE: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset(ALL_PERMISSIONS),
    Role.OPERATOR: frozenset(
        {
            DEVICE_READ,
            MONITOR_READ,
            OPERATION_READ,
            OPERATION_EXECUTE_LOW,
            OPERATION_EXECUTE_MEDIUM,
            OPERATION_EXECUTE_HIGH,
            FILE_METADATA_READ,
            FILE_DOWNLOAD_OUTPUT,
            FILE_MANAGE_INPUT,
        }
    ),
    Role.VIEWER: frozenset({DEVICE_READ, MONITOR_READ, OPERATION_READ, FILE_METADATA_READ}),
}

PERMISSION_MATRIX: typing.Mapping[Role, frozenset[str]] = types.MappingProxyType(_PERMISSIONS_BY_ROLE)


def permissions_for(role: Role | str) -> frozenset[str]:
    """Return the permission set of ``role`` (unknown roles get none)."""
    try:
        resolved = Role(role)
    except ValueError:
        return frozenset()
    return PERMISSION_MATRIX[resolved]


def require_permission(role: Role | str, permission: str) -> bool:
    """True when ``role`` holds ``permission`` in the frozen matrix."""
    return permission in permissions_for(role)
