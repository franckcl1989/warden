"""Permission matrix tests (docs/SECURITY.md §3.1 — exact copy)."""

from __future__ import annotations

import pytest
from app.domain.roles import (
    ALL_PERMISSIONS,
    AUDIT_READ,
    DEVICE_MANAGE,
    DEVICE_READ,
    FILE_DELETE,
    FILE_DOWNLOAD_OUTPUT,
    FILE_MANAGE_INPUT,
    FILE_METADATA_READ,
    MONITOR_READ,
    OPERATION_EXECUTE_HIGH,
    OPERATION_EXECUTE_LOW,
    OPERATION_EXECUTE_MEDIUM,
    OPERATION_READ,
    PERMISSION_MATRIX,
    SYSTEM_READ,
    USER_MANAGE,
    Role,
    permissions_for,
    require_permission,
)

EXPECTED_KEYS = {
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


@pytest.mark.unit
def test_matrix_contains_exactly_the_14_design_permission_keys() -> None:
    assert len(ALL_PERMISSIONS) == 14
    assert ALL_PERMISSIONS == EXPECTED_KEYS


@pytest.mark.unit
def test_matrix_roles_are_exactly_the_three_builtin_roles() -> None:
    assert set(PERMISSION_MATRIX) == {Role.ADMIN, Role.OPERATOR, Role.VIEWER}


@pytest.mark.unit
def test_admin_has_every_permission() -> None:
    assert PERMISSION_MATRIX[Role.ADMIN] == ALL_PERMISSIONS


@pytest.mark.unit
def test_operator_has_exactly_the_design_permissions() -> None:
    expected = {
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
    assert PERMISSION_MATRIX[Role.OPERATOR] == expected
    # The brief's explicit "lacks" list:
    lacks = {USER_MANAGE, AUDIT_READ, SYSTEM_READ, DEVICE_MANAGE, FILE_DELETE}
    assert PERMISSION_MATRIX[Role.OPERATOR] & lacks == set()


@pytest.mark.unit
def test_viewer_only_reads() -> None:
    assert PERMISSION_MATRIX[Role.VIEWER] == {
        DEVICE_READ,
        MONITOR_READ,
        OPERATION_READ,
        FILE_METADATA_READ,
    }


@pytest.mark.unit
def test_require_permission_behaviour() -> None:
    assert require_permission(Role.ADMIN, USER_MANAGE) is True
    assert require_permission("operator", DEVICE_MANAGE) is False
    assert require_permission(Role.OPERATOR, OPERATION_EXECUTE_HIGH) is True
    assert require_permission(Role.VIEWER, OPERATION_EXECUTE_LOW) is False
    assert require_permission("not_a_role", DEVICE_READ) is False
    assert require_permission(Role.ADMIN, "not.a.permission") is False


@pytest.mark.unit
def test_matrix_is_immutable() -> None:
    with pytest.raises(TypeError):
        PERMISSION_MATRIX[Role.ADMIN] = frozenset()  # type: ignore[index]
    with pytest.raises(AttributeError):
        PERMISSION_MATRIX[Role.ADMIN].add("x")  # type: ignore[attr-defined]


@pytest.mark.unit
def test_permissions_for_string_role() -> None:
    assert permissions_for("viewer") == PERMISSION_MATRIX[Role.VIEWER]
    assert permissions_for("bogus") == frozenset()
