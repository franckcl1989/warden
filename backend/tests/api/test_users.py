"""User administration API tests on the real PostgreSQL (API_CONTRACT §3).

Covers admin CRUD, non-admin 403s, forced password change on create, session
revocation on role/status/password changes, optimistic-lock version conflicts
and audit rows.
"""

from __future__ import annotations

import pytest
from app.models.auth import AuditLog, User
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login_csrf,
)

API = "/api/v1"
NEW_USER = "ops.user"
NEW_USER_PASSWORD = "Ops!user-2026-Pass"


def _csrf(db_client: TestClient, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD) -> str:
    response, csrf = login_csrf(db_client, username, password)
    assert response.status_code == 200
    return csrf


def _create_user_via_api(db_client: TestClient, csrf: str, **body: object) -> object:
    payload = {
        "username": NEW_USER,
        "display_name": "运维人员",
        "role": "operator",
        "password": NEW_USER_PASSWORD,
    }
    payload.update(body)
    return db_client.post(f"{API}/users", json=payload, headers={"X-CSRF-Token": csrf})


@pytest.mark.integration
def test_admin_creates_lists_gets_user(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    created = _create_user_via_api(db_client, csrf)
    assert created.status_code == 201
    body = created.json()
    assert body["username"] == NEW_USER
    assert body["role"] == "operator"
    assert body["status"] == "active"
    assert body["must_change_password"] is True
    assert "password_hash" not in created.text

    listing = db_client.get(f"{API}/users", headers={"X-CSRF-Token": csrf})
    assert listing.status_code == 200
    list_body = listing.json()
    assert list_body["total"] == 2
    assert {item["username"] for item in list_body["items"]} == {ADMIN_USERNAME, NEW_USER}

    fetched = db_client.get(f"{API}/users/{body['id']}", headers={"X-CSRF-Token": csrf})
    assert fetched.status_code == 200
    assert fetched.json()["username"] == NEW_USER
    assert _count_audit(db_session, "users.create") == 1


def _count_audit(db_session: Session, action: str) -> int:
    return len(db_session.scalars(select(AuditLog).where(AuditLog.action == action)).all())


@pytest.mark.integration
def test_new_user_must_change_password_at_first_login(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    created = _create_user_via_api(db_client, csrf)
    assert created.status_code == 201
    response, _csrf_token = login_csrf(db_client, NEW_USER, NEW_USER_PASSWORD)
    assert response.status_code == 200
    assert response.json()["user"]["must_change_password"] is True
    me = db_client.get(f"{API}/auth/me").json()
    assert me["user"]["must_change_password"] is True
    assert set(me["permissions"]) == {
        "device.read",
        "monitor.read",
        "operation.read",
        "operation.execute.low",
        "operation.execute.medium",
        "operation.execute.high",
        "file.metadata.read",
        "file.download.output",
        "file.manage.input",
    }


@pytest.mark.integration
def test_username_is_case_insensitively_unique(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    first = _create_user_via_api(db_client, csrf)
    assert first.status_code == 201
    duplicate = _create_user_via_api(db_client, csrf, username="OPS.USER")
    assert duplicate.status_code == 422
    assert duplicate.json()["error"]["code"] == "validation_failed"
    assert duplicate.json()["error"]["details"]["field"] == "username"


@pytest.mark.integration
def test_create_rejects_weak_password(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    response = _create_user_via_api(db_client, csrf, password="password1234")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


@pytest.mark.integration
def test_non_admin_cannot_manage_users(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")
    create_user(db_session, username="operator.1", password="Oper!ator-2026-Pass", role="operator")
    csrf_viewer = _csrf(db_client, "viewer.1", "View!er-2026-Pass")
    csrf_operator = _csrf(db_client, "operator.1", "Oper!ator-2026-Pass")
    for csrf in (csrf_viewer, csrf_operator):
        listing = db_client.get(f"{API}/users", headers={"X-CSRF-Token": csrf})
        assert listing.status_code == 403
        assert listing.json()["error"]["code"] == "permission_denied"
        create_attempt = _create_user_via_api(db_client, csrf, username="blocked.user")
        assert create_attempt.status_code == 403
    # The viewer/operator can still read their own identity.
    assert db_client.get(f"{API}/auth/me").status_code == 200


@pytest.mark.integration
def test_patch_renames_and_audits(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    created = _create_user_via_api(db_client, csrf).json()
    patched = db_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": created["version"], "display_name": "运维一"},
        headers={"X-CSRF-Token": csrf},
    )
    assert patched.status_code == 200
    assert patched.json()["display_name"] == "运维一"
    assert patched.json()["version"] == created["version"] + 1
    assert _count_audit(db_session, "users.update") == 1


@pytest.mark.integration
def test_patch_role_or_status_revokes_sessions(db_client: TestClient, db_app: FastAPI, db_session: Session) -> None:
    create_admin(db_session)
    created = _create_user_via_api(db_client := TestClient(db_app), _csrf(db_client)).json()
    other = TestClient(db_app)
    response, _csrf2 = login_csrf(other, NEW_USER, NEW_USER_PASSWORD)
    assert response.status_code == 200
    assert other.get(f"{API}/auth/me").status_code == 200

    admin_client = TestClient(db_app)
    admin_csrf = _csrf(admin_client)
    role_change = admin_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": created["version"], "role": "viewer"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert role_change.status_code == 200
    assert role_change.json()["role"] == "viewer"
    assert other.get(f"{API}/auth/me").status_code == 401

    other2 = TestClient(db_app)
    response2, _csrf3 = login_csrf(other2, NEW_USER, NEW_USER_PASSWORD)
    assert response2.status_code == 200
    status_change = admin_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": role_change.json()["version"], "status": "disabled"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert status_change.status_code == 200
    assert other2.get(f"{API}/auth/me").status_code == 401


@pytest.mark.integration
def test_patch_new_password_resets_must_change_and_revokes_sessions(
    db_client: TestClient, db_app: FastAPI, db_session: Session
) -> None:
    create_admin(db_session)
    created = _create_user_via_api(db_client := TestClient(db_app), _csrf(db_client)).json()
    other = TestClient(db_app)
    response, _csrf2 = login_csrf(other, NEW_USER, NEW_USER_PASSWORD)
    assert response.status_code == 200
    admin_client = TestClient(db_app)
    admin_csrf = _csrf(admin_client)
    reset = admin_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": created["version"], "new_password": "R3set!-Password-2026"},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert reset.status_code == 200
    assert reset.json()["must_change_password"] is True
    assert other.get(f"{API}/auth/me").status_code == 401
    # The new password works and still forces a change.
    response3, _csrf3 = login_csrf(TestClient(db_app), NEW_USER, "R3set!-Password-2026")
    assert response3.status_code == 200
    assert response3.json()["user"]["must_change_password"] is True


@pytest.mark.integration
def test_patch_version_conflict_returns_412(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    created = _create_user_via_api(db_client, csrf).json()
    stale = db_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": created["version"], "display_name": "第一次修改"},
        headers={"X-CSRF-Token": csrf},
    )
    assert stale.status_code == 200
    conflict = db_client.patch(
        f"{API}/users/{created['id']}",
        json={"version": created["version"], "display_name": "第二次修改"},
        headers={"X-CSRF-Token": csrf},
    )
    assert conflict.status_code == 412
    error = conflict.json()["error"]
    assert error["code"] == "version_conflict"
    assert error["details"]["current_version"] == stale.json()["version"]


@pytest.mark.integration
def test_unknown_user_returns_404(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = _csrf(db_client)
    response = db_client.get(f"{API}/users/00000000-0000-0000-0000-000000000000", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "resource_not_found"
    patch = db_client.patch(
        f"{API}/users/00000000-0000-0000-0000-000000000000",
        json={"version": 1, "display_name": "x"},
        headers={"X-CSRF-Token": csrf},
    )
    assert patch.status_code == 404
    garbage = db_client.get(f"{API}/users/not-a-uuid", headers={"X-CSRF-Token": csrf})
    assert garbage.status_code == 404


@pytest.mark.integration
def test_roles_list_returns_exact_matrix_for_each_role(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="viewer.2", password="View!er-2026-Pass", role="viewer")
    response, csrf = login_csrf(db_client, "viewer.2", "View!er-2026-Pass")
    assert response.status_code == 200
    listing = db_client.get(f"{API}/roles", headers={"X-CSRF-Token": csrf})
    assert listing.status_code == 200
    roles = {item["role"]: set(item["permissions"]) for item in listing.json()["roles"]}
    assert set(roles) == {"admin", "operator", "viewer"}
    assert roles["admin"] >= {"user.manage", "device.manage", "audit.read", "system.read", "file.delete"}
    assert roles["operator"] >= {"operation.execute.high", "file.manage.input"}
    assert roles["operator"] & {"user.manage", "audit.read", "system.read", "device.manage", "file.delete"} == set()
    assert roles["viewer"] == {"device.read", "monitor.read", "operation.read", "file.metadata.read"}


@pytest.mark.integration
def test_roles_requires_login(db_client: TestClient) -> None:
    assert db_client.get(f"{API}/roles").status_code == 401


@pytest.mark.integration
def test_disabled_user_session_loses_access(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="dis.soon", password="Dis!soon-2026-Pass", role="viewer")
    response, csrf = login_csrf(db_client, "dis.soon", "Dis!soon-2026-Pass")
    assert response.status_code == 200
    assert db_client.get(f"{API}/auth/me").status_code == 200
    user = db_session.scalar(select(User).where(User.username == "dis.soon"))
    assert user is not None
    user.status = "disabled"
    db_session.commit()
    assert db_client.get(f"{API}/auth/me").status_code == 401
