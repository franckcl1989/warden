"""Audit API integration tests (docs/API_CONTRACT.md §9, contracts/http-api.json).

Covers the read-only audit API (admin list/filter/get, non-admin 403, 404,
defensive detail sanitization) and the M1 security-event coverage: failed
logins, lockout, csrf.failed, access.denied on mutating 403s and
security.config_changed on weak-protocol connection_config changes, plus the
credentials_replaced marker on credential-rotating device updates.
"""

from __future__ import annotations

import uuid

import pytest
from app.models.auth import AuditLog
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login,
    login_csrf,
)
from tests.api.test_devices import (
    admin_csrf,
    create_device,
    probe_and_get_token,
)

API = "/api/v1"
AUDIT_PATH = f"{API}/audit-logs"
DEVICES_PATH = f"{API}/devices"
PASSWORD = "device-pass-123"


def _count_audit(db: Session, action: str) -> int:
    return len(db.scalars(select(AuditLog).where(AuditLog.action == action)).all())


def _latest_audit(db: Session, action: str) -> AuditLog:
    row = db.scalar(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.occurred_at.desc()))
    assert row is not None
    return row


@pytest.mark.integration
def test_admin_lists_filters_and_gets_audit_rows(db_client: TestClient, db_session: Session) -> None:
    admin = create_admin(db_session)
    response, _csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200

    listing = db_client.get(AUDIT_PATH)
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["page"] == 1 and body["page_size"] == 20
    item = body["items"][0]
    assert item["action"] == "auth.login"
    assert item["actor_username"] == ADMIN_USERNAME
    assert item["actor_user_id"] == str(admin.id)
    assert item["requirement_id"] == "PLT-01"
    assert "detail" not in item
    assert "detail_jsonb" not in listing.text

    by_actor = db_client.get(f"{AUDIT_PATH}?actor_user_id={admin.id}")
    assert by_actor.json()["total"] == 1
    by_actor_mismatch = db_client.get(f"{AUDIT_PATH}?actor_user_id={uuid.uuid4()}")
    assert by_actor_mismatch.json()["total"] == 0
    by_prefix = db_client.get(f"{AUDIT_PATH}?action=auth.")
    assert by_prefix.json()["total"] == 1
    by_prefix_none = db_client.get(f"{AUDIT_PATH}?action=device.")
    assert by_prefix_none.json()["total"] == 0
    by_requirement = db_client.get(f"{AUDIT_PATH}?requirement_id=PLT-01")
    assert by_requirement.json()["total"] == 1
    by_resource = db_client.get(f"{AUDIT_PATH}?resource_type=user")
    assert by_resource.json()["total"] == 1
    window = db_client.get(
        f"{AUDIT_PATH}?from=2026-01-01T00:00:00Z&to=2030-01-01T00:00:00Z"
    )
    assert window.json()["total"] == 1
    past = db_client.get(f"{AUDIT_PATH}?from=2031-01-01T00:00:00Z")
    assert past.json()["total"] == 0
    asc = db_client.get(f"{AUDIT_PATH}?sort=occurred_at")
    assert asc.json()["total"] == 1

    detail = db_client.get(f"{AUDIT_PATH}/{item['id']}")
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["id"] == item["id"]
    assert detail_body["action"] == "auth.login"
    assert detail_body["session_id"] is not None
    assert detail_body["detail"] == {}
    assert "password" not in detail_body["detail"]


@pytest.mark.integration
def test_non_admin_cannot_read_audit(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="operator.1", password="Oper!ator-2026-Pass", role="operator")
    create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")
    for username, password in (("operator.1", "Oper!ator-2026-Pass"), ("viewer.1", "View!er-2026-Pass")):
        response, _csrf = login_csrf(db_client, username, password)
        assert response.status_code == 200
        listing = db_client.get(AUDIT_PATH)
        assert listing.status_code == 403
        assert listing.json()["error"]["code"] == "permission_denied"
        detail = db_client.get(f"{AUDIT_PATH}/{uuid.uuid4()}")
        assert detail.status_code == 403
        assert detail.json()["error"]["code"] == "permission_denied"
    # The operator/viewer can still read their own identity.
    assert db_client.get(f"{API}/auth/me").status_code == 200


@pytest.mark.integration
def test_get_detail_is_sanitized_even_for_tampered_rows(
    db_client: TestClient, db_session: Session
) -> None:
    """Defensive re-sanitization at read: a row written without the writer
    sanitizer (direct ORM insert) must still never leak secrets via the API."""
    create_admin(db_session)
    login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    row = AuditLog(
        action="test.tampered",
        result="success",
        detail_jsonb={
            "password": "hunter2",
            "token": "abc123",
            "authorization": "Bearer xyz",
            "note": "ok",
        },
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)
    detail = db_client.get(f"{AUDIT_PATH}/{row.id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["detail"] == {
        "password": "[REDACTED]",
        "token": "[REDACTED]",
        "authorization": "[REDACTED]",
        "note": "ok",
    }
    for secret in ("hunter2", "abc123", "Bearer xyz"):
        assert secret not in detail.text


@pytest.mark.integration
def test_unknown_or_malformed_id_returns_404(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    missing = db_client.get(f"{AUDIT_PATH}/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "resource_not_found"
    garbage = db_client.get(f"{AUDIT_PATH}/not-a-uuid")
    assert garbage.status_code == 404
    assert garbage.json()["error"]["code"] == "resource_not_found"


@pytest.mark.integration
def test_failed_login_and_lockout_rows_exist(db_client: TestClient, db_session: Session) -> None:
    create_user(db_session, username="lock.me", password="Lock!Me-2026-Pass", role="viewer")
    for _ in range(5):
        response = login(db_client, "lock.me", "Wrong-Pass-2026!")
        assert response.status_code == 422
    assert _count_audit(db_session, "auth.login_failed") == 5
    lock_row = _latest_audit(db_session, "auth.lock")
    assert lock_row.result == "success"
    assert lock_row.detail_jsonb == {"reason": "too many failed logins"}


@pytest.mark.integration
def test_csrf_failed_row_after_bad_csrf_attempt(db_client: TestClient, db_session: Session) -> None:
    admin = create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    no_token = db_client.post(f"{API}/auth/logout")
    assert no_token.status_code == 403
    assert no_token.json()["error"]["code"] == "csrf_failed"
    wrong_token = db_client.post(
        f"{API}/auth/logout", headers={"X-CSRF-Token": "0" * 32}
    )
    assert wrong_token.status_code == 403
    assert _count_audit(db_session, "csrf.failed") == 2
    row = _latest_audit(db_session, "csrf.failed")
    assert row.result == "failure"
    assert row.actor_user_id == admin.id
    assert row.detail_jsonb == {"reason": "invalid_token"}
    assert row.resource_id == f"{API}/auth/logout"
    # A good CSRF attempt succeeds and writes auth.logout, not csrf.failed.
    ok = db_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200
    assert _count_audit(db_session, "csrf.failed") == 2
    assert _count_audit(db_session, "auth.logout") == 1


@pytest.mark.integration
def test_access_denied_row_after_viewer_mutating_403(
    db_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    viewer = create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")
    response, csrf = login_csrf(db_client, "viewer.1", "View!er-2026-Pass")
    assert response.status_code == 200
    denied = db_client.post(
        f"{API}/users",
        json={
            "username": "blocked.user",
            "display_name": "被阻止",
            "role": "viewer",
            "password": "Block!ed-2026-Pass",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"
    # A GET denial must NOT be audited (M1T4 bounded decision: mutating only).
    db_client.get(f"{API}/users", headers={"X-CSRF-Token": csrf})
    assert _count_audit(db_session, "access.denied") == 1
    row = _latest_audit(db_session, "access.denied")
    assert row.result == "permission_denied"
    assert row.actor_user_id == viewer.id
    assert row.detail_jsonb == {
        "permission": "user.manage",
        "method": "POST",
        "path": f"{API}/users",
    }


@pytest.mark.integration
def test_security_config_changed_after_snmp_v2c_patch(
    device_client: TestClient, db_session: Session, device_settings
) -> None:
    del device_settings
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    new_probe = probe_and_get_token(
        device_client, csrf, connection_config={"snmp_version": "v2c"}
    )
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "connection_config": {"snmp_version": "v2c"},
            "probe_token": new_probe["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 200
    assert patched.json()["connection_config"]["snmp_version"] == "v2c"
    row = _latest_audit(db_session, "security.config_changed")
    assert row.result == "success"
    assert row.device_id is not None and str(row.device_id) == device_id
    assert row.detail_jsonb["changed_keys"] == ["snmp_version"]
    # The regular update row still exists; a benign re-PATCH adds no new event.
    benign = probe_and_get_token(device_client, csrf, connection_config={"snmp_version": "v2c"})
    re_patch = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "connection_config": {"snmp_version": "v2c"},
            "probe_token": benign["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "2"},
    )
    assert re_patch.status_code == 200
    assert _count_audit(db_session, "security.config_changed") == 1


@pytest.mark.integration
def test_device_create_audit_row_has_no_credentials(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    row = _latest_audit(db_session, "device.create")
    assert PASSWORD not in str(row.detail_jsonb)
    assert "credentials_digest" in row.detail_jsonb
    assert "password" not in str(row.detail_jsonb)


@pytest.mark.integration
def test_device_update_marks_credentials_replaced(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    new_password = "rotated-pass-456"
    new_probe = probe_and_get_token(
        device_client, csrf, credentials={"username": "admin", "password": new_password}
    )
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "credentials": {"username": "admin", "password": new_password},
            "probe_token": new_probe["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 200
    row = _latest_audit(db_session, "device.update")
    assert row.detail_jsonb.get("credentials_replaced") is True
    assert new_password not in str(row.detail_jsonb)
    assert "credentials_digest" in row.detail_jsonb


@pytest.mark.integration
def test_audit_rows_cover_m1_security_events(db_client: TestClient, db_session: Session) -> None:
    """The M1T1/M1T4 event names are all present after a representative flow."""
    create_admin(db_session)
    response, _csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    login(db_client, ADMIN_USERNAME, "Wrong-Pass-2026!")
    db_client.post(f"{API}/auth/logout")  # bad CSRF -> csrf.failed
    actions = {row.action for row in db_session.scalars(select(AuditLog)).all()}
    assert {"auth.login", "auth.login_failed", "csrf.failed"} <= actions
