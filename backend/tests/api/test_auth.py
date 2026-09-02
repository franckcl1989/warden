"""Auth API integration tests on the real PostgreSQL (docs/API_CONTRACT.md §3).

Covers: login success/failure, lockout, logout, session expiry, password
change with session revocation, reauthentication, CSRF, Origin validation and
IP rate limiting. Everything runs against a freshly migrated ``warden_test``.
"""

from __future__ import annotations

import datetime

import pytest
from app.infrastructure.csrf import hash_csrf_secret, issue_csrf_secret
from app.infrastructure.session_tokens import generate_session_token, hash_session_token
from app.infrastructure.time import utcnow
from app.models.auth import AuditLog, User
from app.models.auth import Session as DBSession
from fastapi import FastAPI
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

API = "/api/v1"
LOCKED_USER = "locked.user"


def _count_audit(db: Session, action: str) -> int:
    return len(db.scalars(select(AuditLog).where(AuditLog.action == action)).all())


@pytest.mark.integration
def test_login_success_sets_cookie_and_returns_csrf(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    body = response.json()
    assert csrf
    assert "session_expires_at" in body
    assert body["user"]["username"] == ADMIN_USERNAME
    assert body["user"]["role"] == "admin"
    assert "password_hash" not in response.text
    assert ADMIN_PASSWORD not in response.text
    cookie = db_client.cookies.get("warden_session")
    assert cookie and cookie not in response.text
    set_cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower()
    assert "path=/" in set_cookie.lower()

    me = db_client.get(f"{API}/auth/me")
    assert me.status_code == 200
    me_body = me.json()
    assert me_body["user"]["username"] == ADMIN_USERNAME
    assert set(me_body["permissions"]) >= {"user.manage", "device.manage", "audit.read"}
    assert me_body["user"]["must_change_password"] is False
    assert _count_audit(db_session, "auth.login") == 1


@pytest.mark.integration
def test_login_wrong_password_generic_error(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response = login(db_client, ADMIN_USERNAME, "Wrong-Pass-2026!")
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["message"] == "用户名或密码错误"
    assert db_client.cookies.get("warden_session") is None


@pytest.mark.integration
def test_login_unknown_username_returns_same_generic_error(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response = login(db_client, "nobody.here", "Whatever-2026!")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"
    assert "nobody.here" not in response.text


@pytest.mark.integration
def test_login_like_pattern_username_does_not_lock_admin_or_enumerate(
    db_client: TestClient, db_session: Session
) -> None:
    """Like-wildcard usernames must be exact-match lookups, not LIKE patterns.

    Regression: ``ilike`` treated ``%``/``_`` as wildcards, so username ``%``
    matched the first row (the admin) and 5 wrong-password attempts locked it;
    the distinct account_locked/account_disabled responses also leaked the
    account state. Every wildcard attempt must behave exactly like an unknown
    username (generic invalid_credentials) and leave admin untouched.
    """
    create_admin(db_session)
    baseline = login(db_client, ADMIN_USERNAME, "Wrong-Pass-2026!")
    assert baseline.status_code == 422
    baseline_error = baseline.json()["error"]
    assert baseline_error["code"] == "validation_failed"
    assert baseline_error["details"]["field"] == "credentials"
    assert baseline_error["message"] == "用户名或密码错误"

    for pattern in ("%", "_dmin", "%dmin%", "%"):
        response = login(db_client, pattern, "Wrong-Pass-2026!")
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == baseline_error["code"]
        assert error["message"] == baseline_error["message"]
        assert error["details"]["field"] == "credentials"

    admin = db_session.scalar(select(User).where(User.username == ADMIN_USERNAME))
    assert admin is not None
    assert admin.status == "active"
    # Only the genuine wrong-password attempt counted; the 4 wildcard attempts
    # must not have touched the admin's failure counter at all.
    assert admin.failed_login_count == 1
    assert admin.locked_until is None
    assert _count_audit(db_session, "auth.lock") == 0
    assert _count_audit(db_session, "auth.login_failed") == 5

    sixth = login(db_client, "%", "Wrong-Pass-2026!")
    assert sixth.status_code == 429
    assert sixth.json()["error"]["code"] == "rate_limited"
    assert sixth.json()["error"]["message"] != "账号已锁定，请稍后重试"


@pytest.mark.integration
def test_five_failures_lock_user_and_write_audit(db_client: TestClient, db_session: Session) -> None:
    create_user(db_session, username="lockme", password="Orig!nal-2026-Pass", role="viewer")
    for _ in range(5):
        response = login(db_client, "lockme", "Wrong-Pass-2026!")
        assert response.status_code == 422
    user = db_session.scalar(select(User).where(User.username == "lockme"))
    assert user is not None
    assert user.status == "locked"
    assert user.failed_login_count == 5
    assert user.locked_until is not None and user.locked_until > utcnow()
    assert _count_audit(db_session, "auth.login_failed") == 5
    assert _count_audit(db_session, "auth.lock") == 1


@pytest.mark.integration
def test_locked_user_login_rejected_with_reason(db_client: TestClient, db_session: Session) -> None:
    create_user(db_session, username=LOCKED_USER, password="Orig!nal-2026-Pass", role="viewer")
    user = db_session.scalar(select(User).where(User.username == LOCKED_USER))
    assert user is not None
    user.status = "locked"
    user.locked_until = utcnow() + datetime.timedelta(minutes=15)
    db_session.commit()
    response = login(db_client, LOCKED_USER, "Orig!nal-2026-Pass")
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert "锁定" in error["message"]


@pytest.mark.integration
def test_disabled_user_login_rejected(db_client: TestClient, db_session: Session) -> None:
    create_user(db_session, username="gone.user", password="Orig!nal-2026-Pass", role="viewer", status="disabled")
    response = login(db_client, "gone.user", "Orig!nal-2026-Pass")
    assert response.status_code == 422
    assert "禁用" in response.json()["error"]["message"]


@pytest.mark.integration
def test_logout_revokes_session_and_me_returns_401(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    logout = db_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
    me = db_client.get(f"{API}/auth/me")
    assert me.status_code == 401
    assert _count_audit(db_session, "auth.logout") == 1


@pytest.mark.integration
def test_me_without_cookie_returns_401(db_client: TestClient) -> None:
    response = db_client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


@pytest.mark.integration
def test_revoked_session_returns_session_expired(db_client: TestClient, db_session: Session) -> None:
    user = create_admin(db_session)
    token = generate_session_token()
    db_session.add(
        DBSession(
            session_id_hash=hash_session_token(token),
            user_id=user.id,
            expires_at=utcnow() + datetime.timedelta(minutes=30),
            absolute_expires_at=utcnow() + datetime.timedelta(hours=12),
            csrf_secret_hash=hash_csrf_secret(issue_csrf_secret()),
            revoked_at=utcnow() - datetime.timedelta(seconds=1),
        )
    )
    db_session.commit()
    db_client.cookies.set("warden_session", token)
    response = db_client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "session_expired"


@pytest.mark.integration
def test_absolutely_expired_session_returns_session_expired(db_client: TestClient, db_session: Session) -> None:
    user = create_admin(db_session)
    token = generate_session_token()
    db_session.add(
        DBSession(
            session_id_hash=hash_session_token(token),
            user_id=user.id,
            expires_at=utcnow() + datetime.timedelta(minutes=30),
            absolute_expires_at=utcnow() - datetime.timedelta(minutes=1),
            csrf_secret_hash=hash_csrf_secret(issue_csrf_secret()),
        )
    )
    db_session.commit()
    db_client.cookies.set("warden_session", token)
    response = db_client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "session_expired"


@pytest.mark.integration
def test_idle_expired_session_returns_session_expired(db_client: TestClient, db_session: Session) -> None:
    user = create_admin(db_session)
    token = generate_session_token()
    db_session.add(
        DBSession(
            session_id_hash=hash_session_token(token),
            user_id=user.id,
            expires_at=utcnow() + datetime.timedelta(minutes=30),
            absolute_expires_at=utcnow() + datetime.timedelta(hours=12),
            csrf_secret_hash=hash_csrf_secret(issue_csrf_secret()),
            last_activity_at=utcnow() - datetime.timedelta(minutes=45),
        )
    )
    db_session.commit()
    db_client.cookies.set("warden_session", token)
    response = db_client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "session_expired"


@pytest.mark.integration
def test_mutating_request_without_valid_csrf_rejected(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    no_token = db_client.post(f"{API}/auth/logout")
    assert no_token.status_code == 403
    assert no_token.json()["error"]["code"] == "csrf_failed"
    wrong_token = db_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": "bm90LXRoZS1zZWNyZXQ"})
    assert wrong_token.status_code == 403
    assert wrong_token.json()["error"]["code"] == "csrf_failed"
    with_token = db_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert with_token.status_code == 200


@pytest.mark.integration
def test_change_password_revokes_other_sessions(db_client: TestClient, db_app: FastAPI, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    other = TestClient(db_app)
    other_response, _other_csrf = login_csrf(other, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert other_response.status_code == 200
    change = db_client.post(
        f"{API}/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "Br@nd-New-2026-Pass"},
        headers={"X-CSRF-Token": csrf},
    )
    assert change.status_code == 200
    assert other.get(f"{API}/auth/me").status_code == 401
    assert db_client.get(f"{API}/auth/me").status_code == 200
    assert login(db_client, ADMIN_USERNAME, ADMIN_PASSWORD).status_code == 422
    assert login(db_client, ADMIN_USERNAME, "Br@nd-New-2026-Pass").status_code == 200
    assert _count_audit(db_session, "auth.password_changed") == 1
    me = db_client.get(f"{API}/auth/me").json()
    assert me["user"]["must_change_password"] is False


@pytest.mark.integration
def test_change_password_policy_violation_rejected(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    short = db_client.post(
        f"{API}/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "abc"},
        headers={"X-CSRF-Token": csrf},
    )
    assert short.status_code == 422
    assert "12" in short.json()["error"]["message"]
    common = db_client.post(
        f"{API}/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "password1234"},
        headers={"X-CSRF-Token": csrf},
    )
    assert common.status_code == 422
    assert "常见弱密码" in common.json()["error"]["message"]
    wrong_current = db_client.post(
        f"{API}/auth/password",
        json={"current_password": "Nope-Nope-2026!", "new_password": "Br@nd-New-2026-Pass"},
        headers={"X-CSRF-Token": csrf},
    )
    assert wrong_current.status_code == 422
    assert "当前密码错误" in wrong_current.json()["error"]["message"]


@pytest.mark.integration
def test_reauth_records_reauthenticated_at(db_client: TestClient, db_session: Session) -> None:
    user = create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    reauth = db_client.post(
        f"{API}/auth/reauth",
        json={"password": ADMIN_PASSWORD},
        headers={"X-CSRF-Token": csrf},
    )
    assert reauth.status_code == 200
    until = reauth.json()["reauthenticated_until"]
    assert until > datetime.datetime.now(datetime.UTC).isoformat()
    session_row = db_session.scalar(select(DBSession).where(DBSession.user_id == user.id))
    assert session_row is not None and session_row.reauthenticated_at is not None
    failed = db_client.post(
        f"{API}/auth/reauth",
        json={"password": "Wrong-Pass-2026!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert failed.status_code == 422
    assert _count_audit(db_session, "auth.reauth") == 2


@pytest.mark.integration
def test_cross_origin_login_rejected(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response = login(db_client, ADMIN_USERNAME, ADMIN_PASSWORD, origin="https://evil.example")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    same_origin = login(db_client, ADMIN_USERNAME, ADMIN_PASSWORD, origin="http://localhost")
    assert same_origin.status_code == 200


@pytest.mark.integration
def test_login_rate_limit_returns_429(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    for _ in range(5):
        assert login(db_client, ADMIN_USERNAME, "Wrong-Pass-2026!").status_code == 422
    sixth = login(db_client, ADMIN_USERNAME, "Wrong-Pass-2026!")
    assert sixth.status_code == 429
    error = sixth.json()["error"]
    assert error["code"] == "rate_limited"
    assert "retry_after_seconds" in error["details"]
    assert error["details"]["scope"] == "login:ip"


@pytest.mark.integration
def test_audit_rows_never_contain_passwords_or_tokens(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    db_client.post(
        f"{API}/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "Br@nd-New-2026-Pass"},
        headers={"X-CSRF-Token": csrf},
    )
    rows = db_session.scalars(select(AuditLog)).all()
    assert len(rows) >= 2
    forbidden = [ADMIN_PASSWORD, "Br@nd-New-2026-Pass", response.json()["csrf_token"]]
    for row in rows:
        assert not any(item in (row.detail_jsonb or {}) for item in forbidden)
        assert not any(item in str(row.detail_jsonb or {}) for item in forbidden)


@pytest.mark.integration
def test_login_success_resets_failed_counter_and_unlocks(db_client: TestClient, db_session: Session) -> None:
    create_user(db_session, username="recover.me", password="Orig!nal-2026-Pass", role="viewer")
    user = db_session.scalar(select(User).where(User.username == "recover.me"))
    assert user is not None
    user.status = "locked"
    user.locked_until = utcnow() - datetime.timedelta(seconds=5)
    user.failed_login_count = 5
    db_session.commit()
    response, _csrf = login_csrf(db_client, "recover.me", "Orig!nal-2026-Pass")
    assert response.status_code == 200
    db_session.refresh(user)
    assert user.status == "active"
    assert user.failed_login_count == 0
    assert user.locked_until is None
    assert user.last_login_at is not None


@pytest.mark.integration
def test_login_never_returns_the_session_token(db_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(db_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    cookie = db_client.cookies.get("warden_session")
    assert cookie is not None
    assert cookie not in response.text
    me = db_client.get(f"{API}/auth/me")
    assert cookie not in me.text


@pytest.mark.integration
def test_must_change_password_user_gated_on_protected_routers(db_client: TestClient, db_session: Session) -> None:
    """SECURITY §2/§3: 首次登录强制改密是服务端门禁，前端隐藏只是 UX。

    must_change_password 用户只能访问 auth 路由（me/password/logout/reauth）；
    其它路由一律 403 permission_denied（permission=password_change_required）；
    改密后访问恢复。
    """
    create_user(
        db_session,
        username="fresh.user",
        password="Init!al-2026-Pass",
        role="admin",
        must_change_password=True,
    )
    response, csrf = login_csrf(db_client, "fresh.user", "Init!al-2026-Pass")
    assert response.status_code == 200
    assert response.json()["user"]["must_change_password"] is True

    # auth 路由保持可用：me 报告标志位
    me = db_client.get(f"{API}/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["must_change_password"] is True

    # 非 auth 路由被门禁拦截（所有角色都有 device.read，
    # 403 只可能来自改密门禁而非权限矩阵）
    devices = db_client.get(f"{API}/devices")
    assert devices.status_code == 403
    error = devices.json()["error"]
    assert error["code"] == "permission_denied"
    assert error["details"]["permission"] == "password_change_required"

    users = db_client.get(f"{API}/users")
    assert users.status_code == 403
    assert users.json()["error"]["details"]["permission"] == "password_change_required"

    # 变更类请求同样被拦截，并按 M1T4 模式写 access.denied 审计
    patch = db_client.patch(
        f"{API}/devices/d-1",
        headers={"If-Match": "1", "X-CSRF-Token": csrf},
        json={"name": "x"},
    )
    assert patch.status_code == 403
    assert patch.json()["error"]["details"]["permission"] == "password_change_required"
    assert _count_audit(db_session, "access.denied") == 1

    # reauth 属于 auth 路由，仍然可用
    reauth = db_client.post(
        f"{API}/auth/reauth",
        json={"password": "Init!al-2026-Pass"},
        headers={"X-CSRF-Token": csrf},
    )
    assert reauth.status_code == 200

    # 改密（auth 路由）成功且清除标志位后，其它路由访问恢复
    change = db_client.post(
        f"{API}/auth/password",
        json={"current_password": "Init!al-2026-Pass", "new_password": "Br@nd-New-2026-Pass"},
        headers={"X-CSRF-Token": csrf},
    )
    assert change.status_code == 200
    assert db_client.get(f"{API}/devices").status_code == 200
    assert db_client.get(f"{API}/auth/me").json()["user"]["must_change_password"] is False

    # logout 始终可用
    logout = db_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
