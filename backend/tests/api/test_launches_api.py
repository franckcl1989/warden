"""Launch API integration tests (M3T4, real PostgreSQL, API_CONTRACT §7).

End-to-end over HTTP for SRV-ACT-03 console.kvm.open: create (201 with the
single-use consume URL; vendor descriptor URL only leaves via the one-shot
GET), single-use/expiry/revocation/cross-user 404 semantics, permission and
capability/availability gates, channel enforcement (task-channel capabilities
are 422 unsupported_operation), concurrency caps (3 active per user, 1 per
device — 429 rate_limited with scope), the HTML auto-redirect consume page
with Referrer-Policy: no-referrer (JSON via Accept negotiation for tests) and
audit rows on create + consume. Launch rows stay issued/consumed — no
operation_tasks rows are ever created (launch is not a task).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.infrastructure.time import utcnow
from app.models.auth import AuditLog, User
from app.models.devices import Device, DeviceCapability
from app.models.launch import LaunchSession
from app.models.operation import OperationTask
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_user,
    login_csrf,
)
from tests.api.rate_limit_helpers import freeze_rate_limit_clock
from tests.api.test_devices import create_device, probe_and_get_token

API = "/api/v1"
LAUNCHES_PATH = f"{API}/devices/{{id}}/launches"
CONSUME_PATH = f"{API}/launches/{{id}}"

OPERATOR_PASSWORD = "Op!pass-2026-Strong"
VIEWER_PASSWORD = "V!ew-2026-Strong"

KVM_CONSOLE_URL = "https://192.0.2.10/console"


def _user_csrf(
    device_client: TestClient,
    db_session: Session,
    *,
    username: str,
    password: str,
    role: str,
) -> tuple[User, str]:
    user = db_session.scalar(select(User).where(User.username == username))
    if user is None:
        user = create_user(
            db_session,
            username=username,
            password=password,
            role=role,
            display_name=f"{role}-{username}",
        )
    response, csrf = login_csrf(device_client, username, password)
    assert response.status_code == 200
    return user, csrf


@pytest.fixture
def onboarded_device(
    device_client: TestClient, db_session: Session,
) -> tuple[str, dict[str, object]]:
    """Admin onboards one fake server and returns (device_id, body)."""
    admin, csrf = _user_csrf(
        device_client,
        db_session,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
        role="admin",
    )
    del admin
    probe = probe_and_get_token(device_client, csrf)
    assert probe["ok"] is True
    created = create_device(device_client, csrf, token=probe["probe_token"], name="fake-srv-launch")
    assert created.status_code == 201
    return str(created.json()["id"]), created.json()


def _create(
    device_client: TestClient,
    csrf: str,
    device_id: str,
    capability_key: str = "console.kvm.open",
) -> object:
    return device_client.post(
        LAUNCHES_PATH.format(id=device_id),
        json={"capability_key": capability_key},
        headers={"X-CSRF-Token": csrf},
    )


def _consume(
    device_client: TestClient, launch_id: str, *, accept: str = "application/json"
) -> object:
    return device_client.get(CONSUME_PATH.format(id=launch_id), headers={"Accept": accept})


def _audit_rows(db_session: Session, action: str) -> list[AuditLog]:
    return list(
        db_session.scalars(
            select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at)
        ).all()
    )


@pytest.mark.integration
def test_create_launch_happy_path_returns_201_issued_row_and_audit(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-launch", password=OPERATOR_PASSWORD, role="operator"
    )
    before = utcnow()

    response = _create(device_client, csrf, device_id)

    assert response.status_code == 201
    body = response.json()
    launch_id = uuid.UUID(body["launch_id"])
    expires_at = datetime.datetime.fromisoformat(body["expires_at"])
    # The ticket lives 60 seconds (API_CONTRACT.md §7: 60 秒未使用即失效).
    assert datetime.timedelta(seconds=50) <= expires_at - before <= datetime.timedelta(seconds=70)
    # The POST returns ONLY the same-origin single-use consume URL; the
    # vendor descriptor URL never reaches the SPA state (single-use GET).
    assert body["url"].endswith(f"/api/v1/launches/{launch_id}")
    assert KVM_CONSOLE_URL not in body["url"]
    assert KVM_CONSOLE_URL not in str(body)

    row = db_session.get(LaunchSession, launch_id)
    assert row is not None
    assert row.status == "issued"
    assert row.device_id == uuid.UUID(device_id)
    assert row.user_id == operator.id
    assert row.capability_key == "console.kvm.open"
    assert row.requirement_id == "SRV-ACT-03"
    assert row.protocol == "kvm"
    assert row.session_id is not None
    assert row.descriptor_url == KVM_CONSOLE_URL
    assert row.descriptor_data.get("kind") == "url"
    assert row.consumed_at is None

    # No task machinery is involved: launch is NOT a task.
    assert db_session.scalar(select(func.count()).select_from(OperationTask)) == 0

    creates = _audit_rows(db_session, "launch.create")
    assert len(creates) == 1
    assert creates[0].actor_user_id == operator.id
    assert creates[0].device_id == uuid.UUID(device_id)
    assert creates[0].requirement_id == "SRV-ACT-03"
    assert creates[0].result == "success"
    assert creates[0].detail_jsonb.get("capability_key") == "console.kvm.open"
    assert "descriptor_url" not in creates[0].detail_jsonb
    assert KVM_CONSOLE_URL not in str(creates[0].detail_jsonb)


@pytest.mark.integration
def test_get_consumes_once_then_uniform_404(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-single", password=OPERATOR_PASSWORD, role="operator"
    )
    created = _create(device_client, csrf, device_id)
    launch_id = created.json()["launch_id"]

    first = _consume(device_client, launch_id)
    assert first.status_code == 200
    assert first.headers.get("Referrer-Policy") == "no-referrer"
    assert first.headers.get("X-Content-Type-Options") == "nosniff"
    descriptor = first.json()["descriptor"]
    assert descriptor["kind"] == "url"
    assert descriptor["url"] == KVM_CONSOLE_URL

    row = db_session.get(LaunchSession, uuid.UUID(launch_id))
    assert row is not None
    assert row.status == "consumed"
    assert row.consumed_at is not None

    consumes = _audit_rows(db_session, "launch.consume")
    assert len(consumes) == 1

    # Single-use: every later read is a uniform non-enumerable 404.
    second = _consume(device_client, launch_id)
    assert second.status_code == 404
    assert second.json()["error"]["code"] == "resource_not_found"
    third = _consume(device_client, launch_id)
    assert third.status_code == 404
    assert len(_audit_rows(db_session, "launch.consume")) == 1


@pytest.mark.integration
def test_get_html_accept_returns_auto_redirect_page(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-html", password=OPERATOR_PASSWORD, role="operator"
    )
    launch_id = _create(device_client, csrf, device_id).json()["launch_id"]

    response = _consume(device_client, launch_id, accept="text/html")

    assert response.status_code == 200
    assert response.headers.get("Content-Type", "").startswith("text/html")
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert "url=" in response.text
    assert KVM_CONSOLE_URL in response.text
    assert "https://" in response.text
    assert "no-referrer" in response.text
    row = db_session.get(LaunchSession, uuid.UUID(launch_id))
    assert row is not None and row.status == "consumed"


@pytest.mark.integration
def test_expired_revoked_and_foreign_launches_are_uniform_404_without_consuming(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-owner", password=OPERATOR_PASSWORD, role="operator"
    )

    def _backdated_row(**values: object) -> uuid.UUID:
        launch_id = uuid.UUID(_create(device_client, csrf, device_id).json()["launch_id"])
        row = db_session.get(LaunchSession, launch_id)
        assert row is not None
        for key, value in values.items():
            setattr(row, key, value)
        db_session.commit()
        return launch_id

    expired_id = _backdated_row(
        expires_at=utcnow() - datetime.timedelta(minutes=1), status="issued"
    )
    revoked_id = _backdated_row(
        status="revoked", revoked_at=utcnow(), expires_at=utcnow() + datetime.timedelta(minutes=1)
    )

    for launch_id in (expired_id, revoked_id):
        response = _consume(device_client, str(launch_id))
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "resource_not_found"
        row = db_session.get(LaunchSession, launch_id)
        assert row is not None and row.status in ("issued", "revoked")

    # A foreign-user GET is a uniform 404 and does NOT consume the ticket.
    # (The ticket is created while the owner session is active — the client
    # cookie then switches to the other operator for the foreign read.)
    foreign_id = uuid.UUID(_create(device_client, csrf, device_id).json()["launch_id"])
    other, other_csrf = _user_csrf(
        device_client, db_session, username="op-foreign", password=OPERATOR_PASSWORD, role="operator"
    )
    del operator, other, other_csrf
    foreign = _consume(device_client, str(foreign_id))
    assert foreign.status_code == 404
    row = db_session.get(LaunchSession, foreign_id)
    assert row is not None and row.status == "issued"
    # The owner can still consume it after logging back in.
    _, owner_csrf = _user_csrf(
        device_client, db_session, username="op-owner", password=OPERATOR_PASSWORD, role="operator"
    )
    assert _consume(device_client, str(foreign_id)).status_code == 200

    # Unknown and malformed ids are the same non-enumerable 404.
    unknown = _consume(device_client, str(uuid.uuid4()))
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "resource_not_found"
    assert _consume(device_client, "not-a-uuid").status_code == 404
    # No audit is written for failed reads (uniform 404 semantics).
    assert len(_audit_rows(db_session, "launch.consume")) == 1


@pytest.mark.integration
def test_viewer_cannot_create_launch_and_device_state_is_checked(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, body = onboarded_device
    _, viewer_csrf = _user_csrf(
        device_client, db_session, username="view-launch", password=VIEWER_PASSWORD, role="viewer"
    )
    denied = _create(device_client, viewer_csrf, device_id)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"
    assert db_session.scalar(select(func.count()).select_from(LaunchSession)) == 0

    # Disabled / not-ready devices refuse launches (no adapter call happens).
    _, admin_csrf = _user_csrf(
        device_client,
        db_session,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
        role="admin",
    )
    row = db_session.get(Device, uuid.UUID(device_id))
    row.enabled = False
    db_session.commit()
    assert _create(device_client, admin_csrf, device_id).status_code == 422

    row.enabled = True
    row.readiness = "not_ready"
    db_session.commit()
    assert _create(device_client, admin_csrf, device_id).status_code == 422

    # A launch never reaches the adapter for unknown devices (404 first).
    assert _create(device_client, admin_csrf, str(uuid.uuid4())).status_code == 404
    del body


@pytest.mark.integration
def test_capability_gates_unsupported_not_configured_and_task_channel(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-gates", password=OPERATOR_PASSWORD, role="operator"
    )

    # Task-channel capability: never creatable as a launch (422).
    task_channel = _create(device_client, csrf, device_id, "power.on")
    assert task_channel.status_code == 422
    assert task_channel.json()["error"]["code"] == "unsupported_operation"
    assert task_channel.json()["error"]["details"]["capability_key"] == "power.on"

    capability = db_session.scalar(
        select(DeviceCapability).where(
            DeviceCapability.device_id == uuid.UUID(device_id),
            DeviceCapability.capability_key == "console.kvm.open",
        )
    )
    assert capability is not None

    capability.support_state = "unsupported"
    capability.reason_code = "no_graphical_console"
    db_session.commit()
    unsupported = _create(device_client, csrf, device_id)
    assert unsupported.status_code == 422
    assert unsupported.json()["error"]["code"] == "unsupported_operation"
    assert unsupported.json()["error"]["details"]["capability_key"] == "console.kvm.open"

    capability.support_state = "not_configured"
    capability.reason_code = "no_graphical_console"
    capability.detail = "管理卡未提供图形控制台"
    db_session.commit()
    not_configured = _create(device_client, csrf, device_id)
    assert not_configured.status_code == 422
    error = not_configured.json()["error"]
    assert error["code"] == "not_configured"
    assert error["details"]["capability_key"] == "console.kvm.open"

    assert db_session.scalar(select(func.count()).select_from(LaunchSession)) == 0


@pytest.mark.integration
def test_adapter_failure_without_console_advertisement_is_not_configured(
    device_client: TestClient, db_session: Session,
) -> None:
    """A saved device whose console is gone at launch time fails honestly
    (no descriptor row, 422 not_configured) instead of fabricating success."""
    admin, csrf = _user_csrf(
        device_client,
        db_session,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
        role="admin",
    )
    del admin
    probe = probe_and_get_token(
        device_client, csrf, connection_config={"no_graphical_console": True}
    )
    assert probe["ok"] is True
    created = create_device(
        device_client,
        csrf,
        token=probe["probe_token"],
        name="fake-no-console",
        connection_config={"no_graphical_console": True},
    )
    assert created.status_code == 201
    device_id = str(created.json()["id"])

    response = _create(device_client, csrf, device_id)

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "not_configured"
    assert error["details"]["capability_key"] == "console.kvm.open"
    assert db_session.scalar(select(func.count()).select_from(LaunchSession)) == 0


@pytest.mark.integration
def test_concurrency_caps_three_per_user_and_one_per_device(
    device_client: TestClient, db_session: Session,
) -> None:
    admin, csrf = _user_csrf(
        device_client,
        db_session,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
        role="admin",
    )
    del admin
    device_ids: list[str] = []
    for index in range(5):
        probe = probe_and_get_token(
            device_client, csrf, management_endpoint=f"192.0.2.{11 + index}"
        )
        created = create_device(
            device_client,
            csrf,
            token=probe["probe_token"],
            name=f"fake-launch-{index}",
            endpoint=f"192.0.2.{11 + index}",
        )
        assert created.status_code == 201, created.text
        device_ids.append(str(created.json()["id"]))

    operator, op_csrf = _user_csrf(
        device_client, db_session, username="op-cap", password=OPERATOR_PASSWORD, role="operator"
    )

    first = _create(device_client, op_csrf, device_ids[0])
    assert first.status_code == 201

    # 1/device: a second active ticket for the same device is refused.
    again = _create(device_client, op_csrf, device_ids[0])
    assert again.status_code == 429
    assert again.json()["error"]["code"] == "rate_limited"
    assert again.json()["error"]["details"]["scope"] == "launch_session_device"

    # 3/user across devices; the 4th concurrent ticket is refused.
    for device_id in device_ids[1:3]:
        assert _create(device_client, op_csrf, device_id).status_code == 201
    over = _create(device_client, op_csrf, device_ids[3])
    assert over.status_code == 429
    assert over.json()["error"]["code"] == "rate_limited"
    assert over.json()["error"]["details"]["scope"] == "launch_session_user"
    assert db_session.scalar(
        select(func.count()).select_from(LaunchSession).where(LaunchSession.status == "issued")
    ) == 3

    # Consuming releases the device slot: a fresh ticket is allowed again.
    consumed = _consume(device_client, first.json()["launch_id"])
    assert consumed.status_code == 200
    released = _create(device_client, op_csrf, device_ids[0])
    assert released.status_code == 201

    # The per-user cap is per user: another operator can still launch.
    other, other_csrf = _user_csrf(
        device_client, db_session, username="op-cap2", password=OPERATOR_PASSWORD, role="operator"
    )
    del operator, other
    assert _create(device_client, other_csrf, device_ids[4]).status_code == 201


@pytest.mark.integration
def test_launch_rate_limit_per_user_per_minute(
    device_client: TestClient, db_session: Session,
) -> None:
    """API_CONTRACT.md §7/§11: launch 10/min/用户 (the DB caps add the real
    concurrency bound). The fixed 60s window must not roll over during the
    11-request burst (M6T2): the limiter clock is frozen so the refusal is
    deterministic at any wall-clock time.
    """
    freeze_rate_limit_clock(device_client.app)
    _, csrf = _user_csrf(
        device_client, db_session, username="op-ratelimit", password=OPERATOR_PASSWORD, role="operator"
    )
    limit = 10  # WardenSettings default launch_rate_limit_per_minute
    for _index in range(limit):
        response = _create(device_client, csrf, str(uuid.uuid4()))
        assert response.status_code == 404  # unknown device: limiter counts the attempt

    limited = _create(device_client, csrf, str(uuid.uuid4()))
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "rate_limited"
    assert limited.json()["error"]["details"]["scope"] == "launch"


@pytest.mark.integration
def test_launch_requires_authentication_and_csrf(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    # Start logged out: the admin session created by the fixture is ended.
    _, first_csrf = _user_csrf(
        device_client, db_session, username=ADMIN_USERNAME, password=ADMIN_PASSWORD, role="admin"
    )
    assert (
        device_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": first_csrf}).status_code
        == 200
    )
    # No session: 401 before anything.
    anonymous = device_client.post(
        LAUNCHES_PATH.format(id=device_id), json={"capability_key": "console.kvm.open"}
    )
    assert anonymous.status_code == 401

    _, csrf = _user_csrf(
        device_client, db_session, username="op-csrf", password=OPERATOR_PASSWORD, role="operator"
    )
    no_csrf = device_client.post(
        LAUNCHES_PATH.format(id=device_id), json={"capability_key": "console.kvm.open"}
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "csrf_failed"
    assert _create(device_client, csrf, device_id).status_code == 201
    # Unauthenticated consume is 401 and does not consume the ticket.
    launch_id = db_session.scalar(select(LaunchSession.id).order_by(LaunchSession.created_at.desc()))
    assert launch_id is not None
    logout = device_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
    assert _consume(device_client, str(launch_id)).status_code == 401
    row = db_session.get(LaunchSession, launch_id)
    assert row is not None and row.status == "issued"
