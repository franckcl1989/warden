"""Operation API integration tests (M2T4, real PostgreSQL, API_CONTRACT §6).

End-to-end over HTTP: preview -> confirm (202 task + same-transaction audit),
drift and token failures (409 preview_stale / 422 validation_failed),
idempotency replay (409 idempotency_conflict + existing_task_id), launch
profile rejection, list/get with the append-only timeline, cancel paths
(queued / running-unfenced / fenced 409), and admin-only verify/resolve with
the fake adapter's verify modes. Tasks stay queued — no worker involved.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.infrastructure.time import utcnow
from app.models.auth import AuditLog, User
from app.models.operation import OperationTask
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
from tests.api.test_devices import create_device, probe_and_get_token
from tests.task_factories import make_task

API = "/api/v1"
PREVIEW_PATH = f"{API}/devices/{{id}}/operation-previews"
OPERATIONS_PATH = f"{API}/devices/{{id}}/operations"

PASSWORD = "device-pass-123"
OPERATOR_PASSWORD = "Op!pass-2026-Strong"
VIEWER_PASSWORD = "V!ew-2026-Strong"


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


def _admin(device_client: TestClient, db_session: Session) -> tuple[User, str]:
    user = db_session.scalar(select(User).where(User.username == ADMIN_USERNAME))
    if user is None:
        user = create_admin(db_session)
    response, csrf = login_csrf(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    return user, csrf


@pytest.fixture
def onboarded_device(
    device_client: TestClient, db_session: Session,
) -> tuple[str, dict[str, object]]:
    """(admin, csrf) onboard a fake server and return (device_id, body)."""
    admin, csrf = _admin(device_client, db_session)
    del admin
    probe = probe_and_get_token(device_client, csrf)
    assert probe["ok"] is True
    created = create_device(device_client, csrf, token=probe["probe_token"], name="fake-srv-01")
    assert created.status_code == 201
    body = created.json()
    return str(body["id"]), body


def _preview(
    device_client: TestClient,
    csrf: str,
    device_id: str,
    capability_key: str,
    parameters: dict[str, object] | None = None,
) -> object:
    return device_client.post(
        PREVIEW_PATH.format(id=device_id),
        json={"capability_key": capability_key, "parameters": parameters or {}},
        headers={"X-CSRF-Token": csrf},
    )


def _confirm(
    device_client: TestClient,
    csrf: str,
    device_id: str,
    preview_token: str,
    *,
    confirmation_text: str,
    idempotency_key: str,
) -> object:
    return device_client.post(
        OPERATIONS_PATH.format(id=device_id),
        json={"preview_token": preview_token, "confirmation_text": confirmation_text},
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": idempotency_key},
    )


def _reauth(device_client: TestClient, csrf: str, password: str) -> object:
    return device_client.post(
        f"{API}/auth/reauth",
        json={"password": password},
        headers={"X-CSRF-Token": csrf},
    )


def _preview_then_confirm(
    device_client: TestClient,
    csrf: str,
    device_id: str,
    *,
    capability_key: str = "power.on",
    confirmation_text: str = "fake-srv-01",
    idempotency_key: str = "api-flow-key-0001",
) -> tuple[object, object]:
    preview = _preview(device_client, csrf, device_id, capability_key)
    assert preview.status_code == 200
    token = str(preview.json()["preview_token"])
    confirmed = _confirm(
        device_client, csrf, device_id, token,
        confirmation_text=confirmation_text,
        idempotency_key=idempotency_key,
    )
    return preview, confirmed


def _audit_actions(db_session: Session) -> list[str]:
    return list(db_session.scalars(select(AuditLog.action)).all())


def _task_rows(db_session: Session) -> list[OperationTask]:
    return list(db_session.scalars(select(OperationTask).order_by(OperationTask.created_at)).all())


@pytest.mark.integration
def test_full_preview_confirm_flow_creates_task_and_audit(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-full", password=OPERATOR_PASSWORD, role="operator"
    )
    preview = _preview(device_client, csrf, device_id, "power.on")
    assert preview.status_code == 401
    assert preview.json()["error"]["code"] == "reauthentication_required"
    assert _reauth(device_client, csrf, OPERATOR_PASSWORD).status_code == 200

    preview, confirmed = _preview_then_confirm(
        device_client, csrf, device_id, idempotency_key="full-flow-key-01"
    )
    body = preview.json()
    assert body["requirement_id"] == "SRV-ACT-02"
    assert body["capability_key"] == "power.on"
    assert body["risk_level"] == "high"
    assert body["target"]["name"] == "fake-srv-01"
    assert body["impact"]
    assert body["steps"]
    assert body["confirmation"] == {"kind": "type_device_name", "expected": "fake-srv-01"}
    assert body["normalized_parameters"] == {}
    assert body["preview_token"]

    assert confirmed.status_code == 202
    task_body = confirmed.json()
    assert task_body["state"] == "queued"
    assert task_body["requirement_id"] == "SRV-ACT-02"
    assert task_body["risk_level"] == "high"
    assert task_body["device"]["name"] == "fake-srv-01"
    assert task_body["requested_by"]["username"] == "op-full"
    assert task_body["timeout_at"] is not None

    task = db_session.get(OperationTask, uuid.UUID(task_body["id"]))
    assert task is not None
    assert task.state == "queued"
    assert task.requested_by == operator.id
    assert task.plan_hash and task.parameter_hash
    assert task.adapter_version == "0.1.0"
    assert task.parameters == {}
    create_audits = [
        row
        for row in db_session.scalars(
            select(AuditLog).where(AuditLog.action == "operation.create")
        ).all()
        if row.task_id == task.id
    ]
    assert len(create_audits) == 1
    assert create_audits[0].requirement_id == "SRV-ACT-02"
    assert create_audits[0].result == "accepted"
    assert "operation.preview" in _audit_actions(db_session)

    # Timeline event for the created task exists (DATA_MODEL.md §7.3); the
    # client cookie from the operator login carries the session.
    detail = device_client.get(f"{API}/operations/{task.id}")
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["state"] == "queued"
    assert [event["state"] for event in detail_body["events"]] == ["queued"]


@pytest.mark.integration
def test_confirm_replay_same_key_is_idempotency_conflict(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-idem", password=OPERATOR_PASSWORD, role="operator"
    )
    del operator
    assert _reauth(device_client, csrf, OPERATOR_PASSWORD).status_code == 200
    preview, confirmed = _preview_then_confirm(
        device_client, csrf, device_id, idempotency_key="replay-key-0001"
    )
    assert confirmed.status_code == 202
    first_id = confirmed.json()["id"]
    replay = _confirm(
        device_client, csrf, device_id, str(preview.json()["preview_token"]),
        confirmation_text="fake-srv-01", idempotency_key="replay-key-0001",
    )
    assert replay.status_code == 409
    error = replay.json()["error"]
    assert error["code"] == "idempotency_conflict"
    assert error["details"]["existing_task_id"] == first_id
    assert len(_task_rows(db_session)) == 1


@pytest.mark.integration
def test_confirm_wrong_device_name_and_tampered_token(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-name", password=OPERATOR_PASSWORD, role="operator"
    )
    assert _reauth(device_client, csrf, OPERATOR_PASSWORD).status_code == 200
    preview = _preview(device_client, csrf, device_id, "power.on")
    token = str(preview.json()["preview_token"])

    wrong_name = _confirm(
        device_client, csrf, device_id, token,
        confirmation_text="some-other-device", idempotency_key="name-key-00001",
    )
    assert wrong_name.status_code == 422
    error = wrong_name.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "confirmation_text"

    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    bad_token = _confirm(
        device_client, csrf, device_id, tampered,
        confirmation_text="fake-srv-01", idempotency_key="tamper-key-0001",
    )
    assert bad_token.status_code == 422
    error = bad_token.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "preview_token"

    missing_key = device_client.post(
        OPERATIONS_PATH.format(id=device_id),
        json={"preview_token": token, "confirmation_text": "fake-srv-01"},
        headers={"X-CSRF-Token": csrf},
    )
    assert missing_key.status_code == 422
    assert missing_key.json()["error"]["details"]["field"] == "idempotency_key"
    assert _task_rows(db_session) == []


@pytest.mark.integration
def test_confirm_device_version_bump_is_preview_stale(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, device_body = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-ver", password=OPERATOR_PASSWORD, role="operator"
    )
    assert _reauth(device_client, csrf, OPERATOR_PASSWORD).status_code == 200
    preview = _preview(device_client, csrf, device_id, "power.on")
    assert preview.status_code == 200
    admin, admin_csrf = _admin(device_client, db_session)
    del admin
    patched = device_client.patch(
        f"{API}/devices/{device_id}",
        json={"name": "fake-srv-renamed"},
        headers={"X-CSRF-Token": admin_csrf, "If-Match": str(device_body["version"])},
    )
    assert patched.status_code == 200
    assert patched.json()["version"] == device_body["version"] + 1
    # Log back in as the operator: the admin login replaced the client cookie,
    # and the CSRF token is per-session.
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-ver", password=OPERATOR_PASSWORD, role="operator"
    )
    del operator
    confirmed = _confirm(
        device_client, csrf, device_id, str(preview.json()["preview_token"]),
        confirmation_text="fake-srv-01", idempotency_key="version-key-001",
    )
    assert confirmed.status_code == 409
    error = confirmed.json()["error"]
    assert error["code"] == "preview_stale"
    assert "设备配置已变化" in error["details"]["reason"]
    assert _task_rows(db_session) == []


@pytest.mark.integration
def test_viewer_cannot_preview_confirm_or_cancel(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="view-user", password=VIEWER_PASSWORD, role="viewer"
    )
    preview = _preview(device_client, csrf, device_id, "power.on")
    assert preview.status_code == 403
    assert preview.json()["error"]["details"]["permission"] == "operation.execute.high"
    assert "access.denied" in _audit_actions(db_session)

    seeded = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=db_session.scalar(select(User.id).where(User.username == "view-user")),
        index=0,
        idempotency_key="seed-viewer",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="queued",
    )
    cancelled = device_client.post(
        f"{API}/operations/{seeded.id}/cancel",
        headers={"X-CSRF-Token": csrf},
    )
    assert cancelled.status_code == 403
    assert db_session.get(OperationTask, seeded.id).state == "queued"


@pytest.mark.integration
def test_unsupported_and_launch_capabilities_are_rejected(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    _, csrf = _user_csrf(
        device_client, db_session, username="op-cap", password=OPERATOR_PASSWORD, role="operator"
    )
    assert _reauth(device_client, csrf, OPERATOR_PASSWORD).status_code == 200
    unsupported = _preview(device_client, csrf, device_id, "health.overall")
    assert unsupported.status_code == 422
    assert unsupported.json()["error"]["code"] == "unsupported_operation"
    unknown = _preview(device_client, csrf, device_id, "interface.admin.set")
    assert unknown.status_code == 422
    assert unknown.json()["error"]["code"] == "unsupported_operation"

    launch_preview = _preview(device_client, csrf, device_id, "console.kvm.open")
    assert launch_preview.status_code == 200
    confirmed = _confirm(
        device_client, csrf, device_id, str(launch_preview.json()["preview_token"]),
        confirmation_text="fake-srv-01", idempotency_key="launch-key-0001",
    )
    assert confirmed.status_code == 422
    error = confirmed.json()["error"]
    assert error["code"] == "unsupported_operation"
    assert error["details"]["capability_key"] == "console.kvm.open"
    assert _task_rows(db_session) == []


@pytest.mark.integration
def test_cancel_paths_queued_running_unfenced_and_fenced(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator, csrf = _user_csrf(
        device_client, db_session, username="op-cancel", password=OPERATOR_PASSWORD, role="operator"
    )
    now = utcnow()

    queued = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-cancel-q",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="queued",
    )
    cancelled = device_client.post(
        f"{API}/operations/{queued.id}/cancel", headers={"X-CSRF-Token": csrf}
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    db_session.expire_all()
    assert db_session.get(OperationTask, queued.id).state == "cancelled"
    assert "operation.cancel" in _audit_actions(db_session)

    running_unfenced = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=1,
        idempotency_key="seed-cancel-r",
        requirement_id="SRV-ACT-04",
        capability_key="logs.support_bundle.collect",
        conflict_scope="device_read_heavy",
        state="running",
        lease_owner="worker-1",
        lease_expires_at=now + datetime.timedelta(minutes=5),
        timeout_at=now + datetime.timedelta(minutes=10),
    )
    cancelled_running = device_client.post(
        f"{API}/operations/{running_unfenced.id}/cancel", headers={"X-CSRF-Token": csrf}
    )
    assert cancelled_running.status_code == 200
    assert cancelled_running.json()["state"] == "cancelled"

    fenced = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=2,
        idempotency_key="seed-cancel-f",
        requirement_id="SRV-ACT-02",
        capability_key="power.cycle",
        state="running",
        lease_owner="worker-1",
        lease_expires_at=now + datetime.timedelta(minutes=5),
        dispatch_started_at=now,
    )
    fenced_cancel = device_client.post(
        f"{API}/operations/{fenced.id}/cancel", headers={"X-CSRF-Token": csrf}
    )
    assert fenced_cancel.status_code == 409
    error = fenced_cancel.json()["error"]
    assert error["code"] == "preview_stale"
    assert "派发" in error["details"]["reason"]

    terminal = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=3,
        idempotency_key="seed-cancel-t",
        requirement_id="SRV-ACT-02",
        capability_key="manager.reset",
        state="succeeded",
        finished_at=now,
    )
    terminal_cancel = device_client.post(
        f"{API}/operations/{terminal.id}/cancel", headers={"X-CSRF-Token": csrf}
    )
    assert terminal_cancel.status_code == 409
    assert terminal_cancel.json()["error"]["code"] == "preview_stale"


@pytest.mark.integration
def test_verify_admin_only_success_and_resolve_evidence_required(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator = create_user(
        db_session, username="op-verify", password=OPERATOR_PASSWORD, role="operator"
    )
    admin = db_session.scalar(select(User).where(User.username == ADMIN_USERNAME))
    assert admin is not None

    verification_task = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-verify-1",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="verification_required",
        verification_state=None,
    )

    # Operator session first: verify and resolve-verification must 403.
    operator_csrf = _user_csrf(
        device_client, db_session, username="op-verify", password=OPERATOR_PASSWORD, role="operator"
    )[1]
    as_operator = device_client.post(
        f"{API}/operations/{verification_task.id}/verify",
        headers={"X-CSRF-Token": operator_csrf},
    )
    assert as_operator.status_code == 403
    resolved_by_operator = device_client.post(
        f"{API}/operations/{verification_task.id}/resolve-verification",
        json={
            "outcome": "succeeded",
            "evidence_type": "device_ui",
            "reference": "BMC 页面电源状态为 On",
            "reason": "现场查看 BMC 页面确认系统已开机",
        },
        headers={"X-CSRF-Token": operator_csrf},
    )
    assert resolved_by_operator.status_code == 403

    # Admin session last (its login replaced the client cookie).
    admin_csrf = _admin(device_client, db_session)[1]
    verified = device_client.post(
        f"{API}/operations/{verification_task.id}/verify",
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert verified.status_code == 200
    body = verified.json()
    assert body["state"] == "succeeded"
    assert body["verification_state"] == "passed"
    assert body["evidence"]["verification"]["succeeded"] is True
    db_session.expire_all()
    assert db_session.get(OperationTask, verification_task.id).state == "succeeded"
    assert "operation.verify" in _audit_actions(db_session)


@pytest.mark.integration
def test_verify_ambiguous_keeps_task_verification_required(
    device_client: TestClient, db_session: Session,
) -> None:
    admin, admin_csrf = _admin(device_client, db_session)
    probe = probe_and_get_token(
        device_client, admin_csrf, connection_config={"verify_ambiguous_mode": True}
    )
    assert probe["ok"] is True
    created = create_device(
        device_client, admin_csrf, token=probe["probe_token"],
        name="fake-srv-ambiguous",
        connection_config={"verify_ambiguous_mode": True},
    )
    assert created.status_code == 201
    device_id = str(created.json()["id"])
    operator = create_user(
        db_session, username="op-amb", password=OPERATOR_PASSWORD, role="operator"
    )
    task = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-verify-amb",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="verification_required",
        error_code="ambiguous_result",
    )
    verified = device_client.post(
        f"{API}/operations/{task.id}/verify",
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert verified.status_code == 200
    body = verified.json()
    assert body["state"] == "verification_required"
    assert body["error_code"] == "ambiguous_result"
    assert body["evidence"]["verification"]["ambiguous"] is True
    db_session.expire_all()
    stored = db_session.get(OperationTask, task.id)
    assert stored is not None and stored.state == "verification_required"


@pytest.mark.integration
def test_resolve_verification_requires_evidence_and_state(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator = create_user(
        db_session, username="op-res", password=OPERATOR_PASSWORD, role="operator"
    )
    admin, admin_csrf = _admin(device_client, db_session)
    task = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-resolve-1",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="verification_required",
    )
    resolve_path = f"{API}/operations/{task.id}/resolve-verification"

    missing_fields = device_client.post(
        resolve_path,
        json={"outcome": "succeeded", "evidence_type": "other", "reference": ""},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert missing_fields.status_code == 422
    bad_type = device_client.post(
        resolve_path,
        json={
            "outcome": "succeeded",
            "evidence_type": "word_of_mouth",
            "reference": "x",
            "reason": "口头确认",
        },
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert bad_type.status_code == 422

    resolved = device_client.post(
        resolve_path,
        json={
            "outcome": "succeeded",
            "evidence_type": "device_log",
            "reference": "SEL 事件记录 2026-09-01",
            "reason": "SEL 记录显示系统完成开机序列",
        },
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert resolved.status_code == 200
    body = resolved.json()
    assert body["state"] == "succeeded"
    assert body["verification_state"] == "passed"
    assert body["evidence"]["resolution"]["evidence_type"] == "device_log"
    assert "operation.resolve" in _audit_actions(db_session)

    again = device_client.post(
        resolve_path,
        json={
            "outcome": "failed",
            "evidence_type": "device_ui",
            "reference": "later",
            "reason": "task already resolved",
        },
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "preview_stale"


@pytest.mark.integration
def test_resolve_failure_outcome_marks_task_failed(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator = create_user(
        db_session, username="op-fail", password=OPERATOR_PASSWORD, role="operator"
    )
    admin, admin_csrf = _admin(device_client, db_session)
    task = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-resolve-fail",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="verification_required",
    )
    resolved = device_client.post(
        f"{API}/operations/{task.id}/resolve-verification",
        json={
            "outcome": "failed",
            "evidence_type": "device_cli",
            "reference": "CLI 显示 Off",
            "reason": "现场 CLI 显示系统仍为关机",
        },
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert resolved.status_code == 200
    body = resolved.json()
    assert body["state"] == "failed"
    assert body["verification_state"] == "failed"
    assert body["error_code"] == "operation_failed"


@pytest.mark.integration
def test_operations_list_filters_and_get_detail(
    device_client: TestClient, db_session: Session, onboarded_device: tuple[str, dict[str, object]],
) -> None:
    device_id, _ = onboarded_device
    operator = create_user(
        db_session, username="op-list", password=OPERATOR_PASSWORD, role="operator"
    )
    assert login_csrf(device_client, "op-list", OPERATOR_PASSWORD)[0].status_code == 200
    queued = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=0,
        idempotency_key="seed-list-1",
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        state="queued",
    )
    running = make_task(
        db_session,
        device_id=uuid.UUID(device_id),
        requested_by=operator.id,
        index=1,
        idempotency_key="seed-list-2",
        requirement_id="SRV-ACT-04",
        capability_key="logs.support_bundle.collect",
        conflict_scope="device_read_heavy",
        state="running",
    )
    del running

    response = device_client.get(f"{API}/operations")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 2
    by_key = {item["capability_key"]: item for item in items}
    assert by_key["power.on"]["state"] == "queued"
    assert by_key["power.on"]["requested_by"]["username"] == "op-list"
    assert by_key["power.on"]["device"]["name"] == "fake-srv-01"

    filtered = device_client.get(f"{API}/operations", params={"state": "queued"})
    assert [item["capability_key"] for item in filtered.json()["items"]] == ["power.on"]
    filtered = device_client.get(
        f"{API}/operations", params={"requirement_id": "SRV-ACT-04"}
    )
    assert [item["capability_key"] for item in filtered.json()["items"]] == [
        "logs.support_bundle.collect"
    ]

    detail = device_client.get(f"{API}/operations/{queued.id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["state"] == "queued"
    assert body["parameters"] == {}
    assert body["events"] == []
    assert body["evidence"] is None

    missing = device_client.get(f"{API}/operations/{uuid.uuid4()}")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "resource_not_found"
