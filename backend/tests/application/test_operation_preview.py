"""Operation preview/confirm application tests (M2T4, real PostgreSQL).

Covers create_preview / confirm_and_create_task directly: preview plan
fields + 60s token, capability support states, parameter schema rejections,
permission gating, high-risk reauth, mutex device_busy, and the invariant
that previews NEVER contact the device (fake adapter call counters stay at
zero). Confirm tests cover re-verification: expired/tampered tokens, device
version drift, launch-channel rejection, name mismatch, capability drift and
idempotency replay semantics (409 idempotency_conflict + original task id).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.adapters.fake import FakeSimpleAdapter
from app.application import operations as op_service
from app.application.operations import AuditContext, OperationPreview
from app.config import WardenSettings
from app.domain.errors import AppError
from app.infrastructure.preview_tokens import PreviewTokenSigner
from app.infrastructure.time import utcnow
from app.models.auth import Session as AuthSession
from app.models.auth import User
from app.models.devices import Device, DeviceCapability
from app.models.operation import OperationTask
from sqlalchemy.orm import Session

from tests.api.auth_helpers import create_admin, create_user
from tests.task_factories import make_task

SERVER_ACT_KEYS = (
    ("SRV-ACT-01", "manager.reset"),
    ("SRV-ACT-02", "power.on"),
    ("SRV-ACT-02", "power.off"),
    ("SRV-ACT-02", "power.cycle"),
    ("SRV-ACT-03", "console.kvm.open"),
    ("SRV-ACT-04", "logs.support_bundle.collect"),
)

IDEM_KEY = "preview-test-key-1"


@pytest.fixture
def settings(fresh_test_db_dsn: str, tmp_path) -> WardenSettings:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        credential_master_key_file=key_file,
        session_secret_file=session_file,
    )


@pytest.fixture
def audit() -> AuditContext:
    return AuditContext(
        actor_user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        source_ip="127.0.0.1",
        user_agent_summary="pytest",
        request_id="test-request",
    )


def _session_row(db: Session, user: User, *, reauthenticated_at: datetime.datetime | None = None) -> AuthSession:
    now = utcnow()
    row = AuthSession(
        session_id_hash=f"hash-{uuid.uuid4()}",
        user_id=user.id,
        expires_at=now + datetime.timedelta(minutes=30),
        absolute_expires_at=now + datetime.timedelta(hours=12),
        reauthenticated_at=reauthenticated_at,
        csrf_secret_hash="csrf-secret-hash",
        client_summary="pytest",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@pytest.fixture
def device(db_session: Session) -> Device:
    device = Device(
        name="fake-srv-01",
        device_type="server",
        management_endpoint="192.0.2.10",
        adapter_key="fake.simple",
        connection_config={},
        enabled=True,
        readiness="ready",
    )
    db_session.add(device)
    db_session.flush()
    now = utcnow()
    for requirement_id, capability_key in SERVER_ACT_KEYS:
        db_session.add(
            DeviceCapability(
                device_id=device.id,
                capability_key=capability_key,
                support_state="supported",
                requirement_id=requirement_id,
                discovery_method="fake.simple",
                last_checked_at=now,
                adapter_version="0.1.0",
            )
        )
    db_session.commit()
    db_session.refresh(device)
    return device


@pytest.fixture
def operator(db_session: Session) -> User:
    return create_user(
        db_session, username="op-user", password="Op!pass-12345", role="operator"
    )


@pytest.fixture
def operator_session(db_session: Session, operator: User) -> AuthSession:
    return _session_row(db_session, operator, reauthenticated_at=utcnow())


def _preview(
    db_session: Session,
    settings: WardenSettings,
    device: Device,
    user: User,
    session: AuthSession,
    audit: AuditContext,
    *,
    capability_key: str = "power.on",
    parameters: dict[str, object] | None = None,
) -> OperationPreview:
    return op_service.create_preview(
        db_session,
        device=device,
        capability_key=capability_key,
        parameters=parameters or {},
        user=user,
        session=session,
        settings=settings,
        logger=None,
        audit=audit,
    )


def _confirm(
    db_session: Session,
    settings: WardenSettings,
    device: Device,
    user: User,
    session: AuthSession,
    audit: AuditContext,
    preview: OperationPreview,
    *,
    confirmation_text: str | None = None,
    idempotency_key: str = IDEM_KEY,
) -> OperationTask:
    return op_service.confirm_and_create_task(
        db_session,
        device=device,
        preview_token=preview.preview_token,
        confirmation_text=confirmation_text if confirmation_text is not None else device.name,
        idempotency_key=idempotency_key,
        user=user,
        session=session,
        settings=settings,
        logger=None,
        audit=audit,
    )


def _error_code(excinfo: pytest.ExceptionInfo[AppError]) -> str:
    return excinfo.value.code


@pytest.mark.integration
def test_preview_happy_path_plan_fields_token_and_expiry(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    plan = preview.plan
    assert plan.requirement_id == "SRV-ACT-02"
    assert plan.capability_key == "power.on"
    assert plan.risk_level == "high"
    assert plan.conflict_scope == "device"
    assert plan.timeout_seconds == 600
    assert plan.steps
    assert plan.impact
    assert preview.expires_at - utcnow() <= datetime.timedelta(seconds=61)
    assert preview.expires_at > utcnow()
    claims = PreviewTokenSigner(settings.session_secret).verify(
        preview.preview_token, now=utcnow()
    )
    assert claims.user_id == operator.id
    assert claims.device_id == device.id
    assert claims.device_version == device.version
    assert claims.capability_key == "power.on"
    assert claims.risk_level == "high"
    assert claims.parameters == {}
    assert claims.parameter_hash == plan.parameter_hash


@pytest.mark.integration
def test_preview_never_contacts_the_device(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def _record(name: str):
        def _inner(*_args: object, **_kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"preview must not call the device ({name})")

        return _inner

    monkeypatch.setattr(FakeSimpleAdapter, "probe", _record("probe"))
    monkeypatch.setattr(FakeSimpleAdapter, "discover", _record("discover"))
    monkeypatch.setattr(FakeSimpleAdapter, "collect", _record("collect"))
    monkeypatch.setattr(FakeSimpleAdapter, "preflight_operation", _record("preflight"))
    monkeypatch.setattr(FakeSimpleAdapter, "execute_operation", _record("execute"))
    monkeypatch.setattr(FakeSimpleAdapter, "verify_operation", _record("verify"))
    _preview(db_session, settings, device, operator, operator_session, audit)
    assert calls == []


@pytest.mark.integration
def test_preview_unsupported_capability_maps_to_unsupported_operation(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, operator_session, audit,
                 capability_key="interface.admin.set")
    assert _error_code(excinfo) == "unsupported_operation"
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, operator_session, audit,
                 capability_key="health.overall")
    assert _error_code(excinfo) == "unsupported_operation"


@pytest.mark.integration
def test_preview_not_configured_capability_is_rejected(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    row = select_device_capability(db_session, device.id, "power.off")
    assert row is not None
    row.support_state = "not_configured"
    row.reason_code = "missing_platform_config"
    db_session.commit()
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, operator_session, audit,
                 capability_key="power.off")
    assert _error_code(excinfo) == "not_configured"
    assert excinfo.value.details.get("capability_key") == "power.off"


@pytest.mark.integration
def test_preview_rejects_bad_parameters(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, operator_session, audit,
                 capability_key="logs.support_bundle.collect", parameters={"extra": 1})
    assert _error_code(excinfo) == "validation_failed"


def select_device_capability(db: Session, device_id: uuid.UUID, key: str) -> DeviceCapability | None:
    from sqlalchemy import select

    return db.scalar(
        select(DeviceCapability).where(
            DeviceCapability.device_id == device_id,
            DeviceCapability.capability_key == key,
        )
    )


@pytest.mark.integration
def test_preview_denied_for_viewer(
    db_session: Session, settings: WardenSettings, device: Device, audit: AuditContext,
) -> None:
    viewer = create_user(db_session, username="viewer-user", password="V!ew-pass-12345", role="viewer")
    viewer_session = _session_row(db_session, viewer, reauthenticated_at=utcnow())
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, viewer, viewer_session, audit)
    assert _error_code(excinfo) == "permission_denied"
    assert excinfo.value.details.get("permission") == "operation.execute.high"


@pytest.mark.integration
def test_preview_high_risk_without_reauth_is_rejected(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    audit: AuditContext,
) -> None:
    fresh_session = _session_row(db_session, operator, reauthenticated_at=None)
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, fresh_session, audit)
    assert _error_code(excinfo) == "reauthentication_required"
    assert "reauthenticated_until" in excinfo.value.details


@pytest.mark.integration
def test_preview_low_risk_without_reauth_is_allowed(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    audit: AuditContext,
) -> None:
    fresh_session = _session_row(db_session, operator, reauthenticated_at=None)
    preview = _preview(db_session, settings, device, operator, fresh_session, audit,
                       capability_key="logs.support_bundle.collect")
    assert preview.plan.risk_level == "low"


@pytest.mark.integration
def test_preview_device_busy_when_mutex_held(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    make_task(
        db_session,
        device_id=device.id,
        requested_by=operator.id,
        requirement_id="SRV-ACT-02",
        capability_key="power.cycle",
        idempotency_key="busy-holder-0001",
    )
    with pytest.raises(AppError) as excinfo:
        _preview(db_session, settings, device, operator, operator_session, audit)
    assert _error_code(excinfo) == "device_busy"
    assert "conflict_task_id" in excinfo.value.details


@pytest.mark.integration
def test_confirm_happy_path_creates_task_in_db(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    task = _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert task.state == "queued"
    assert task.requirement_id == "SRV-ACT-02"
    assert task.capability_key == "power.on"
    assert task.device_id == device.id
    assert task.requested_by == operator.id
    assert task.risk_level == "high"
    assert task.idempotency_key == IDEM_KEY
    assert task.timeout_at is not None
    assert task.plan_hash and task.parameter_hash and task.adapter_version == "0.1.0"
    stored = db_session.get(OperationTask, task.id)
    assert stored is not None and stored.state == "queued"


@pytest.mark.integration
def test_confirm_wrong_device_name_is_rejected(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview,
                 confirmation_text="other-device")
    assert _error_code(excinfo) == "validation_failed"
    assert excinfo.value.details.get("field") == "confirmation_text"


@pytest.mark.integration
def test_confirm_missing_idempotency_key_is_rejected(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview,
                 idempotency_key=None)  # type: ignore[arg-type]
    assert _error_code(excinfo) == "validation_failed"
    assert excinfo.value.details.get("field") == "idempotency_key"


@pytest.mark.integration
def test_confirm_tampered_token_is_validation_failed(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    tampered = preview.preview_token[:-1] + ("0" if preview.preview_token[-1] != "0" else "1")
    with pytest.raises(AppError) as excinfo:
        op_service.confirm_and_create_task(
            db_session,
            device=device,
            preview_token=tampered,
            confirmation_text=device.name,
            idempotency_key=IDEM_KEY,
            user=operator,
            session=operator_session,
            settings=settings,
            logger=None,
            audit=audit,
        )
    assert _error_code(excinfo) == "validation_failed"
    assert excinfo.value.details.get("field") == "preview_token"


@pytest.mark.integration
def test_confirm_expired_token_is_preview_stale(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    past = utcnow() - datetime.timedelta(seconds=1)
    expired = PreviewTokenSigner(settings.session_secret).create(
        user_id=operator.id,
        device_id=device.id,
        device_version=device.version,
        requirement_id="SRV-ACT-02",
        capability_key="power.on",
        risk_level="high",
        parameters={},
        parameter_hash="deadbeef" * 8,
        expires_at=past,
    )
    with pytest.raises(AppError) as excinfo:
        op_service.confirm_and_create_task(
            db_session,
            device=device,
            preview_token=expired,
            confirmation_text=device.name,
            idempotency_key=IDEM_KEY,
            user=operator,
            session=operator_session,
            settings=settings,
            logger=None,
            audit=audit,
        )
    assert _error_code(excinfo) == "preview_stale"
    assert "过期" in str(excinfo.value.details.get("reason", ""))


@pytest.mark.integration
def test_confirm_device_version_drift_is_preview_stale(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    device.version += 1
    db_session.commit()
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "preview_stale"
    assert "设备配置已变化" in str(excinfo.value.details.get("reason", ""))


@pytest.mark.integration
def test_confirm_launch_channel_profile_is_unsupported_operation(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit,
                       capability_key="console.kvm.open")
    assert preview.plan.channel == "launch"
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "unsupported_operation"
    assert excinfo.value.details.get("capability_key") == "console.kvm.open"


@pytest.mark.integration
def test_confirm_capability_drift_is_preview_stale(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    row = select_device_capability(db_session, device.id, "power.on")
    assert row is not None
    row.support_state = "unsupported"
    db_session.commit()
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "preview_stale"


@pytest.mark.integration
def test_confirm_mutex_drift_is_device_busy(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    make_task(
        db_session,
        device_id=device.id,
        requested_by=operator.id,
        requirement_id="SRV-ACT-02",
        capability_key="power.cycle",
        idempotency_key="busy-drift-0001",
    )
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "device_busy"
    assert "conflict_task_id" in excinfo.value.details


@pytest.mark.integration
def test_idempotency_replay_returns_original_task_conflict(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    first = _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    # A retried submission (same key, even the same token) must not create a
    # second task: the DB unique (requested_by, idempotency_key) fires and the
    # 409 points at the ORIGINAL task.
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "idempotency_conflict"
    assert excinfo.value.details.get("existing_task_id") == str(first.id)
    count = db_session.scalar(_task_count(db_session, operator.id, IDEM_KEY))
    assert count == 1


@pytest.mark.integration
def test_idempotency_scope_is_per_user_not_per_device(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    del operator, operator_session
    admin = create_admin(db_session)
    admin_session = _session_row(db_session, admin, reauthenticated_at=utcnow())
    preview = _preview(db_session, settings, device, admin, admin_session, audit)
    _confirm(db_session, settings, device, admin, admin_session, audit, preview)
    other_device = Device(
        name="fake-srv-02",
        device_type="server",
        management_endpoint="192.0.2.11",
        adapter_key="fake.simple",
        connection_config={},
        enabled=True,
        readiness="ready",
    )
    db_session.add(other_device)
    db_session.flush()
    now = utcnow()
    for requirement_id, capability_key in SERVER_ACT_KEYS:
        db_session.add(
            DeviceCapability(
                device_id=other_device.id,
                capability_key=capability_key,
                support_state="supported",
                requirement_id=requirement_id,
                discovery_method="fake.simple",
                last_checked_at=now,
                adapter_version="0.1.0",
            )
        )
    db_session.commit()
    second_preview = _preview(db_session, settings, other_device, admin, admin_session, audit)
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, other_device, admin, admin_session, audit, second_preview)
    assert _error_code(excinfo) == "idempotency_conflict"
    # The 409 points at the ORIGINAL task, even though this request targets a
    # different device: scope is (requested_by, idempotency_key) per
    # DATA_MODEL.md §7.1 — clients must scope keys per action.
    original = _first_task(db_session, admin.id, IDEM_KEY)
    assert original is not None
    assert excinfo.value.details.get("existing_task_id") == str(original.id)


def _task_count(db: Session, user_id: uuid.UUID, idempotency_key: str) -> int:
    from sqlalchemy import func, select

    return (
        select(func.count())
        .select_from(OperationTask)
        .where(
            OperationTask.requested_by == user_id,
            OperationTask.idempotency_key == idempotency_key,
        )
    )


def _first_task(db: Session, user_id: uuid.UUID, idempotency_key: str) -> OperationTask | None:
    from sqlalchemy import select

    return db.scalar(
        select(OperationTask).where(
            OperationTask.requested_by == user_id,
            OperationTask.idempotency_key == idempotency_key,
        )
    )


@pytest.mark.integration
def test_confirm_rechecks_reauth_window_for_high_risk(
    db_session: Session, settings: WardenSettings, device: Device, operator: User,
    operator_session: AuthSession, audit: AuditContext,
) -> None:
    # Reauth is valid at preview time; the window closes before confirm, so
    # the confirm-time recheck must reject the submission.
    preview = _preview(db_session, settings, device, operator, operator_session, audit)
    operator_session.reauthenticated_at = utcnow() - datetime.timedelta(minutes=6)
    with pytest.raises(AppError) as excinfo:
        _confirm(db_session, settings, device, operator, operator_session, audit, preview)
    assert _error_code(excinfo) == "reauthentication_required"
