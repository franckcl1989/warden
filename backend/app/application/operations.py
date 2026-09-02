"""Operation two-phase flow and task lifecycle use cases (PLT-05).

docs/API_CONTRACT.md §6 (two-phase preview/confirm + task queries),
SECURITY.md §4 (保护链 12 步), PRODUCT_DESIGN.md §7.1 (流程 8 步),
DATA_MODEL.md §7/§11 (task rows + same-transaction audit).

Flow semantics (M2T4):

- ``create_preview``: snapshot-only planning — permission (operation.execute
  per profile risk), device state, capability support, mutex, parameter schema
  and (high risk) the 5-minute reauth window are checked; the device is NEVER
  contacted (DEVICE_ADAPTERS.md §2.4). Success signs a 60-second preview token
  binding user/device/version/capability/risk/parameters (API_CONTRACT §6.1)
  and REGISTERS its hash in the single-use ledger (``preview_token_uses``,
  migration 0010 — SECURITY.md §4 item 7: 一次性).
- ``confirm_and_create_task``: re-verifies EVERYTHING against the token claims
  and the CURRENT persisted state; any drift is 409 ``preview_stale``
  (API_CONTRACT.md §6.1: 任何变化返回 409 preview_stale，要求重新预览). Task
  creation + audit + the atomic token claim (conditional UPDATE on
  ``consumed_at IS NULL``) commit in ONE transaction (DATA_MODEL.md §11): a
  replayed token with a fresh Idempotency-Key can never create a second task
  (SECURITY.md §13 — 重放确认令牌不能产生第二次执行), and a rolled-back
  confirm un-consumes automatically. The (requested_by, idempotency_key)
  unique constraint is the idempotency authority — a duplicate key returns 409
  ``idempotency_conflict`` with the ORIGINAL task id even when the request
  differs (scope is per user, not per device; clients must scope keys per
  action — documented M2T4 decision).
- ``cancel_task`` / ``verify_task`` / ``resolve_task`` implement the §6.2
  semantics; verify/resolve are admin-only (M2T4 controller decision) and
  terminal transitions + their audit commit atomically. ``verify_task``
  rebuilds the previous execution result from the PERSISTED task row
  (device_job_id / evidence / error fields) and hands it to
  ``adapter.verify_operation`` — a device_job_status verify only ever queries
  the persisted job (DATA_MODEL.md §7.1: 存在时只查询，不重复创建).

The worker's preflight -> fence -> execute -> verify wiring is M2T6; tasks
created here stay ``queued``.
"""

from __future__ import annotations

import datetime
import json
import re
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters import UnknownAdapterError, get_adapter
from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.adapter import (
    AdapterError,
    DeviceAdapter,
    DeviceSession,
    OperationResult,
)
from app.domain.errors import AppError
from app.domain.operation import MUTEX_SCOPES, TaskState, VerificationState
from app.domain.operation_plan import (
    CapabilityView,
    DeviceSnapshot,
    OperationPlan,
    OperationRequest,
    execute_permission_for,
    plan_operation,
)
from app.domain.roles import require_permission as matrix_require
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialKeyring, EncryptedSecret, credential_aad
from app.infrastructure.preview_tokens import (
    IDEMPOTENCY_KEY_MAX_LENGTH,
    IDEMPOTENCY_KEY_MIN_LENGTH,
    IDEMPOTENCY_KEY_PATTERN,
    TOKEN_TTL_SECONDS,
    PreviewTokenClaims,
    PreviewTokenExpired,
    PreviewTokenInvalid,
    PreviewTokenSigner,
    token_hash,
)
from app.infrastructure.sessions import is_reauthenticated
from app.infrastructure.tasks import ACTIVE_MUTEX_STATES, append_event
from app.infrastructure.time import utcnow
from app.models.auth import Session as AuthSession
from app.models.auth import User
from app.models.devices import Device, DeviceCapability, DeviceCredential
from app.models.operation import OperationTask, OperationTaskEvent, PreviewTokenUse

PLT_05 = "PLT-05"

MESSAGE_PREVIEW_EXPIRED = "预览令牌已过期，请重新预览"
MESSAGE_PREVIEW_NEEDED = "需要先获取有效的操作预览"
MESSAGE_PREVIEW_STALE = "设备或能力状态已变化，请重新预览"
MESSAGE_PREVIEW_USED = "预览令牌已被使用，请重新预览"
MESSAGE_PREVIEW_NOT_REGISTERED = "预览令牌未在服务端登记，请重新预览"
MESSAGE_IDEMPOTENCY_CONFLICT = "已存在使用该幂等键提交的操作任务"
MESSAGE_DEVICE_BUSY = "该设备已有正在执行的任务，请稍后重试"

_IDEMPOTENCY_RE = re.compile(IDEMPOTENCY_KEY_PATTERN)


@dataclass(frozen=True)
class AuditContext:
    """Request metadata the operation services attach to audit rows."""

    actor_user_id: uuid.UUID
    session_id: uuid.UUID
    source_ip: str | None
    user_agent_summary: str | None
    request_id: str


@dataclass(frozen=True)
class OperationPreview:
    """create_preview outcome: the plan plus the signed 60s confirmation token."""

    plan: OperationPlan
    preview_token: str
    expires_at: datetime.datetime


def _audit_denial(
    logger: AuditLogger | None,
    audit: AuditContext,
    *,
    permission: str,
    path: str,
    device_id: uuid.UUID | None = None,
) -> None:
    """Audit one permission denial with the REAL endpoint resource (M2T4 fix).

    Denials must name the target endpoint resource (the actual path with the
    real device/task id) so a security investigation can reconstruct what was
    attempted; the hardcoded placeholder path of the original M2T4 build is
    gone. ``resource_id`` mirrors the deps.py truncation (varchar(64)).
    """
    if logger is None:
        return
    logger.record(
        action="access.denied",
        actor_user_id=audit.actor_user_id,
        session_id=audit.session_id,
        resource_type="operation",
        resource_id=path[:64],
        device_id=device_id,
        requirement_id=PLT_05,
        request_id=audit.request_id,
        result="permission_denied",
        source_ip=audit.source_ip,
        user_agent_summary=audit.user_agent_summary,
        detail={"permission": permission, "method": "POST", "path": path},
    )


def _enforce_execute_permission(
    user: User,
    risk_level: str,
    *,
    logger: AuditLogger | None,
    audit: AuditContext,
    path: str,
    device_id: uuid.UUID | None = None,
) -> None:
    """SECURITY.md §3.1: operation.execute.<risk> per profile risk."""
    permission = execute_permission_for(risk_level)
    if matrix_require(user.role, permission):
        return
    _audit_denial(
        logger, audit, permission=permission, path=path, device_id=device_id
    )
    raise auth_errors.permission_denied(permission)


def _signer(settings: WardenSettings) -> PreviewTokenSigner:
    return PreviewTokenSigner(settings.session_secret)


def _snapshot(db: Session, device: Device) -> DeviceSnapshot:
    capability_rows = db.scalars(
        select(DeviceCapability).where(DeviceCapability.device_id == device.id)
    ).all()
    return DeviceSnapshot(
        device_id=device.id,
        device_name=device.name,
        device_type=device.device_type,
        device_version=device.version,
        adapter_key=device.adapter_key,
        enabled=device.enabled,
        readiness=device.readiness,
        capabilities=tuple(
            CapabilityView(
                capability_key=row.capability_key,
                support_state=row.support_state,
                requirement_id=row.requirement_id,
                discovery_method=row.discovery_method,
                adapter_version=row.adapter_version,
                reason_code=row.reason_code,
                detail=row.detail,
            )
            for row in capability_rows
        ),
    )


def build_snapshot(db: Session, device: Device) -> DeviceSnapshot:
    """Public snapshot builder (M2T6 worker wiring reuses it)."""
    return _snapshot(db, device)


def _active_mutex_task(
    db: Session, device_id: uuid.UUID, conflict_scope: str
) -> OperationTask | None:
    """One active task holding the device mutex for this scope, if any.

    The partial unique index ``uq_operation_tasks_active_mutex`` enforces this
    at the database; this read gives the API a friendly 409 device_busy before
    the insert. Read scopes (device_read etc.) never conflict.
    """
    if conflict_scope not in MUTEX_SCOPES:
        return None
    return db.scalar(
        select(OperationTask)
        .where(
            OperationTask.device_id == device_id,
            OperationTask.conflict_scope == conflict_scope,
            OperationTask.state.in_(ACTIVE_MUTEX_STATES),
        )
        .order_by(OperationTask.created_at, OperationTask.id)
        .limit(1)
    )


def _device_busy(task: OperationTask, *, now: datetime.datetime) -> AppError:
    details: dict[str, object] = {"conflict_task_id": str(task.id)}
    if task.timeout_at is not None:
        retry = int((task.timeout_at - now).total_seconds())
        details["retry_after_seconds"] = max(1, retry)
    return AppError("device_busy", MESSAGE_DEVICE_BUSY, details=details)


def _preview_stale(reason: str) -> AppError:
    return AppError("preview_stale", MESSAGE_PREVIEW_STALE, details={"reason": reason})


def _require_valid_idempotency_key(idempotency_key: str | None) -> None:
    if not idempotency_key:
        raise auth_errors.validation_failed("idempotency_key", "请求头 Idempotency-Key 必填")
    if (
        len(idempotency_key) < IDEMPOTENCY_KEY_MIN_LENGTH
        or len(idempotency_key) > IDEMPOTENCY_KEY_MAX_LENGTH
        or _IDEMPOTENCY_RE.fullmatch(idempotency_key) is None
    ):
        raise auth_errors.validation_failed(
            "idempotency_key",
            "Idempotency-Key 只能包含字母、数字、点、下划线和连字符，长度 8-128",
        )


def _verify_preview_token(
    settings: WardenSettings,
    preview_token: str | None,
    *,
    now: datetime.datetime,
    user_id: uuid.UUID,
    device: Device,
) -> PreviewTokenClaims:
    """Signature/expiry/user/device binding checks on the preview token.

    Error mapping (M2T4 controller decisions): invalid signature/format -> 422
    validation_failed field=preview_token; expired -> 409 preview_stale
    reason=已过期; ownership/device binding drift -> 409 preview_stale.
    """
    if not preview_token:
        raise auth_errors.validation_failed("preview_token", MESSAGE_PREVIEW_NEEDED)
    try:
        claims = _signer(settings).verify(preview_token, now=now)
    except PreviewTokenExpired:
        raise _preview_stale(MESSAGE_PREVIEW_EXPIRED) from None
    except PreviewTokenInvalid as exc:
        raise auth_errors.validation_failed("preview_token", str(exc)) from None
    if claims.user_id != user_id:
        raise _preview_stale("该预览令牌不属于当前用户")
    if claims.device_id != device.id:
        raise _preview_stale("该预览令牌不属于目标设备")
    return claims


def create_preview(
    db: Session,
    *,
    device: Device,
    capability_key: str,
    parameters: dict[str, object],
    user: User,
    session: AuthSession,
    settings: WardenSettings,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> OperationPreview:
    """Protection-chain steps for one preview (no device contact).

    Raises: unsupported_operation (unknown/unsupported capability),
    not_configured, permission_denied, validation_failed, device_busy,
    reauthentication_required. Never talks to the device — only the persisted
    snapshot (DEVICE_ADAPTERS.md §2.4; tests enforce it via adapter call
    counters). Registers the issued token's hash in the single-use ledger
    (migration 0010) so confirm can claim it atomically.
    """
    current = now if now is not None else utcnow()
    if not device.enabled:
        raise auth_errors.validation_failed("device", "设备已停用，无法执行操作")
    if device.readiness != "ready":
        raise auth_errors.validation_failed("device", "设备未就绪，无法执行操作")
    probe_plan = plan_operation(
        _snapshot(db, device),
        OperationRequest(capability_key=capability_key, parameters=parameters),
    )
    preview_path = f"/devices/{device.id}/operation-previews"
    _enforce_execute_permission(
        user,
        probe_plan.risk_level,
        logger=logger,
        audit=audit,
        path=preview_path,
        device_id=device.id,
    )
    conflict = _active_mutex_task(db, device.id, probe_plan.conflict_scope)
    if conflict is not None:
        raise _device_busy(conflict, now=current)
    if probe_plan.risk_level == "high" and not is_reauthenticated(
        session, current, settings.reauth_ttl_minutes
    ):
        raise auth_errors.reauthentication_required(
            current + datetime.timedelta(minutes=settings.reauth_ttl_minutes)
        )
    expires_at = current + datetime.timedelta(seconds=TOKEN_TTL_SECONDS)
    token = _signer(settings).create(
        user_id=user.id,
        device_id=device.id,
        device_version=device.version,
        requirement_id=probe_plan.requirement_id,
        capability_key=probe_plan.capability_key,
        risk_level=probe_plan.risk_level,
        parameters=probe_plan.normalized_parameters,
        parameter_hash=probe_plan.parameter_hash,
        expires_at=expires_at,
    )
    # Register the token in the single-use ledger (migration 0010): the
    # confirm-time claim needs a row to consume. ON CONFLICT DO NOTHING keeps
    # two identical preview requests in the same second (deterministic token —
    # same payload/expiry) from raising; both receive the same token and only
    # the first confirm can claim it. The caller (route) commits.
    db.execute(
        pg_insert(PreviewTokenUse)
        .values(
            token_hash=token_hash(token),
            user_id=user.id,
            device_id=device.id,
            created_at=current,
            expires_at=expires_at,
        )
        .on_conflict_do_nothing()
    )
    if logger is not None:
        logger.record(
            action="operation.preview",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="device",
            resource_id=str(device.id),
            device_id=device.id,
            requirement_id=probe_plan.requirement_id,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "capability_key": probe_plan.capability_key,
                "risk_level": probe_plan.risk_level,
                "parameter_hash": probe_plan.parameter_hash,
                "preview_expires_at": expires_at.isoformat(),
            },
        )
    return OperationPreview(plan=probe_plan, preview_token=token, expires_at=expires_at)


def _map_plan_drift(exc: AppError) -> AppError:
    """Confirm-time plan failures mean the preview went stale, not bad input.

    The parameters were validated and the capability supported when the token
    was signed; a failure NOW means the world changed between preview and
    confirm (capability support state change or schema/registry drift), which
    API_CONTRACT.md §6.1 maps to 409 preview_stale.
    """
    return _preview_stale(f"{MESSAGE_PREVIEW_STALE}（{exc.message}）")


def _claim_preview_token(
    db: Session,
    *,
    preview_token: str,
    task_id: uuid.UUID,
    consumed_at: datetime.datetime,
) -> bool:
    """Atomically claim one issued preview token for ``task_id``.

    Single-use enforcement (SECURITY.md §4 item 7 / §13, migration 0010):
    the conditional UPDATE matches ONLY an unconsumed ledger row — a replay
    of an already-consumed token returns zero rows and can never reach a
    second task insert. The claim runs in the CALLER's transaction (the same
    one that creates the task — the task row already exists because the
    caller flushed it before claiming, which the consumed_by_task_id FK
    requires): commit makes it durable, rollback un-consumes, and the row
    lock serializes concurrent confirms of the same token (the second one
    sees ``consumed_at`` set).
    """
    claimed_id = db.execute(
        update(PreviewTokenUse)
        .where(
            PreviewTokenUse.token_hash == token_hash(preview_token),
            PreviewTokenUse.consumed_at.is_(None),
        )
        .values(
            consumed_at=consumed_at,
            consumed_by_task_id=task_id,
        )
        .returning(PreviewTokenUse.id)
    ).scalar_one_or_none()
    return claimed_id is not None


def _find_existing_task(db: Session, user_id: uuid.UUID, idempotency_key: str) -> OperationTask | None:
    return db.scalar(
        select(OperationTask).where(
            OperationTask.requested_by == user_id,
            OperationTask.idempotency_key == idempotency_key,
        )
    )


def confirm_and_create_task(
    db: Session,
    *,
    device: Device,
    preview_token: str | None,
    confirmation_text: str,
    idempotency_key: str | None,
    user: User,
    session: AuthSession,
    settings: WardenSettings,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> OperationTask:
    """Protection-chain steps 6-8: confirm and persist the operation task.

    Every preview check is re-run against the CURRENT state; drift raises 409
    ``preview_stale``. The single-use token claim (conditional UPDATE on the
    ledger row, migration 0010), the task insert, its initial event and the
    audit commit in ONE transaction (DATA_MODEL.md §11) — a replay of an
    already-consumed token matches zero rows and raises 409 preview_stale
    (SECURITY.md §13: 重放不能产生第二次执行), and a rolled-back transaction
    un-consumes automatically. The DB unique constraint (requested_by,
    idempotency_key) is the idempotency authority and its IntegrityError maps
    to 409 ``idempotency_conflict`` + existing_task_id.
    """
    current = now if now is not None else utcnow()
    _require_valid_idempotency_key(idempotency_key)
    assert idempotency_key is not None
    existing = _find_existing_task(db, user.id, idempotency_key)
    if existing is not None:
        raise AppError(
            "idempotency_conflict",
            MESSAGE_IDEMPOTENCY_CONFLICT,
            details={"existing_task_id": str(existing.id)},
        )
    claims = _verify_preview_token(
        settings, preview_token, now=current, user_id=user.id, device=device
    )
    if claims.device_version != device.version:
        raise _preview_stale("设备配置已变化，请重新预览")
    try:
        probe_plan = plan_operation(
            _snapshot(db, device),
            OperationRequest(
                capability_key=claims.capability_key, parameters=claims.parameters
            ),
        )
    except AppError as exc:
        raise _map_plan_drift(exc) from None
    if probe_plan.requirement_id != claims.requirement_id:
        raise _preview_stale("能力来源需求已变化，请重新预览")
    if probe_plan.risk_level != claims.risk_level:
        raise _preview_stale("风险等级已变化，请重新预览")
    if probe_plan.parameter_hash != claims.parameter_hash:
        raise _preview_stale("参数已变化，请重新预览")
    if probe_plan.channel != "task":
        # Launch-channel capabilities belong to the /launches contract
        # (API_CONTRACT.md §6.1: 连接类能力不进入副作用任务队列).
        raise AppError(
            "unsupported_operation",
            "该能力属于远程连接类，不支持作为持久化任务提交",
            details={
                "requirement_id": probe_plan.requirement_id,
                "capability_key": probe_plan.capability_key,
            },
        )
    submit_path = f"/devices/{device.id}/operations"
    _enforce_execute_permission(
        user,
        probe_plan.risk_level,
        logger=logger,
        audit=audit,
        path=submit_path,
        device_id=device.id,
    )
    if confirmation_text != device.name:
        raise auth_errors.validation_failed(
            "confirmation_text", "输入的设备名称与目标设备不一致，请重新确认"
        )
    if probe_plan.risk_level == "high" and not is_reauthenticated(
        session, current, settings.reauth_ttl_minutes
    ):
        raise auth_errors.reauthentication_required(
            current + datetime.timedelta(minutes=settings.reauth_ttl_minutes)
        )
    conflict = _active_mutex_task(db, device.id, probe_plan.conflict_scope)
    if conflict is not None:
        raise _device_busy(conflict, now=current)
    # _verify_preview_token raised unless a syntactically valid token string
    # was supplied; the ledger claim needs the concrete token for its hash.
    assert preview_token is not None

    task = OperationTask(
        requirement_id=probe_plan.requirement_id,
        capability_key=probe_plan.capability_key,
        device_id=device.id,
        requested_by=user.id,
        risk_level=probe_plan.risk_level,
        parameters=dict(probe_plan.normalized_parameters),
        idempotency_key=idempotency_key,
        conflict_scope=probe_plan.conflict_scope,
        state=TaskState.QUEUED.value,
        plan_hash=probe_plan.plan_hash,
        parameter_hash=probe_plan.parameter_hash,
        adapter_version=probe_plan.adapter_version,
        timeout_at=current + datetime.timedelta(seconds=probe_plan.timeout_seconds),
    )
    db.add(task)
    # Flush so the task row exists BEFORE the claim (the consumed_by_task_id
    # FK requires the referenced task row) and before the append-only event
    # row that references task_id (append_event rows carry the FK).
    db.flush()
    claimed = _claim_preview_token(
        db,
        preview_token=preview_token,
        task_id=task.id,
        consumed_at=current,
    )
    if not claimed:
        # The token was never registered OR is already consumed; roll back
        # the just-flushed task row and distinguish so an honest 422
        # (forged/unknown) never masks a real replay. The claim failure ends
        # the transaction: nothing of the confirm may persist.
        db.rollback()
        use_row = db.scalar(
            select(PreviewTokenUse).where(
                PreviewTokenUse.token_hash == token_hash(preview_token)
            )
        )
        if use_row is not None and use_row.consumed_at is not None:
            raise _preview_stale(MESSAGE_PREVIEW_USED)
        raise auth_errors.validation_failed(
            "preview_token", MESSAGE_PREVIEW_NOT_REGISTERED
        )
    append_event(
        db,
        task_id=task.id,
        state=TaskState.QUEUED.value,
        message="任务已创建，等待执行",
    )
    if logger is not None:
        logger.record_in(
            db,
            action="operation.create",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="operation_task",
            resource_id=str(task.id),
            device_id=device.id,
            requirement_id=probe_plan.requirement_id,
            task_id=task.id,
            request_id=audit.request_id,
            result="accepted",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "capability_key": probe_plan.capability_key,
                "risk_level": probe_plan.risk_level,
                "conflict_scope": probe_plan.conflict_scope,
                "timeout_seconds": probe_plan.timeout_seconds,
                "parameter_hash": probe_plan.parameter_hash,
            },
        )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = ""
        diag = getattr(exc.orig, "diag", None)
        if diag is not None:
            constraint = str(getattr(diag, "constraint_name", "") or "")
        if constraint == "uq_operation_tasks_requested_by_idempotency":
            existing = _find_existing_task(db, user.id, idempotency_key)
            if existing is not None:
                raise AppError(
                    "idempotency_conflict",
                    MESSAGE_IDEMPOTENCY_CONFLICT,
                    details={"existing_task_id": str(existing.id)},
                ) from None
        if constraint == "uq_operation_tasks_active_mutex":
            conflict = _active_mutex_task(db, device.id, probe_plan.conflict_scope)
            if conflict is not None:
                raise _device_busy(conflict, now=current) from None
        raise
    db.refresh(task)
    return task


def get_task(db: Session, task_id: str) -> OperationTask:
    try:
        key = uuid.UUID(task_id)
    except ValueError:
        raise auth_errors.resource_not_found("operation_task") from None
    task = db.get(OperationTask, key)
    if task is None:
        raise auth_errors.resource_not_found("operation_task")
    return task


def list_operations(
    db: Session,
    *,
    page: int,
    page_size: int,
    device_id: uuid.UUID | None,
    requirement_id: str | None,
    capability_key: str | None,
    requested_by: uuid.UUID | None,
    state: str | None,
) -> tuple[list[tuple[OperationTask, str, str]], int]:
    """API_CONTRACT.md §6.2: task list with device/user filters + pagination.

    Rows are (task, device_name, requester_username); the detail fields stay
    on the single-task endpoint.
    """
    conditions = []
    if device_id is not None:
        conditions.append(OperationTask.device_id == device_id)
    if requirement_id is not None:
        conditions.append(OperationTask.requirement_id == requirement_id)
    if capability_key is not None:
        conditions.append(OperationTask.capability_key == capability_key)
    if requested_by is not None:
        conditions.append(OperationTask.requested_by == requested_by)
    if state is not None:
        conditions.append(OperationTask.state == state)
    base = (
        select(OperationTask, Device.name, User.username)
        .join(Device, Device.id == OperationTask.device_id)
        .join(User, User.id == OperationTask.requested_by)
        .where(*conditions)
    )
    total = db.scalar(
        select(func.count()).select_from(base.subquery())
    ) or 0
    rows = db.execute(
        base.order_by(OperationTask.created_at.desc(), OperationTask.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [(row[0], str(row[1]), str(row[2])) for row in rows], int(total)


def get_operation_row(
    db: Session, task_id: str
) -> tuple[OperationTask, str, str] | None:
    """Single task joined with its device name and requester username."""
    try:
        key = uuid.UUID(task_id)
    except ValueError:
        return None
    row = db.execute(
        select(OperationTask, Device.name, User.username)
        .join(Device, Device.id == OperationTask.device_id)
        .join(User, User.id == OperationTask.requested_by)
        .where(OperationTask.id == key)
    ).one_or_none()
    if row is None:
        return None
    return (row[0], str(row[1]), str(row[2]))


def list_task_events(db: Session, task_id: uuid.UUID) -> list[OperationTaskEvent]:
    """The task timeline, oldest first (DATA_MODEL.md §7.3, append-only)."""
    return list(
        db.scalars(
            select(OperationTaskEvent)
            .where(OperationTaskEvent.task_id == task_id)
            .order_by(OperationTaskEvent.occurred_at, OperationTaskEvent.id)
        ).all()
    )


def _cancel_policy_for(task: OperationTask) -> str:
    """The profile's cancel_policy, read ONLY from the generated registry.

    Task rows carry the requirement/capability the profile was created from;
    registry profiles are immutable per product version, so the lookup always
    resolves (a miss is an invariant breach and fails loudly).
    """
    profile = OPERATION_PROFILES.get(f"{task.requirement_id}:{task.capability_key}")
    if profile is None:
        msg = f"operation profile {task.requirement_id}:{task.capability_key} missing from registry"
        raise RuntimeError(msg)
    return profile.cancel_policy


def cancel_task(
    db: Session,
    *,
    task: OperationTask,
    user: User,
    session: AuthSession,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> OperationTask:
    """API_CONTRACT.md §6.2 cancel semantics.

    queued -> cancelled anytime; running -> cancelled only when no dispatch
    fence exists AND the profile cancel_policy allows it; fenced or other
    states return 409 preview_stale (M2T4 decision: fence 后返回 409
    preview_stale with an explicit reason). Terminal: the state write, event
    and audit commit in one transaction (DATA_MODEL.md §11).
    """
    from app.domain.operation import TaskCancellationPolicy

    current = now if now is not None else utcnow()
    _enforce_execute_permission(
        user,
        task.risk_level,
        logger=logger,
        audit=audit,
        path=f"/operations/{task.id}/cancel",
        device_id=task.device_id,
    )
    state = TaskState(task.state)
    fenced = task.dispatch_started_at is not None
    if not TaskCancellationPolicy.can_cancel(
        state,
        dispatch_started=fenced,
        cancel_policy=_cancel_policy_for(task) if state is TaskState.RUNNING else "before_dispatch_only",
    ):
        reason = (
            "任务已派发到设备，无法取消"
            if state is TaskState.RUNNING and fenced
            else f"任务当前状态为 {state.value}，无法取消"
        )
        raise _preview_stale(reason)
    updated = db.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task.id,
            OperationTask.state == task.state,
        )
        .values(
            state=TaskState.CANCELLED.value,
            lease_owner=None,
            lease_expires_at=None,
            finished_at=current,
            updated_at=current,
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if updated is None:
        raise _preview_stale("任务状态已变化，无法取消")
    append_event(
        db,
        task_id=updated.id,
        state=TaskState.CANCELLED.value,
        message="用户取消任务",
    )
    if logger is not None:
        logger.record_in(
            db,
            action="operation.cancel",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="operation_task",
            resource_id=str(updated.id),
            device_id=updated.device_id,
            requirement_id=updated.requirement_id,
            task_id=updated.id,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={"capability_key": updated.capability_key, "state": updated.state},
        )
    db.commit()
    db.refresh(updated)
    return updated


def _device_session(
    db: Session,
    *,
    device: Device,
    keyring: CredentialKeyring,
) -> DeviceSession:
    """Decrypted per-verify device session (SECURITY.md §5: plaintext only
    inside the adapter call boundary)."""
    credential = db.get(DeviceCredential, device.id)
    if credential is None:
        raise auth_errors.validation_failed("credentials", "设备凭据不存在")
    encrypted = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    raw = keyring.decrypt(
        encrypted,
        aad=credential_aad(str(device.id), device.adapter_key, credential.secret_schema_version),
    )
    credentials = json.loads(raw)
    if not isinstance(credentials, dict):
        raise auth_errors.validation_failed("credentials", "设备凭据内容无效")
    return DeviceSession(
        device_id=device.id,
        management_endpoint=device.management_endpoint,
        connection_config=dict(device.connection_config),
        credentials=credentials,
    )


def verify_task(
    db: Session,
    *,
    task: OperationTask,
    device: Device,
    keyring: CredentialKeyring,
    user: User,
    session: AuthSession,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> OperationTask:
    """Admin read-back verify on a verification_required task (§6.2).

    Calls the adapter's ``verify_operation`` (read-only — the action is never
    replayed), then transitions per the outcome: verification_required ->
    succeeded (verification_state=passed) / failed, or stays
    verification_required with error ambiguous_result when neither outcome is
    provable (DATA_MODEL.md §7.2). The transition + event + audit commit in
    one transaction (DATA_MODEL.md §11).
    """
    current = now if now is not None else utcnow()
    if task.state != TaskState.VERIFICATION_REQUIRED.value:
        raise _preview_stale(f"任务当前状态为 {task.state}，不能回读验证")
    try:
        adapter: DeviceAdapter = get_adapter(device.adapter_key)
    except UnknownAdapterError:
        raise auth_errors.validation_failed("adapter_key", "未知的适配器键") from None
    probe_plan = plan_operation(
        _snapshot(db, device),
        OperationRequest(capability_key=task.capability_key, parameters=dict(task.parameters)),
    )
    device_session = _device_session(db, device=device, keyring=keyring)
    # Verify only ever QUERIES the persisted execution (DATA_MODEL.md §7.1:
    # 存在时只查询，不重复创建; DEVICE_ADAPTERS.md §9): the stored
    # device_job_id / evidence / error fields are handed to the adapter as
    # the previous OperationResult so device_job_status strategies poll the
    # PERSISTED job instead of re-executing or inventing one. The M2T6
    # executor stores those fields; M2T4's admin verify honors them.
    persisted_result = OperationResult(
        ok=task.error_code is None,
        evidence=dict(task.evidence) if task.evidence else {},
        error_code=task.error_code,
        error_detail=task.error_detail,
        device_job_id=task.device_job_id,
    )
    try:
        result = adapter.verify_operation(device_session, probe_plan, persisted_result)
    except AdapterError as exc:
        raise AppError(exc.code, exc.message) from None
    evidence: dict[str, object] = {
        "verification": {
            "succeeded": result.succeeded,
            "ambiguous": result.ambiguous,
            **dict(result.evidence),
        }
    }
    if result.ambiguous:
        message = "回读验证无法确认操作结果，等待人工核验"
        values: dict[str, object] = {
            "evidence": evidence,
            "error_code": "ambiguous_result",
            "updated_at": current,
            "version": OperationTask.version + 1,
        }
        outcome = "ambiguous"
        event_state = TaskState.VERIFICATION_REQUIRED.value
    elif result.succeeded:
        message = "回读验证确认操作成功"
        values = {
            "state": TaskState.SUCCEEDED.value,
            "verification_state": VerificationState.PASSED.value,
            "evidence": evidence,
            "error_code": None,
            "error_detail": None,
            "result_summary": message,
            "finished_at": current,
            "lease_owner": None,
            "lease_expires_at": None,
            "updated_at": current,
            "version": OperationTask.version + 1,
        }
        outcome = "succeeded"
        event_state = TaskState.SUCCEEDED.value
    else:
        message = "回读验证确认操作未达到预期结果"
        values = {
            "state": TaskState.FAILED.value,
            "verification_state": VerificationState.FAILED.value,
            "evidence": evidence,
            "error_code": result.error_code or "operation_failed",
            "error_detail": message,
            "result_summary": message,
            "finished_at": current,
            "lease_owner": None,
            "lease_expires_at": None,
            "updated_at": current,
            "version": OperationTask.version + 1,
        }
        outcome = "failed"
        event_state = TaskState.FAILED.value
    updated = db.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task.id,
            OperationTask.state == TaskState.VERIFICATION_REQUIRED.value,
        )
        .values(**values)
        .returning(OperationTask)
    ).scalar_one_or_none()
    if updated is None:
        raise _preview_stale("任务状态已变化，无法回读验证")
    append_event(db, task_id=updated.id, state=event_state, message=message)
    if logger is not None:
        logger.record_in(
            db,
            action="operation.verify",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="operation_task",
            resource_id=str(updated.id),
            device_id=updated.device_id,
            requirement_id=updated.requirement_id,
            task_id=updated.id,
            request_id=audit.request_id,
            result=outcome,
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={"capability_key": updated.capability_key},
        )
    db.commit()
    db.refresh(updated)
    return updated


def resolve_task(
    db: Session,
    *,
    task: OperationTask,
    outcome: str,
    evidence_type: str,
    reference: str,
    reason: str,
    user: User,
    session: AuthSession,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> OperationTask:
    """Admin resolve of a verification_required task from external evidence.

    API_CONTRACT.md §6.2: the admin marks the verified conclusion from
    reviewable evidence; only-verbal judgement cannot mark success (all three
    fields are required and validated by the route). verification_required ->
    succeeded/failed; the transition + event + audit commit in one transaction.
    """
    current = now if now is not None else utcnow()
    if task.state != TaskState.VERIFICATION_REQUIRED.value:
        raise _preview_stale(f"任务当前状态为 {task.state}，不能标记核验结论")
    succeeded = outcome == "succeeded"
    evidence = dict(task.evidence) if task.evidence else {}
    evidence["resolution"] = {
        "outcome": outcome,
        "evidence_type": evidence_type,
        "reference": reference,
        "reason": reason,
    }
    message = "人工核验确认操作成功" if succeeded else "人工核验确认操作失败"
    updated = db.execute(
        update(OperationTask)
        .where(
            OperationTask.id == task.id,
            OperationTask.state == TaskState.VERIFICATION_REQUIRED.value,
        )
        .values(
            state=TaskState.SUCCEEDED.value if succeeded else TaskState.FAILED.value,
            verification_state=VerificationState.PASSED.value
            if succeeded
            else VerificationState.FAILED.value,
            evidence=evidence,
            error_code=None if succeeded else "operation_failed",
            error_detail=None if succeeded else f"人工核验判定失败：{reason[:300]}",
            result_summary=message,
            finished_at=current,
            lease_owner=None,
            lease_expires_at=None,
            updated_at=current,
            version=OperationTask.version + 1,
        )
        .returning(OperationTask)
    ).scalar_one_or_none()
    if updated is None:
        raise _preview_stale("任务状态已变化，无法标记核验结论")
    append_event(db, task_id=updated.id, state=updated.state, message=message)
    if logger is not None:
        logger.record_in(
            db,
            action="operation.resolve",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="operation_task",
            resource_id=str(updated.id),
            device_id=updated.device_id,
            requirement_id=updated.requirement_id,
            task_id=updated.id,
            request_id=audit.request_id,
            result=outcome,
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "capability_key": updated.capability_key,
                "evidence_type": evidence_type,
            },
        )
    db.commit()
    db.refresh(updated)
    return updated
