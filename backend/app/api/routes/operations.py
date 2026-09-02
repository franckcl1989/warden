"""Operation two-phase API and task lifecycle endpoints (PLT-05).

operationIds EXACTLY per contracts/http-api.json: device_operation_previews_create,
device_operations_create, operations_list, operations_get, operations_cancel,
operations_verify, operations_resolve_verification. Semantics per
API_CONTRACT.md §6.1/§6.2 and SECURITY.md §4 protection chain; the route layer
stays thin — checks, token handling and transitions live in
``app.application.operations``.

Permission notes (M2T4 decisions): preview/confirm/cancel authenticate through
``get_auth_context`` and enforce ``operation.execute.<risk>`` per profile risk
inside the application service (the risk is only known after the profile
resolves, so it cannot be a route dependency); verify and resolve-verification
are ADMIN-ONLY (API_CONTRACT.md §6.2: 管理员对 verification_required 触发适配
器回读 / 根据可复核外部证据标记核验结论) via ``require_admin`` below. Reads
need ``operation.read`` (SECURITY.md §3.1: viewer may read).
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Callable
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_credential_keyring,
    get_db,
    get_rate_limiter,
    require_permission,
)
from app.application import operations as op_service
from app.application.devices import get_device
from app.application.operations import AuditContext
from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.roles import OPERATION_READ, Role
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialKeyring
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.sessions import client_summary
from app.models.auth import User
from app.models.devices import Device
from app.models.operation import OperationTask

router = APIRouter(tags=["operations"])

STATE_PATTERN = (
    r"^(queued|running|waiting_device|succeeded|failed|timed_out|cancelled|verification_required)$"
)

MAX_PAGE_SIZE = 100


class TargetDeviceView(BaseModel):
    id: uuid.UUID
    name: str


class ConfirmationView(BaseModel):
    kind: str
    expected: str


class OperationPreviewResponse(BaseModel):
    requirement_id: str
    capability_key: str
    risk_level: str
    target: TargetDeviceView
    normalized_parameters: dict[str, object]
    impact: str
    steps: list[str]
    confirmation: ConfirmationView
    preview_token: str
    expires_at: datetime.datetime


class OperationPreviewRequest(BaseModel):
    capability_key: str = Field(min_length=1, max_length=64)
    parameters: dict[str, object] = Field(default_factory=dict)


class OperationSubmitRequest(BaseModel):
    preview_token: str = Field(min_length=1, max_length=1024)
    confirmation_text: str = Field(min_length=1, max_length=256)


class OperationResolveRequest(BaseModel):
    outcome: str = ""
    evidence_type: str = ""
    reference: str = ""
    reason: str = ""


RESOLVE_OUTCOMES = frozenset({"succeeded", "failed"})
RESOLVE_EVIDENCE_TYPES = frozenset({"device_ui", "device_cli", "device_log", "task_record", "other"})


def _validate_resolve_request(body: OperationResolveRequest) -> None:
    """Route-level resolve validation: deterministic 422 validation_failed.

    API_CONTRACT.md §6.2: resolve requires outcome + evidence_type + reference
    + reason (仅口头判断不能标记成功). RequestValidationError (400) would
    otherwise swallow the semantic reasons, so the four fields are checked
    here with Chinese reasons instead of pydantic constraints.
    """
    if body.outcome not in RESOLVE_OUTCOMES:
        raise auth_errors.validation_failed("outcome", "核验结论只能是 succeeded 或 failed")
    if body.evidence_type not in RESOLVE_EVIDENCE_TYPES:
        raise auth_errors.validation_failed("evidence_type", "证据类型不在允许的白名单内")
    if not body.reference or len(body.reference) > 300:
        raise auth_errors.validation_failed("reference", "证据引用必填且不超过 300 字")
    if not body.reason or len(body.reason) > 500:
        raise auth_errors.validation_failed("reason", "核验理由必填且不超过 500 字")


class OperationUserRef(BaseModel):
    id: uuid.UUID
    username: str


class OperationTaskView(BaseModel):
    """Task view shared by list/get/cancel/verify/resolve/confirm responses."""

    id: uuid.UUID
    requirement_id: str
    capability_key: str
    risk_level: str
    state: str
    device: TargetDeviceView
    requested_by: OperationUserRef
    progress_percent: int
    current_step: str | None
    dispatch_started_at: datetime.datetime | None
    device_job_id: str | None
    timeout_at: datetime.datetime | None
    result_summary: str | None
    error_code: str | None
    error_detail: str | None
    verification_state: str | None
    started_at: datetime.datetime | None
    finished_at: datetime.datetime | None
    created_at: datetime.datetime
    updated_at: datetime.datetime
    version: int


class OperationEventView(BaseModel):
    id: uuid.UUID
    state: str
    step: str | None
    progress_percent: int | None
    message: str | None
    device_job_id: str | None
    occurred_at: datetime.datetime


class OperationTaskDetail(OperationTaskView):
    """Single-task view: the task plus its timeline (DATA_MODEL.md §7.3).

    File links land in M2T5 (files API); the M2T4 detail carries task fields,
    events and result/evidence rows.
    """

    conflict_scope: str
    parameters: dict[str, object]
    idempotency_key: str
    plan_hash: str | None
    parameter_hash: str | None
    adapter_version: str | None
    evidence: dict[str, object] | None
    events: list[OperationEventView]


class OperationsListResponse(BaseModel):
    items: list[OperationTaskView]
    page: int
    page_size: int
    total: int


def _audit_context(request: Request, context: AuthContext) -> AuditContext:
    source_ip = request.client.host if request.client else None
    return AuditContext(
        actor_user_id=context.user.id,
        session_id=context.session.id,
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        request_id=str(request.scope.get("request_id") or ""),
    )


def _request_logger(request: Request) -> AuditLogger | None:
    """The app-level audit writer; None when no DSN is configured (no audit)."""
    return getattr(request.app.state, "audit_logger", None)


def _deny_admin(request: Request, context: AuthContext, permission_label: str) -> NoReturn:
    logger = _request_logger(request)
    source_ip = request.client.host if request.client else None
    if logger is not None:
        logger.record(
            action="access.denied",
            actor_user_id=context.user.id,
            session_id=context.session.id,
            resource_type="operation",
            requirement_id=op_service.PLT_05,
            request_id=str(request.scope.get("request_id") or ""),
            result="permission_denied",
            source_ip=source_ip,
            user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
            detail={
                "permission": permission_label,
                "method": request.method,
                "path": request.url.path,
            },
        )
    raise auth_errors.permission_denied(permission_label)


def require_admin(permission_label: str) -> Callable[..., AuthContext]:
    """Route dependency: verify/resolve-verification are admin-only (§6.2).

    The SECURITY.md §3.1 matrix has no per-action key for these two actions,
    so the gate is the admin role itself; denials are audited like
    require_permission denials (M1T4 pattern).
    """

    def _check(
        context: Annotated[AuthContext, Depends(get_auth_context)],
        request: Request,
    ) -> AuthContext:
        if context.user.role == Role.ADMIN.value:
            return context
        _deny_admin(request, context, permission_label)

    return _check


def _task_view(task: OperationTask, *, device: TargetDeviceView, requested_by: OperationUserRef) -> OperationTaskView:
    return OperationTaskView(
        id=task.id,
        requirement_id=task.requirement_id,
        capability_key=task.capability_key,
        risk_level=task.risk_level,
        state=task.state,
        device=device,
        requested_by=requested_by,
        progress_percent=task.progress_percent,
        current_step=task.current_step,
        dispatch_started_at=task.dispatch_started_at,
        device_job_id=task.device_job_id,
        timeout_at=task.timeout_at,
        result_summary=task.result_summary,
        error_code=task.error_code,
        error_detail=task.error_detail,
        verification_state=task.verification_state,
        started_at=task.started_at,
        finished_at=task.finished_at,
        created_at=task.created_at,
        updated_at=task.updated_at,
        version=task.version,
    )


def _device_ref(device: Device) -> TargetDeviceView:
    return TargetDeviceView(id=device.id, name=device.name)


def _requested_by(db: Session, task: OperationTask) -> OperationUserRef:
    username = db.scalar(select(User.username).where(User.id == task.requested_by))
    return OperationUserRef(id=task.requested_by, username=username or "unknown")


def _task_context_row(db: Session, task: OperationTask) -> tuple[TargetDeviceView, OperationUserRef]:
    """Device reference (with name) + requester reference for a task view."""
    device_row = db.get(Device, task.device_id)
    device = (
        _device_ref(device_row)
        if device_row is not None
        else TargetDeviceView(id=task.device_id, name="unknown")
    )
    return device, _requested_by(db, task)


def _detail_view(db: Session, task: OperationTask) -> OperationTaskDetail:
    """Full single-task view: task fields + timeline (used by get/verify/resolve)."""
    device_view, requested_by = _task_context_row(db, task)
    base = _task_view(task, device=device_view, requested_by=requested_by)
    events = op_service.list_task_events(db, task.id)
    return OperationTaskDetail(
        **base.model_dump(),
        conflict_scope=task.conflict_scope,
        parameters=dict(task.parameters),
        idempotency_key=task.idempotency_key,
        plan_hash=task.plan_hash,
        parameter_hash=task.parameter_hash,
        adapter_version=task.adapter_version,
        evidence=dict(task.evidence) if task.evidence else None,
        events=[
            OperationEventView(
                id=event.id,
                state=event.state,
                step=event.step,
                progress_percent=event.progress_percent,
                message=event.message,
                device_job_id=event.device_job_id,
                occurred_at=event.occurred_at,
            )
            for event in events
        ],
    )


def _settings(request: Request) -> WardenSettings:
    settings: WardenSettings = request.app.state.settings
    return settings


@router.post(
    "/devices/{id}/operation-previews",
    operation_id="device_operation_previews_create",
    response_model=OperationPreviewResponse,
    responses={
        "401": {"description": "unauthenticated/session_expired/reauthentication_required"},
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "device_busy"},
        "422": {"description": "validation_failed / unsupported_operation / not_configured"},
        "429": {"description": "rate_limited"},
    },
)
def device_operation_previews_create(
    id: str,
    body: OperationPreviewRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> OperationPreviewResponse:
    rate = limiter.check_operation_preview(str(context.user.id))
    if not rate.allowed:
        raise auth_errors.rate_limited(rate.retry_after_seconds, "operation_preview")
    device = get_device(db, id)
    logger = _request_logger(request)
    outcome = op_service.create_preview(
        db,
        device=device,
        capability_key=body.capability_key,
        parameters=body.parameters,
        user=context.user,
        session=context.session,
        settings=_settings(request),
        logger=logger,
        audit=_audit_context(request, context),
    )
    # Persist the single-use token ledger row (migration 0010): the token is
    # issued NOW, so its ledger registration must be durable before the
    # response leaves — confirm claims it in its own transaction.
    db.commit()
    plan = outcome.plan
    return OperationPreviewResponse(
        requirement_id=plan.requirement_id,
        capability_key=plan.capability_key,
        risk_level=plan.risk_level,
        target=_device_ref(device),
        normalized_parameters=plan.normalized_parameters,
        impact=plan.impact,
        steps=list(plan.steps),
        confirmation=ConfirmationView(kind="type_device_name", expected=device.name),
        preview_token=outcome.preview_token,
        expires_at=outcome.expires_at,
    )


@router.post(
    "/devices/{id}/operations",
    operation_id="device_operations_create",
    response_model=OperationTaskView,
    status_code=202,
    responses={
        "401": {"description": "unauthenticated/session_expired/reauthentication_required"},
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "preview_stale / idempotency_conflict / device_busy"},
        "422": {"description": "validation_failed / unsupported_operation / not_configured"},
        "429": {"description": "rate_limited"},
    },
)
def device_operations_create(
    id: str,
    body: OperationSubmitRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> OperationTaskView:
    rate = limiter.check_operation_submit(str(context.user.id))
    if not rate.allowed:
        raise auth_errors.rate_limited(rate.retry_after_seconds, "operation_submit")
    device = get_device(db, id)
    task = op_service.confirm_and_create_task(
        db,
        device=device,
        preview_token=body.preview_token,
        confirmation_text=body.confirmation_text,
        idempotency_key=idempotency_key,
        user=context.user,
        session=context.session,
        settings=_settings(request),
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    device_view, requested_by = _task_context_row(db, task)
    return _task_view(task, device=device_view, requested_by=requested_by)


@router.get(
    "/operations",
    operation_id="operations_list",
    response_model=OperationsListResponse,
    responses={"403": {"description": "permission_denied"}},
)
def operations_list(
    context: Annotated[AuthContext, Depends(require_permission(OPERATION_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    requirement_id: str | None = Query(default=None, max_length=32),
    capability_key: str | None = Query(default=None, max_length=64),
    requested_by: Annotated[uuid.UUID | None, Query()] = None,
    state: str | None = Query(default=None, pattern=STATE_PATTERN),
) -> OperationsListResponse:
    del context
    rows, total = op_service.list_operations(
        db,
        page=page,
        page_size=page_size,
        device_id=device_id,
        requirement_id=requirement_id,
        capability_key=capability_key,
        requested_by=requested_by,
        state=state,
    )
    items: list[OperationTaskView] = []
    for task, device_name, username in rows:
        items.append(
            _task_view(
                task,
                device=TargetDeviceView(id=task.device_id, name=device_name),
                requested_by=OperationUserRef(id=task.requested_by, username=username),
            )
        )
    return OperationsListResponse(items=items, page=page, page_size=page_size, total=total)


@router.get(
    "/operations/{id}",
    operation_id="operations_get",
    response_model=OperationTaskDetail,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def operations_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(OPERATION_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> OperationTaskDetail:
    del context
    row = op_service.get_operation_row(db, id)
    if row is None:
        raise auth_errors.resource_not_found("operation_task")
    task, _device_name, _username = row
    return _detail_view(db, task)


@router.post(
    "/operations/{id}/cancel",
    operation_id="operations_cancel",
    response_model=OperationTaskView,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "preview_stale（fence 后或状态不允许）"},
    },
)
def operations_cancel(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationTaskView:
    task = op_service.get_task(db, id)
    updated = op_service.cancel_task(
        db,
        task=task,
        user=context.user,
        session=context.session,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    device_view, requested_by = _task_context_row(db, updated)
    return _task_view(updated, device=device_view, requested_by=requested_by)


@router.post(
    "/operations/{id}/verify",
    operation_id="operations_verify",
    response_model=OperationTaskDetail,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "preview_stale（任务不在 verification_required）"},
        "422": {"description": "validation_failed / adapter error codes"},
    },
)
def operations_verify(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(require_admin("operation.verify"))],
    db: Annotated[Session, Depends(get_db)],
    keyring: Annotated[CredentialKeyring, Depends(get_credential_keyring)],
) -> OperationTaskDetail:
    task = op_service.get_task(db, id)
    device = db.get(Device, task.device_id)
    if device is None:
        raise auth_errors.resource_not_found("device")
    updated = op_service.verify_task(
        db,
        task=task,
        device=device,
        keyring=keyring,
        user=context.user,
        session=context.session,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    return _detail_view(db, updated)


@router.post(
    "/operations/{id}/resolve-verification",
    operation_id="operations_resolve_verification",
    response_model=OperationTaskDetail,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "preview_stale（任务不在 verification_required）"},
        "422": {"description": "validation_failed"},
    },
)
def operations_resolve_verification(
    id: str,
    body: OperationResolveRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_admin("operation.resolve_verification"))],
    db: Annotated[Session, Depends(get_db)],
) -> OperationTaskDetail:
    _validate_resolve_request(body)
    task = op_service.get_task(db, id)
    updated = op_service.resolve_task(
        db,
        task=task,
        outcome=body.outcome,
        evidence_type=body.evidence_type,
        reference=body.reference,
        reason=body.reason,
        user=context.user,
        session=context.session,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    return _detail_view(db, updated)
