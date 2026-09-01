"""Read-only audit query API (docs/API_CONTRACT.md §9, contracts/http-api.json).

operationIds EXACTLY per contracts/http-api.json: ``audit_logs_list`` and
``audit_logs_get`` (support PLT-07, docs/TRACEABILITY.md §6). Both require
``audit.read`` — admin-only per the SECURITY.md §3.1 matrix.

Audit is READ-ONLY by design: there are no update/delete/export endpoints
(TRACEABILITY PLT-07 边界: 只追加脱敏记录; SECURITY.md §12). The list omits
``detail_jsonb``; the single-record view returns the detail as sanitized at
write time (app.infrastructure.audit.sanitize_detail) and re-sanitizes
defensively at read, so the response can never contain passwords or tokens.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import ColumnElement, Row, func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.domain import auth_errors
from app.domain.roles import AUDIT_READ
from app.infrastructure.audit import sanitize_detail
from app.models.auth import AuditLog, User

router = APIRouter(prefix="/audit-logs", tags=["audit"])

SORT_PATTERN = (
    r"^-?(occurred_at|actor_user_id|action|resource_type|device_id|requirement_id|result)$"
)
SORT_COLUMNS: dict[str, ColumnElement[object]] = {
    "occurred_at": cast(ColumnElement[object], AuditLog.occurred_at),
    "actor_user_id": cast(ColumnElement[object], AuditLog.actor_user_id),
    "action": cast(ColumnElement[object], AuditLog.action),
    "resource_type": cast(ColumnElement[object], AuditLog.resource_type),
    "device_id": cast(ColumnElement[object], AuditLog.device_id),
    "requirement_id": cast(ColumnElement[object], AuditLog.requirement_id),
    "result": cast(ColumnElement[object], AuditLog.result),
}


class AuditLogListItem(BaseModel):
    """One audit row in the list view: no detail_jsonb (API_CONTRACT §9)."""

    id: str
    occurred_at: datetime.datetime
    actor_username: str | None
    actor_user_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    device_id: str | None
    requirement_id: str | None
    request_id: str | None
    task_id: str | None
    result: str
    source_ip: str | None
    user_agent_summary: str | None


class AuditLogListResponse(BaseModel):
    items: list[AuditLogListItem]
    page: int
    page_size: int
    total: int


class AuditLogDetailItem(AuditLogListItem):
    """Single-record view: adds the session id and the sanitized detail."""

    session_id: str | None
    detail: dict[str, object]


def _item_view(log: AuditLog, actor_username: str | None) -> AuditLogListItem:
    return AuditLogListItem(
        id=str(log.id),
        occurred_at=log.occurred_at,
        actor_username=actor_username,
        actor_user_id=str(log.actor_user_id) if log.actor_user_id else None,
        action=log.action,
        resource_type=log.resource_type,
        resource_id=log.resource_id,
        device_id=str(log.device_id) if log.device_id else None,
        requirement_id=log.requirement_id,
        request_id=log.request_id,
        task_id=str(log.task_id) if log.task_id else None,
        result=log.result,
        source_ip=log.source_ip,
        user_agent_summary=log.user_agent_summary,
    )


def _escape_like(value: str) -> str:
    """Escape LIKE metacharacters so the action filter is a literal prefix."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _uuid_or_error(value: str | None, field: str) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        raise auth_errors.validation_failed(field, "无效的 UUID") from None


@router.get(
    "",
    operation_id="audit_logs_list",
    response_model=AuditLogListResponse,
    responses={"403": {"description": "permission_denied"}, "422": {"description": "validation_failed"}},
)
def audit_logs_list(
    context: Annotated[AuthContext, Depends(require_permission(AUDIT_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(default="-occurred_at", pattern=SORT_PATTERN),
    actor_user_id: str | None = Query(default=None, max_length=64),
    action: str | None = Query(default=None, min_length=1, max_length=255),
    resource_type: str | None = Query(default=None, max_length=64),
    device_id: str | None = Query(default=None, max_length=64),
    requirement_id: str | None = Query(default=None, max_length=32),
    from_: Annotated[datetime.datetime | None, Query(alias="from")] = None,
    to_: Annotated[datetime.datetime | None, Query(alias="to")] = None,
) -> AuditLogListResponse:
    del context
    filters: list[ColumnElement[bool]] = []
    if (actor_key := _uuid_or_error(actor_user_id, "actor_user_id")) is not None:
        filters.append(AuditLog.actor_user_id == actor_key)
    if action is not None:
        filters.append(AuditLog.action.like(_escape_like(action) + "%", escape="\\"))
    if resource_type is not None:
        filters.append(AuditLog.resource_type == resource_type)
    if (device_key := _uuid_or_error(device_id, "device_id")) is not None:
        filters.append(AuditLog.device_id == device_key)
    if requirement_id is not None:
        filters.append(AuditLog.requirement_id == requirement_id)
    if from_ is not None:
        filters.append(AuditLog.occurred_at >= from_)
    if to_ is not None:
        filters.append(AuditLog.occurred_at <= to_)
    base = (
        select(AuditLog, User.username)
        .outerjoin(User, User.id == AuditLog.actor_user_id)
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    column = SORT_COLUMNS[sort.lstrip("-")]
    order = column.asc() if not sort.startswith("-") else column.desc()
    rows: list[Row[tuple[AuditLog, str | None]]] = list(
        db.execute(
            base.order_by(order, AuditLog.occurred_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return AuditLogListResponse(
        items=[_item_view(log, username) for log, username in rows],
        page=page,
        page_size=page_size,
        total=int(total),
    )


@router.get(
    "/{id}",
    operation_id="audit_logs_get",
    response_model=AuditLogDetailItem,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def audit_logs_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(AUDIT_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> AuditLogDetailItem:
    del context
    try:
        key = uuid.UUID(id)
    except ValueError:
        raise auth_errors.resource_not_found("audit_log") from None
    log = db.get(AuditLog, key)
    if log is None:
        raise auth_errors.resource_not_found("audit_log")
    username = (
        db.scalar(select(User.username).where(User.id == log.actor_user_id))
        if log.actor_user_id is not None
        else None
    )
    item = _item_view(log, username)
    return AuditLogDetailItem(
        id=item.id,
        occurred_at=item.occurred_at,
        actor_username=item.actor_username,
        actor_user_id=item.actor_user_id,
        action=item.action,
        resource_type=item.resource_type,
        resource_id=item.resource_id,
        device_id=item.device_id,
        requirement_id=item.requirement_id,
        request_id=item.request_id,
        task_id=item.task_id,
        result=item.result,
        source_ip=item.source_ip,
        user_agent_summary=item.user_agent_summary,
        session_id=str(log.session_id) if log.session_id is not None else None,
        detail=cast(dict[str, object], sanitize_detail(log.detail_jsonb or {})),
    )
