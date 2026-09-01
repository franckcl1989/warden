"""User administration endpoints (docs/API_CONTRACT.md §3, contracts/http-api.json).

operationIds: users_list, users_create, users_get, users_update. All routes
require ``user.manage`` (admin-only per the SECURITY.md §3.1 matrix). Users
are never deleted; ``status=disabled`` is the removal path (DATA_MODEL §3.1).
Optimistic locking uses the integer ``version`` in the PATCH body (API_CONTRACT
§1 keeps If-Match for devices; users use the body field, documented in the
route docstring). Every create/update is audited.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import ColumnElement, func, select, update
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_audit_logger, get_db, require_permission
from app.domain import auth_errors
from app.domain.password_policy import validate_password
from app.domain.roles import USER_MANAGE
from app.infrastructure.audit import AuditLogger
from app.infrastructure.passwords import hash_password
from app.infrastructure.sessions import client_summary
from app.infrastructure.time import utcnow
from app.models.auth import Session as DBSession
from app.models.auth import User

router = APIRouter(prefix="/users", tags=["users"])

PLT_01 = "PLT-01"

MAX_USERNAME_LENGTH = 64
MAX_DISPLAY_NAME_LENGTH = 128
MAX_PASSWORD_LENGTH = 256

SORT_COLUMNS: dict[str, ColumnElement[object]] = {
    "username": cast(ColumnElement[object], User.username),
    "display_name": cast(ColumnElement[object], User.display_name),
    "role": cast(ColumnElement[object], User.role),
    "status": cast(ColumnElement[object], User.status),
    "created_at": cast(ColumnElement[object], User.created_at),
}


class UserView(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    username: str
    display_name: str
    role: str
    status: str
    must_change_password: bool
    last_login_at: datetime.datetime | None
    created_at: datetime.datetime
    updated_at: datetime.datetime
    version: int


class UserListResponse(BaseModel):
    items: list[UserView]
    page: int
    page_size: int
    total: int


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=MAX_USERNAME_LENGTH)
    display_name: str = Field(min_length=1, max_length=MAX_DISPLAY_NAME_LENGTH)
    role: str = Field(pattern=r"^(admin|operator|viewer)$")
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("username", "display_name")
    @classmethod
    def _no_whitespace(cls, value: str) -> str:
        if any(char.isspace() for char in value):
            raise ValueError("no whitespace allowed")
        return value


class UserUpdateRequest(BaseModel):
    version: int = Field(ge=1)
    display_name: str | None = Field(default=None, min_length=1, max_length=MAX_DISPLAY_NAME_LENGTH)
    role: str | None = Field(default=None, pattern=r"^(admin|operator|viewer)$")
    status: str | None = Field(default=None, pattern=r"^(active|disabled)$")
    new_password: str | None = Field(default=None, min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("display_name")
    @classmethod
    def _no_whitespace_display_name(cls, value: str | None) -> str | None:
        if value is not None and any(char.isspace() for char in value):
            raise ValueError("no whitespace allowed")
        return value


def _resolve_user(db: Session, user_id: str) -> User:
    try:
        key = uuid.UUID(user_id)
    except ValueError:
        raise auth_errors.resource_not_found("user") from None
    user = db.get(User, key)
    if user is None:
        raise auth_errors.resource_not_found("user")
    return user


def _user_view(user: User) -> UserView:
    return UserView(
        id=str(user.id),
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        status=user.status,
        must_change_password=user.must_change_password,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        version=user.version,
    )


def _audit(
    request: Request,
    logger: AuditLogger,
    *,
    action: str,
    user: User,
    detail: object | None = None,
) -> None:
    source_ip = request.client.host if request.client else None
    logger.record(
        action=action,
        actor_user_id=getattr(request.state, "actor_user_id", None),
        resource_type="user",
        resource_id=str(user.id),
        requirement_id=PLT_01,
        request_id=str(request.scope.get("request_id") or ""),
        result="success",
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        detail=detail,
    )


@router.get(
    "",
    operation_id="users_list",
    response_model=UserListResponse,
    responses={"403": {"description": "permission_denied"}},
)
def users_list(
    context: Annotated[AuthContext, Depends(require_permission(USER_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(default="username", pattern=r"^-?(username|display_name|role|status|created_at)$"),
) -> UserListResponse:
    del context
    column = SORT_COLUMNS[sort.lstrip("-")]
    order = column.asc() if not sort.startswith("-") else column.desc()
    total = db.scalar(select(func.count()).select_from(User)) or 0
    rows = db.scalars(
        select(User).order_by(order, User.username.asc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return UserListResponse(
        items=[_user_view(row) for row in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.post(
    "",
    operation_id="users_create",
    response_model=UserView,
    status_code=201,
    responses={"403": {"description": "permission_denied"}, "422": {"description": "validation_failed"}},
)
def users_create(
    body: UserCreateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(USER_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> UserView:
    violations = validate_password(body.password, body.username)
    if violations:
        raise auth_errors.password_policy_violated(violations[0])
    existing = db.scalar(select(User).where(User.username.ilike(body.username)).limit(1))
    if existing is not None:
        raise auth_errors.username_taken()
    user = User(
        username=body.username,
        display_name=body.display_name,
        role=body.role,
        password_hash=hash_password(body.password),
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    request.state.actor_user_id = context.user.id
    _audit(request, logger, action="users.create", user=user, detail={"role": user.role})
    return _user_view(user)


@router.get(
    "/{id}",
    operation_id="users_get",
    response_model=UserView,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def users_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(USER_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
) -> UserView:
    del context
    return _user_view(_resolve_user(db, id))


@router.patch(
    "/{id}",
    operation_id="users_update",
    response_model=UserView,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "412": {"description": "version_conflict"},
        "422": {"description": "validation_failed"},
    },
)
def users_update(
    id: str,
    body: UserUpdateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(USER_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> UserView:
    user = _resolve_user(db, id)
    if user.version != body.version:
        raise auth_errors.version_conflict(user.version)

    changed: list[str] = []
    if body.display_name is not None:
        user.display_name = body.display_name
        changed.append("display_name")
    if body.role is not None and body.role != user.role:
        user.role = body.role
        changed.append("role")
    if body.status is not None and body.status != user.status:
        user.status = body.status
        changed.append("status")
    if body.new_password is not None:
        violations = validate_password(body.new_password, user.username)
        if violations:
            raise auth_errors.password_policy_violated(violations[0])
        user.password_hash = hash_password(body.new_password)
        user.must_change_password = True
        changed.append("new_password")

    now = utcnow()
    # Role/status/password changes revoke the user's sessions (SECURITY.md §2).
    if any(item in changed for item in ("role", "status", "new_password")):
        db.execute(
            update(DBSession)
            .where(DBSession.user_id == user.id, DBSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
    user.version += 1
    db.commit()
    db.refresh(user)
    request.state.actor_user_id = context.user.id
    _audit(request, logger, action="users.update", user=user, detail={"fields": changed})
    return _user_view(user)
