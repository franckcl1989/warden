"""Authentication endpoints (docs/API_CONTRACT.md §3, contracts/http-api.json).

operationIds: auth_login, auth_logout, auth_get_me, auth_change_password,
auth_reauthenticate. Session tokens live only in the HttpOnly cookie; the
database keeps hashes. Every state change is audited with requirement_id
PLT-01.
"""

from __future__ import annotations

import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, check_origin, get_audit_logger, get_auth_context, get_db, get_rate_limiter
from app.domain import auth_errors
from app.domain.password_policy import validate_password
from app.domain.roles import permissions_for
from app.infrastructure.audit import AuditLogger
from app.infrastructure.csrf import encode_csrf_token, hash_csrf_secret, issue_csrf_secret
from app.infrastructure.passwords import hash_password, verify_password
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.session_tokens import (
    expire_session_cookie,
    generate_session_token,
    hash_session_token,
    make_session_cookie,
)
from app.infrastructure.sessions import client_summary, reauthenticated_until
from app.infrastructure.time import utcnow
from app.models.auth import Session as DBSession
from app.models.auth import User

router = APIRouter(prefix="/auth", tags=["auth"])

PLT_01 = "PLT-01"

MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 256
MAX_DISPLAY_NAME_LENGTH = 128


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


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=MAX_USERNAME_LENGTH)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("username")
    @classmethod
    def _no_whitespace_username(cls, value: str) -> str:
        if any(char.isspace() for char in value):
            raise ValueError("no whitespace allowed in username")
        return value


class LoginResponse(BaseModel):
    user: UserView
    csrf_token: str
    session_expires_at: datetime.datetime


class MeResponse(BaseModel):
    user: UserView
    permissions: list[str]
    session_expires_at: datetime.datetime


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class ReauthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class ReauthResponse(BaseModel):
    reauthenticated_until: datetime.datetime


class OkResponse(BaseModel):
    ok: bool


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


def _request_context(request: Request) -> tuple[str | None, str | None]:
    return request.client.host if request.client else None, request.headers.get("user-agent")


def _audit(
    request: Request,
    logger: AuditLogger,
    *,
    action: str,
    user: User | None = None,
    session: DBSession | None = None,
    result: str = "success",
    detail: object | None = None,
) -> None:
    source_ip, user_agent = _request_context(request)
    logger.record(
        action=action,
        actor_user_id=user.id if user else None,
        session_id=session.id if session else None,
        resource_type="user",
        resource_id=str(user.id) if user else None,
        requirement_id=PLT_01,
        request_id=str(request.scope.get("request_id") or ""),
        result=result,
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, user_agent),
        detail=detail,
    )


def _authenticate(
    db: Session,
    username: str,
    password: str,
    request: Request,
    logger: AuditLogger,
    *,
    lockout_after_failures: int,
    lockout_minutes: int,
) -> User:
    """Resolve username+password into an active user or raise.

    Enforces lockout (``lockout_after_failures`` failures → ``lockout_minutes``
    lock) and the generic error for wrong credentials; status checks produce
    their own validation_failed reasons. Failed attempts and lock events are
    audited here because they happen before a session exists.
    """
    user = db.scalar(select(User).where(User.username.ilike(username)).limit(1))
    now = utcnow()
    if user is None:
        # Burn comparable verification time so unknown and known usernames
        # behave alike (no user enumeration by timing). The synthetic hash is
        # well-formed Argon2id but never matches any real password.
        verify_password(
            "$argon2id$v=19$m=65536,t=3,p=1$"
            "c29tZXNhbHRmb3J3YXJkZW4$YWRtaW4xMjM0NTY3ODkwMDEyMzQ1Njc4OTAxMjM0NTY3OA",
            password,
        )
        _audit(request, logger, action="auth.login_failed", result="failure")
        raise auth_errors.invalid_credentials()
    if user.status == "disabled":
        raise auth_errors.account_disabled()
    if user.status == "locked" and user.locked_until is not None and user.locked_until > now:
        raise auth_errors.account_locked()
    if user.status == "locked":
        # Lock window passed: auto-unlock before attempting verification.
        user.status = "active"
        user.locked_until = None
        user.failed_login_count = 0
    ok, _needs_rehash = verify_password(user.password_hash, password)
    if not ok:
        user.failed_login_count += 1
        _audit(
            request,
            logger,
            action="auth.login_failed",
            user=user,
            result="failure",
            detail={"failed_attempts": user.failed_login_count},
        )
        if user.failed_login_count >= lockout_after_failures:
            user.status = "locked"
            user.locked_until = now + datetime.timedelta(minutes=lockout_minutes)
            _audit(
                request,
                logger,
                action="auth.lock",
                user=user,
                result="success",
                detail={"reason": "too many failed logins"},
            )
        db.commit()
        raise auth_errors.invalid_credentials()
    if _needs_rehash:
        user.password_hash = hash_password(password)
    return user


@router.post(
    "/login",
    operation_id="auth_login",
    response_model=LoginResponse,
    responses={"422": {"description": "validation_failed"}, "429": {"description": "rate_limited"}},
)
def auth_login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> LoginResponse:
    check_origin(request)
    source_ip = request.client.host if request.client else "unknown"
    rate = limiter.check_login(source_ip)
    if not rate.allowed:
        raise auth_errors.rate_limited(rate.retry_after_seconds, "login:ip")

    settings = request.app.state.settings
    user = _authenticate(
        db,
        body.username,
        body.password,
        request,
        logger,
        lockout_after_failures=settings.login_lockout_after_failures,
        lockout_minutes=settings.login_lockout_minutes,
    )

    now = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    user.status = "active"
    user.last_login_at = now

    token = generate_session_token()
    csrf_secret = issue_csrf_secret()
    session = DBSession(
        session_id_hash=hash_session_token(token),
        user_id=user.id,
        expires_at=now + datetime.timedelta(minutes=settings.session_idle_minutes),
        absolute_expires_at=now + datetime.timedelta(hours=settings.session_absolute_hours),
        csrf_secret_hash=hash_csrf_secret(csrf_secret),
        client_summary=client_summary(source_ip, request.headers.get("user-agent")),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    response.headers.append(
        "set-cookie",
        make_session_cookie(token, secure=settings.session_cookie_secure),
    )
    _audit(request, logger, action="auth.login", user=user, session=session)
    return LoginResponse(
        user=_user_view(user),
        csrf_token=encode_csrf_token(csrf_secret),
        session_expires_at=session.absolute_expires_at,
    )


@router.post(
    "/logout",
    operation_id="auth_logout",
    response_model=OkResponse,
    responses={"401": {"description": "unauthenticated/session_expired"}, "403": {"description": "csrf_failed"}},
)
def auth_logout(
    request: Request,
    response: Response,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> OkResponse:
    now = utcnow()
    context.session.revoked_at = now
    db.commit()
    response.headers.append(
        "set-cookie",
        expire_session_cookie(secure=request.app.state.settings.session_cookie_secure),
    )
    _audit(request, logger, action="auth.logout", user=context.user, session=context.session)
    return OkResponse(ok=True)


@router.get(
    "/me",
    operation_id="auth_get_me",
    response_model=MeResponse,
    responses={"401": {"description": "unauthenticated/session_expired"}},
)
def auth_get_me(context: Annotated[AuthContext, Depends(get_auth_context)]) -> MeResponse:
    return MeResponse(
        user=_user_view(context.user),
        permissions=sorted(permissions_for(context.user.role)),
        session_expires_at=context.session.absolute_expires_at,
    )


@router.post(
    "/password",
    operation_id="auth_change_password",
    response_model=OkResponse,
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "403": {"description": "csrf_failed"},
        "422": {"description": "validation_failed"},
    },
)
def auth_change_password(
    body: ChangePasswordRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> OkResponse:
    ok, _needs_rehash = verify_password(context.user.password_hash, body.current_password)
    if not ok:
        _audit(
            request,
            logger,
            action="auth.password_changed",
            user=context.user,
            session=context.session,
            result="failure",
        )
        raise auth_errors.current_password_wrong()
    violations = validate_password(body.new_password, context.user.username)
    if violations:
        _audit(
            request,
            logger,
            action="auth.password_changed",
            user=context.user,
            session=context.session,
            result="failure",
        )
        raise auth_errors.password_policy_violated(violations[0])
    now = utcnow()
    context.user.password_hash = hash_password(body.new_password)
    context.user.must_change_password = False
    # Revoke every other session of this user (SECURITY.md §2).
    db.execute(
        update(DBSession)
        .where(DBSession.user_id == context.user.id, DBSession.id != context.session.id, DBSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    context.session.reauthenticated_at = now
    db.commit()
    _audit(request, logger, action="auth.password_changed", user=context.user, session=context.session)
    return OkResponse(ok=True)


@router.post(
    "/reauth",
    operation_id="auth_reauthenticate",
    response_model=ReauthResponse,
    responses={
        "401": {"description": "unauthenticated/session_expired/reauthentication_required"},
        "403": {"description": "csrf_failed"},
        "422": {"description": "validation_failed"},
    },
)
def auth_reauthenticate(
    body: ReauthRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
) -> ReauthResponse:
    ok, _needs_rehash = verify_password(context.user.password_hash, body.password)
    if not ok:
        _audit(
            request,
            logger,
            action="auth.reauth",
            user=context.user,
            session=context.session,
            result="failure",
        )
        raise auth_errors.current_password_wrong()
    context.session.reauthenticated_at = utcnow()
    db.commit()
    _audit(request, logger, action="auth.reauth", user=context.user, session=context.session)
    settings = request.app.state.settings
    return ReauthResponse(
        reauthenticated_until=reauthenticated_until(
            context.session, utcnow(), settings.reauth_ttl_minutes
        )
    )
