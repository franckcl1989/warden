"""Shared FastAPI dependencies (extended by M1T1 with the auth chain).

``get_auth_context`` resolves the session cookie, enforces expiry/CSRF/rate
limits and loads the user; ``require_permission`` gates routes on the frozen
permission matrix (docs/SECURITY.md §3.1). All failures surface through the
unified AppError envelope with stable contract codes.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import WardenSettings
from app.domain.auth_errors import (
    csrf_failed,
    dependency_unavailable,
    permission_denied,
    rate_limited,
    session_expired,
    unauthenticated,
)
from app.domain.errors import AppError
from app.domain.roles import require_permission as matrix_require
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.csrf import (
    CSRF_HEADER_NAME,
    is_origin_allowed,
    normalize_origin,
    verify_csrf_token,
)
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.readiness import ReadinessRegistry
from app.infrastructure.request_id import get_current_request_id
from app.infrastructure.session_tokens import SESSION_COOKIE_NAME, hash_session_token
from app.infrastructure.sessions import client_summary, session_is_valid
from app.infrastructure.time import utcnow
from app.models.auth import Session as DBSession
from app.models.auth import User

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Security events on the request path carry the platform-auth support id
# (docs/TRACEABILITY.md PLT-01: 本地认证与三类角色, SECURITY.md §2-3).
PLT_01 = "PLT-01"


@dataclass(frozen=True)
class AuthContext:
    """The authenticated principal: user plus the session it came from."""

    user: User
    session: DBSession


def get_request_id() -> str:
    """Dependency returning the current request's X-Request-ID value."""
    return get_current_request_id()


def get_readiness_registry(request: Request) -> ReadinessRegistry:
    registry: ReadinessRegistry = request.app.state.readiness
    return registry


def get_db(request: Request) -> Iterator[Session]:
    """Open one SQLAlchemy session for the request (commit in the route)."""
    factory: sessionmaker[Session] | None = getattr(request.app.state, "session_factory", None)
    if factory is None:
        raise dependency_unavailable()
    with factory() as db:
        yield db


def get_audit_logger(request: Request) -> AuditLogger:
    logger: AuditLogger = request.app.state.audit_logger
    return logger


def _audit_security_event(
    request: Request,
    *,
    action: str,
    result: str,
    session: DBSession | None,
    user: User | None,
    detail: dict[str, object],
) -> None:
    """Write a security audit row for CSRF/permission failures (M1T4).

    docs/SECURITY.md §12 / DATA_MODEL.md §9.1. Bounded to events that have a
    resolved session so the row attributes to the actor; anonymous pre-session
    failures (login-time Origin checks) stay covered by IP rate limiting
    (documented decision in the M1T4 report). Uses the app-level AuditLogger
    (its own transaction), never the request's session; a missing logger
    (no DSN configured) is a no-op.
    """
    logger: AuditLogger | None = getattr(request.app.state, "audit_logger", None)
    if logger is None:
        return
    source_ip = request.client.host if request.client else None
    logger.record(
        action=action,
        actor_user_id=user.id if user is not None else (session.user_id if session is not None else None),
        session_id=session.id if session is not None else None,
        resource_type="request",
        # audit_logs.resource_id is varchar(64); long operation paths (e.g.
        # /operations/{uuid}/resolve-verification) are truncated so a security
        # event never fails its own audit row (fail-closed denial must record).
        resource_id=request.url.path[:64],
        requirement_id=PLT_01,
        request_id=str(request.scope.get("request_id") or ""),
        result=result,
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        detail=detail,
    )


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


def get_credential_keyring(request: Request) -> CredentialKeyring:
    """The credential keystore, built lazily from the mounted secret file.

    SECURITY.md §5: the master key is derived from the read-only Secret file
    (never env/logs). Built once per process on first use; a missing or too
    short key surfaces as ``dependency_unavailable`` so device onboarding
    fails loudly instead of writing unencryptable rows.
    """
    ring: CredentialKeyring | None = getattr(request.app.state, "credential_keyring", None)
    if ring is not None:
        return ring
    settings: WardenSettings = request.app.state.settings
    try:
        material = settings.credential_master_key.get_secret_value().encode("utf-8")
        ring = CredentialKeyring.from_current(CredentialCipher(material))
    except ValueError as exc:
        raise dependency_unavailable("credential_keyring") from exc
    request.app.state.credential_keyring = ring
    return ring


def _allowed_origins(settings: WardenSettings) -> set[str]:
    normalized = normalize_origin(settings.public_url)
    return {normalized} if normalized is not None else set()


def check_origin(request: Request) -> None:
    """Reject requests whose Origin/Referer is not the deployment origin.

    docs/API_CONTRACT.md: 登录和终端握手验证 Origin. Non-browser clients
    without either header pass (SameSite=Strict + per-session CSRF token
    remain the session defenses).
    """
    settings: WardenSettings = request.app.state.settings
    allowed = _allowed_origins(settings)
    if not is_origin_allowed(
        origin=request.headers.get("origin"),
        referer=request.headers.get("referer"),
        allowed_origins=allowed,
    ):
        raise csrf_failed()


def get_auth_context(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthContext:
    """Resolve the session cookie into a valid session + user.

    Raises: unauthenticated (no/unknown cookie, disabled user),
    session_expired (revoked/idle/absolute expiry), csrf_failed (mutating
    request without a valid X-CSRF-Token or wrong origin), rate_limited
    (per-session 300/min). Refreshes ``last_activity_at`` at most once a
    minute to keep read traffic off the write path.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise unauthenticated()
    session = db.scalar(
        select(DBSession).where(DBSession.session_id_hash == hash_session_token(token))
    )
    if session is None:
        raise unauthenticated()
    settings: WardenSettings = request.app.state.settings
    now = utcnow()
    if not session_is_valid(session, now, settings.session_idle_minutes):
        session.revoked_at = now
        db.commit()
        raise session_expired()
    if request.method in MUTATING_METHODS:
        raw_token = request.headers.get(CSRF_HEADER_NAME, "")
        if not raw_token or not verify_csrf_token(raw_token, session.csrf_secret_hash):
            _audit_security_event(
                request,
                action="csrf.failed",
                result="failure",
                session=session,
                user=None,
                detail={"reason": "invalid_token"},
            )
            raise csrf_failed()
        try:
            check_origin(request)
        except AppError:
            _audit_security_event(
                request,
                action="csrf.failed",
                result="failure",
                session=session,
                user=None,
                detail={"reason": "origin_mismatch"},
            )
            raise
    limiter: RateLimiter = request.app.state.rate_limiter
    result = limiter.check_session(session.session_id_hash)
    if not result.allowed:
        raise rate_limited(result.retry_after_seconds, "session")
    if now - session.last_activity_at > datetime.timedelta(minutes=1):
        session.last_activity_at = now
        db.commit()
    user = db.get(User, session.user_id)
    if user is None or user.status == "disabled":
        raise unauthenticated()
    return AuthContext(user=user, session=session)


def require_permission(permission: str) -> Callable[..., AuthContext]:
    """Dependency factory: resolve the auth context and check the matrix.

    Denials on mutating endpoints (POST/PATCH/PUT/DELETE) are audited as
    ``access.denied`` with result ``permission_denied`` (M1T4 decision: GET
    denials are too noisy and stay un-audited — bounded per the brief).
    """

    def _check(
        context: Annotated[AuthContext, Depends(get_auth_context)],
        request: Request,
    ) -> AuthContext:
        if not matrix_require(context.user.role, permission):
            if request.method in MUTATING_METHODS:
                _audit_security_event(
                    request,
                    action="access.denied",
                    result="permission_denied",
                    session=context.session,
                    user=context.user,
                    detail={
                        "permission": permission,
                        "method": request.method,
                        "path": request.url.path,
                    },
                )
            raise permission_denied(permission)
        return context

    return _check


def require_password_changed(
    context: Annotated[AuthContext, Depends(get_auth_context)],
    request: Request,
) -> AuthContext:
    """Gate every protected router except auth: forced password change first.

    SECURITY.md §2 (管理员创建时要求首次登录修改) and §3 (服务端每次请求重新
    校验是安全边界, 前端隐藏按钮只改善体验). A user with
    ``must_change_password`` must reach only the auth router (``/auth/me``
    reports the flag, ``/auth/password``, ``/auth/logout`` and ``/auth/reauth``
    stay callable); any other endpoint is denied with ``permission_denied``
    and ``details.permission="password_change_required"`` — the only contract
    code whose ``safe_detail_fields`` include ``permission``, so the client
    can route to the forced-change view without new error codes (contracts are
    immutable without an ADR). Mutating denials are audited like permission
    denials (M1T4 pattern). ``/health/*`` lives outside ``/api/v1`` and is not
    gated.
    """
    if not context.user.must_change_password:
        return context
    if request.method in MUTATING_METHODS:
        _audit_security_event(
            request,
            action="access.denied",
            result="permission_denied",
            session=context.session,
            user=context.user,
            detail={
                "permission": "password_change_required",
                "method": request.method,
                "path": request.url.path,
            },
        )
    raise permission_denied("password_change_required")
