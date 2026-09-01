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
from app.domain.roles import require_permission as matrix_require
from app.infrastructure.audit import AuditLogger
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
from app.infrastructure.sessions import session_is_valid
from app.infrastructure.time import utcnow
from app.models.auth import Session as DBSession
from app.models.auth import User

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


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
            raise csrf_failed()
        check_origin(request)
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
    """Dependency factory: resolve the auth context and check the matrix."""

    def _check(
        context: Annotated[AuthContext, Depends(get_auth_context)],
    ) -> AuthContext:
        if not matrix_require(context.user.role, permission):
            raise permission_denied(permission)
        return context

    return _check
