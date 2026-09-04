"""Launch endpoints (M3T4, PLT-09 launch 部分, API_CONTRACT.md §7).

operationIds EXACTLY per contracts/http-api.json: ``device_launches_create``
(POST /devices/{id}/launches) and ``launches_get`` (GET /launches/{id}).
The route layer stays thin — protection, adapter call and ticket persistence
live in ``app.application.launches``.

POST issues one 60-second launch ticket and returns ONLY the same-origin
single-use consume URL (the vendor descriptor URL never reaches the SPA
state). GET consumes the ticket exactly once: Accept negotiation returns an
HTML auto-redirect page for browsers (default) or the JSON descriptor for
tests/integrations; every response carries ``Referrer-Policy: no-referrer``
so the browser's navigation to the vendor page leaks no platform referrer
(API_CONTRACT.md §7, ADR-006: 不代理厂商页面、不注入凭据). Reads that match
nothing — consumed, expired, revoked, foreign-user or unknown ids — are a
uniform 404 (non-enumerable).
"""

from __future__ import annotations

import datetime
import html
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_credential_keyring,
    get_db,
    get_rate_limiter,
)
from app.application import launches as launch_service
from app.application.devices import get_device
from app.application.operations import AuditContext
from app.domain import auth_errors
from app.domain.operation_plan import execute_permission_for
from app.domain.roles import require_permission as matrix_require
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialKeyring
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.sessions import client_summary
from app.models.launch import LaunchSession

router = APIRouter(tags=["launches"])

LAUNCH_PAGE_TITLE = "正在打开设备远程控制台"


class LaunchCreateRequest(BaseModel):
    """API_CONTRACT.md §7: launch 请求只接受 capability_key 与 profile 参数."""

    capability_key: str = Field(min_length=1, max_length=64)


class LaunchCreateResponse(BaseModel):
    """201 issue response: the ticket id, its expiry and the single-use
    same-origin consume URL. The vendor descriptor URL is NOT included —
    it leaves the platform exactly once through GET /launches/{id}."""

    launch_id: uuid.UUID
    expires_at: datetime.datetime
    url: str


class LaunchDescriptorPayload(BaseModel):
    kind: str
    url: str | None = None
    display_hint: str | None = None


class LaunchConsumeResponse(BaseModel):
    """JSON consume view (Accept: application/json); browsers get the HTML
    auto-redirect page instead. Never contains credentials."""

    launch_id: uuid.UUID
    device_id: uuid.UUID
    capability_key: str
    requirement_id: str
    descriptor: LaunchDescriptorPayload


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
    return getattr(request.app.state, "audit_logger", None)


def _consume_response(row: LaunchSession) -> LaunchConsumeResponse:
    hint = row.descriptor_data.get("display_hint")
    return LaunchConsumeResponse(
        launch_id=row.id,
        device_id=row.device_id,
        capability_key=row.capability_key,
        requirement_id=row.requirement_id,
        descriptor=LaunchDescriptorPayload(
            kind=str(row.descriptor_data.get("kind") or "url"),
            url=row.descriptor_url,
            display_hint=hint if isinstance(hint, str) else None,
        ),
    )


def _redirect_page(url: str) -> str:
    """Tiny auto-redirect page (meta refresh; navigates the current tab).

    The vendor URL is single-use: it is embedded here exactly once and the
    page adds a no-referrer meta as defense in depth on top of the
    ``Referrer-Policy`` response header. No iframe/proxy of the vendor page
    (ADR-006); the URL was scheme-validated (http/https) by the service.
    """
    escaped = html.escape(url, quote=True)
    return (
        "<!doctype html>\n"
        '<html lang="zh-CN">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{html.escape(LAUNCH_PAGE_TITLE)}</title>\n"
        f'<meta http-equiv="refresh" content="0; url={escaped}">\n'
        "</head>\n"
        "<body>\n"
        f"<p>{html.escape(LAUNCH_PAGE_TITLE)}，请稍候…</p>\n"
        f'<p>如果页面没有自动跳转，请<a href="{escaped}">点击此处打开设备控制台</a>。</p>\n'
        "</body>\n"
        "</html>\n"
    )


def _consume_headers() -> dict[str, str]:
    return {
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }


def _wants_html(request: Request) -> bool:
    """Browsers (and default clients) get the HTML auto-redirect page;
    explicit ``Accept: application/json`` gets the JSON descriptor."""
    accept = request.headers.get("accept") or ""
    return "application/json" not in accept


@router.post(
    "/devices/{id}/launches",
    operation_id="device_launches_create",
    response_model=LaunchCreateResponse,
    status_code=201,
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "403": {"description": "permission_denied / csrf_failed"},
        "404": {"description": "resource_not_found"},
        "422": {"description": "unsupported_operation / not_configured / validation_failed"},
        "429": {"description": "rate_limited（含每用户 3、每设备 1 活动票据上限）"},
    },
)
def device_launches_create(
    id: str,
    body: LaunchCreateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    keyring: Annotated[CredentialKeyring, Depends(get_credential_keyring)],
) -> LaunchCreateResponse:
    rate = limiter.check_launch(str(context.user.id))
    if not rate.allowed:
        raise auth_errors.rate_limited(rate.retry_after_seconds, "launch")
    device = get_device(db, id)
    row = launch_service.create_launch(
        db,
        device=device,
        capability_key=body.capability_key,
        user=context.user,
        session=context.session,
        keyring=keyring,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
        telnet_allowed=bool(request.app.state.settings.telnet_enabled),
    )
    db.commit()
    db.refresh(row)
    if row.protocol in launch_service.TERMINAL_LAUNCH_PROTOCOLS:
        # Terminal tickets (console.ssh.open/telnet.open, M5T4): consumed by
        # the WebSocket endpoint — the URL points at the WS route (the SPA
        # swaps http(s) for ws(s)); there is no descriptor GET for them.
        url = str(request.url_for("terminal_sessions_connect", ticket=str(row.id)))
    else:
        url = str(request.url_for("launches_get", id=str(row.id)))
    return LaunchCreateResponse(launch_id=row.id, expires_at=row.expires_at, url=url)


@router.get(
    "/launches/{id}",
    operation_id="launches_get",
    response_model=LaunchConsumeResponse,
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "404": {"description": "resource_not_found（已使用/已过期/已撤销/非本人/未知，统一 404）"},
    },
)
def launches_get(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> JSONResponse | HTMLResponse:
    """One-shot descriptor read: first GET consumes; later GETs are 404.

    The atomic claim (user-owned + issued + unexpired) runs first; a
    permission re-check against the ticket's own profile follows — a user
    demoted since issue can no longer consume (role changes revoke sessions
    anyway — SECURITY.md §3.1 server-side re-validation). Any failure raises
    before commit, so a refused read never consumes the ticket.
    """
    consumed = launch_service.consume_launch(
        db,
        launch_id=id,
        user_id=context.user.id,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    if consumed is None:
        raise auth_errors.resource_not_found("launch_session")
    profile = OPERATION_PROFILES.get(f"{consumed.requirement_id}:{consumed.capability_key}")
    if profile is None or not matrix_require(
        context.user.role, execute_permission_for(profile.risk)
    ):
        raise auth_errors.resource_not_found("launch_session")
    db.commit()
    db.refresh(consumed)
    if _wants_html(request):
        return HTMLResponse(
            content=_redirect_page(consumed.descriptor_url or ""),
            headers={**_consume_headers(), "Content-Type": "text/html; charset=utf-8"},
        )
    body = _consume_response(consumed)
    return JSONResponse(
        content=body.model_dump(mode="json"),
        headers=_consume_headers(),
    )
