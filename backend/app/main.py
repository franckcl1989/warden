"""FastAPI application factory for the Warden API shell.

M0T3 builds the shell later milestones extend: logging, request-id
middleware, unified exception handlers, health endpoints and an empty
``/api/v1`` router. M0T4 wires the PostgreSQL readiness probe; the probe is
registered only when a database DSN is configured. M1T1 mounts the auth,
users and roles routers and the session/rate-limit/audit services. M1T3 mounts
the device onboarding router (probe/create/list/get/patch/re-probe/
capabilities) and the lazy credential keyring dependency. M1T4 mounts the
read-only audit query router (audit_logs_list / audit_logs_get).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI

from app.api.deps import require_password_changed
from app.api.errors import register_exception_handlers
from app.api.routes import (
    alerts,
    audit,
    auth,
    collection_runs,
    devices,
    metrics,
    operations,
    overview,
    roles,
    users,
)
from app.api.routes.health import router as health_router
from app.config import WardenSettings, get_settings
from app.infrastructure.audit import AuditLogger
from app.infrastructure.db import DatabaseProbe, create_db_engine, create_session_factory
from app.infrastructure.logging import configure_logging
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.readiness import ReadinessRegistry
from app.infrastructure.request_id import RequestIDMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    del app
    yield


def create_app(settings: WardenSettings | None = None) -> FastAPI:
    """Build the application: logging, middleware, handlers and routes."""
    configured_settings = settings if settings is not None else get_settings()
    configure_logging()
    app = FastAPI(title="Warden API", version="0.1.0", lifespan=lifespan)
    app.state.settings = configured_settings
    app.state.readiness = ReadinessRegistry()
    app.state.rate_limiter = RateLimiter(
        login_per_minute=configured_settings.login_rate_limit_per_minute,
        session_per_minute=configured_settings.session_rate_limit_per_minute,
        probe_per_minute=configured_settings.probe_rate_limit_per_minute,
        operation_preview_per_minute=configured_settings.operation_preview_rate_limit_per_minute,
        operation_submit_per_minute=configured_settings.operation_submit_rate_limit_per_minute,
    )
    app.state.session_factory = None
    app.state.audit_logger = None
    app.state.engine = None
    app.state.credential_keyring = None
    if configured_settings.postgres_dsn or configured_settings.postgres_dsn_file is not None:
        engine = create_db_engine(configured_settings.database_url)
        app.state.engine = engine
        app.state.session_factory = create_session_factory(engine)
        app.state.audit_logger = AuditLogger(app.state.session_factory)
        app.state.readiness.register(DatabaseProbe(engine=engine))
    app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    api_v1_router = APIRouter(prefix="/api/v1")
    api_v1_router.include_router(auth.router)
    # SECURITY.md §2/§3: must_change_password 用户只能访问 auth 路由
    # (me/password/logout/reauth)；其余受保护路由一律被强制改密门禁拦截，
    # 服务端强制执行，前端隐藏只是 UX。
    api_v1_router.include_router(users.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(roles.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(devices.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(audit.router, dependencies=[Depends(require_password_changed)])
    # M2T3 monitoring reads (PLT-03/PLT-04): overview, metrics, collection
    # runs and alerts live in their own routers; components/events ride on the
    # devices router above.
    api_v1_router.include_router(metrics.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(collection_runs.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(overview.router, dependencies=[Depends(require_password_changed)])
    api_v1_router.include_router(alerts.router, dependencies=[Depends(require_password_changed)])
    # M2T4 two-phase operations API (PLT-05): preview/confirm + task lifecycle.
    api_v1_router.include_router(operations.router, dependencies=[Depends(require_password_changed)])
    app.include_router(api_v1_router)
    return app


app = create_app()
