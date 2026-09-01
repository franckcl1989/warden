"""FastAPI application factory for the Warden API shell.

M0T3 builds the shell later milestones extend: logging, request-id
middleware, unified exception handlers, health endpoints and an empty
``/api/v1`` router. M0T4 wires the PostgreSQL readiness probe; the probe is
registered only when a database DSN is configured. M1T1 mounts the auth,
users and roles routers and the session/rate-limit/audit services.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.api.errors import register_exception_handlers
from app.api.routes import auth, roles, users
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
    )
    app.state.session_factory = None
    app.state.audit_logger = None
    app.state.engine = None
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
    api_v1_router.include_router(users.router)
    api_v1_router.include_router(roles.router)
    app.include_router(api_v1_router)
    return app


app = create_app()
