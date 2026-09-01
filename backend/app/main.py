"""FastAPI application factory for the Warden API shell.

M0T3 builds the shell later milestones extend: logging, request-id
middleware, unified exception handlers, health endpoints and an empty
``/api/v1`` router. M0T4 wires the PostgreSQL readiness probe; the probe is
registered only when a database DSN is configured.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.api.errors import register_exception_handlers
from app.api.routes.health import router as health_router
from app.config import WardenSettings, get_settings
from app.infrastructure.db import DatabaseProbe, create_db_engine
from app.infrastructure.logging import configure_logging
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
    if configured_settings.postgres_dsn or configured_settings.postgres_dsn_file is not None:
        app.state.readiness.register(
            DatabaseProbe(engine=create_db_engine(configured_settings.database_url))
        )
    app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    api_v1_router = APIRouter(prefix="/api/v1")
    app.include_router(api_v1_router)
    return app


app = create_app()
