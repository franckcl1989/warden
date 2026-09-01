"""FastAPI application factory for the Warden API shell.

M0T3 builds the shell later milestones extend: logging, request-id
middleware, unified exception handlers, health endpoints and an empty
``/api/v1`` router. No services are wired yet (DB arrives in M0T4).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.api.errors import register_exception_handlers
from app.api.routes.health import router as health_router
from app.config import WardenSettings, get_settings
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
    app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    api_v1_router = APIRouter(prefix="/api/v1")
    app.include_router(api_v1_router)
    return app


app = create_app()
