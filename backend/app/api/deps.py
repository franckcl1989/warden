"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from app.infrastructure.readiness import ReadinessRegistry
from app.infrastructure.request_id import get_current_request_id


def get_request_id() -> str:
    """Dependency returning the current request's X-Request-ID value."""
    return get_current_request_id()


def get_readiness_registry(request: Request) -> ReadinessRegistry:
    registry: ReadinessRegistry = request.app.state.readiness
    return registry
