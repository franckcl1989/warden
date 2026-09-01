"""Health endpoints: /health/live and /health/ready.

Both paths are absolute (NOT under /api/v1) exactly as written in
``contracts/http-api.json``; operationIds are ``health_live``/``health_ready``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_readiness_registry
from app.api.errors import ErrorEnvelope
from app.infrastructure.readiness import ReadinessRegistry

router = APIRouter(tags=["system"])


class HealthStatus(BaseModel):
    status: str


class ProbeView(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class ReadinessReport(BaseModel):
    status: str
    probes: list[ProbeView]


@router.get(
    "/health/live",
    operation_id="health_live",
    response_model=HealthStatus,
    responses={"500": {"model": ErrorEnvelope}},
)
async def health_live() -> HealthStatus:
    return HealthStatus(status="ok")


@router.get(
    "/health/ready",
    operation_id="health_ready",
    response_model=ReadinessReport,
    responses={"500": {"model": ErrorEnvelope}},
)
async def health_ready(
    registry: Annotated[ReadinessRegistry, Depends(get_readiness_registry)],
) -> ReadinessReport:
    summary = await registry.summary()
    return ReadinessReport(
        status=summary.status,
        probes=[ProbeView(name=result.name, ok=result.ok, detail=result.detail) for result in summary.probes],
    )
