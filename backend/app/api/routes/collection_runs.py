"""Collection-run history API (docs/API_CONTRACT.md §5).

operationId EXACTLY per contracts/http-api.json: ``device_collection_runs_list``
(support PLT-03). Requires ``monitor.read`` (viewer ok). Returns the run rows
WITHOUT lease internals (lease_owner/lease_expires_at stay server-side —
API_CONTRACT.md §5: 采集历史和错误; DATA_MODEL.md §5.1).
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.application.devices import get_device
from app.application.monitoring import list_collection_runs
from app.domain.roles import MONITOR_READ

router = APIRouter(tags=["monitoring"])

COLLECTION_TYPE_PATTERN = r"^(reachability|health|metrics|logs|discovery)$"
COLLECTION_STATE_PATTERN = r"^(scheduled|running|succeeded|partial|failed|cancelled)$"


class CollectionRunView(BaseModel):
    id: uuid.UUID
    collection_type: str
    scheduled_at: datetime.datetime
    started_at: datetime.datetime | None
    finished_at: datetime.datetime | None
    state: str
    attempt_count: int
    success_count: int
    failure_count: int
    error_code: str | None
    error_summary: str | None


class DeviceCollectionRunsListResponse(BaseModel):
    device_id: uuid.UUID
    items: list[CollectionRunView]
    page: int
    page_size: int
    total: int


@router.get(
    "/devices/{id}/collection-runs",
    operation_id="device_collection_runs_list",
    response_model=DeviceCollectionRunsListResponse,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def device_collection_runs_list(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    collection_type: str | None = Query(default=None, pattern=COLLECTION_TYPE_PATTERN),
    state: str | None = Query(default=None, pattern=COLLECTION_STATE_PATTERN),
) -> DeviceCollectionRunsListResponse:
    del context
    device = get_device(db, id)
    rows, total = list_collection_runs(
        db,
        device=device,
        page=page,
        page_size=page_size,
        collection_type=collection_type,
        state=state,
    )
    return DeviceCollectionRunsListResponse(
        device_id=device.id,
        items=[
            CollectionRunView(
                id=row.id,
                collection_type=row.collection_type,
                scheduled_at=row.scheduled_at,
                started_at=row.started_at,
                finished_at=row.finished_at,
                state=row.state,
                attempt_count=row.attempt_count,
                success_count=row.success_count,
                failure_count=row.failure_count,
                error_code=row.error_code,
                error_summary=row.error_summary,
            )
            for row in rows
        ],
        page=page,
        page_size=page_size,
        total=total,
    )
