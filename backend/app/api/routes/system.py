"""System status API (docs/API_CONTRACT.md §9, ARCHITECTURE.md §9).

operationId EXACTLY per contracts/http-api.json: ``system_status_get``
(support PLT-08). Permission ``system.read`` — admin only (SECURITY.md §3.1).

The response is the honest component/queue summary the /system page renders
(component derivations are documented in app/application/system_status.py):
maintenance state from the single-row system_state, component statuses
(api/database/file_storage/worker/ingest), the operation-task queue summary,
last-24h collection outcomes + current failures, and the
verification_required count. A database outage surfaces as 503
``dependency_unavailable`` (the request cannot assemble ANY component
honestly), never as a fabricated row.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.application.system_status import build_system_status
from app.domain.roles import SYSTEM_READ
from app.infrastructure.time import utcnow

router = APIRouter(tags=["system"])


class ApiComponentStatus(BaseModel):
    status: str = "ok"
    detail: str = ""


class DatabaseComponentStatus(BaseModel):
    status: str
    detail: str = ""


class FileStorageComponentStatus(BaseModel):
    status: str
    detail: str = ""


class WorkerComponentStatus(BaseModel):
    status: str
    detail: str = ""
    last_activity_at: datetime.datetime | None = None
    collection_lag_seconds: int | None = None


class IngestComponentStatus(BaseModel):
    status: str
    detail: str = ""
    events_received_total: int
    last_received_at: datetime.datetime | None = None


class ComponentsView(BaseModel):
    api: ApiComponentStatus
    database: DatabaseComponentStatus
    file_storage: FileStorageComponentStatus
    worker: WorkerComponentStatus
    ingest: IngestComponentStatus


class MaintenanceView(BaseModel):
    active: bool
    since: datetime.datetime | None = None
    reason: str | None = None


class QueueSummaryView(BaseModel):
    operation_tasks: dict[str, int]
    oldest_queued_age_seconds: int | None = None


class CollectionOutcomeView(BaseModel):
    succeeded: int = 0
    partial: int = 0
    failed: int = 0


class CollectionFailureView(BaseModel):
    device_id: uuid.UUID
    device_name: str
    collection_type: str
    error_code: str | None = None
    failed_at: datetime.datetime


class CollectionSummaryView(BaseModel):
    last_24h: CollectionOutcomeView
    current_failures: list[CollectionFailureView]


class VerificationSummaryView(BaseModel):
    count: int
    oldest_at: datetime.datetime | None = None


class SystemStatusResponse(BaseModel):
    as_of: datetime.datetime
    maintenance: MaintenanceView
    components: ComponentsView
    queues: QueueSummaryView
    collection: CollectionSummaryView
    verification_required: VerificationSummaryView


@router.get(
    "/system/status",
    operation_id="system_status_get",
    response_model=SystemStatusResponse,
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "403": {"description": "permission_denied / password_change_required"},
        "503": {"description": "dependency_unavailable（数据库不可用时无法诚实汇总）"},
    },
)
def system_status_get(
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(SYSTEM_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> SystemStatusResponse:
    """Protected component status + queue summary (PLT-08, system.read)."""
    del context
    settings = request.app.state.settings
    report = build_system_status(db, settings=settings, now=utcnow())
    return SystemStatusResponse(
        as_of=report.as_of,
        maintenance=MaintenanceView(
            active=report.maintenance_active,
            since=report.maintenance_since,
            reason=report.maintenance_reason,
        ),
        components=ComponentsView(
            api=ApiComponentStatus(
                status=report.api.status,
                detail=report.api.detail,
            ),
            database=DatabaseComponentStatus(
                status=report.database.status,
                detail=report.database.detail,
            ),
            file_storage=FileStorageComponentStatus(
                status=report.file_storage.status,
                detail=report.file_storage.detail,
            ),
            worker=WorkerComponentStatus(
                status=report.worker.status,
                detail=report.worker.detail,
                last_activity_at=report.worker.last_activity_at,
                collection_lag_seconds=report.worker.collection_lag_seconds,
            ),
            ingest=IngestComponentStatus(
                status=report.ingest.status,
                detail=report.ingest.detail,
                events_received_total=report.ingest.events_received_total,
                last_received_at=report.ingest.last_received_at,
            ),
        ),
        queues=QueueSummaryView(
            operation_tasks=report.operation_task_counts,
            oldest_queued_age_seconds=report.oldest_queued_age_seconds,
        ),
        collection=CollectionSummaryView(
            last_24h=CollectionOutcomeView(**report.last_24h_outcomes),
            current_failures=[
                CollectionFailureView(
                    device_id=failure.device_id,
                    device_name=failure.device_name,
                    collection_type=failure.collection_type,
                    error_code=failure.error_code,
                    failed_at=failure.failed_at,
                )
                for failure in report.current_failures
            ],
        ),
        verification_required=VerificationSummaryView(
            count=report.verification_required_count,
            oldest_at=report.verification_required_oldest_at,
        ),
    )
