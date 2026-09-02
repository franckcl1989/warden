"""Alert read APIs (docs/API_CONTRACT.md §5, PRODUCT_DESIGN.md §6.4).

operationIds EXACTLY per contracts/http-api.json: ``alerts_list`` and
``alerts_get`` (support PLT-04). Requires ``monitor.read`` (viewer ok).

Shows ONLY rows the alert engine created (ADR-025): no synthetic problems.
List rows omit ``evidence`` (heavy detail); the single-record view returns the
full row — evidence JSONB plus the first/last/resolved timeline (there is no
separate timeline table; DATA_MODEL.md §6.1 evidence covers it). Resolved
alerts stay queryable within their 180-day retention (DATA_MODEL.md §10).
There are no acknowledge/close/dispatch APIs in 0.1.0 (API_CONTRACT.md §5).
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import Row
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.application.monitoring import get_alert_row, list_alerts
from app.domain import auth_errors
from app.domain.roles import MONITOR_READ
from app.models.observation import Alert

router = APIRouter(tags=["monitoring"])

ALERT_STATUS_PATTERN = r"^(active|resolved)$"
ALERT_SEVERITY_PATTERN = r"^(warning|critical)$"


class AlertDeviceRef(BaseModel):
    id: uuid.UUID
    name: str
    device_type: str


class AlertListItem(BaseModel):
    id: uuid.UUID
    device: AlertDeviceRef
    component_id: uuid.UUID | None
    rule_key: str
    severity: str
    status: str
    title: str
    first_occurred_at: datetime.datetime
    last_occurred_at: datetime.datetime
    resolved_at: datetime.datetime | None


class AlertsListResponse(BaseModel):
    items: list[AlertListItem]
    page: int
    page_size: int
    total: int


class AlertDetailItem(AlertListItem):
    """Single-record view: the full engine-created row plus its timeline."""

    dedupe_key: str
    signal_count: int
    version: int
    evidence: dict[str, object]
    created_at: datetime.datetime
    updated_at: datetime.datetime


@router.get(
    "/alerts",
    operation_id="alerts_list",
    response_model=AlertsListResponse,
    responses={"403": {"description": "permission_denied"}},
)
def alerts_list(
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default="active", pattern=ALERT_STATUS_PATTERN),
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: str | None = Query(default=None, pattern=ALERT_SEVERITY_PATTERN),
    rule_key: str | None = Query(default=None, max_length=64),
) -> AlertsListResponse:
    del context
    rows, total = list_alerts(
        db,
        page=page,
        page_size=page_size,
        status=status,
        device_id=device_id,
        severity=severity,
        rule_key=rule_key,
    )
    return AlertsListResponse(
        items=[_list_item(row) for row in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/alerts/{id}",
    operation_id="alerts_get",
    response_model=AlertDetailItem,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def alerts_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> AlertDetailItem:
    del context
    try:
        alert_key = uuid.UUID(id)
    except ValueError:
        raise auth_errors.resource_not_found("alert") from None
    row = get_alert_row(db, alert_key)
    if row is None:
        raise auth_errors.resource_not_found("alert")
    alert: Alert = row[0]
    item = _list_item(row)
    return AlertDetailItem(
        **item.model_dump(),
        dedupe_key=alert.dedupe_key,
        signal_count=alert.signal_count,
        version=alert.version,
        evidence=dict(alert.evidence),
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


def _list_item(row: Row[tuple[Alert, str, str]]) -> AlertListItem:
    alert: Alert = row[0]
    return AlertListItem(
        id=alert.id,
        device=AlertDeviceRef(id=alert.device_id, name=row[1], device_type=row[2]),
        component_id=alert.component_id,
        rule_key=alert.rule_key,
        severity=alert.severity,
        status=alert.status,
        title=alert.title,
        first_occurred_at=alert.first_occurred_at,
        last_occurred_at=alert.last_occurred_at,
        resolved_at=alert.resolved_at,
    )
