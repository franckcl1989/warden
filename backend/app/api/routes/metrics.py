"""Monitoring metric read APIs (docs/API_CONTRACT.md §5).

operationIds EXACTLY per contracts/http-api.json: ``device_metrics_latest``
and ``device_metrics_series`` (support PLT-03). Both need ``monitor.read``
(viewer ok per the SECURITY.md §3.1 matrix).

Series resolution rules (API_CONTRACT.md §5, M2T3): within 7 days raw
granularity, 7-30 days 5m rollups, 30-180 days 1h rollups; the client may
request a COARSER resolution than the window default, never a finer one
(422). The rules apply to numeric gauge series — state/boolean/counter keys
are always served as raw change points and checkpoints (DATA_MODEL.md §5.4:
rollups are gauge-only). An empty series is a 200 with metadata and no
points — an honest empty, never a 404. Each series response carries unit,
per-point quality and the ACTUAL resolution served.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.application.devices import get_device
from app.application.monitoring import list_latest_metrics, read_series
from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.observation import (
    ONE_HOUR_RESOLUTION_MAX_DAYS,
    SERIES_RESOLUTIONS,
    default_resolution_for_window,
    is_finer_resolution,
)
from app.domain.roles import MONITOR_READ
from app.generated.metrics import METRIC_DEFINITIONS
from app.infrastructure.time import utcnow

router = APIRouter(tags=["monitoring"])

RESOLUTION_PATTERN = r"^(raw|5m|1h)$"
MAX_SERIES_WINDOW_DAYS = ONE_HOUR_RESOLUTION_MAX_DAYS


class ComponentRef(BaseModel):
    id: uuid.UUID
    kind: str
    native_id: str
    name: str


class LatestMetricItem(BaseModel):
    metric_key: str
    value: float | str | bool | None
    unit: str | None
    quality: str
    observed_at: datetime.datetime
    source: str
    freshness: str


class LatestComponentGroup(BaseModel):
    component: ComponentRef | None
    metrics: list[LatestMetricItem]


class DeviceMetricsLatestResponse(BaseModel):
    device_id: uuid.UUID
    as_of: datetime.datetime
    items: list[LatestComponentGroup]
    page: int
    page_size: int
    total: int


class SeriesPointView(BaseModel):
    """One series point; rollup points carry the window statistics too."""

    timestamp: datetime.datetime
    value: float | str | bool | None
    quality: str
    source: str | None = None
    min_value: float | None = None
    max_value: float | None = None
    last_value: float | None = None
    count: int | None = None


class DeviceMetricsSeriesResponse(BaseModel):
    device_id: uuid.UUID
    metric_key: str
    series: str  # gauge | state | monotonic_counter
    value_type: str
    unit: str | None
    component_id: uuid.UUID | None
    resolution: str  # ACTUAL resolution served (API_CONTRACT.md §5)
    points: list[SeriesPointView]


@router.get(
    "/devices/{id}/metrics/latest",
    operation_id="device_metrics_latest",
    response_model=DeviceMetricsLatestResponse,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def device_metrics_latest(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> DeviceMetricsLatestResponse:
    del context
    device = get_device(db, id)
    settings: WardenSettings = request.app.state.settings
    now = utcnow()
    groups, total = list_latest_metrics(
        db,
        device=device,
        page=page,
        page_size=page_size,
        now=now,
        settings=settings,
    )
    items: list[LatestComponentGroup] = []
    for group in groups:
        component = group.component
        items.append(
            LatestComponentGroup(
                component=(
                    ComponentRef(
                        id=component[0], kind=component[1], native_id=component[2], name=component[3]
                    )
                    if component is not None
                    else None
                ),
                metrics=[
                    LatestMetricItem(
                        metric_key=metric.metric_key,
                        value=metric.value,
                        unit=metric.unit,
                        quality=metric.quality,
                        observed_at=metric.observed_at,
                        source=metric.source,
                        freshness=metric.freshness,
                    )
                    for metric in group.metrics
                ],
            )
        )
    return DeviceMetricsLatestResponse(
        device_id=device.id,
        as_of=now,
        items=items,
        page=page,
        page_size=page_size,
        total=total,
    )


def _validate_window(
    from_: datetime.datetime,
    to_: datetime.datetime,
    now: datetime.datetime,
) -> None:
    if from_ >= to_:
        raise auth_errors.validation_failed("from", "from 必须早于 to")
    window = to_ - from_
    if window > datetime.timedelta(days=MAX_SERIES_WINDOW_DAYS):
        raise auth_errors.validation_failed(
            "from", f"查询范围不能超过 {MAX_SERIES_WINDOW_DAYS} 天"
        )
    if from_ < now - datetime.timedelta(days=MAX_SERIES_WINDOW_DAYS):
        raise auth_errors.validation_failed(
            "from", f"起始时间不能早于保留期（{MAX_SERIES_WINDOW_DAYS} 天）"
        )


def _resolve_series_resolution(metric_key: str, window: datetime.timedelta, requested: str | None) -> str:
    """API_CONTRACT.md §5: pick the actual resolution for a gauge window."""
    definition = METRIC_DEFINITIONS[metric_key]
    default = default_resolution_for_window(window.total_seconds())
    if requested is None:
        return default
    if definition.series != "gauge":
        # Rollups are gauge-only (DATA_MODEL.md §5.4): the requested
        # resolution cannot be honored for other series kinds — the response
        # reports the actual ("raw") resolution.
        return "raw"
    if requested not in SERIES_RESOLUTIONS:
        raise auth_errors.validation_failed("resolution", "无效的分辨率")
    if is_finer_resolution(requested, default):
        raise auth_errors.validation_failed(
            "resolution",
            "不能请求超出保留期的细粒度分辨率：该时间范围只支持 "
            f"{default} 或更粗（7 天内 raw / 7-30 天 5m / 30-180 天 1h）",
        )
    return requested


@router.get(
    "/devices/{id}/metrics/series",
    operation_id="device_metrics_series",
    response_model=DeviceMetricsSeriesResponse,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "422": {"description": "validation_failed"},
    },
)
def device_metrics_series(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    metric: Annotated[str, Query(min_length=1, max_length=64)],
    from_: Annotated[datetime.datetime, Query(alias="from")],
    to_: Annotated[datetime.datetime, Query(alias="to")],
    component_id: Annotated[uuid.UUID | None, Query()] = None,
    resolution: str | None = Query(default=None, pattern=RESOLUTION_PATTERN),
) -> DeviceMetricsSeriesResponse:
    del context
    if metric not in METRIC_DEFINITIONS:
        raise auth_errors.validation_failed("metric", "指标键不在 contracts/metrics.json 中")
    device = get_device(db, id)
    now = utcnow()
    _validate_window(from_, to_, now)
    actual = _resolve_series_resolution(metric, to_ - from_, resolution)
    result = read_series(
        db,
        device=device,
        metric_key=metric,
        component_id=component_id,
        from_=from_,
        to_=to_,
        resolution=actual,
    )
    return DeviceMetricsSeriesResponse(
        device_id=device.id,
        metric_key=result.metric_key,
        series=result.series_kind,
        value_type=result.value_type,
        unit=result.unit,
        component_id=component_id,
        resolution=result.resolution,
        points=[
            SeriesPointView(
                timestamp=point.timestamp,
                value=point.value,
                quality=point.quality,
                source=point.source,
                min_value=point.min_value,
                max_value=point.max_value,
                last_value=point.last_value,
                count=point.count,
            )
            for point in result.points
        ],
    )
