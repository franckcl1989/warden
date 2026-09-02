"""Overview API (docs/API_CONTRACT.md §5, PRODUCT_DESIGN.md §3).

operationId EXACTLY per contracts/http-api.json: ``overview_get`` (support
PLT-03). Requires ``monitor.read`` (viewer ok).

PRODUCT_DESIGN.md §3 semantics: the top stats answer 哪些设备不可达、哪些设备
不健康、哪些人工操作尚未结束; the attention list follows the 离线 > 严重 >
警告 > 数据过期 ordering and shows only engine-created problems; recent
operations stay empty until M2T4 (this endpoint returns the empty state with
the query shape in place). Counts come from the real tables — unknown states
are shown as unknown, never fabricated into zeros.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_db, require_permission
from app.application.monitoring import build_overview
from app.domain.roles import MONITOR_READ
from app.infrastructure.time import utcnow

router = APIRouter(tags=["monitoring"])


class OverviewStats(BaseModel):
    device_total: int
    reachability: dict[str, int]
    health: dict[str, int]
    active_critical_alerts: int
    operations_running: int
    operations_verification_required: int


class DeviceTypeSummary(BaseModel):
    reachability: dict[str, int]
    health: dict[str, int]


class AttentionProblem(BaseModel):
    id: uuid.UUID
    rule_key: str
    severity: str
    title: str
    first_occurred_at: datetime.datetime
    last_occurred_at: datetime.datetime


class AttentionDevice(BaseModel):
    id: uuid.UUID
    name: str
    device_type: str
    vendor: str | None
    model: str | None


class AttentionItem(BaseModel):
    """PRODUCT_DESIGN.md §3.3: 设备名称、类型/型号、问题摘要、首次发生时间、
    最近采集时间和详情入口. ``rank`` mirrors the sort order (0=offline)."""

    device: AttentionDevice
    problems: list[AttentionProblem]
    last_collected_at: datetime.datetime | None
    rank: int


class OverviewResponse(BaseModel):
    as_of: datetime.datetime
    stats: OverviewStats
    device_types: dict[str, DeviceTypeSummary]
    attention: list[AttentionItem]
    # 最近操作 (PRODUCT_DESIGN.md §3.4) — M2T4 fills this from the task API.
    recent_operations: list[object]


@router.get(
    "/overview",
    operation_id="overview_get",
    response_model=OverviewResponse,
    responses={"403": {"description": "permission_denied"}},
)
def overview_get(
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> OverviewResponse:
    del context
    del request
    now = utcnow()
    overview = build_overview(db, now=now)
    return OverviewResponse(
        as_of=now,
        stats=OverviewStats(
            device_total=overview.device_total,
            reachability=overview.reachability,
            health=overview.health,
            active_critical_alerts=overview.active_critical_alerts,
            operations_running=overview.operations_running,
            operations_verification_required=overview.operations_verification_required,
        ),
        device_types={
            device_type: DeviceTypeSummary(**summary)
            for device_type, summary in overview.device_types.items()
        },
        attention=[
            AttentionItem(
                device=AttentionDevice(
                    id=item.device_id,
                    name=item.device_name,
                    device_type=item.device_type,
                    vendor=item.vendor,
                    model=item.model,
                ),
                problems=[
                    AttentionProblem(
                        id=problem.id,
                        rule_key=problem.rule_key,
                        severity=problem.severity,
                        title=problem.title,
                        first_occurred_at=problem.first_occurred_at,
                        last_occurred_at=problem.last_occurred_at,
                    )
                    for problem in item.problems
                ],
                last_collected_at=item.last_collected_at,
                rank=item.rank,
            )
            for item in overview.attention
        ],
        recent_operations=list(overview.recent_operations),
    )
