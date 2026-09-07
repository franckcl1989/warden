"""System-state and ingest-heartbeat rows (migration 0015, PLT-08).

docs/DEPLOYMENT.md §8 (维护模式由部署命令设置并持久化到 PostgreSQL) and
ARCHITECTURE.md §9/API_CONTRACT.md §9 (GET /system/status 汇总接收器状态).
Column layout mirrors migration ``0015_system_state`` exactly.
"""

from __future__ import annotations

import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

SYSTEM_STATE_ROW_ID = 1
INGEST_HEARTBEAT_ROW_ID = 1


class SystemState(Base):
    """Single-row maintenance-mode state (docs/DEPLOYMENT.md §8).

    The row appears on first use (app upsert or the ``warden maintenance``
    host CLI); an absent row reads as maintenance OFF. ``updated_at`` is the
    last transition time.
    """

    __tablename__ = "system_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=SYSTEM_STATE_ROW_ID)
    maintenance_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    maintenance_since: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    maintenance_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (CheckConstraint("id = 1", name="ck_system_state_single_row"),)


class IngestHeartbeat(Base):
    """Single-row durable ingest heartbeat (ARCHITECTURE.md §9, M6T3b).

    ``updated_at`` is the process-alive stamp: the ingest service (M5T1)
    upserts this row at startup and every heartbeat interval whether or not
    events arrived; ``events_received_total`` accumulates durably (survives
    ingest restarts) and ``last_received_at`` is the newest received event.
    """

    __tablename__ = "ingest_heartbeat"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=INGEST_HEARTBEAT_ROW_ID)
    events_received_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_received_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (CheckConstraint("id = 1", name="ck_ingest_heartbeat_single_row"),)
