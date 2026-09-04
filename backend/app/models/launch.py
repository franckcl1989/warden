"""ORM model for launch sessions (docs/API_CONTRACT.md §7, PLT-09).

Column layout mirrors migration ``0013_launch_sessions`` exactly. A launch
session row is the one-time ticket for a remote-connection launch
(console.kvm.open in M3T4): it binds the ticket to the user, the web
session that created it, the device, the capability and the device-side
descriptor URL, and enforces the 60-second expiry + single-use consumption
semantics. Launch is NOT a task: no operation_tasks row, no dispatch fence,
no idempotency key (M3T4 report; API_CONTRACT.md §6.1: 连接类能力不进入副作用
任务队列).

``session_id`` references the web session that issued the ticket
(API_CONTRACT.md §7: 票据绑定...来源会话). The FK is ON DELETE CASCADE on
purpose: the login-session retention sweep (0008 model, 30-day cleanup)
must never be blocked by stale ticket rows — launch rows only cover their
60-second window plus the 30-day retention margin, so a cascaded row is
always long-expired history; the audit trail lives in the permanent
audit_logs stream (launch.create / launch.consume), never in this row.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.uuid7 import uuid7
from app.models.base import Base

LAUNCH_STATUSES = ("issued", "consumed", "expired", "revoked", "failed")
LAUNCH_PROTOCOLS = ("kvm", "ssh", "telnet", "web")


class LaunchSession(Base):
    """One issued remote-connection launch ticket (DATA_MODEL.md §10 set).

    ``status`` starts ``issued`` and moves to ``consumed`` atomically on the
    single GET (conditional UPDATE), ``expired`` by the maintenance sweep
    once ``expires_at`` passes, or ``revoked``/``failed`` by future terminal
    flows. The CHECK ties ``consumed_at`` to the consumed status so a
    consumed row always carries its consumption time.
    """

    __tablename__ = "launch_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    capability_key: Mapped[str] = mapped_column(String(64), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(32), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    descriptor_url: Mapped[str | None] = mapped_column(Text)
    descriptor_data: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="issued", server_default="issued"
    )
    # The device configuration version at issue time (API_CONTRACT.md §7:
    # 票据绑定…设备版本; migration 0014). The terminal WebSocket connect
    # refuses a ticket whose device was re-configured afterwards — the
    # operator must re-probe and issue a new launch. Nullable: rows created
    # before 0014 carry no binding (always historical).
    device_version: Mapped[int | None] = mapped_column(Integer)
    consumed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    __table_args__ = (
        Index("ix_launch_sessions_user_created", "user_id", "created_at"),
        Index("ix_launch_sessions_device_created", "device_id", "created_at"),
        Index("ix_launch_sessions_expires_at", "expires_at"),
        CheckConstraint(
            "status IN ('issued', 'consumed', 'expired', 'revoked', 'failed')",
            name="ck_launch_sessions_status",
        ),
        CheckConstraint(
            "protocol IN ('kvm', 'ssh', 'telnet', 'web')", name="ck_launch_sessions_protocol"
        ),
        CheckConstraint(
            "(status = 'consumed') = (consumed_at IS NOT NULL)",
            name="ck_launch_sessions_consumed",
        ),
        CheckConstraint(
            "status <> 'revoked' OR revoked_at IS NOT NULL", name="ck_launch_sessions_revoked"
        ),
        CheckConstraint("version >= 1", name="ck_launch_sessions_version"),
    )
