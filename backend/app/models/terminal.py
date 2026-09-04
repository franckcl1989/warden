"""ORM model for browser terminal sessions (M5T4, API_CONTRACT.md §7/§11).

Column layout mirrors migration ``0014_terminal_sessions`` exactly. One
``TerminalSession`` row is created when the WebSocket connect claims a
60-second launch ticket (protocol ssh/telnet) and lives while the terminal
is open; it records ONLY session metadata — who, which device, which
protocol, when it opened/closed and why. Terminal CONTENT is never stored
(SECURITY.md §8: 0.1.0 不记录终端正文；ARCHITECTURE.md §5.4: 终端流不进普通日
志): the audit trail (terminal.handshake_ok / terminal.handshake_failed /
terminal.closed) carries the same metadata, never the byte stream.

Bounds (ARCHITECTURE.md §5.4): a session is closed at 2h total or 15min idle
(defaults; deployment-configurable). The API process enforces both live and
the retention sweep closes rows whose stored activity proves staleness — a
crashed API must not leave an open row behind forever (it would block the
per-device-1 / per-user-3 concurrency caps of API_CONTRACT.md §11).

``launch_session_id`` is UNIQUE: the one-time ticket can create at most one
session even under a claim race.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.uuid7 import uuid7
from app.models.base import Base

TERMINAL_PROTOCOLS = ("ssh", "telnet")
TERMINAL_STATUSES = ("open", "closed")
#: Machine close-reason vocabulary (mirrors migration 0014's CHECK).
TERMINAL_CLOSE_REASONS = (
    "user_closed",
    "idle_timeout",
    "max_duration",
    "handshake_failed",
    "device_connection_lost",
    "client_disconnected",
    "server_restart",
    "internal_error",
)


class TerminalSession(Base):
    """One open/closed browser-terminal session (API_CONTRACT.md §7)."""

    __tablename__ = "terminal_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    launch_session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("launch_sessions.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    capability_key: Mapped[str] = mapped_column(String(64), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="open", server_default="open"
    )
    opened_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    closed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[str | None] = mapped_column(String(32))
    last_activity_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("launch_session_id", name="uq_terminal_sessions_launch_session"),
        Index("ix_terminal_sessions_user_opened", "user_id", "opened_at"),
        Index("ix_terminal_sessions_device_opened", "device_id", "opened_at"),
        Index("ix_terminal_sessions_open_activity", "status", "last_activity_at"),
        Index("ix_terminal_sessions_opened_at", "opened_at"),
        CheckConstraint(
            "protocol IN ('ssh', 'telnet')", name="ck_terminal_sessions_protocol"
        ),
        CheckConstraint(
            "status IN ('open', 'closed')", name="ck_terminal_sessions_status"
        ),
        CheckConstraint(
            "(status = 'closed') = (closed_at IS NOT NULL)",
            name="ck_terminal_sessions_closed",
        ),
        CheckConstraint(
            "status <> 'closed' OR close_reason IS NOT NULL",
            name="ck_terminal_sessions_close_reason",
        ),
        CheckConstraint(
            "close_reason IS NULL OR close_reason IN ('user_closed', 'idle_timeout', "
            "'max_duration', 'handshake_failed', 'device_connection_lost', "
            "'client_disconnected', 'server_restart', 'internal_error')",
            name="ck_terminal_sessions_reason_values",
        ),
    )
