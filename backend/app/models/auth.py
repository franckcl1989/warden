"""ORM models for identity: users, sessions and the append-only audit log.

docs/DATA_MODEL.md §3/§9. Column layout mirrors migration ``0002_users_sessions_audit``
exactly. ``audit_logs`` is append-only at two levels: the database trigger (see
the migration) and the ORM listeners below, so application code cannot silently
update or delete audit rows through the session either.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    column,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.uuid7 import uuid7
from app.models.base import Base

USER_ROLES = ("admin", "operator", "viewer")
USER_STATUSES = ("active", "disabled", "locked")


class AuditAppendOnlyError(RuntimeError):
    """Raised by the ORM layer when code attempts to mutate an audit row."""


class User(Base):
    """A local platform account (docs/DATA_MODEL.md §3.1).

    Usernames are case-insensitively unique via a functional unique index on
    ``lower(username)`` (plain text column; documented in migration 0002).
    Users are never hard-deleted; removal means ``status=disabled``.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", server_default="active")
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    locked_until: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    last_login_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    __table_args__ = (
        Index("ix_users_username_lower", func.lower(column("username")), unique=True),
        CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="ck_users_role"),
        CheckConstraint("status IN ('active', 'disabled', 'locked')", name="ck_users_status"),
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
        CheckConstraint("version >= 1", name="ck_users_version"),
    )


class Session(Base):
    """One login session (docs/DATA_MODEL.md §3.3).

    The opaque 256-bit token lives only in the HttpOnly cookie; the database
    stores its SHA-256 hash. The CSRF secret is stored hashed the same way.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    session_id_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_activity_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    reauthenticated_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    csrf_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_summary: Mapped[str | None] = mapped_column(String(255))
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    __table_args__ = (
        Index("ix_sessions_user_id_revoked_at", "user_id", "revoked_at"),
        CheckConstraint("version >= 1", name="ck_sessions_version"),
    )


class AuditLog(Base):
    """Append-only audit trail (docs/DATA_MODEL.md §9.1, SECURITY.md §12).

    No update/delete is possible: the database rejects it with a trigger and
    the ORM rejects it in listeners. ``detail`` is sanitized by
    ``app.infrastructure.audit`` before it ever reaches a row; the model does
    not enforce that, the writer does.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    device_id: Mapped[uuid.UUID | None] = mapped_column()
    requirement_id: Mapped[str | None] = mapped_column(String(32))
    request_id: Mapped[str | None] = mapped_column(String(64))
    task_id: Mapped[uuid.UUID | None] = mapped_column()
    # String(32) since migration 0004: security events record stable error
    # codes (e.g. "permission_denied") as the result value.
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="success", server_default="success")
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent_summary: Mapped[str | None] = mapped_column(String(255))
    detail_jsonb: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_actor_occurred_at", "actor_user_id", "occurred_at"),
    )


@event.listens_for(AuditLog, "before_update")
def _reject_audit_update(_mapper: object, _connection: object, _target: object) -> None:
    raise AuditAppendOnlyError("audit_logs is append-only: updates are rejected")


@event.listens_for(AuditLog, "before_delete")
def _reject_audit_delete(_mapper: object, _connection: object, _target: object) -> None:
    raise AuditAppendOnlyError("audit_logs is append-only: deletes are rejected")
