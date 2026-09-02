"""ORM models for devices, credentials, capabilities and components.

docs/DATA_MODEL.md §4.1-§4.4. Column layout mirrors migration
``0003_devices_credentials_capabilities_components`` exactly. The component
status vocabulary comes from contracts/metrics.json enum_sets.component_status
(unknown/ok/warning/critical/absent). ``device_credentials`` stores only the
AES-256-GCM ciphertext payload (SECURITY.md §5); plaintext exists only inside
the probe boundary.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.uuid7 import uuid7
from app.models.base import Base

DEVICE_TYPES = ("server", "synology_nas", "core_switch", "access_switch")
READINESS_STATES = ("not_ready", "ready", "misconfigured")
REACHABILITY_STATES = ("unknown", "online", "offline")
HEALTH_STATES = ("unknown", "healthy", "warning", "critical")
SUPPORT_STATES = ("supported", "unsupported", "not_configured")
COMPONENT_STATUSES = ("unknown", "ok", "warning", "critical", "absent")


class Device(Base):
    """A managed hardware device (docs/DATA_MODEL.md §4.1)."""

    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_type: Mapped[str] = mapped_column(String(32), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    management_endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter_key: Mapped[str] = mapped_column(String(64), nullable=False)
    connection_config: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    readiness: Mapped[str] = mapped_column(String(16), nullable=False)
    reachability: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unknown", server_default="unknown"
    )
    health: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unknown", server_default="unknown"
    )
    last_known_health: Mapped[str | None] = mapped_column(String(16))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    firmware_version: Mapped[str | None] = mapped_column(String(64))
    last_seen_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    last_collected_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    next_poll_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    consecutive_successes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Per-collection-type last finished_at map {type: ISO-8601} plus the
    # internal "_backoff" extension {type: ISO-8601} for credential-error
    # backoff (M2T2, migration 0006; updated in the run completion transaction).
    collection_state: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("name", name="uq_devices_name"),
        UniqueConstraint(
            "device_type", "management_endpoint", "adapter_key", name="uq_devices_type_endpoint_adapter"
        ),
        CheckConstraint(
            "device_type IN ('server', 'synology_nas', 'core_switch', 'access_switch')",
            name="ck_devices_device_type",
        ),
        CheckConstraint(
            "readiness IN ('not_ready', 'ready', 'misconfigured')", name="ck_devices_readiness"
        ),
        CheckConstraint(
            "reachability IN ('unknown', 'online', 'offline')", name="ck_devices_reachability"
        ),
        CheckConstraint(
            "health IN ('unknown', 'healthy', 'warning', 'critical')", name="ck_devices_health"
        ),
        CheckConstraint("consecutive_failures >= 0", name="ck_devices_consecutive_failures"),
        CheckConstraint("consecutive_successes >= 0", name="ck_devices_consecutive_successes"),
        CheckConstraint("version >= 1", name="ck_devices_version"),
    )


class DeviceCredential(Base):
    """One-to-one encrypted credentials (docs/DATA_MODEL.md §4.2, SECURITY.md §5)."""

    __tablename__ = "device_credentials"

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    secret_schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("key_version >= 1", name="ck_device_credentials_key_version"),
        CheckConstraint(
            "secret_schema_version >= 1", name="ck_device_credentials_secret_schema_version"
        ),
    )


class DeviceCapability(Base):
    """Discovered capability support (docs/DATA_MODEL.md §4.3)."""

    __tablename__ = "device_capabilities"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    capability_key: Mapped[str] = mapped_column(String(64), nullable=False)
    support_state: Mapped[str] = mapped_column(String(16), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(32), nullable=False)
    discovery_method: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(Text)
    last_checked_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("device_id", "capability_key", name="uq_device_capabilities_device_key"),
        CheckConstraint(
            "support_state IN ('supported', 'unsupported', 'not_configured')",
            name="ck_device_capabilities_support_state",
        ),
    )


class Component(Base):
    """Unified component current state (docs/DATA_MODEL.md §4.4)."""

    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    native_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    properties: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    first_seen_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("device_id", "kind", "native_id", name="uq_components_device_kind_native"),
        CheckConstraint(
            "status IN ('unknown', 'ok', 'warning', 'critical', 'absent')",
            name="ck_components_status",
        ),
    )
