"""ORM models for the controlled file layer (docs/DATA_MODEL.md §8, M2T5).

Column layout mirrors migration ``0011_files`` exactly.

- ``File``: one upload session / stored file (status uploading -> ready /
  quarantined; deleted is the admin logical-delete terminal state). The
  ``sha256`` column records the PLAINTEXT content hash (verification record
  and firmware checksum); ``storage_name`` is that hash. The physical file on
  the volume is keyed ``storage_name`` for plain files and
  ``storage_name-<row id>`` for encrypted ones (AES-GCM randomization makes
  identical plaintexts encrypt differently — ``application/files.py``
  derives the storage key, ``infrastructure/files.py`` validates it).
- ``FileLink``: binds a file to a device/task and a purpose; task rows carry
  no storage paths (DATA_MODEL.md §8.2). ``task_id`` cascades so the
  retention purge of an eventless terminal task can never be blocked by a
  stale link (0010 pattern).
- ``DeviceFileTicket``: DB-backed device-pull ticket (API_CONTRACT.md §8,
  SECURITY.md §7/§9): binds file/device/purpose/expected source IP/expiry;
  revocation is an explicit ``revoked_at`` write (task end / unmount in
  M2T6). The ticket id is a random UUID4 — never enumerable, single-purpose.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.domain.file_types import STORAGE_BACKEND
from app.domain.uuid7 import uuid7
from app.models.base import Base

# States of operation_tasks that still reference a file: queued (not yet
# executed — the input/output is still needed), running and waiting_device
# (the action is executing/verifying). verification_required no longer needs
# the file (read-backs never consume it).
ACTIVE_FILE_REFERENCE_STATES = ("queued", "running", "waiting_device")


class File(Base):
    """One controlled file / upload session (docs/DATA_MODEL.md §8.1).

    The row is created ``uploading`` with the declared size; content streams
    to the volume spool; ``complete_upload`` verifies size/hash/magic and
    moves the row to ``ready`` (content on disk) or ``quarantined`` (magic
    mismatch, content retained but never usable). ``deleted`` is the logical
    delete terminal state — physical bytes leave only via the delayed
    retention cleanup (DATA_MODEL.md §8.2/§10). Sensitive types
    (support_bundle/config_backup/operation_log) are stored encrypted:
    ``encrypted``/``key_version`` describe the on-disk envelope.
    """

    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    file_type: Mapped[str] = mapped_column(String(32), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    # Content SHA-256, set atomically with ``sha256`` at complete_upload:
    # uploading sessions carry no hash yet (NULL is allowed until ready).
    storage_name: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(128))
    sha256: Mapped[str | None] = mapped_column(String(64))
    storage_backend: Mapped[str] = mapped_column(
        String(32), nullable=False, default=STORAGE_BACKEND, server_default=STORAGE_BACKEND
    )
    encrypted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    key_version: Mapped[int | None] = mapped_column(Integer)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="uploading", server_default="uploading"
    )
    # DB column ``metadata`` (DATA_MODEL.md §8.1); the attribute name avoids
    # SQLAlchemy's reserved ``metadata`` class attribute (Base.metadata).
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    __table_args__ = (
        Index("ix_files_status_created", "status", "created_at"),
        Index("ix_files_type_status", "file_type", "status"),
        Index("ix_files_uploaded_by_created", "uploaded_by", "created_at"),
        Index("ix_files_storage_name", "storage_name"),
        CheckConstraint(
            "file_type IN ('firmware', 'virtual_media', 'support_bundle', "
            "'config_backup', 'operation_log')",
            name="ck_files_file_type",
        ),
        CheckConstraint(
            "status IN ('uploading', 'ready', 'quarantined', 'deleted')",
            name="ck_files_status",
        ),
        CheckConstraint("size_bytes > 0", name="ck_files_size_bytes"),
        CheckConstraint(
            "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'", name="ck_files_sha256"
        ),
        CheckConstraint(
            "storage_name IS NULL OR storage_name ~ '^[0-9a-f]{64}$'",
            name="ck_files_storage_name",
        ),
        CheckConstraint(
            "(encrypted = false AND key_version IS NULL) OR "
            "(encrypted = true AND key_version IS NOT NULL)",
            name="ck_files_encryption",
        ),
        CheckConstraint("version >= 1", name="ck_files_version"),
    )


class FileLink(Base):
    """Binds a file to a device and/or task for one purpose (DATA_MODEL.md §8.2)."""

    __tablename__ = "file_links"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT")
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operation_tasks.id", ondelete="CASCADE")
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_file_links_file_id", "file_id"),
        Index("ix_file_links_device_id", "device_id"),
        Index("ix_file_links_task_id", "task_id"),
        CheckConstraint(
            "purpose IN ('input_firmware', 'input_virtual_media', 'output_support_bundle', "
            "'output_config_backup', 'output_operation_log')",
            name="ck_file_links_purpose",
        ),
        CheckConstraint(
            "device_id IS NOT NULL OR task_id IS NOT NULL",
            name="ck_file_links_target",
        ),
    )


class DeviceFileTicket(Base):
    """DB-backed device-pull ticket (docs/API_CONTRACT.md §8, SECURITY.md §7/§9).

    Serves exactly one file to one device from its expected source IP until
    expiry or explicit revocation (``revoked_at``). Tickets are short-lived
    (virtual media <= 24 h, firmware = operation plan window), never appear in
    normal access logs, and are purged by the retention sweep shortly after
    expiry. The random UUID4 id is the URL token.
    """

    __tablename__ = "device_file_tickets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operation_tasks.id", ondelete="CASCADE")
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_device_file_tickets_expires_at", "expires_at"),
        CheckConstraint(
            "purpose IN ('firmware', 'virtual_media')", name="ck_device_file_tickets_purpose"
        ),
        CheckConstraint(
            "char_length(expected_ip) BETWEEN 7 AND 64",
            name="ck_device_file_tickets_expected_ip",
        ),
    )
