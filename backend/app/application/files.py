"""Controlled file use cases (PLT-06): uploads, downloads, tickets, links.

docs/API_CONTRACT.md §8, DATA_MODEL.md §8, SECURITY.md §9, ARCHITECTURE.md
§3.6. Flow semantics (M2T5):

- ``create_upload``: type quota straight from settings (API_CONTRACT.md §8;
  config_backup/operation_log share the support-bundle band), concurrent
  sessions capped at 2 per user (API_CONTRACT.md §11) by counting active
  uploading rows, zero/oversized declarations rejected. The file row is the
  upload session (status=uploading).
- ``stream_upload_chunk``: append to the volume spool with the declared-size
  quota enforced BEFORE each write (SECURITY.md §9); an oversize stream
  aborts the session (row -> deleted with error metadata, spool removed) —
  the retry of a fully-uploaded PUT is tolerated (spool already == declared
  means the retry duplicates nothing). Interrupted sessions are abandoned:
  the retention sweep closes rows + spool older than 24 h; a network drop
  mid-stream therefore forces a fresh session (documented).
- ``complete_upload``: size consistency + server-side SHA-256 + magic sniff
  (``domain/file_types.py``); the SHA-256 was ACCUMULATED while the chunks
  streamed (``FileStorage.write_upload_chunk`` keeps a running digest — the
  up-to-50 GiB spool is never re-read at complete; after a process restart
  the digest state is gone and complete falls back to exactly one spool
  re-read). Magic mismatch for archive-typed payloads quarantines the row
  (content retained, never usable); success moves the spool to the final
  hash-addressed path (atomic publish, never a truncate of a shared ready
  file) and records encrypted/key_version for sensitive types (AES-GCM
  envelope, ``infrastructure/files.py``). The row only becomes ``ready``
  after the content is durably on the volume (DATA_MODEL.md §11: 文件元数据
  ready 只在内容落盘后提交).
- ``storage_key``: plain rows are stored under their content SHA-256;
  encrypted rows under ``<sha256>-<row-id>`` — per-file AES-GCM keys mean
  identical plaintexts encrypt differently, so each row owns its physical
  file (delete-safe; physical cleanup counts live references).
- Downloads enforce the SECURITY.md §3.1 matrix by file class (inputs need
  file.manage.input, outputs file.download.output — viewers metadata only);
  only ``ready`` files are served.
- Device-pull tickets are DB-backed (random UUID4 ids — never enumerable),
  bind file/device/purpose/expected source IP/expiry, are revoked
  explicitly, and serve nothing else (API_CONTRACT.md §8, SECURITY.md §7).
  Source IP is only ever the direct socket peer of the serving request
  (routes pass ``request.client.host``; X-Forwarded-For is never trusted).
- ``delete_file`` is admin-only, logical; active task links (queued/running/
  waiting_device) return 409. The error code for an active-link conflict is
  ``device_busy`` with the conflict task id: the 27-code catalog has no
  file-specific conflict code (contracts are immutable without an ADR) and
  device_busy is the only registered 409 carrying a task reference.

Audit actions (requirement_id PLT-06): file.upload_create/complete/
quarantine/failed, file.download, file.delete, file.retention_delete,
file.physical_cleanup, device_file_ticket.issue/serve/revoke. Content bytes,
storage names in logs and ticket URLs never enter audit/normal logs.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import ipaddress
import re
import socket
import threading
import uuid
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from typing import cast as typing_cast
from urllib.parse import quote

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.adapter import ArtifactDescriptor
from app.domain.errors import AppError
from app.domain.file_types import (
    FILE_TYPES,
    NOTE_UNEXPECTED_MAGIC,
    SNIFF_PREFIX_BYTES,
    download_permission_for,
    file_type_is_sensitive,
    quota_bytes_for,
    sniff_magic,
    upload_permission_for,
)
from app.domain.roles import require_permission as matrix_require
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import FileKeyCipher
from app.infrastructure.files import (
    FileCorruptionError,
    FileStorage,
    FileStorageError,
    QuotaExceededError,
    StoredFile,
)
from app.infrastructure.time import utcnow
from app.models.auth import AuditLog, User
from app.models.devices import Device
from app.models.files import ACTIVE_FILE_REFERENCE_STATES, DeviceFileTicket, File, FileLink
from app.models.operation import OperationTask

PLT_06 = "PLT-06"

# API_CONTRACT.md §11: 文件上传每用户最多 2 个并发 (counted on uploading rows).
MAX_CONCURRENT_UPLOADS = 2
UPLOAD_RETRY_AFTER_SECONDS = 30.0
# In-process shard count for per-upload serialization (see module docstring
# on _shard_lock; single-process deployment like the rate limiter, ADR-024).
UPLOAD_LOCK_SHARDS = 64

MESSAGE_SIZE_MISMATCH = "上传内容大小与声明不一致"
MESSAGE_QUOTA_EXCEEDED = "上传内容超过声明的文件大小，上传已中止"
MESSAGE_FILE_NOT_READY = "文件未就绪（仅 ready 状态的文件可用于任务）"
MESSAGE_FILE_NOT_DOWNLOADABLE = "文件未就绪，无法下载"
MESSAGE_FILE_IN_USE = "文件正被运行中的任务引用，无法删除"
MESSAGE_STORAGE_UNAVAILABLE = "文件存储不可用"
MESSAGE_TICKET_NOT_FOUND = "设备拉取票据无效或已过期"

FILENAME_DISPLAY_MAX = 255
_NAME_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\"\\]")


@dataclass(frozen=True)
class FileAuditContext:
    """Request metadata the file services attach to audit rows."""

    actor_user_id: uuid.UUID | None
    session_id: uuid.UUID | None
    source_ip: str | None
    user_agent_summary: str | None
    request_id: str


@dataclass(frozen=True)
class FileDownload:
    """One downloadable file: metadata row + its storage identity."""

    file: File
    stored: StoredFile


@dataclass(frozen=True)
class TicketServe:
    """One valid device-pull ticket plus its ready file."""

    ticket: DeviceFileTicket
    file: File
    stored: StoredFile


def storage_unavailable(purpose: str) -> AppError:
    return AppError(
        "storage_unavailable", MESSAGE_STORAGE_UNAVAILABLE, details={"purpose": purpose}
    )


def file_not_found() -> AppError:
    return auth_errors.resource_not_found("file")


def upload_not_found() -> AppError:
    return auth_errors.resource_not_found("file_upload")


def ticket_not_found() -> AppError:
    """Every ticket failure maps to the same 404 (never enumerable)."""
    return auth_errors.resource_not_found("device_file_ticket")


def _safe_manifest(manifest: dict[str, object]) -> dict[str, object]:
    """JSON-safe manifest copy (nested mappings/lists of scalars only).

    Adapter manifests are flat JSON-shaped; anything else is refused loudly
    (never silently truncated into the file metadata).
    """
    import json as _json

    try:
        raw = _json.dumps(manifest, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("artifact manifest is not JSON-serializable") from exc
    parsed = _json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("artifact manifest must be a JSON object")
    return parsed


def storage_key(file_row: File) -> str:
    """Volume key for a row: content sha256, or sha256-<row id> when encrypted.

    AES-GCM randomization (per-file key + nonce) means two identical
    plaintexts produce different ciphertexts, so encrypted rows always own a
    distinct physical file. The derived string still only ever contains the
    content hash and the internal row id — never user input.
    """
    name = file_row.storage_name
    if name is None:
        # Only rows that never completed (no content) reach this state; the
        # callers guard on it (retention) or on status=ready (downloads).
        raise ValueError("file row has no storage name (upload never completed)")
    if not file_row.encrypted:
        return name
    return f"{name}-{file_row.id}"


def _audit(
    logger: AuditLogger | None,
    audit: FileAuditContext,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    device_id: uuid.UUID | None = None,
    task_id: uuid.UUID | None = None,
    result: str = "success",
    detail: dict[str, object] | None = None,
    requirement_id: str = PLT_06,
) -> None:
    if logger is None:
        return
    logger.record(
        action=action,
        actor_user_id=audit.actor_user_id,
        session_id=audit.session_id,
        resource_type=resource_type,
        resource_id=resource_id,
        device_id=device_id,
        requirement_id=requirement_id,
        request_id=audit.request_id,
        task_id=task_id,
        result=result,
        source_ip=audit.source_ip,
        user_agent_summary=audit.user_agent_summary,
        detail=detail,
    )


def parse_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


def ensure_file_usable(file_row: File) -> None:
    """Guard for task wiring (M2T6): only ready files may be consumed."""
    if file_row.status != "ready":
        raise auth_errors.validation_failed("status", MESSAGE_FILE_NOT_READY)


def create_upload(
    db: Session,
    *,
    user: User,
    file_type: str,
    size_bytes: int,
    original_filename: str,
    settings: WardenSettings,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> File:
    """Open an upload session: quota/concurrency checks + uploading row."""
    if file_type not in FILE_TYPES:
        raise auth_errors.validation_failed("file_type", "不支持的文件类型")
    permission = upload_permission_for(file_type)
    if not matrix_require(user.role, permission):
        raise auth_errors.permission_denied(permission)
    quota = quota_bytes_for(file_type, settings)
    if size_bytes <= 0:
        raise auth_errors.validation_failed("size_bytes", "文件大小必须大于 0")
    if size_bytes > quota:
        raise auth_errors.validation_failed(
            "size_bytes", f"文件大小超过该类型的配额上限（{quota} 字节）"
        )
    name = original_filename.strip()
    if not name or len(name) > FILENAME_DISPLAY_MAX:
        raise auth_errors.validation_failed(
            "original_filename", "文件名不能为空且长度不能超过 255 字符"
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise auth_errors.validation_failed(
            "original_filename", "文件名不能包含控制字符"
        )
    active = int(
        db.scalar(
            select(func.count())
            .select_from(File)
            .where(File.uploaded_by == user.id, File.status == "uploading")
        )
        or 0
    )
    if active >= MAX_CONCURRENT_UPLOADS:
        raise auth_errors.rate_limited(UPLOAD_RETRY_AFTER_SECONDS, "file_upload")
    row = File(
        file_type=file_type,
        original_filename=name,
        size_bytes=size_bytes,
        uploaded_by=user.id,
        status="uploading",
    )
    db.add(row)
    db.flush()  # assign the UUIDv7 id now: the audit + callers reference it
    if logger is not None and audit is not None:
        logger.record_in(
            db,
            action="file.upload_create",
            actor_user_id=audit.actor_user_id,
            session_id=audit.session_id,
            resource_type="file",
            resource_id=str(row.id),
            requirement_id=PLT_06,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "file_type": file_type,
                "size_bytes": size_bytes,
                "status": "uploading",
            },
        )
    return row


_UPLOAD_LOCKS = tuple(threading.Lock() for _ in range(UPLOAD_LOCK_SHARDS))


def shard_lock_for(upload_id: str) -> threading.Lock:
    """Serialize spool writes/finalize per upload within this process.

    The API and worker are a single process per deployment (ADR-024) like
    the in-process rate limiter; chunk appends and the finalize move never
    race here. Multi-process deployments would need DB-level fencing
    (documented single-process caveat).
    """
    return _UPLOAD_LOCKS[zlib.crc32(upload_id.encode("utf-8")) % UPLOAD_LOCK_SHARDS]


def stream_upload_chunk(
    db: Session,
    *,
    upload_id: str,
    user_id: uuid.UUID,
    chunk: bytes,
    storage: FileStorage,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> int:
    """Append one content chunk to the session's spool (quota enforced first).

    Returns the spooled byte count after the chunk. An oversize stream
    aborts (row -> deleted, spool removed, failure audit); a retried PUT
    whose spool already holds the full declared size is tolerated (idempotent
    retry semantics for the session).
    """
    parsed = parse_uuid(upload_id)
    if parsed is None:
        raise upload_not_found()
    row = db.scalar(select(File).where(File.id == parsed))
    if row is None or row.uploaded_by != user_id or row.status != "uploading":
        raise upload_not_found()
    try:
        with shard_lock_for(upload_id):
            current = storage.upload_size(upload_id)
            if current == row.size_bytes:
                # Full-content retry of an already-complete PUT: duplicate
                # nothing (RFC idempotent retry semantics for the session).
                return current
            storage.write_upload_chunk(upload_id, chunk, declared_size=row.size_bytes)
    except QuotaExceededError as exc:
        raise _upload_failed(
            db,
            row,
            error_code="size_exceeded",
            message=MESSAGE_QUOTA_EXCEEDED,
            storage=storage,
            logger=logger,
            audit=audit,
        ) from exc
    except FileStorageError as exc:
        raise storage_unavailable("file_upload") from exc
    return storage.upload_size(upload_id)


def _abort_upload_row(db: Session, row: File, *, error_code: str) -> None:
    metadata = dict(row.metadata_json)
    metadata["error_code"] = error_code
    row.metadata_json = metadata
    row.status = "deleted"
    row.version += 1


def _upload_failed(
    db: Session,
    row: File,
    *,
    error_code: str,
    message: str,
    storage: FileStorage | None = None,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> AppError:
    """Abort an upload: row -> deleted with error metadata, spool removed,
    failure audit, and a validation error for the client."""
    _abort_upload_row(db, row, error_code=error_code)
    if storage is not None:
        with contextlib.suppress(FileStorageError):
            storage.remove_upload(str(row.id))  # the spool sweep retries otherwise
    if logger is not None and audit is not None:
        logger.record(
            action="file.upload_failed",
            actor_user_id=audit.actor_user_id,
            session_id=audit.session_id,
            resource_type="file",
            resource_id=str(row.id),
            requirement_id=PLT_06,
            request_id=audit.request_id,
            result="failure",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={"error_code": error_code, "file_type": row.file_type},
        )
    return AppError(
        "validation_failed", message, details={"field": "size_bytes", "reason": error_code}
    )


def complete_upload(
    db: Session,
    *,
    upload_id: str,
    user: User,
    storage: FileStorage,
    key_cipher: FileKeyCipher | None,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> File:
    """Verify size/hash/magic and move the spool to its final storage path.

    Raises validation errors for size/hash inconsistency (row aborted) and
    returns the row ``ready`` (verified) or ``quarantined`` (unexpected
    magic — content retained for inspection but never usable).

    Hashing uses the digest accumulated while the chunks streamed
    (``FileStorage.upload_digest``); when that state is absent (process
    restart) it falls back to one spool re-read. The sniff prefix is a
    bounded head read — neither path ever loads the whole spool into
    memory.
    """
    parsed = parse_uuid(upload_id)
    if parsed is None:
        raise upload_not_found()
    row = db.scalar(select(File).where(File.id == parsed))
    if row is None or row.uploaded_by != user.id or row.status != "uploading":
        raise upload_not_found()
    try:
        with shard_lock_for(upload_id):
            spool_size = storage.upload_size(upload_id)
            if spool_size == 0:
                raise _upload_failed(
                    db,
                    row,
                    error_code="no_content",
                    message="上传尚未收到任何内容",
                    storage=storage,
                    logger=logger,
                    audit=audit,
                )
            if spool_size != row.size_bytes:
                raise _upload_failed(
                    db,
                    row,
                    error_code="size_mismatch",
                    message=MESSAGE_SIZE_MISMATCH,
                    storage=storage,
                    logger=logger,
                    audit=audit,
                )
            content_hash = storage.upload_digest(upload_id)
            if content_hash is None:
                # Restart lost the in-stream digest state: one bounded
                # re-read recomputes it from the spool (size-verified above).
                digest = hashlib.sha256()
                for data in storage.read_upload_chunks(upload_id):
                    digest.update(data)
                content_hash = digest.hexdigest()
            prefix = storage.read_head(upload_id, SNIFF_PREFIX_BYTES)
            verdict = sniff_magic(prefix, row.file_type)
            encrypted = file_type_is_sensitive(row.file_type)
            if encrypted and key_cipher is None:
                raise AppError(
                    "dependency_unavailable", "文件主密钥未配置，无法加密存储",
                    details={"dependency": "file_keyring"},
                )
            try:
                # Physical key: encrypted rows are stored under their
                # row-scoped key (AES-GCM randomization -> identical
                # plaintexts encrypt differently); plain rows under the
                # content hash. ``storage_key(row)`` reproduces it.
                physical_key = f"{content_hash}-{row.id}" if encrypted else content_hash
                stored = storage.store_final(
                    upload_id,
                    physical_key,
                    key_cipher=key_cipher if encrypted else None,
                )
            except FileStorageError as exc:
                raise storage_unavailable("file_upload") from exc
            # The physical content is on the volume: only now does the row
            # become usable (DATA_MODEL.md §11). The stored key equals the
            # content hash in both branches (plain rows store raw bytes
            # under the hash; encrypted rows get the row-scoped variant).
            row.storage_name = content_hash
            row.sha256 = content_hash
            row.mime_type = verdict.mime_type
            row.encrypted = encrypted
            row.key_version = stored.key_version
            metadata = dict(row.metadata_json)
            if verdict.note is not None:
                metadata["magic_note"] = verdict.note
            row.metadata_json = metadata
            quarantined = verdict.note == NOTE_UNEXPECTED_MAGIC
            row.status = "quarantined" if quarantined else "ready"
            row.version += 1
    except AppError:
        raise
    except FileStorageError as exc:
        raise storage_unavailable("file_upload") from exc
    if logger is not None and audit is not None:
        if row.status == "quarantined":
            logger.record(
                action="file.upload_quarantine",
                actor_user_id=audit.actor_user_id,
                session_id=audit.session_id,
                resource_type="file",
                resource_id=str(row.id),
                requirement_id=PLT_06,
                request_id=audit.request_id,
                result="failure",
                source_ip=audit.source_ip,
                user_agent_summary=audit.user_agent_summary,
                detail={
                    "file_type": row.file_type,
                    "size_bytes": row.size_bytes,
                    "reason": "unexpected_magic",
                },
            )
        else:
            logger.record(
                action="file.upload_complete",
                actor_user_id=audit.actor_user_id,
                session_id=audit.session_id,
                resource_type="file",
                resource_id=str(row.id),
                requirement_id=PLT_06,
                request_id=audit.request_id,
                result="success",
                source_ip=audit.source_ip,
                user_agent_summary=audit.user_agent_summary,
                detail={
                    "file_type": row.file_type,
                    "size_bytes": row.size_bytes,
                    "sha256": content_hash,
                    "encrypted": encrypted,
                    "mime_type": row.mime_type,
                },
            )
    return row


def get_file_row(db: Session, file_id: str) -> File:
    parsed = parse_uuid(file_id)
    if parsed is None:
        raise file_not_found()
    row = db.get(File, parsed)
    if row is None:
        raise file_not_found()
    return row


def list_files(
    db: Session,
    *,
    page: int,
    page_size: int,
    file_type: str | None = None,
    status: str | None = None,
    uploader_id: str | None = None,
) -> tuple[list[tuple[File, str]], int]:
    """Metadata listing (newest first) with optional type/status/uploader."""
    filters = []
    if file_type is not None:
        filters.append(File.file_type == file_type)
    if status is not None:
        filters.append(File.status == status)
    if uploader_id is not None:
        parsed_uploader = parse_uuid(uploader_id)
        if parsed_uploader is None:
            raise auth_errors.validation_failed("uploader_id", "用户 ID 不合法")
        filters.append(File.uploaded_by == parsed_uploader)
    total = int(
        db.scalar(select(func.count()).select_from(File).where(*filters)) or 0
    )
    rows = db.execute(
        select(File, User.username)
        .join(User, User.id == File.uploaded_by)
        .where(*filters)
        .order_by(File.created_at.desc(), File.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [(row, username) for row, username in rows], total


def file_links(db: Session, file_id: uuid.UUID) -> list[FileLink]:
    return list(
        db.scalars(
            select(FileLink)
            .where(FileLink.file_id == file_id)
            .order_by(FileLink.created_at.desc())
        ).all()
    )


def _enforce_download_permission(user: User, file_row: File) -> None:
    permission = download_permission_for(file_row.file_type)
    if not matrix_require(user.role, permission):
        raise auth_errors.permission_denied(permission)


def prepare_download(
    db: Session,
    *,
    file_id: str,
    user: User,
    storage: FileStorage,
    key_cipher: FileKeyCipher | None,
) -> FileDownload:
    """Load a ready file and probe its volume copy for streaming.

    The probe (size parity + envelope header) runs BEFORE the response is
    built so integrity problems surface as clean errors instead of
    mid-stream connection kills.
    """
    row = get_file_row(db, file_id)
    _enforce_download_permission(user, row)
    if row.status != "ready":
        raise auth_errors.validation_failed("status", MESSAGE_FILE_NOT_DOWNLOADABLE)
    if row.encrypted and key_cipher is None:
        raise AppError(
            "dependency_unavailable", "文件主密钥未配置，无法解密下载",
            details={"dependency": "file_keyring"},
        )
    stored = StoredFile(
        storage_key=storage_key(row),
        encrypted=row.encrypted,
        size_bytes=row.size_bytes,
        key_version=row.key_version,
    )
    try:
        storage.probe_read(stored, key_cipher=key_cipher)
    except FileCorruptionError as exc:
        # A stored file failing its own integrity checks is a server-side
        # data-integrity incident; the server log carries the classification
        # (no user data in either path).
        raise AppError("internal_error", "文件完整性校验失败，无法提供服务") from exc
    except FileStorageError as exc:
        raise storage_unavailable("file_download") from exc
    return FileDownload(file=row, stored=stored)


def _active_task_link_exists(db: Session, file_id: uuid.UUID) -> OperationTask | None:
    return db.scalar(
        select(OperationTask)
        .join(FileLink, FileLink.task_id == OperationTask.id)
        .where(
            FileLink.file_id == file_id,
            OperationTask.state.in_(ACTIVE_FILE_REFERENCE_STATES),
        )
        .order_by(OperationTask.created_at.desc())
    )


def delete_file(
    db: Session,
    *,
    file_id: str,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> File:
    """Admin logical delete; 409 while an active task references the file."""
    row = get_file_row(db, file_id)
    conflict = _active_task_link_exists(db, row.id)
    if conflict is not None:
        raise AppError(
            "device_busy",
            MESSAGE_FILE_IN_USE,
            details={"conflict_task_id": str(conflict.id)},
        )
    row.status = "deleted"
    row.version += 1
    if logger is not None and audit is not None:
        logger.record_in(
            db,
            action="file.delete",
            actor_user_id=audit.actor_user_id,
            session_id=audit.session_id,
            resource_type="file",
            resource_id=str(row.id),
            requirement_id=PLT_06,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={"file_type": row.file_type, "size_bytes": row.size_bytes},
        )
    return row


# --------------------------------------------------------------------------
# Device-pull tickets (API_CONTRACT.md §8, SECURITY.md §7/§9)
# --------------------------------------------------------------------------


def resolve_management_ip(endpoint: str) -> str:
    """Resolve the device's management endpoint to an IPv4 at issue time.

    The ticket pins the exact peer IP the device will pull from; a hostname
    endpoint is resolved ONCE at ticket issue (a later DNS change makes the
    exact-match fail closed with a 404 — documented behavior). IPv6 literals
    are refused: 0.1.0 device pulls are management-IPv4 (network policy
    CIDRs are IPv4); an IPv6 endpoint is a validation error, not a guess.
    """
    try:
        parsed = ipaddress.ip_address(endpoint)
    except ValueError:
        try:
            resolved = socket.gethostbyname(endpoint)
            parsed = ipaddress.ip_address(resolved)
        except OSError as exc:
            raise auth_errors.validation_failed(
                "device", "无法解析设备管理地址，不能签发设备拉取票据"
            ) from exc
    if parsed.version != 4:
        raise auth_errors.validation_failed(
            "device", "设备拉取票据仅支持 IPv4 管理地址"
        )
    return str(parsed)


def issue_device_file_ticket(
    db: Session,
    *,
    file_row: File,
    device: Device,
    purpose: str,
    expires_at: datetime.datetime,
    task_id: uuid.UUID | None = None,
    actor_ip: str | None = None,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> DeviceFileTicket:
    """Issue one DB-backed pull ticket bound to file/device/IP/purpose/expiry.

    The expected source IP is resolved from the device's CURRENT management
    endpoint (``resolve_management_ip``) at issue time; the serving endpoint
    compares only its direct socket peer against it (SECURITY.md §7).
    """
    ensure_file_usable(file_row)
    if purpose not in ("firmware", "virtual_media"):
        raise auth_errors.validation_failed("purpose", "票据用途只能是固件或虚拟介质")
    if purpose != file_row.file_type:
        raise auth_errors.validation_failed(
            "purpose", "票据用途必须与文件类型一致"
        )
    if expires_at <= utcnow():
        raise auth_errors.validation_failed("expires_at", "票据过期时间必须在未来")
    expected_ip = resolve_management_ip(device.management_endpoint)
    ticket = DeviceFileTicket(
        file_id=file_row.id,
        device_id=device.id,
        purpose=purpose,
        expected_ip=expected_ip,
        created_by_task_id=task_id,
        expires_at=expires_at,
    )
    db.add(ticket)
    if logger is not None and audit is not None:
        logger.record_in(
            db,
            action="device_file_ticket.issue",
            actor_user_id=audit.actor_user_id,
            session_id=audit.session_id,
            resource_type="device_file_ticket",
            resource_id=str(ticket.id),
            device_id=device.id,
            requirement_id=PLT_06,
            request_id=audit.request_id,
            task_id=task_id,
            result="success",
            source_ip=actor_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "file_type": file_row.file_type,
                "expected_ip": expected_ip,
                "expires_at": expires_at.isoformat(),
                "purpose": purpose,
            },
        )
    return ticket


def _serve_ticket_row(
    db: Session,
    ticket_id: str,
    *,
    source_ip: str | None,
) -> tuple[DeviceFileTicket, File]:
    """Load a ticket and apply EVERY serve condition; any failure is a 404.

    Unknown/expired/revoked/mismatched-IP/missing-or-unready file all map to
    the same response so the endpoint never leaks which condition failed
    (never enumerable, SECURITY.md §7).
    """
    parsed = parse_uuid(ticket_id)
    if parsed is None:
        raise ticket_not_found()
    ticket = db.get(DeviceFileTicket, parsed)
    if ticket is None:
        raise ticket_not_found()
    if ticket.revoked_at is not None or ticket.expires_at <= utcnow():
        raise ticket_not_found()
    if ticket.expected_ip != source_ip:
        raise ticket_not_found()
    file_row = db.get(File, ticket.file_id)
    if file_row is None or file_row.status != "ready":
        raise ticket_not_found()
    if file_row.file_type != ticket.purpose:
        raise ticket_not_found()
    return ticket, file_row


def prepare_ticket_stream(
    db: Session,
    *,
    ticket_id: str,
    source_ip: str | None,
    storage: FileStorage,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> TicketServe:
    """Validate the ticket against the direct peer IP and probe the file.

    Tickets only ever bind firmware/virtual_media files (purpose ==
    file_type, enforced at issue and serve), which are stored PLAIN
    (ARCHITECTURE.md §3.6) — device pulls never need the file master key.
    """
    ticket, file_row = _serve_ticket_row(db, ticket_id, source_ip=source_ip)
    stored = StoredFile(
        storage_key=storage_key(file_row),
        encrypted=file_row.encrypted,
        size_bytes=file_row.size_bytes,
        key_version=file_row.key_version,
    )
    try:
        storage.probe_read(stored, key_cipher=None)
    except (FileCorruptionError, FileStorageError) as exc:
        raise ticket_not_found() from exc
    # Audit the FIRST serve only (volume-safe per M2T5 decision: resumed
    # range requests are not individual audit events).
    served = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.action == "device_file_ticket.serve",
            AuditLog.resource_id == str(ticket.id),
        )
    )
    if (served or 0) == 0 and logger is not None:
        logger.record(
            action="device_file_ticket.serve",
            actor_user_id=None,
            session_id=None,
            resource_type="device_file_ticket",
            resource_id=str(ticket.id),
            device_id=ticket.device_id,
            requirement_id=PLT_06,
            task_id=ticket.created_by_task_id,
            result="success",
            source_ip=source_ip,
            detail={
                "file_type": file_row.file_type,
                "size_bytes": file_row.size_bytes,
                "purpose": ticket.purpose,
            },
        )
    return TicketServe(ticket=ticket, file=file_row, stored=stored)


def revoke_device_file_ticket(
    db: Session,
    *,
    ticket_id: str,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
    device_id: uuid.UUID | None = None,
) -> DeviceFileTicket | None:
    """Explicitly revoke a ticket (task end / virtual-media unmount, M2T6).

    Idempotent: the conditional update only fires on an unrevoked row, so a
    second revocation writes no second audit. Returns None when the ticket
    does not exist (caller decides the response).
    """
    parsed = parse_uuid(ticket_id)
    if parsed is None:
        return None
    ticket = db.get(DeviceFileTicket, parsed)
    if ticket is None:
        return None
    result = db.execute(
        update(DeviceFileTicket)
        .where(DeviceFileTicket.id == parsed, DeviceFileTicket.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    changed = typing_cast(Any, result).rowcount or 0
    if changed:
        db.refresh(ticket)
    if changed and logger is not None and audit is not None:
        logger.record(
            action="device_file_ticket.revoke",
            actor_user_id=audit.actor_user_id,
            session_id=audit.session_id,
            resource_type="device_file_ticket",
            resource_id=str(ticket.id),
            device_id=device_id or ticket.device_id,
            requirement_id=PLT_06,
            request_id=audit.request_id,
            task_id=ticket.created_by_task_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={"purpose": ticket.purpose},
        )
    return ticket


# --------------------------------------------------------------------------
# Worker-side operation file flows (M3T3; adapter boundary: the adapter yields
# bytes/descriptors, the worker persists rows/links — no adapter file paths)
# --------------------------------------------------------------------------

# file_link purposes for operation inputs/outputs (DATA_MODEL.md §8.2).
PURPOSE_INPUT_FIRMWARE = "input_firmware"
PURPOSE_INPUT_VIRTUAL_MEDIA = "input_virtual_media"
PURPOSE_OUTPUT_SUPPORT_BUNDLE = "output_support_bundle"
PURPOSE_OUTPUT_CONFIG_BACKUP = "output_config_backup"
PURPOSE_OUTPUT_OPERATION_LOG = "output_operation_log"

# Artifact file types the worker may persist for operation tasks. All three
# are sensitive types stored encrypted at rest (SECURITY.md §9); the link
# purposes below exist since the M2T5 migration (output_config_backup /
# output_operation_log) — M5T3 wires the switch config/diagnostic artifacts.
OPERATION_OUTPUT_FILE_TYPES = frozenset(
    {"support_bundle", "config_backup", "operation_log"}
)

# Ticket TTL for virtual-media pulls (ARCHITECTURE.md §3.6: 虚拟介质 <= 24 h).
VIRTUAL_MEDIA_TICKET_HOURS = 24


def operation_artifact_file_link_purpose(file_type: str) -> str:
    if file_type == "support_bundle":
        return PURPOSE_OUTPUT_SUPPORT_BUNDLE
    if file_type == "config_backup":
        return PURPOSE_OUTPUT_CONFIG_BACKUP
    if file_type == "operation_log":
        return PURPOSE_OUTPUT_OPERATION_LOG
    raise ValueError(f"unsupported operation artifact type: {file_type}")


def input_file_link_purpose(file_type: str) -> str:
    if file_type == "firmware":
        return PURPOSE_INPUT_FIRMWARE
    if file_type == "virtual_media":
        return PURPOSE_INPUT_VIRTUAL_MEDIA
    raise ValueError(f"unsupported operation input type: {file_type}")


def ticket_url_for(settings: WardenSettings, ticket: DeviceFileTicket) -> str:
    """The device-pull URL for a ticket (SECURITY.md §7: bound + revocable).

    The base is the operator-declared ``device_access_base_url`` (the URL the
    DEVICE can reach — NAT/proxy deployments differ from the UI's
    ``public_url``) or ``public_url``. Ticket URLs never enter logs/evidence;
    they are handed to the adapter for the device call only.
    """
    base = settings.device_access_base_url or settings.public_url
    return f"{base.rstrip('/')}/api/v1/device-file-access/{ticket.id}"


def active_device_file_ticket(
    db: Session,
    *,
    device_id: uuid.UUID,
    file_id: uuid.UUID,
    purpose: str,
) -> DeviceFileTicket | None:
    """The unrevoked, unexpired ticket for (device, file, purpose), if any."""
    return db.scalar(
        select(DeviceFileTicket)
        .where(
            DeviceFileTicket.device_id == device_id,
            DeviceFileTicket.file_id == file_id,
            DeviceFileTicket.purpose == purpose,
            DeviceFileTicket.revoked_at.is_(None),
            DeviceFileTicket.expires_at > utcnow(),
        )
        .order_by(DeviceFileTicket.created_at.desc())
        .limit(1)
    )


def link_input_file(
    db: Session,
    *,
    file_row: File,
    device_id: uuid.UUID,
    task_id: uuid.UUID,
    created_by: uuid.UUID,
) -> FileLink:
    """One input file_link row for an operation task (idempotent per task)."""
    purpose = input_file_link_purpose(file_row.file_type)
    existing = db.scalar(
        select(FileLink).where(
            FileLink.file_id == file_row.id,
            FileLink.device_id == device_id,
            FileLink.task_id == task_id,
            FileLink.purpose == purpose,
        )
    )
    if existing is not None:
        return existing
    link = FileLink(
        file_id=file_row.id,
        device_id=device_id,
        task_id=task_id,
        purpose=purpose,
        created_by=created_by,
    )
    db.add(link)
    return link


def store_operation_artifact(
    db: Session,
    *,
    artifact: ArtifactDescriptor,
    device_id: uuid.UUID,
    task_id: uuid.UUID,
    created_by: uuid.UUID,
    storage: FileStorage,
    key_cipher: FileKeyCipher | None,
    logger: AuditLogger | None = None,
    audit: FileAuditContext | None = None,
) -> File:
    """Persist one worker-produced artifact: content + ready row + file_link.

    The artifact bytes are spooled and finalized through the SAME storage
    paths as uploads (atomic publish, content-hash naming, AES-GCM envelope
    for sensitive types). The row becomes ``ready`` only after the bytes are
    durable (DATA_MODEL.md §11) and the file_link binds device/task/purpose
    in the same transaction. ``artifact.file_type`` must be an operation
    output type the platform encrypts (support_bundle) — the adapter never
    stores files itself.
    """
    if artifact.file_type not in OPERATION_OUTPUT_FILE_TYPES:
        raise auth_errors.validation_failed("artifact", "不支持的产物类型")
    content = artifact.content_bytes
    if not content:
        raise auth_errors.validation_failed("artifact", "产物内容为空")
    encrypted = file_type_is_sensitive(artifact.file_type)
    if encrypted and key_cipher is None:
        raise AppError(
            "dependency_unavailable",
            "文件主密钥未配置，无法加密保存操作产物",
            details={"dependency": "file_keyring"},
        )
    upload_id = str(uuid.uuid4())
    try:
        row = File(
            file_type=artifact.file_type,
            original_filename=artifact.filename[:FILENAME_DISPLAY_MAX],
            size_bytes=len(content),
            mime_type=artifact.mime_type,
            uploaded_by=created_by,
            status="uploading",
        )
        db.add(row)
        db.flush()  # the row id keys the physical file of encrypted rows
        with shard_lock_for(upload_id):
            chunk_size = 1024 * 1024
            for offset in range(0, len(content), chunk_size):
                storage.write_upload_chunk(
                    upload_id, content[offset : offset + chunk_size], declared_size=len(content)
                )
            content_hash = storage.upload_digest(upload_id)
            if content_hash is None:
                digest = hashlib.sha256()
                for data in storage.read_upload_chunks(upload_id):
                    digest.update(data)
                content_hash = digest.hexdigest()
            # Encrypted rows are stored under ``sha256-<row id>`` — the exact
            # key ``storage_key(row)`` later derives for downloads.
            physical_key = f"{content_hash}-{row.id}" if encrypted else content_hash
            try:
                stored = storage.store_final(
                    upload_id, physical_key, key_cipher=key_cipher if encrypted else None
                )
            except FileStorageError as exc:
                raise storage_unavailable("operation_artifact") from exc
            row.sha256 = content_hash
            row.storage_name = content_hash
            row.encrypted = encrypted
            row.key_version = stored.key_version if encrypted else None
            row.status = "ready"
            if artifact.manifest:
                # The artifact manifest (adapter-declared metadata: model/
                # VRP + per-source hashes) travels on the file row so later
                # consumers (e.g. config.restore origin/identity checks)
                # read it without re-parsing task evidence. JSON-safe: the
                # adapter manifests are flat JSON-shaped dicts.
                row.metadata_json = _safe_manifest(artifact.manifest)
            link = FileLink(
                file_id=row.id,
                device_id=device_id,
                task_id=task_id,
                purpose=operation_artifact_file_link_purpose(artifact.file_type),
                created_by=created_by,
            )
            db.add(link)
    except FileStorageError as exc:
        raise storage_unavailable("operation_artifact") from exc
    if logger is not None and audit is not None:
        _audit(
            logger,
            audit,
            action="file.operation_artifact",
            resource_type="file",
            resource_id=str(row.id),
            device_id=device_id,
            task_id=task_id,
            result="success",
            detail={
                "file_type": artifact.file_type,
                "size_bytes": len(content),
                "sha256": content_hash,
                "encrypted": encrypted,
                "mime_type": row.mime_type,
            },
        )
    return row


@dataclass(frozen=True)
class ByteRange:
    """A parsed, satisfiable single byte range (inclusive start/end)."""

    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start + 1


def parse_range_header(header: str | None, total: int) -> ByteRange | None:
    """RFC 7233 single-range parsing for device pulls.

    Returns None when the header is absent/malformed/multi-range (serve the
    full body, 200) — only a single ``bytes=a-b``/``bytes=a-``/``bytes=-n``
    range yields a partial. Callers treat an unsatisfiable range
    (start >= total) by sending 416 themselves.
    """
    if not header or total <= 0:
        return None
    if not header.startswith("bytes=") or "," in header:
        return None
    spec = header[len("bytes=") :].strip()
    if spec.startswith("-"):  # suffix: last n bytes
        try:
            suffix = int(spec[1:])
        except ValueError:
            return None
        if suffix <= 0:
            return None
        length = min(suffix, total)
        return ByteRange(start=total - length, end=total - 1)
    if "-" not in spec:
        return None
    raw_start, raw_end = spec.split("-", 1)
    try:
        start = int(raw_start)
    except ValueError:
        return None
    if start < 0:
        return None
    if start >= total:
        # Unsatisfiable marker (RFC 7233 §4.4): the route answers 416.
        return ByteRange(start=start, end=start)
    if raw_end == "":
        return ByteRange(start=start, end=total - 1)
    try:
        end = int(raw_end)
    except ValueError:
        return None
    if end < start:
        return None
    return ByteRange(start=start, end=min(end, total - 1))


def stream_chunks(
    storage: FileStorage,
    download: FileDownload | TicketServe,
    *,
    byte_range: ByteRange | None,
    key_cipher: FileKeyCipher | None,
) -> Iterator[bytes]:
    """Bounded chunk iterator for downloads/pulls (start/limit windowed)."""
    stored = download.stored
    start = byte_range.start if byte_range is not None else 0
    limit = byte_range.length if byte_range is not None else None
    return storage.open_chunks(stored, key_cipher=key_cipher, start=start, limit=limit)


def attachment_header(original_filename: str) -> str:
    """Content-Disposition value that stays header-serializable for ANY name.

    Header serialization is latin-1: raw non-latin-1 characters (Chinese
    upload names are legal) would raise UnicodeEncodeError, so the plain
    ``filename=`` carries an ASCII-safe fallback (non-ASCII replaced by
    ``?``, RFC 6266 §5) and the ORIGINAL name rides percent-encoded as RFC
    5987 ``filename*=UTF-8''...`` (``safe=''`` — the header-value specials
    ``; " \\`` and control characters are all encoded). CR/LF/quotes/
    backslashes never survive into either value.
    """
    safe = _NAME_CONTROL_RE.sub("_", original_filename or "warden-file")
    safe = safe.strip() or "warden-file"
    try:
        safe.encode("ascii")
    except UnicodeEncodeError:
        fallback = safe.encode("ascii", "replace").decode("ascii")[:160] or "warden-file"
        return (
            f'attachment; filename="{fallback}"; '
            f"filename*=UTF-8''{quote(original_filename or 'warden-file', safe='')}"
        )
    return f'attachment; filename="{safe[:160]}"'
