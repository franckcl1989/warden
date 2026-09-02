"""Controlled file API (PLT-06): upload sessions, metadata, download, delete.

operationIds EXACTLY per contracts/http-api.json: file_uploads_create,
file_uploads_put_content, file_uploads_complete, files_list, files_get,
files_download, files_delete. Semantics per API_CONTRACT.md §8 and
SECURITY.md §9 (streaming upload with server-side SHA-256 + quotas,
permissioned downloads, admin logical delete with active-task 409); the
route layer stays thin — session/verification logic lives in
``app.application.files``.

Permission notes (M2T5 decisions): upload/download permission depends on the
file TYPE (inputs firmware/virtual_media -> file.manage.input; outputs ->
file.download.output), which is only known after the row loads, so the route
gates on the auth context and the application service enforces the matrix
(like the risk-dependent operation.execute checks). Viewers can list/get
metadata only (file.metadata.read) and never download.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Iterator
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_db,
    get_file_keyring,
    get_file_storage,
    require_permission,
)
from app.application import files as file_service
from app.application.files import FileAuditContext
from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.errors import AppError
from app.domain.roles import FILE_DELETE, FILE_METADATA_READ
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import FileKeyCipher
from app.infrastructure.files import (
    FileCorruptionError,
    FileStorage,
    FileStorageError,
    StoredFile,
)
from app.infrastructure.sessions import client_summary
from app.models.files import File

router = APIRouter(prefix="/files", tags=["files"])

MAX_PAGE_SIZE = 100

# Route buffer: accumulate the request stream and flush one storage/DB
# round-trip per ~1 MiB (bounded per-chunk cost for multi-GiB uploads).
PUT_FLUSH_BYTES = 1024 * 1024

_STATUS_PATTERN = r"^(uploading|ready|quarantined|deleted)$"
_TYPE_PATTERN = r"^(firmware|virtual_media|support_bundle|config_backup|operation_log)$"


class FileUploadCreateRequest(BaseModel):
    # Type/size/name semantics are validated by the application service (422
    # validation_failed with Chinese reasons); pydantic only enforces shape.
    file_type: str = Field(max_length=32)
    size_bytes: int = Field(ge=0, le=100 * 1024**4)
    original_filename: str = Field(max_length=255)


class FileUploadContentView(BaseModel):
    received_bytes: int


class UploaderView(BaseModel):
    id: uuid.UUID
    username: str


class FileLinkView(BaseModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    task_id: uuid.UUID | None
    purpose: str
    created_at: datetime.datetime


class FileView(BaseModel):
    """Metadata view (never content): hash/size/type/status + links."""

    id: uuid.UUID
    file_type: str
    original_filename: str
    size_bytes: int
    mime_type: str | None
    sha256: str | None
    storage_backend: str
    encrypted: bool
    key_version: int | None
    status: str
    metadata: dict[str, object]
    uploaded_by: UploaderView
    links: list[FileLinkView] = Field(default_factory=list)
    created_at: datetime.datetime
    updated_at: datetime.datetime
    version: int


class FileListResponse(BaseModel):
    items: list[FileView]
    page: int
    page_size: int
    total: int


def _username_for(db: Session, user_id: uuid.UUID) -> str:
    from sqlalchemy import select

    from app.models.auth import User

    name = db.scalar(select(User.username).where(User.id == user_id))
    return name or "unknown"


def _file_view(db: Session, row: File, *, username: str) -> FileView:
    links = file_service.file_links(db, row.id)
    return FileView(
        id=row.id,
        file_type=row.file_type,
        original_filename=row.original_filename,
        size_bytes=row.size_bytes,
        mime_type=row.mime_type,
        sha256=row.sha256,
        storage_backend=row.storage_backend,
        encrypted=row.encrypted,
        key_version=row.key_version,
        status=row.status,
        metadata=dict(row.metadata_json),
        uploaded_by=UploaderView(id=row.uploaded_by, username=username),
        links=[
            FileLinkView(
                id=link.id,
                device_id=link.device_id,
                task_id=link.task_id,
                purpose=link.purpose,
                created_at=link.created_at,
            )
            for link in links
        ],
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.version,
    )


def _audit_context(request: Request, context: AuthContext) -> FileAuditContext:
    source_ip = request.client.host if request.client else None
    return FileAuditContext(
        actor_user_id=context.user.id,
        session_id=context.session.id,
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        request_id=str(request.scope.get("request_id") or ""),
    )


def _request_logger(request: Request) -> AuditLogger | None:
    return getattr(request.app.state, "audit_logger", None)


def _settings(request: Request) -> WardenSettings:
    settings: WardenSettings = request.app.state.settings
    return settings


@router.post(
    "/uploads",
    operation_id="file_uploads_create",
    response_model=FileView,
    status_code=201,
    responses={
        "403": {"description": "permission_denied"},
        "422": {"description": "validation_failed（类型/大小/名称/配额）"},
        "429": {"description": "rate_limited（每用户最多 2 个并发上传）"},
        "503": {"description": "storage_unavailable"},
    },
)
def file_uploads_create(
    body: FileUploadCreateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FileView:
    row = file_service.create_upload(
        db,
        user=context.user,
        file_type=body.file_type,
        size_bytes=body.size_bytes,
        original_filename=body.original_filename,
        settings=_settings(request),
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    db.commit()
    db.refresh(row)
    return _file_view(db, row, username=context.user.username)


def _process_chunk(
    session_factory: sessionmaker[Session],
    storage: FileStorage,
    *,
    upload_id: str,
    user_id: uuid.UUID,
    chunk: bytes,
    logger: object,
    audit: FileAuditContext,
) -> int:
    """One streamed chunk: check ownership/status, append under the quota.

    Runs on a worker thread with its own DB session (thread affinity); the
    audit context travels per chunk but only failures write rows. A
    validation abort (oversize stream) marks the session row deleted INSIDE
    the service: that state must be committed before the error propagates
    (otherwise the session teardown would roll it back).
    """
    with session_factory() as db:
        try:
            total = file_service.stream_upload_chunk(
                db,
                upload_id=upload_id,
                user_id=user_id,
                chunk=chunk,
                storage=storage,
                logger=logger,  # type: ignore[arg-type]
                audit=audit,
            )
            db.commit()
            return total
        except AppError:
            db.commit()  # persist the abort state (row -> deleted)
            raise


@router.put(
    "/uploads/{id}/content",
    operation_id="file_uploads_put_content",
    response_model=FileUploadContentView,
    responses={
        "404": {"description": "resource_not_found（会话不存在/不属于当前用户/已完成）"},
        "422": {"description": "validation_failed（超过声明的文件大小，会话已中止）"},
        "503": {"description": "storage_unavailable"},
    },
)
async def file_uploads_put_content(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    storage: Annotated[FileStorage, Depends(get_file_storage)],
) -> FileUploadContentView:
    """Stream the raw body to the upload spool (quota enforced mid-stream).

    Async endpoint: the body is consumed chunk by chunk instead of buffered,
    so a declared-oversized or hostile body aborts on the first chunk past
    the declaration (SECURITY.md §9). Each flushed chunk runs its DB check +
    append on a worker thread with its own session.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise auth_errors.dependency_unavailable()
    audit = _audit_context(request, context)
    logger = _request_logger(request)
    buffer = bytearray()
    received = 0
    try:
        async for chunk in request.stream():
            buffer.extend(chunk)
            if len(buffer) < PUT_FLUSH_BYTES:
                continue
            received = await run_in_threadpool(
                _process_chunk,
                session_factory,
                storage,
                upload_id=id,
                user_id=context.user.id,
                chunk=bytes(buffer),
                logger=logger,
                audit=audit,
            )
            buffer.clear()
        if buffer:
            received = await run_in_threadpool(
                _process_chunk,
                session_factory,
                storage,
                upload_id=id,
                user_id=context.user.id,
                chunk=bytes(buffer),
                logger=logger,
                audit=audit,
            )
    except AppError:
        raise
    except Exception:
        structlog.get_logger().exception("file_upload_stream_failed", upload_id=id)
        raise auth_errors.internal() from None
    return FileUploadContentView(received_bytes=received)


@router.post(
    "/uploads/{id}/complete",
    operation_id="file_uploads_complete",
    response_model=FileView,
    responses={
        "404": {"description": "resource_not_found"},
        "422": {"description": "validation_failed（大小不一致/魔数不符）"},
        "503": {"description": "storage_unavailable / dependency_unavailable"},
    },
)
def file_uploads_complete(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[FileStorage, Depends(get_file_storage)],
    keyring: Annotated[FileKeyCipher, Depends(get_file_keyring)],
) -> FileView:
    row = file_service.complete_upload(
        db,
        upload_id=id,
        user=context.user,
        storage=storage,
        key_cipher=keyring,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    db.commit()
    db.refresh(row)
    return _file_view(db, row, username=context.user.username)


@router.get(
    "",
    operation_id="files_list",
    response_model=FileListResponse,
    responses={"403": {"description": "permission_denied"}},
)
def files_list(
    context: Annotated[AuthContext, Depends(require_permission(FILE_METADATA_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    file_type: str | None = Query(default=None, pattern=_TYPE_PATTERN),
    status: str | None = Query(default=None, pattern=_STATUS_PATTERN),
    uploader_id: str | None = Query(default=None, max_length=64),
) -> FileListResponse:
    del context
    rows, total = file_service.list_files(
        db,
        page=page,
        page_size=page_size,
        file_type=file_type,
        status=status,
        uploader_id=uploader_id,
    )
    items = [_file_view(db, row, username=name) for row, name in rows]
    return FileListResponse(items=items, page=page, page_size=page_size, total=total)


@router.get(
    "/{id}",
    operation_id="files_get",
    response_model=FileView,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def files_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(FILE_METADATA_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> FileView:
    del context
    row = file_service.get_file_row(db, id)
    return _file_view(db, row, username=_username_for(db, row.uploaded_by))


def _download_response(
    *,
    row: File,
    stored: StoredFile,
    byte_range: file_service.ByteRange | None,
    storage: FileStorage,
    key_cipher: FileKeyCipher | None,
) -> Response:
    """Build the streaming response (attachment + nosniff, SECURITY.md §9).

    The volume copy was already probed before this call (prepare_*); the
    generator maps a mid-stream integrity/storage failure to a log line and a
    clean connection end — headers are already sent at that point, so the
    log carries the failure classification (no user content anywhere).
    """
    headers = {
        "Content-Type": row.mime_type or "application/octet-stream",
        "Content-Disposition": file_service.attachment_header(row.original_filename),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Accept-Ranges": "bytes",
    }
    status_code = 200
    if byte_range is not None:
        headers["Content-Range"] = f"bytes {byte_range.start}-{byte_range.end}/{row.size_bytes}"
        headers["Content-Length"] = str(byte_range.length)
        status_code = 206
    else:
        headers["Content-Length"] = str(row.size_bytes)

    log = structlog.get_logger()
    download_obj = file_service.FileDownload(file=row, stored=stored)
    file_id = str(row.id)

    def _iterator() -> Iterator[bytes]:
        try:
            yield from file_service.stream_chunks(
                storage, download_obj, byte_range=byte_range, key_cipher=key_cipher
            )
        except FileCorruptionError:
            log.error("file_stream_corruption", file_id=file_id)
        except FileStorageError:
            log.error("file_stream_storage_failed", file_id=file_id)

    return StreamingResponse(
        _iterator(),
        status_code=status_code,
        headers=headers,
        media_type=None,
    )


@router.get(
    "/{id}/download",
    operation_id="files_download",
    responses={
        "200": {"description": "ready 文件流式下载"},
        "403": {"description": "permission_denied（观察员不可下载）"},
        "404": {"description": "resource_not_found"},
        "422": {"description": "validation_failed（文件未就绪）"},
        "503": {"description": "storage_unavailable / dependency_unavailable"},
    },
)
def files_download(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[FileStorage, Depends(get_file_storage)],
    keyring: Annotated[FileKeyCipher, Depends(get_file_keyring)],
) -> Response:
    download = file_service.prepare_download(
        db,
        file_id=id,
        user=context.user,
        storage=storage,
        key_cipher=keyring,
    )
    logger = _request_logger(request)
    if logger is not None:
        logger.record(
            action="file.download",
            actor_user_id=context.user.id,
            session_id=context.session.id,
            resource_type="file",
            resource_id=str(download.file.id),
            requirement_id=file_service.PLT_06,
            request_id=str(request.scope.get("request_id") or ""),
            result="success",
            source_ip=request.client.host if request.client else None,
            user_agent_summary=client_summary(
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
            ),
            detail={
                "file_type": download.file.file_type,
                "size_bytes": download.file.size_bytes,
                "encrypted": download.file.encrypted,
            },
        )
    return _download_response(
        row=download.file,
        stored=download.stored,
        byte_range=None,
        storage=storage,
        key_cipher=keyring,
    )


@router.delete(
    "/{id}",
    operation_id="files_delete",
    response_model=FileView,
    responses={
        "403": {"description": "permission_denied（仅管理员）"},
        "404": {"description": "resource_not_found"},
        "409": {"description": "device_busy（被运行中任务引用）"},
    },
)
def files_delete(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(FILE_DELETE))],
    db: Annotated[Session, Depends(get_db)],
) -> FileView:
    row = file_service.delete_file(
        db,
        file_id=id,
        logger=_request_logger(request),
        audit=_audit_context(request, context),
    )
    db.commit()
    db.refresh(row)
    return _file_view(db, row, username=context.user.username)
