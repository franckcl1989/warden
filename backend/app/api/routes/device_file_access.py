"""Device pull endpoint: GET /device-file-access/{ticket} (PLT-06).

API_CONTRACT.md §8 / SECURITY.md §7 (设备拉取固件/虚拟介质使用专用票据，绑定
设备来源 IP、文件、用途和有效期；来源 IP 只取服务端直接 socket 对端地址，不信任
X-Forwarded-For；端点不能枚举文件、不能换取其他文件；票据 URL 不写普通访问日
志). operationId EXACTLY ``device_file_access_get``.

Design notes (M2T5):

- The route carries NO user session — devices pull with the ticket alone; it
  is mounted outside the password-change/router gates in main.py.
- ``request.client.host`` is the ONLY trusted source address (SECURITY.md
  §7). Behind Nginx the real peer normally arrives via ``X-Forwarded-For``,
  which is never trusted — the deployment must forward the device network
  connection instead (deployment note). The TestClient peer is ``testclient``
  — API tests seed tickets with that expected IP and document the
  limitation; real tickets are issued with the device's resolved management
  IP (``application/files.py::issue_device_file_ticket``).
- Every failure (unknown/expired/revoked/IP mismatch/unready file) maps to
  the same 404 so the endpoint never leaks which condition failed.
- Range: a single satisfiable ``bytes`` range -> 206 partial with
  Content-Range; unsatisfiable -> 416; malformed/multi-range/absent -> 200
  full body.
- No request-line logging exists in this codebase and the ticket id never
  reaches structured logs: serve events are audited (first serve per ticket +
  revocation only, administrators only). The ticket id appears solely in
  audit rows and the URL the operator was given — never in normal logs.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_file_storage
from app.application import files as file_service
from app.application.files import FileAuditContext
from app.infrastructure.files import (
    FileCorruptionError,
    FileStorage,
    FileStorageError,
)
from app.infrastructure.sessions import client_summary

router = APIRouter(tags=["device-file-access"])


@router.get(
    "/device-file-access/{ticket}",
    operation_id="device_file_access_get",
    responses={
        "200": {"description": "完整文件流 (200) 或 Range 部分内容 (206)"},
        "404": {"description": "resource_not_found（票据无效/过期/已撤销/来源 IP 不符）"},
        "416": {"description": "Range 不满足"},
        "503": {"description": "storage_unavailable"},
    },
)
def device_file_access_get(
    ticket: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    storage: Annotated[FileStorage, Depends(get_file_storage)],
) -> Response:
    """Serve the bound file to the bound device (direct peer IP exact match)."""
    source_ip = request.client.host if request.client else None
    audit = FileAuditContext(
        actor_user_id=None,
        session_id=None,
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        request_id=str(request.scope.get("request_id") or ""),
    )
    logger = getattr(request.app.state, "audit_logger", None)
    serve = file_service.prepare_ticket_stream(
        db,
        ticket_id=ticket,
        source_ip=source_ip,
        storage=storage,
        logger=logger,
        audit=audit,
    )
    byte_range = file_service.parse_range_header(
        request.headers.get("range"), serve.file.size_bytes
    )
    if byte_range is not None and byte_range.start >= serve.file.size_bytes:
        # RFC 7233 §4.4: a single unsatisfiable range gets a plain 416 (the
        # device-facing endpoint is binary, not the JSON error envelope).
        return Response(status_code=416)
    headers = {
        "Content-Type": serve.file.mime_type or "application/octet-stream",
        "Content-Disposition": file_service.attachment_header(serve.file.original_filename),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        "Accept-Ranges": "bytes",
    }
    status_code = 200
    if byte_range is not None:
        headers[
            "Content-Range"
        ] = f"bytes {byte_range.start}-{byte_range.end}/{serve.file.size_bytes}"
        headers["Content-Length"] = str(byte_range.length)
        status_code = 206
    else:
        headers["Content-Length"] = str(serve.file.size_bytes)

    log = structlog.get_logger()
    file_id = str(serve.file.id)

    def _iterator() -> Iterator[bytes]:
        try:
            yield from file_service.stream_chunks(
                storage, serve, byte_range=byte_range, key_cipher=None
            )
        except FileCorruptionError:
            log.error("device_pull_corruption", file_id=file_id)
        except FileStorageError:
            log.error("device_pull_storage_failed", file_id=file_id)

    return StreamingResponse(
        _iterator(), status_code=status_code, headers=headers, media_type=None
    )
