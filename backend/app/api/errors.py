"""Unified error envelope and exception-to-envelope handlers.

Allowed codes, HTTP statuses and safe detail fields come only from
``contracts/error-codes.json`` (via the generated registry). Unknown
exceptions become ``internal_error`` with a generic message, no details and
the request_id linking the response to the server-side log.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.domain.errors import CATALOG, AppError
from app.infrastructure.request_id import get_current_request_id

INTERNAL_ERROR_MESSAGE = "服务器内部错误"
INVALID_REQUEST_MESSAGE = "请求参数不合法"


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, object]
    request_id: str


class ErrorEnvelope(BaseModel):
    error: ErrorBody


def _error_response(
    status_code: int, envelope: ErrorEnvelope, *, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=envelope.model_dump(mode="json"), headers=headers)


def _current_request_id(request: Request) -> str:
    return str(request.scope.get("request_id") or get_current_request_id())


def _internal_error(request: Request) -> tuple[ErrorEnvelope, str]:
    request_id = _current_request_id(request)
    return (
        ErrorEnvelope(
            error=ErrorBody(
                code="internal_error",
                message=INTERNAL_ERROR_MESSAGE,
                details={},
                request_id=request_id,
            )
        ),
        request_id,
    )


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    request_id = _current_request_id(request)
    if CATALOG.get(exc.code) is None:
        # Unregistered code: only the boundary may turn it into internal_error.
        envelope, _ = _internal_error(request)
        return _error_response(
            status_code=CATALOG.http_status_for("internal_error"),
            envelope=envelope,
        )
    return _error_response(
        status_code=CATALOG.http_status_for(exc.code),
        envelope=ErrorEnvelope(
            error=ErrorBody(
                code=exc.code,
                message=exc.message,
                details=CATALOG.filter_details(exc.code, exc.details),
                request_id=request_id,
            )
        ),
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    if errors:
        first = errors[0]
        field = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
        reason = str(first.get("msg", "invalid request"))
    else:
        field = ""
        reason = "invalid request"
    return _error_response(
        status_code=CATALOG.http_status_for("invalid_request"),
        envelope=ErrorEnvelope(
            error=ErrorBody(
                code="invalid_request",
                message=INVALID_REQUEST_MESSAGE,
                details={"field": field, "reason": reason},
                request_id=_current_request_id(request),
            )
        ),
    )


async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _current_request_id(request)
    structlog.get_logger().exception(
        "unhandled_exception",
        error_type=type(exc).__name__,
        path=request.url.path,
        request_id=request_id,
    )
    envelope, _ = _internal_error(request)
    # This handler runs on ServerErrorMiddleware, outside the request-id
    # middleware; the response must carry the header itself.
    return _error_response(
        status_code=CATALOG.http_status_for("internal_error"),
        envelope=envelope,
        headers={"x-request-id": request_id},
    )


def register_exception_handlers(app: FastAPI) -> None:
    # FastAPI's ExceptionHandler type narrows to `exc: Exception`; the concrete
    # exception classes are statically narrower, hence the targeted ignores.
    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, internal_error_handler)
