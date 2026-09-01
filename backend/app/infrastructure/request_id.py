"""Request-ID middleware.

Accepts an inbound ``X-Request-ID`` only when it matches the contract pattern
(``^[A-Za-z0-9-]{1,64}$``), otherwise generates a UUID. The id is stored in a
``contextvars.ContextVar`` (read via ``get_current_request_id``), echoed in
the response header, and bound into structlog context for the request.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar, Token

from starlette.types import ASGIApp, Message, Receive, Scope, Send
from structlog.contextvars import bind_contextvars, unbind_contextvars

INBOUND_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
REQUEST_ID_HEADER = b"x-request-id"

_request_id_var: ContextVar[str] = ContextVar("request_id", default="")


def get_current_request_id() -> str:
    """Return the request id bound for the current request ("" when none)."""
    return _request_id_var.get()


def _select_request_id(scope: Scope) -> str:
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == REQUEST_ID_HEADER:
            candidate = value.decode("ascii", errors="ignore")
            if INBOUND_REQUEST_ID_PATTERN.fullmatch(candidate) is not None:
                return candidate
            return uuid.uuid4().hex
    return uuid.uuid4().hex


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _select_request_id(scope)
        # FastAPI moves the generic Exception handler to ServerErrorMiddleware,
        # which runs outside this middleware; stamping the scope keeps the id
        # available to handlers even after the contextvar is reset.
        scope["request_id"] = request_id
        token: Token[str] = _request_id_var.set(request_id)
        bind_contextvars(request_id=request_id)

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((REQUEST_ID_HEADER, request_id.encode("ascii")))
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            _request_id_var.reset(token)
            unbind_contextvars("request_id")
