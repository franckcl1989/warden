"""SSE realtime stream over ``ui_events`` (API_CONTRACT.md §10).

Support PLT-09 (实时进度与终端 — SSE 部分): ``GET /api/v1/events/stream``
(operation_id ``events_stream``, contracts/http-api.json). ARCHITECTURE.md
§5.3: SSE only reads the short-lived ``ui_events`` rows (entity type, entity
id, version, event type) and never pushes big payloads; the client refetches
the REST resource on receipt.

Semantics (binding):

- Authentication goes through the session COOKIE (EventSource cannot set
  headers) — GET is safe, so no CSRF token is needed; the endpoint requires
  ``monitor.read`` (viewer allowed). The auth dependency's read transaction
  is committed immediately by the route so the request never holds an open
  database transaction for the stream's lifetime.
- Poll-based: every poll opens its own short-lived session and reads
  ``ui_events`` since the cursor. PostgreSQL LISTEN/NOTIFY may only ever be a
  lossy wakeup optimization (ADR-024) — correctness here never depends on it.
- ``Last-Event-ID`` (header ``last-event-id``) resumes after that id; a fresh
  connection starts at the current head (no historical replay — the frontend
  refetches REST state on page load). A cursor that fell out of the 10-minute
  window (or whose row was purged) yields ``event: reset`` once and the
  stream continues from the current head (API_CONTRACT.md §10:
  窗口外返回 event: reset，客户端重新拉取 REST 数据).
- Keepalive comments every ``sse_keepalive_seconds``; the stream response is
  ``text/event-stream`` with no-cache headers and ``X-Accel-Buffering: no``.
- The ``data:`` line carries ONLY the small shape ``{"entity_id","version"}``
  (API_CONTRACT.md §10 example); ``ui_events.payload`` is never transmitted.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import AuthContext, get_db, require_permission
from app.application.maintenance import UI_EVENT_RETENTION
from app.domain.roles import MONITOR_READ
from app.infrastructure.time import utcnow
from app.models.observation import UiEvent

router = APIRouter(tags=["realtime"])

# ui_events retention == the SSE replay window (DATA_MODEL.md §11: 默认保留
# 10 分钟; application/maintenance.py UI_EVENT_RETENTION).
STREAM_WINDOW = UI_EVENT_RETENTION

MAX_EVENTS_PER_POLL = 200
RESET_EVENT = "event: reset\ndata: {}\n\n"
KEEPALIVE_COMMENT = ": ping\n\n"

_log = structlog.get_logger()


def _session_factory(request: Request) -> sessionmaker[Session]:
    factory: sessionmaker[Session] | None = getattr(request.app.state, "session_factory", None)
    if factory is None:
        from app.domain.auth_errors import dependency_unavailable

        raise dependency_unavailable()
    return factory


def _format_event(row: UiEvent) -> str:
    """One SSE event: ``id:``/``event:``/``data:`` with the small payload."""
    data = {"entity_id": str(row.entity_id) if row.entity_id is not None else None, "version": row.version}
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f"id: {row.id}\nevent: {row.event_type}\ndata: {body}\n\n"


def _poll_once(
    factory: sessionmaker[Session],
    *,
    cursor: int,
) -> tuple[list[UiEvent], int, bool]:
    """One poll. Returns (rows, new_cursor, reset_needed).

    ``reset_needed`` signals that the client cursor fell out of the retained
    window: the stream emits ``event: reset`` once and continues from the
    current head (API_CONTRACT.md §10: 窗口外返回 event: reset，客户端重新拉取
    REST 数据).
    """
    cutoff = utcnow() - STREAM_WINDOW
    with factory() as session:
        if cursor > 0:
            anchor = session.get(UiEvent, cursor)
            if anchor is None or anchor.occurred_at < cutoff:
                head = session.scalar(select(UiEvent.id).order_by(UiEvent.id.desc()).limit(1))
                return [], head if head is not None else cursor, True
        rows = list(
            session.scalars(
                select(UiEvent)
                .where(UiEvent.id > cursor, UiEvent.occurred_at >= cutoff)
                .order_by(UiEvent.id)
                .limit(MAX_EVENTS_PER_POLL)
            ).all()
        )
    if not rows:
        return [], cursor, False
    return rows, rows[-1].id, False


async def _stream_events(
    request: Request,
    factory: sessionmaker[Session],
    *,
    initial_cursor: int,
    poll_interval: float,
    keepalive_seconds: float,
) -> AsyncIterator[str]:
    cursor = initial_cursor
    last_keepalive = time.monotonic()
    while True:
        if await request.is_disconnected():
            return
        try:
            rows, cursor, reset_needed = await asyncio.to_thread(
                _poll_once, factory, cursor=cursor
            )
        except Exception:
            _log.exception("sse_poll_failed", cursor=cursor)
            rows, reset_needed = [], False
        if reset_needed:
            yield RESET_EVENT
            last_keepalive = time.monotonic()
        if rows:
            for row in rows:
                yield _format_event(row)
            last_keepalive = time.monotonic()
        now = time.monotonic()
        if now - last_keepalive >= keepalive_seconds:
            yield KEEPALIVE_COMMENT
            last_keepalive = now
        await asyncio.sleep(poll_interval)


def _initial_cursor(request: Request, factory: sessionmaker[Session]) -> int:
    """Resume cursor from ``Last-Event-ID``; fresh clients start at the head.

    A fresh connection must NOT replay the retained window (the frontend loads
    REST state on page load); a reconnect replays only events the client has
    not seen yet.
    """
    raw = request.headers.get("last-event-id", "")
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    if raw:
        _log.warning("sse_invalid_last_event_id", value=raw[:64])
    with factory() as session:
        head = session.scalar(select(UiEvent.id).order_by(UiEvent.id.desc()).limit(1))
    return head if head is not None else 0


@router.get(
    "/events/stream",
    operation_id="events_stream",
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "403": {"description": "permission_denied / password_change_required"},
        "503": {"description": "dependency_unavailable"},
    },
)
def events_stream(
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> StreamingResponse:
    """Stream ui_events as server-sent events (PLT-09, monitor.read)."""
    del context
    factory = _session_factory(request)
    settings = request.app.state.settings
    # Commit the auth dependency's read transaction and release its
    # connection: the stream must not hold one open transaction for minutes.
    db.commit()
    cursor = _initial_cursor(request, factory)
    return StreamingResponse(
        _stream_events(
            request,
            factory,
            initial_cursor=cursor,
            poll_interval=settings.sse_poll_interval_seconds,
            keepalive_seconds=settings.sse_keepalive_seconds,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
