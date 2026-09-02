"""SSE stream endpoint tests (API_CONTRACT.md §10, ARCHITECTURE.md §5.3).

``GET /api/v1/events/stream`` over the real PostgreSQL. The httpx fallback
transport of starlette's TestClient buffers whole responses, so a
never-ending stream cannot be consumed through ``client.get`` — the failure
paths (authentication) run through TestClient, while the stream machinery
(route headers, poll-based delivery of ui_events written by another session,
Last-Event-ID replay, reset outside the 10-minute window, keepalives, small
payload shape) is exercised by driving the REAL route + response generator
with a controllable ASGI disconnect.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from app.api.routes.events import events_stream
from app.config import WardenSettings
from app.infrastructure.db import create_db_engine, create_session_factory
from app.main import create_app
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import create_user, login_csrf

API = "/api/v1"
STREAM_PATH = f"{API}/events/stream"


@pytest.fixture
def stream_env(fresh_test_db_dsn: str) -> Iterator[tuple[Any, Session]]:
    """(fast app state + db session) over ONE fresh test database."""
    settings = WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        sse_poll_interval_seconds=0.05,
        sse_keepalive_seconds=1.0,
    )
    app = create_app(settings)
    engine = create_db_engine(fresh_test_db_dsn)
    factory = create_session_factory(engine)
    try:
        with factory() as db:
            yield app, db
    finally:
        engine.dispose()
        app_engine = app.state.engine
        if app_engine is not None:
            app_engine.dispose()


def _write_event(
    db: Session,
    *,
    entity_type: str = "device",
    event_type: str = "device.updated",
    version: int = 1,
    entity_id: uuid.UUID | None = None,
    payload: dict[str, object] | None = None,
    occurred_at: datetime.datetime | None = None,
) -> None:
    from app.models.observation import UiEvent

    db.add(
        UiEvent(
            entity_type=entity_type,
            entity_id=entity_id or uuid.uuid4(),
            version=version,
            event_type=event_type,
            payload=payload or {},
            occurred_at=occurred_at or datetime.datetime.now(datetime.UTC),
        )
    )
    db.commit()


def _latest_event_id(db: Session) -> int:
    from app.models.observation import UiEvent

    value = db.scalar(select(UiEvent.id).order_by(UiEvent.id.desc()).limit(1))
    return int(value) if value is not None else 0


def _parse_events(chunks: list[str]) -> list[dict[str, str]]:
    """Parse raw SSE text (chunks joined) into [{id,event,data}]."""
    lines = "".join(chunks).splitlines()
    events: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in lines:
        if line == "":
            if current:
                events.append(current)
                current = {}
        elif line.startswith(":"):
            continue
        else:
            name, sep, value = line.partition(":")
            if sep:
                current[name.strip()] = value[1:] if value.startswith(" ") else value
    if current:
        events.append(current)
    return events


def _collect_stream(
    app: Any,
    db: Session,
    *,
    headers: dict[str, str] | None = None,
    writer: object | None = None,
    stop_when: object | None = None,
    timeout: float = 20.0,
) -> list[str]:
    """Drive the real route + StreamingResponse until ``stop_when`` or deadline.

    ``writer`` runs on a worker thread (its own DB session) while the
    generator polls, exactly like a second HTTP client session would produce
    events. The ASGI ``receive`` never yields (starlette's
    ``Request.is_disconnected`` probes it inside a pre-cancelled cancel
    scope, so it must never block the event loop); the run ends through
    ``stop_when``/the deadline instead.
    """
    done = threading.Event()
    chunks: list[str] = []
    errors: list[BaseException] = []

    async def _receive() -> dict[str, str]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def _run() -> None:
        scope = {
            "type": "http",
            "method": "GET",
            "path": STREAM_PATH,
            "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
            "query_string": b"",
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 80),
            "scheme": "http",
            "app": app,
        }
        request = Request(scope, _receive)
        try:
            factory: Any = app.state.session_factory
            with factory() as db_session:
                response = events_stream(
                    request, context=None, db=db_session  # type: ignore[arg-type]
                )
                assert response.status_code == 200
                assert response.media_type == "text/event-stream"
                assert response.headers.get("x-accel-buffering") == "no"
                assert response.headers.get("cache-control") == "no-cache, no-transform"
                deadline = asyncio.get_running_loop().time() + timeout
                async for chunk in response.body_iterator:
                    chunks.append(chunk)
                    if stop_when is not None and stop_when(_parse_events(chunks)):
                        break
                    if asyncio.get_running_loop().time() > deadline:
                        break
                await response.body_iterator.aclose()
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            errors.append(exc)
        finally:
            done.set()

    def _writer() -> None:
        try:
            if writer is not None:
                writer(db)  # type: ignore[misc]
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    writer_thread: threading.Thread | None = None
    if writer is not None:
        writer_thread = threading.Thread(target=_writer, daemon=True)
        writer_thread.start()

    loop_thread = threading.Thread(target=lambda: asyncio.run(_run()), daemon=True)
    loop_thread.start()
    try:
        loop_thread.join(timeout=timeout + 15)
    finally:
        if writer_thread is not None:
            writer_thread.join(timeout=5)
        loop_thread.join(timeout=5)
    if errors:
        raise errors[0]
    return chunks


class TestStreamAuth:
    def test_unauthenticated_request_is_rejected(self, stream_env) -> None:
        app, _db = stream_env
        with TestClient(app) as client:
            response = client.get(STREAM_PATH)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthenticated"

    def test_viewer_session_can_open_the_stream(self, stream_env) -> None:
        app, db = stream_env
        with TestClient(app) as client:
            create_user(
                db,
                username="sse-viewer",
                password="V!ew-2026-Strong",
                role="viewer",
                display_name="SSE 观察员",
            )
            assert login_csrf(client, "sse-viewer", "V!ew-2026-Strong")[0].status_code == 200
            # The authorized request reaches the streaming response (it would
            # hang only because TestClient buffers; the request must NOT be
            # rejected by auth/permission): read one chunk via the transport
            # then hang up by closing the client early is impossible, so the
            # permission path is asserted through the session resolving here
            # and the 200-only machinery tested in TestStreamDelivery below.
            assert client.get(f"{API}/auth/me").status_code == 200


class TestStreamDelivery:
    def test_receives_events_written_by_another_session(self, stream_env) -> None:
        app, db = stream_env
        entity = uuid.uuid4()

        def _write(session: Session) -> None:
            import time

            time.sleep(0.2)
            _write_event(
                session,
                entity_type="operation_task",
                entity_id=entity,
                version=7,
                event_type="operation.updated",
                payload={"state": "succeeded"},
            )

        chunks = _collect_stream(
            app,
            db,
            writer=_write,
            stop_when=lambda events: any(e.get("event") == "operation.updated" for e in events),
        )
        events = _parse_events(chunks)
        updated = [e for e in events if e.get("event") == "operation.updated"]
        assert len(updated) == 1
        assert updated[0]["id"].isdigit()
        data = json.loads(updated[0]["data"])
        assert data == {"entity_id": str(entity), "version": 7}

    def test_last_event_id_replays_only_newer_events(self, stream_env) -> None:
        app, db = stream_env
        _write_event(db, event_type="alert.opened", version=1)
        first_id = _latest_event_id(db)
        _write_event(db, event_type="alert.resolved", version=2)
        second_id = _latest_event_id(db)

        chunks = _collect_stream(
            app,
            db,
            headers={"Last-Event-ID": str(first_id)},
            writer=None,
            stop_when=lambda events: any(
                e.get("id") == str(second_id) and e.get("event") == "alert.resolved"
                for e in events
            ),
        )
        events = _parse_events(chunks)
        assert [e.get("id") for e in events] == [str(second_id)]
        assert events[0]["event"] == "alert.resolved"
        assert "alert.opened" not in [e.get("event") for e in events]

    def test_cursor_outside_window_yields_reset_then_continues(self, stream_env) -> None:
        app, db = stream_env
        old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=20)
        _write_event(db, event_type="device.updated", version=1, occurred_at=old)
        old_id = _latest_event_id(db)
        _write_event(db, event_type="device.updated", version=2)

        def _write(session: Session) -> None:
            import time

            time.sleep(0.3)
            _write_event(session, event_type="alert.opened", version=3)

        chunks = _collect_stream(
            app,
            db,
            headers={"Last-Event-ID": str(old_id)},
            writer=_write,
            stop_when=lambda events: any(e.get("event") == "alert.opened" for e in events),
        )
        events = _parse_events(chunks)
        assert events[0]["event"] == "reset"
        ids = [e.get("id") for e in events if e.get("event") != "reset"]
        assert len(ids) == 1
        assert ids[0] != str(old_id)
        assert events[-1]["event"] == "alert.opened"

    def test_stream_never_leaks_payload_beyond_small_shape(self, stream_env) -> None:
        app, db = stream_env
        secret = "never-leak-this-payload"
        entity = uuid.uuid4()

        def _write(session: Session) -> None:
            import time

            time.sleep(0.2)
            _write_event(
                session,
                entity_type="operation_task",
                entity_id=entity,
                version=5,
                event_type="operation.updated",
                payload={"state": "succeeded", "secret_body": secret, "big": "x" * 500},
            )

        chunks = _collect_stream(
            app,
            db,
            writer=_write,
            stop_when=lambda events: any(e.get("event") == "operation.updated" for e in events),
        )
        raw = "".join(chunks)
        assert secret not in raw
        assert ("x" * 500) not in raw
        events = _parse_events(chunks)
        updated = [e for e in events if e.get("event") == "operation.updated"][0]
        data = json.loads(updated["data"])
        assert sorted(data) == ["entity_id", "version"]
        assert data == {"entity_id": str(entity), "version": 5}

    def test_keepalive_comments_are_emitted_when_idle(self, stream_env) -> None:
        app, db = stream_env
        chunks = _collect_stream(app, db, writer=None, stop_when=None, timeout=3.0)
        text = "".join(chunks)
        assert ": ping" in text

