"""Browser terminal endpoints (M5T4, PLT-09 终端部分, API_CONTRACT.md §7/§11).

- ``WS /terminal/sessions/{ticket}`` — operation_id
  ``terminal_sessions_connect`` (contracts/http-api.json): handshake
  checks (Origin against the deployment origin, session cookie, forced
  password change) happen BEFORE the upgrade and are HTTP-level denials,
  then the endpoint ACCEPTS FIRST and only afterwards claims the one-time
  ticket (incl. device-version binding) and dials the device (asyncssh
  with the pinned host-key fingerprint for SSH; telnet after BOTH gates —
  SECURITY.md §6/ADR-007), bridging the raw byte stream with backpressure
  (ARCHITECTURE.md §5.4: WebSocket 建立后由 API 进程连接目标 SSH/Telnet; 会话
  最长 2 小时、空闲 15 分钟断开 — injectable via deployment settings).
  Terminal CONTENT is never logged or recorded (SECURITY.md §8/§12): only
  metadata enters logs and audit rows.
- ``POST /terminal/sessions/{id}/close`` — operation_id
  ``terminal_sessions_close``: closes one session by id (row + live WS).

Wire protocol (text frames are CONTROL ONLY; terminal bytes travel as
binary frames so they can never collide):

- server -> client: ``{"type":"ready","session_id":..,"protocol":..}`` once
  the session is open; ``{"type":"closed","reason":..}`` before a normal
  server-side close; ``{"type":"refused","code":..,"reason":..,
  "protocol":..}`` before a refusal close (ticket/gate/dial/platform
  failures — ``reason`` is the machine key and ``code`` mirrors it in the
  private-use 4000-4999 range); the client may send
  ``{"type":"resize","cols":n,"rows":n}`` (PTY window change).
- Delivery model (empirically pinned on uvicorn): a WebSocket close BEFORE
  ``accept()`` is an HTTP 403 handshake denial — the close code never
  reaches the client (the browser sees error + close 1006). The endpoint
  therefore keeps ONLY the HTTP-level auth conditions pre-accept (Origin,
  session cookie, forced password change — 4401/4403, client-knowable), and
  accepts first so every server-side refusal is a real post-accept close:
  one machine ``refused`` JSON frame followed by the code (4404 ticket
  unavailable — unknown/expired/used/foreign/device-version drift, uniform
  like the M3T4 uniform-404; 4429 concurrency cap; 4101 device handshake
  failed — the audit carries the stable error code, the payload never
  appears anywhere; 4500 unexpected platform failure). A refusal never
  consumes the ticket (a claim refusal rolls back; a dial refusal closes
  the row with ``handshake_failed`` + audit and the consumed ticket cannot
  replay — SECURITY.md §8 semantics unchanged).
- Refusal reason vocabulary (``application/terminal_sessions.py``):
  ticket_unavailable / capacity_user / capacity_device /
  password_change_required / handshake_failed / internal_error.

Close-reason vocabulary (row + closed frame + audit): user_closed /
idle_timeout / max_duration / handshake_failed / device_connection_lost /
client_disconnected / internal_error (models/terminal.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import time
import uuid
from dataclasses import dataclass
from threading import Lock
from typing import Annotated, Any, cast

import structlog
from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import AuthContext, get_auth_context
from app.application import terminal_sessions as terminal_service
from app.application.collection import build_device_session
from app.application.terminal_sessions import (
    CAPACITY_DEVICE,
    CAPACITY_USER,
    REFUSAL_PASSWORD_CHANGE,
    WS_CLOSE_CAPACITY,
    WS_CLOSE_FORBIDDEN,
    WS_CLOSE_HANDSHAKE_FAILED,
    WS_CLOSE_INTERNAL_ERROR,
    WS_CLOSE_TICKET_UNAVAILABLE,
    WS_CLOSE_UNAUTHENTICATED,
    ClaimOutcome,
    ssh_target_from,
    telnet_target_from,
)
from app.config import WardenSettings
from app.domain.adapter import DeviceSession
from app.domain.auth_errors import dependency_unavailable, resource_not_found
from app.domain.errors import AppError
from app.infrastructure.audit import AuditLogger
from app.infrastructure.csrf import is_origin_allowed, normalize_origin
from app.infrastructure.protocols.terminal.errors import TerminalTransportError
from app.infrastructure.protocols.terminal.ssh import InteractiveSsh, open_interactive_ssh
from app.infrastructure.protocols.terminal.telnet import TelnetConnection, open_telnet
from app.infrastructure.request_id import get_current_request_id
from app.infrastructure.session_tokens import SESSION_COOKIE_NAME, hash_session_token
from app.infrastructure.sessions import client_summary, session_is_valid
from app.infrastructure.time import utcnow
from app.models.auth import Session as WebSession
from app.models.auth import User
from app.models.devices import Device
from app.models.launch import LaunchSession
from app.models.terminal import TerminalSession

router = APIRouter(tags=["terminal"])

_log = structlog.get_logger()

#: Backpressure: max device chunks buffered for the WebSocket sender; the
#: device pump stalls on a full queue (asyncssh's SSH window then throttles
#: the device — the WS consumer's pace governs the read side).
_OUTBOUND_QUEUE_MAX = 64
#: DB last-activity refresh throttle while a session is active (the idle
#: timers run on in-memory monotonic clocks; the row only feeds the
#: retention sweep after a crash).
_ACTIVITY_DB_REFRESH_SECONDS = 20.0

PLT_09 = "PLT-09"


def _settings_of(websocket: WebSocket) -> WardenSettings:
    return cast(WardenSettings, websocket.app.state.settings)


def _factory_of(app: Any) -> sessionmaker[Session]:
    factory: sessionmaker[Session] | None = getattr(app.state, "session_factory", None)
    if factory is None:
        raise dependency_unavailable()
    return factory


def _origin_allowed(websocket: WebSocket) -> bool:
    settings = _settings_of(websocket)
    allowed = normalize_origin(settings.public_url)
    return is_origin_allowed(
        origin=websocket.headers.get("origin"),
        referer=websocket.headers.get("referer"),
        allowed_origins={allowed} if allowed is not None else set(),
    )


# ---------------------------------------------------------------------------
# WS cookie authentication (same chain as get_auth_context minus CSRF: the
# terminal handshake verifies Origin instead — SECURITY.md §2/§10).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AuthResolution:
    user: User
    web_session: WebSession


def _resolve_auth(
    factory: sessionmaker[Session],
    cookies: dict[str, str],
    settings: WardenSettings,
) -> _AuthResolution | None:
    token = cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    with factory() as db:
        web_session = db.scalar(
            select(WebSession).where(WebSession.session_id_hash == hash_session_token(token))
        )
        if web_session is None:
            return None
        now = utcnow()
        if not session_is_valid(web_session, now, settings.session_idle_minutes):
            web_session.revoked_at = now
            db.commit()
            return None
        user = db.get(User, web_session.user_id)
        if user is None or user.status == "disabled":
            return None
        if now - web_session.last_activity_at > datetime.timedelta(minutes=1):
            web_session.last_activity_at = now
            db.commit()
        return _AuthResolution(user=user, web_session=web_session)


def _claim(
    factory: sessionmaker[Session],
    *,
    ticket: str,
    user: User,
    settings: WardenSettings,
) -> ClaimOutcome:
    """Claim the ticket + open the session row in one committed transaction."""
    with factory() as db:
        outcome = terminal_service.claim_terminal_session(
            db, ticket=ticket, user=user, settings=settings
        )
        if outcome.ok:
            db.commit()
        else:
            db.rollback()
        return outcome


def _refusal_close_code(refusal: str) -> int:
    if refusal in (CAPACITY_USER, CAPACITY_DEVICE):
        return WS_CLOSE_CAPACITY
    if refusal == REFUSAL_PASSWORD_CHANGE:
        return WS_CLOSE_FORBIDDEN
    return WS_CLOSE_TICKET_UNAVAILABLE


# ---------------------------------------------------------------------------
# audit helpers (metadata only — content NEVER enters audit/log rows)
# ---------------------------------------------------------------------------


def _audit_record(
    app: Any,
    *,
    action: str,
    result: str,
    actor_user_id: uuid.UUID,
    session_id: uuid.UUID,
    terminal_row: TerminalSession,
    source_ip: str | None,
    user_agent_summary: str | None,
    request_id: str,
    detail: dict[str, object],
) -> None:
    logger: AuditLogger | None = getattr(app.state, "audit_logger", None)
    if logger is None:
        return
    logger.record(
        action=action,
        actor_user_id=actor_user_id,
        session_id=session_id,
        resource_type="terminal_session",
        resource_id=str(terminal_row.id),
        device_id=terminal_row.device_id,
        requirement_id=terminal_row.requirement_id,
        request_id=request_id,
        result=result,
        source_ip=source_ip,
        user_agent_summary=user_agent_summary,
        detail=detail,
    )


def _ws_audit_meta(
    websocket: WebSocket, auth: _AuthResolution
) -> tuple[str | None, str | None, str]:
    source_ip = websocket.client.host if websocket.client else None
    return (
        source_ip,
        client_summary(source_ip, websocket.headers.get("user-agent")),
        str(websocket.scope.get("request_id") or get_current_request_id()),
    )


def _device_session_sync(app: Any, *, device_id: uuid.UUID) -> DeviceSession | None:
    """Decrypted device session for the dial (credentials never leave the
    call boundary; SECURITY.md §5). None = keyring unavailable."""
    keyring = getattr(app.state, "credential_keyring", None)
    if keyring is None:
        return None
    factory = _factory_of(app)
    with factory() as db:
        device = db.get(Device, device_id)
        if device is None:
            return None
        return build_device_session(db, device=device, keyring=keyring)


# ---------------------------------------------------------------------------
# in-process session registry (POST close -> live WS)
# ---------------------------------------------------------------------------


class TerminalRegistry:
    """In-process map of live terminal sessions (single-replica API).

    ``request_close`` wakes the bridge of one session; a registry miss means
    the session ended already or lives in another process — the POST close
    still closes the row and audits (the database is authoritative).
    """

    def __init__(self) -> None:
        self._bridges: dict[uuid.UUID, _TerminalBridge] = {}
        self._lock = Lock()

    def register(self, session_id: uuid.UUID, bridge: _TerminalBridge) -> None:
        with self._lock:
            self._bridges[session_id] = bridge

    def unregister(self, session_id: uuid.UUID) -> None:
        with self._lock:
            self._bridges.pop(session_id, None)

    def request_close(self, session_id: uuid.UUID, *, reason: str) -> bool:
        with self._lock:
            bridge = self._bridges.get(session_id)
        if bridge is None:
            return False
        bridge.request_close(reason)
        return True


def _registry_of(websocket: WebSocket) -> TerminalRegistry:
    registry: TerminalRegistry | None = getattr(websocket.app.state, "terminal_registry", None)
    if registry is None:
        registry = TerminalRegistry()
        websocket.app.state.terminal_registry = registry
    return registry


# ---------------------------------------------------------------------------
# bridge (live session)
# ---------------------------------------------------------------------------


class _Endpoint:
    """Structural async byte-stream endpoint (SSH channel / telnet stream)."""

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def read_chunk(self) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    def resize(self, cols: int, rows: int) -> None:
        raise NotImplementedError


class _TelnetEndpoint(_Endpoint):
    def __init__(self, connection: TelnetConnection) -> None:
        self._connection = connection

    async def write(self, data: bytes) -> None:
        await self._connection.write(data)

    async def read_chunk(self) -> bytes:
        return await self._connection.read_raw_chunk()

    async def close(self) -> None:
        await self._connection.close()

    def resize(self, cols: int, rows: int) -> None:
        del cols, rows  # telnet has no window-change signal in 0.1.0


class _SshEndpoint(_Endpoint):
    def __init__(self, session: InteractiveSsh) -> None:
        self._session = session

    async def write(self, data: bytes) -> None:
        await self._session.write(data)

    async def read_chunk(self) -> bytes:
        return await self._session.read_chunk()

    async def close(self) -> None:
        await self._session.close()

    def resize(self, cols: int, rows: int) -> None:
        self._session.resize(cols, rows)


@dataclass
class _BridgeContext:
    """Everything one bridge needs (audit/registry/settings metadata)."""

    websocket: WebSocket
    factory: sessionmaker[Session]
    settings: WardenSettings
    registry: TerminalRegistry
    auth: _AuthResolution
    terminal_row: TerminalSession
    launch_row: LaunchSession
    opened_monotonic: float


class _TerminalBridge:
    """Bidirectional device<->WebSocket pump with bounds and backpressure.

    Ownership: exactly one task runs ``run``; on exit the endpoint, the
    session row and the audit trail are finalized ONCE (conditional row
    close — races with POST /close and the maintenance sweep cannot double
    close or double audit).
    """

    _REASONS_BY_WAITER = frozenset({"idle_timeout", "max_duration", "user_closed"})

    def __init__(self, context: _BridgeContext, endpoint: _Endpoint) -> None:
        self._ctx = context
        self._endpoint = endpoint
        self._close_requested = asyncio.Event()
        self._requested_reason: str | None = None
        self._request_lock = Lock()
        self._activity_event = asyncio.Event()
        self._last_activity = context.opened_monotonic
        self._last_db_activity = 0.0

    def request_close(self, reason: str) -> None:
        with self._request_lock:
            if self._requested_reason is None:
                self._requested_reason = reason
                self._close_requested.set()

    def _touch(self) -> None:
        self._last_activity = time.monotonic()
        self._activity_event.set()

    # -- pumps ---------------------------------------------------------------

    async def _device_to_queue(self, outbound: asyncio.Queue[bytes | None]) -> str | None:
        """Device stdout -> outbound queue. A full queue stalls the read —
        the device-side flow control (SSH window / TCP) then throttles it
        (backpressure: the WebSocket consumer's pace governs the reads)."""
        while True:
            chunk = await self._endpoint.read_chunk()
            if not chunk:
                return "device_connection_lost"  # device closed the session
            await outbound.put(chunk)
            self._touch()
        return None

    async def _sender(self, outbound: asyncio.Queue[bytes | None]) -> None:
        """Queue -> WebSocket binary frames; a dead client ends the bridge."""
        while True:
            chunk = await outbound.get()
            if chunk is None:
                return
            await self._ctx.websocket.send_bytes(chunk)

    async def _receiver(self) -> str | None:
        """WebSocket -> device stdin (binary) + control frames (text)."""
        while True:
            message = await self._ctx.websocket.receive()
            if message.get("type") == "websocket.disconnect":
                raise WebSocketDisconnect(code=int(message.get("code") or 1000))
            if message.get("type") != "websocket.receive":
                continue
            if "bytes" in message and isinstance(message.get("bytes"), bytes):
                await self._endpoint.write(message["bytes"])
                self._touch()
            elif "text" in message and isinstance(message.get("text"), str):
                await self._handle_control(message["text"])
        return None

    async def _handle_control(self, text: str) -> None:
        try:
            control = json.loads(text)
        except (ValueError, TypeError):
            return  # ignore malformed control frames (never log content)
        if not isinstance(control, dict):
            return
        if control.get("type") == "resize":
            cols = control.get("cols")
            rows = control.get("rows")
            if isinstance(cols, int) and isinstance(rows, int) and cols > 0 and rows > 0:
                self._endpoint.resize(cols, rows)
                self._touch()

    async def _idle_waiter(self) -> str | None:
        """Idle bound (default 15 min): no traffic in either direction."""
        idle_seconds = float(self._ctx.settings.terminal_session_idle_seconds)
        while True:
            remaining = self._last_activity + idle_seconds - time.monotonic()
            if remaining <= 0:
                return "idle_timeout"
            self._activity_event.clear()
            try:
                await asyncio.wait_for(self._activity_event.wait(), timeout=remaining)
            except TimeoutError:
                continue  # re-check the bound (an event may fire in between)

    async def _max_waiter(self) -> str | None:
        """Total-session bound (default 2 h)."""
        max_seconds = float(self._ctx.settings.terminal_session_max_seconds)
        remaining = self._ctx.opened_monotonic + max_seconds - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)
        return "max_duration"

    async def _close_waiter(self) -> str | None:
        """POST /terminal/sessions/{id}/close signal."""
        await self._close_requested.wait()
        with self._request_lock:
            return self._requested_reason or "user_closed"

    async def _activity_persister(self) -> None:
        """Throttled row refresh so the crash-recovery sweep's idle math is
        sane; stops when the bridge ends (canceled with the other tasks)."""
        while True:
            await asyncio.sleep(_ACTIVITY_DB_REFRESH_SECONDS)
            if time.monotonic() - self._last_db_activity < _ACTIVITY_DB_REFRESH_SECONDS:
                continue
            self._last_db_activity = time.monotonic()
            opened_row = self._ctx.terminal_row.opened_at
            at = opened_row + datetime.timedelta(
                seconds=self._last_activity - self._ctx.opened_monotonic
            )
            try:
                await asyncio.to_thread(self._persist_activity, self._ctx.terminal_row.id, at)
            except Exception:  # noqa: BLE001 - best effort; never kill the session
                _log.warning(
                    "terminal_activity_persist_failed",
                    session_id=str(self._ctx.terminal_row.id),
                )

    def _persist_activity(self, session_id: uuid.UUID, at: datetime.datetime) -> None:
        with self._ctx.factory() as db:
            terminal_service.touch_terminal_session(db, session_id=session_id, at=at)
            db.commit()

    # -- lifecycle -----------------------------------------------------------

    async def run(self) -> None:
        """Pump until an end condition; then finalize row + audit + close.

        ``reason`` is initialized BEFORE the ready send: any unexpected
        failure below (including a client disconnect while sending ready)
        still finalizes the row instead of leaking it to the retention
        sweep.
        """
        self._ctx.registry.register(self._ctx.terminal_row.id, self)
        outbound: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_OUTBOUND_QUEUE_MAX)
        reason = "internal_error"
        try:
            try:
                await self._ctx.websocket.send_text(
                    json.dumps(
                        {
                            "type": "ready",
                            "session_id": str(self._ctx.terminal_row.id),
                            "protocol": self._ctx.terminal_row.protocol,
                        }
                    )
                )
            except WebSocketDisconnect:
                reason = "client_disconnected"
                return
            pumps: dict[asyncio.Task[str | None], str] = {
                asyncio.create_task(self._device_to_queue(outbound)): "device",
                asyncio.create_task(self._sender(outbound)): "sender",
                asyncio.create_task(self._receiver()): "receiver",
                asyncio.create_task(self._idle_waiter()): "idle",
                asyncio.create_task(self._max_waiter()): "max",
                asyncio.create_task(self._close_waiter()): "close",
                asyncio.create_task(self._activity_persister()): "activity",
            }
            try:
                done, pending = await asyncio.wait(
                    pumps, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    pump_name = pumps.get(task, "?")
                    try:
                        result = task.result()
                    except WebSocketDisconnect:
                        reason = "client_disconnected"
                        break
                    except Exception:  # noqa: BLE001 - one faulty pump closes the session
                        _log.warning(
                            "terminal_bridge_pump_failed",
                            session_id=str(self._ctx.terminal_row.id),
                            pump=pump_name,
                        )
                        reason = "internal_error"
                        break
                    if result in self._REASONS_BY_WAITER:
                        reason = result
                        break
                    if result is not None and pump_name == "device":
                        reason = result
                        break
                else:
                    reason = "internal_error"
            finally:
                for task in pending:
                    task.cancel()
                with contextlib.suppress(BaseException):
                    await asyncio.gather(*pending)
        finally:
            await self._finalize(reason)

    async def _finalize(self, reason: str) -> None:
        self._ctx.registry.unregister(self._ctx.terminal_row.id)
        with contextlib.suppress(Exception):  # noqa: BLE001 - teardown must not raise
            await asyncio.wait_for(self._endpoint.close(), timeout=5.0)
        duration_seconds = int(max(0.0, time.monotonic() - self._ctx.opened_monotonic))
        outcome = await asyncio.to_thread(self._close_row, reason)
        if outcome.closed_now:
            source_ip, agent, request_id = _ws_audit_meta(self._ctx.websocket, self._ctx.auth)
            await asyncio.to_thread(
                _audit_record,
                self._ctx.websocket.app,
                action="terminal.closed",
                result="success",
                actor_user_id=self._ctx.auth.user.id,
                session_id=self._ctx.auth.web_session.id,
                terminal_row=self._ctx.terminal_row,
                source_ip=source_ip,
                user_agent_summary=agent,
                request_id=request_id,
                detail={
                    "reason": reason,
                    "protocol": self._ctx.terminal_row.protocol,
                    "capability_key": self._ctx.terminal_row.capability_key,
                    "duration_seconds": duration_seconds,
                },
            )
        if reason != "client_disconnected":
            with contextlib.suppress(Exception):  # noqa: BLE001 - client may be gone
                await self._ctx.websocket.send_text(json.dumps({"type": "closed", "reason": reason}))
                await self._ctx.websocket.close(code=1000)
        _log.info(
            "terminal_session_closed",
            session_id=str(self._ctx.terminal_row.id),
            device_id=str(self._ctx.terminal_row.device_id),
            protocol=self._ctx.terminal_row.protocol,
            reason=reason,
            duration_seconds=duration_seconds,
        )

    def _close_row(self, reason: str) -> terminal_service.CloseOutcome:
        with self._ctx.factory() as db:
            outcome = terminal_service.close_terminal_session(
                db,
                session_id=str(self._ctx.terminal_row.id),
                user_id=None,  # system close: ownership was proven at claim
                reason=reason,
            )
            if outcome.closed_now:
                db.commit()
            else:
                db.rollback()
            return outcome


# ---------------------------------------------------------------------------
# dialing
# ---------------------------------------------------------------------------


async def _dial(websocket: WebSocket, *, terminal_row: TerminalSession) -> _Endpoint | tuple[str, str]:
    """Dial the device from the API process (ARCHITECTURE.md §5.4).

    Returns the endpoint or ``(error_code, detail_code)`` for the
    handshake-failed close (the audit carries the stable codes — never the
    payload).
    """
    device_session = await asyncio.to_thread(
        _device_session_sync, websocket.app, device_id=terminal_row.device_id
    )
    if device_session is None:
        return "not_configured", "credential_unavailable"
    try:
        if terminal_row.protocol == "ssh":
            config = ssh_target_from(device_session)
            session = await open_interactive_ssh(config)
            return _SshEndpoint(session)
        target = telnet_target_from(device_session)
        connection = await open_telnet(target)
        return _TelnetEndpoint(connection)
    except AppError as exc:
        return exc.code, "configuration_error"
    except TerminalTransportError as exc:
        return exc.code, exc.detail or exc.code


# ---------------------------------------------------------------------------
# WS route
# ---------------------------------------------------------------------------


def _claim_protocol(outcome: ClaimOutcome) -> str | None:
    """Protocol of a claim outcome (None when the ticket is unknowable)."""
    if outcome.ok and outcome.terminal_session is not None:
        return outcome.terminal_session.protocol
    return None


async def _refuse(
    websocket: WebSocket,
    *,
    code: int,
    reason: str,
    protocol: str | None,
) -> None:
    """One post-accept refusal: a machine JSON frame, then the close code.

    Both are ONLY deliverable after the 101 upgrade (a pre-accept close is
    an HTTP 403 handshake denial). The frame carries the reason KEY the
    browser maps to Chinese copy; the code (private-use 4000-4999) mirrors
    it and stays the fallback if a proxy ever drops the frame. Refusals
    never consume the ticket (claim refusals roll back; a dial refusal
    consumed the ticket but closed its row + audited handshake_failed — no
    replay possible either way).
    """
    with contextlib.suppress(Exception):  # noqa: BLE001 - client may be gone
        await websocket.send_text(
            json.dumps(
                {"type": "refused", "code": code, "reason": reason, "protocol": protocol}
            )
        )
        await websocket.close(code=code)


async def _fail_setup_internal(
    websocket: WebSocket,
    factory: sessionmaker[Session],
    terminal_row: TerminalSession,
    auth: _AuthResolution,
) -> None:
    """Unexpected exception after the claim committed (ticket consumed, row
    OPEN): close the row with internal_error + audit NOW instead of leaving
    it to the retention sweep, then refuse the client (post-accept code)."""
    _log.warning(
        "terminal_session_setup_failed",
        session_id=str(terminal_row.id),
        device_id=str(terminal_row.device_id),
        protocol=terminal_row.protocol,
    )
    outcome = await asyncio.to_thread(
        _close_row_internal_error, factory, terminal_row, utcnow()
    )
    if outcome.closed_now:
        source_ip, agent, request_id = _ws_audit_meta(websocket, auth)
        await asyncio.to_thread(
            _audit_record,
            websocket.app,
            action="terminal.closed",
            result="success",
            actor_user_id=auth.user.id,
            session_id=auth.web_session.id,
            terminal_row=terminal_row,
            source_ip=source_ip,
            user_agent_summary=agent,
            request_id=request_id,
            detail={
                "reason": "internal_error",
                "protocol": terminal_row.protocol,
                "capability_key": terminal_row.capability_key,
                "duration_seconds": 0,
            },
        )
    await _refuse(
        websocket,
        code=WS_CLOSE_INTERNAL_ERROR,
        reason="internal_error",
        protocol=terminal_row.protocol,
    )


@router.websocket("/terminal/sessions/{ticket}", name="terminal_sessions_connect")
async def terminal_sessions_connect(websocket: WebSocket, ticket: str) -> None:
    """SSH/Telnet browser terminal over one one-time ticket (PLT-09).

    Accept-first-then-validate: the HTTP-level auth conditions (Origin,
    session cookie, forced password change) close BEFORE the upgrade — a
    real ASGI server answers a pre-accept close with HTTP 403, which is
    fine for these client-knowable conditions. Every server-side refusal
    after the upgrade (ticket claim, device gates, dial, unexpected
    failures) is a deliverable post-accept close: one machine ``refused``
    frame then the private-use close code (see the module docstring).
    """
    settings = _settings_of(websocket)
    factory = _factory_of(websocket.app)
    if not _origin_allowed(websocket):
        await websocket.close(code=WS_CLOSE_FORBIDDEN)
        return
    auth = await asyncio.to_thread(_resolve_auth, factory, dict(websocket.cookies), settings)
    if auth is None:
        await websocket.close(code=WS_CLOSE_UNAUTHENTICATED)
        return
    if auth.user.must_change_password:
        await websocket.close(code=WS_CLOSE_FORBIDDEN)
        return

    # Accept FIRST: every refusal below must be deliverable to the client
    # (uvicorn delivers close codes only after the 101 upgrade).
    await websocket.accept()
    outcome = await asyncio.to_thread(
        _claim, factory, ticket=ticket, user=auth.user, settings=settings
    )
    if not outcome.ok:
        await _refuse(
            websocket,
            code=_refusal_close_code(outcome.refusal),
            reason=outcome.refusal,
            protocol=_claim_protocol(outcome),
        )
        return
    terminal_row = outcome.terminal_session
    launch_row = outcome.launch
    assert terminal_row is not None and launch_row is not None

    try:
        dialed = await _dial(websocket, terminal_row=terminal_row)
        if isinstance(dialed, tuple):
            error_code, detail = dialed
            await asyncio.to_thread(
                _close_row_handshake_failed, factory, terminal_row, utcnow()
            )
            source_ip, agent, request_id = _ws_audit_meta(websocket, auth)
            await asyncio.to_thread(
                _audit_record,
                websocket.app,
                action="terminal.handshake_failed",
                result="failure",
                actor_user_id=auth.user.id,
                session_id=auth.web_session.id,
                terminal_row=terminal_row,
                source_ip=source_ip,
                user_agent_summary=agent,
                request_id=request_id,
                detail={
                    "protocol": terminal_row.protocol,
                    "capability_key": terminal_row.capability_key,
                    "error_code": error_code,
                    "reason_code": detail,
                },
            )
            await _refuse(
                websocket,
                code=WS_CLOSE_HANDSHAKE_FAILED,
                reason="handshake_failed",
                protocol=terminal_row.protocol,
            )
            return

        source_ip, agent, request_id = _ws_audit_meta(websocket, auth)
        await asyncio.to_thread(
            _audit_record,
            websocket.app,
            action="terminal.handshake_ok",
            result="success",
            actor_user_id=auth.user.id,
            session_id=auth.web_session.id,
            terminal_row=terminal_row,
            source_ip=source_ip,
            user_agent_summary=agent,
            request_id=request_id,
            detail={
                "protocol": terminal_row.protocol,
                "capability_key": terminal_row.capability_key,
            },
        )
    except Exception:  # noqa: BLE001 - never leave an open row to the sweep
        await _fail_setup_internal(websocket, factory, terminal_row, auth)
        return
    bridge = _TerminalBridge(
        _BridgeContext(
            websocket=websocket,
            factory=factory,
            settings=settings,
            registry=_registry_of(websocket),
            auth=auth,
            terminal_row=terminal_row,
            launch_row=launch_row,
            opened_monotonic=time.monotonic(),
        ),
        dialed,
    )
    await bridge.run()


def _close_row_handshake_failed(
    factory: sessionmaker[Session],
    terminal_row: TerminalSession,
    now: datetime.datetime,
) -> None:
    with factory() as db:
        terminal_service.close_terminal_session(
            db,
            session_id=str(terminal_row.id),
            user_id=None,
            reason="handshake_failed",
            now=now,
        )
        db.commit()


def _close_row_internal_error(
    factory: sessionmaker[Session],
    terminal_row: TerminalSession,
    now: datetime.datetime,
) -> terminal_service.CloseOutcome:
    """Conditional internal_error close; ``closed_now`` decides the audit
    (idempotent — races with a concurrent close cannot double-audit)."""
    with factory() as db:
        outcome = terminal_service.close_terminal_session(
            db,
            session_id=str(terminal_row.id),
            user_id=None,
            reason="internal_error",
            now=now,
        )
        if outcome.closed_now:
            db.commit()
        else:
            db.rollback()
        return outcome


# ---------------------------------------------------------------------------
# close endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/terminal/sessions/{id}/close",
    operation_id="terminal_sessions_close",
    responses={
        "401": {"description": "unauthenticated/session_expired"},
        "403": {"description": "permission_denied / csrf_failed"},
        "404": {"description": "resource_not_found（未知或非本人的会话）"},
    },
)
async def terminal_sessions_close(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(get_auth_context)],
) -> dict[str, object]:
    """Close one terminal session (user-initiated; API_CONTRACT.md §7).

    Closes the row first (exactly one actor audits per session — the
    conditional close is idempotent), then wakes the live bridge so the
    WebSocket receives the closed frame. Foreign/unknown ids are a uniform
    404.
    """
    factory = _factory_of(request.app)
    outcome = await asyncio.to_thread(
        _close_http, factory, id, context.user.id
    )
    if outcome is None:
        raise resource_not_found("terminal_session")
    registry: TerminalRegistry | None = getattr(request.app.state, "terminal_registry", None)
    session_key = _parse_uuid(id)
    if session_key is not None and registry is not None:
        registry.request_close(session_key, reason="user_closed")
    if outcome["closed_now"]:
        row = cast(TerminalSession, outcome["row"])
        source_ip = request.client.host if request.client else None
        await asyncio.to_thread(
            _audit_record,
            request.app,
            action="terminal.closed",
            result="success",
            actor_user_id=context.user.id,
            session_id=context.session.id,
            terminal_row=row,
            source_ip=source_ip,
            user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
            request_id=str(request.scope.get("request_id") or ""),
            detail={
                "reason": "user_closed",
                "protocol": row.protocol,
                "capability_key": row.capability_key,
            },
        )
    return {
        "session_id": outcome["session_id"],
        "status": "closed",
        "close_reason": outcome["close_reason"],
    }


def _parse_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _close_http(
    factory: sessionmaker[Session],
    session_id: str,
    user_id: uuid.UUID,
) -> dict[str, object] | None:
    """Ownership-scoped conditional close; None = unknown/foreign id.

    When the row was already closed by another actor (bridge / maintenance),
    the CURRENT close_reason is re-read after the transaction so the
    response never reports a stale open state.
    """
    key = _parse_uuid(session_id)
    if key is None:
        return None
    with factory() as db:
        row = db.scalar(
            select(TerminalSession).where(
                TerminalSession.id == key, TerminalSession.user_id == user_id
            )
        )
        if row is None:
            return None
        result = terminal_service.close_terminal_session(
            db, session_id=session_id, user_id=user_id, reason="user_closed"
        )
        if result.closed_now:
            db.commit()
            db.refresh(row)
            reason = "user_closed"
        else:
            db.rollback()
            current = db.scalar(
                select(TerminalSession).where(TerminalSession.id == key)
            )
            reason = (current.close_reason if current is not None else None) or "closed"
        return {
            "session_id": session_id,
            "close_reason": reason,
            "closed_now": result.closed_now,
            "row": row,
        }
