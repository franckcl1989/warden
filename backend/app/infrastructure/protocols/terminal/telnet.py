"""Telnet transport for the browser terminal (M5T4).

SECURITY.md §6 / ADR-007: Telnet is a WEAK (cleartext) protocol. 0.1.0 uses
it ONLY inside the interactive browser terminal after two explicit gates
(the deployment-wide ``WARDEN_TELNET_ENABLED`` setting AND the per-device
``connection_config.telnet`` opt-in — both audited; automation never uses
Telnet, DEVICE_ADAPTERS.md §6). The UI shows a persistent weak-protocol
warning while a Telnet session is open.

The client is a minimal RFC 854 telnet driver:

- it negotiates ECHO + SUPPRESS-GO-AHEAD (the server echoes keystrokes);
- every other option is refused (``WONT``/``DONT``) and sub-negotiations
  (``IAC SB ... IAC SE``) are discarded — never parsed as terminal content;
- the login conversation is prompt-driven (``Username:`` / ``Password:``);
  the connection never logs or records any exchanged byte.

Content rule (SECURITY.md §8): the byte stream is forwarded raw between the
device and the WebSocket; this module never logs it, never stores it and
never echoes it to any log sink.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from app.infrastructure.protocols.terminal.errors import TerminalTransportError

CONNECT_TIMEOUT_SECONDS = 10.0
_LOGIN_STAGE_TIMEOUT = 10.0

# Telnet IAC option bytes (RFC 854/855).
IAC = 0xFF
WILL = 0xFB
WONT = 0xFC
DO = 0xFD
DONT = 0xFE
SB = 0xFA
SE = 0xF0

OPT_ECHO = 1
OPT_SUPPRESS_GO_AHEAD = 3

_LOGIN_PROMPT_RE = re.compile(rb"username|user name|login", re.IGNORECASE)
_PASSWORD_PROMPT_RE = re.compile(rb"password", re.IGNORECASE)
_AUTH_FAILED_RE = re.compile(rb"authentication failed|invalid|refused|error", re.IGNORECASE)

#: Login-stage read size; login prompts never need a bigger lookahead.
_LOGIN_READ_CHUNK = 512

#: Cap on protocol bytes buffered across reads (a peer streaming an
#: unterminated sub-negotiation is not trusted to grow memory).
_IAC_BUFFER_MAX = 4096


@dataclass
class TelnetTarget:
    """One telnet connect target (credentials exist only inside the call
    boundary — SECURITY.md §5; resolved IP comes from the platform policy)."""

    host: str
    port: int
    username: str
    password: str


class _OptionState:
    """Tiny negotiated-option state (echo/suppress-go-ahead accepted)."""

    def __init__(self) -> None:
        self.server_echo = False
        self.server_suppress_go_ahead = False
        self.want_echo = False

    def accept_server_will(self, option: int) -> bool:
        if option == OPT_ECHO:
            self.server_echo = True
            return True
        if option == OPT_SUPPRESS_GO_AHEAD:
            self.server_suppress_go_ahead = True
            return True
        return False

    def accept_server_do(self, option: int) -> bool:
        # The client never performs local echo (the server echoes when it
        # accepted ECHO); suppress-go-ahead is agreed for prompt-driven I/O.
        return option == OPT_SUPPRESS_GO_AHEAD


@dataclass
class TelnetConnection:
    """An open telnet stream: raw device bytes in/out (negotiation handled)."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    options: _OptionState
    #: Bytes already consumed from the socket during the login conversation
    #: but belonging to the session output (e.g. the banner after the login
    #: confirmation); served before any further socket reads.
    pending: bytes = b""
    #: Protocol-parser state across reads (a real telnet peer may split IAC
    #: sequences and sub-negotiations across TCP segments — M5T4 review
    #: fix): the 1-2 bytes of an IAC command truncated at a chunk boundary,
    #: whether the stream is inside an unterminated ``IAC SB ...`` payload,
    #: and how many payload bytes were swallowed since the SB started
    #: (bounded — a pathological peer that never sends IAC SE is not
    #: trusted to swallow the session forever). Protocol bytes never surface
    #: as terminal content.
    _partial_command: bytearray = field(default_factory=bytearray, repr=False)
    _in_subnegotiation: bool = field(default=False, repr=False)
    _subnegotiation_dropped: int = field(default=0, repr=False)

    async def write(self, data: bytes) -> None:
        """Forward user bytes; escape any embedded IAC (0xFF -> 0xFF 0xFF)."""
        if IAC in data:
            data = data.replace(bytes([IAC]), bytes([IAC, IAC]))
        self.writer.write(data)
        await self.writer.drain()

    async def read_raw_chunk(self) -> bytes:
        """Next chunk of user-visible bytes (IAC commands stripped).

        Negotiation-only reads are drained internally: a pure-protocol chunk
        must never look like EOF (b'') to the stream consumer. b'' is
        returned only at the real EOF.
        """
        while True:
            if self.pending:
                chunk = self.pending
                self.pending = b""
            else:
                chunk = await self.reader.read(4096)
                if not chunk:
                    return b""
            visible = await self._process(chunk)
            if visible:
                return visible

    async def _process(self, data: bytes) -> bytes:
        """Strip/negotiate IAC sequences; return the user-visible remainder.

        Incremental state machine: an IAC command truncated at the end of a
        read is buffered in ``_partial_command`` and completed with the next
        chunk; an unterminated ``IAC SB ...`` payload is discarded across
        reads until ``IAC SE`` (never buffered — payload bytes are dropped
        as they arrive).
        """
        if self._partial_command:
            combined = bytes(self._partial_command) + data
            self._partial_command.clear()
        else:
            combined = data
        remaining = bytearray()
        index = 0
        length = len(combined)
        while index < length:
            byte = combined[index]
            if self._in_subnegotiation:
                if byte != IAC:
                    self._subnegotiation_dropped += 1
                    if self._subnegotiation_dropped > _IAC_BUFFER_MAX:
                        # Pathological peer: never sends IAC SE. Stop
                        # swallowing so the session survives (the payload
                        # beyond the cap is dropped, not guessed).
                        self._in_subnegotiation = False
                        self._subnegotiation_dropped = 0
                    index += 1
                    continue
                if index + 1 >= length:
                    # IAC at the chunk end: SE/IAC-pair byte arrives with
                    # the next read — buffer the single byte.
                    self._partial_command.extend(combined[index:])
                    return bytes(remaining)
                following = combined[index + 1]
                if following == SE:
                    self._in_subnegotiation = False
                    self._subnegotiation_dropped = 0
                    index += 2
                elif following == IAC:
                    # Escaped 0xFF inside the payload (RFC 854).
                    self._subnegotiation_dropped += 1
                    index += 2
                else:
                    # Stray IAC: payload byte (dropped); scan on from it.
                    index += 1
                continue
            if byte != IAC:
                remaining.append(byte)
                index += 1
                continue
            if index + 2 >= length:
                # A truncated IAC command at a chunk boundary: the next read
                # will deliver the rest — buffer the partial sequence
                # instead of dropping it (a real telnet peer splits
                # sequences; the old code dropped the tail AND mis-parsed
                # the next chunk's leading bytes as content).
                self._partial_command.extend(combined[index:])
                return bytes(remaining)
            command = combined[index + 1]
            option = combined[index + 2]
            index += 3
            if command in (WILL, WONT, DO, DONT) and option == SB:
                # Malformed framing: stop parsing this chunk.
                break
            if command == SB:
                # Sub-negotiation: discard the payload until IAC SE.
                self._in_subnegotiation = True
                self._subnegotiation_dropped = 0
                continue
            if command == WILL:
                reply = (
                    bytes([IAC, DO, option])
                    if self.options.accept_server_will(option)
                    else bytes([IAC, DONT, option])
                )
                self.writer.write(reply)
                await self.writer.drain()
            elif command == DO:
                reply = (
                    bytes([IAC, WILL, option])
                    if self.options.accept_server_do(option)
                    else bytes([IAC, WONT, option])
                )
                self.writer.write(reply)
                await self.writer.drain()
            elif command in (WONT, DONT):
                # The server declined: keep state untouched.
                continue
        return bytes(remaining)

    async def close(self) -> None:
        self.writer.close()
        with _suppress:
            await self.writer.wait_closed()


class _Suppress:
    def __enter__(self) -> _Suppress:
        return self
        return None

    def __exit__(self, *_exc: object) -> bool:
        return True


_suppress = _Suppress()


async def _read_until_prompt(
    reader: asyncio.StreamReader,
    pattern: re.Pattern[bytes],
    *,
    stage: str,
    wait_seconds: float,
    auth_failed: re.Pattern[bytes],
) -> tuple[bytes, asyncio.StreamReader]:
    """Read until ``pattern`` appears (case-insensitive) or EOF/timeout.

    Returns (tail_after_match, reader) — bytes consumed past the prompt are
    handed back so session content is never eaten by the login logic. An
    explicit authentication-failure answer (or EOF) raises
    ``TerminalTransportError(authentication_failed)``.
    """
    accumulated = bytearray()
    try:
        while True:
            if auth_failed.search(accumulated) is not None:
                raise TerminalTransportError(
                    "authentication_failed", "Telnet 登录被设备拒绝", detail="auth_failed"
                )
            match = pattern.search(accumulated)
            if match is not None:
                return bytes(accumulated[match.end() :]), reader
            chunk = await asyncio.wait_for(reader.read(_LOGIN_READ_CHUNK), timeout=wait_seconds)
            if not chunk:
                msg = f"Telnet 服务器在等待{stage}时关闭连接"
                raise TerminalTransportError("authentication_failed", msg, detail=stage)
            accumulated.extend(chunk)
    except TimeoutError as exc:
        msg = f"Telnet 登录等待{stage}超时（{int(wait_seconds)} 秒窗口）"
        raise TerminalTransportError("network_unreachable", msg, detail=stage) from exc


async def _login(connection: TelnetConnection, target: TelnetTarget) -> None:
    """Prompt-driven telnet login (Username: / Password:).

    Failures raise ``TerminalTransportError(authentication_failed)``; the
    sim's own "Authentication failed" answer is matched explicitly so a
    wrong credential surfaces as authentication_failed, never as EOF alone.
    Content arriving after the login confirmation (banner/prompt) is stashed
    on the connection so the terminal sees it.
    """
    _tail, _reader = await _read_until_prompt(
        connection.reader,
        _LOGIN_PROMPT_RE,
        stage="用户名提示",
        wait_seconds=_LOGIN_STAGE_TIMEOUT,
        auth_failed=_AUTH_FAILED_RE,
    )
    connection.writer.write(target.username.encode("utf-8") + b"\r")
    await connection.writer.drain()
    _tail, _reader = await _read_until_prompt(
        connection.reader,
        _PASSWORD_PROMPT_RE,
        stage="密码提示",
        wait_seconds=_LOGIN_STAGE_TIMEOUT,
        auth_failed=_AUTH_FAILED_RE,
    )
    connection.writer.write(target.password.encode("utf-8") + b"\r")
    await connection.writer.drain()
    tail, _reader = await _read_until_prompt(
        connection.reader,
        re.compile(rb"login succeeded|>\s*$|\]\s*$"),
        stage="登录结果",
        wait_seconds=_LOGIN_STAGE_TIMEOUT,
        auth_failed=_AUTH_FAILED_RE,
    )
    connection.pending = tail


async def open_telnet(
    target: TelnetTarget,
    *,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
) -> TelnetConnection:
    """Open an authenticated telnet stream (weak-protocol session).

    Only ever used by the interactive browser terminal after the global AND
    per-device telnet gates (SECURITY.md §6, ADR-007).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=connect_timeout,
        )
    except TimeoutError as exc:
        raise TerminalTransportError(
            "network_unreachable", "Telnet 连接超时（10 秒连接窗口）", detail="connect_timeout"
        ) from exc
    except OSError as exc:
        raise TerminalTransportError(
            "network_unreachable",
            f"Telnet 网络不可达：{exc.strerror or str(exc)[:160]}",
            detail="unreachable",
        ) from exc
    connection = TelnetConnection(reader=reader, writer=writer, options=_OptionState())
    try:
        # Ask for server-side echo + suppress-go-ahead up front (like
        # telnetd does); the server agrees or refuses via WILL/WONT.
        writer.write(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_SUPPRESS_GO_AHEAD]))
        await writer.drain()
        await _login(connection, target)
    except TerminalTransportError:
        await connection.close()
        raise
    except OSError as exc:
        await connection.close()
        raise TerminalTransportError(
            "protocol_error", f"Telnet 会话异常：{str(exc)[:160]}", detail="session_error"
        ) from exc
    return connection
