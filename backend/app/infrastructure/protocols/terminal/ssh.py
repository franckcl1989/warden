"""Interactive SSH transport for the browser terminal (M5T4).

The WebSocket terminal is an interactive login shell over SSH WITHOUT a
PTY in 0.1.0 (design decision 6 of the M5T4 report: the [sim] semantics
need no pty; ``resize`` is accepted and no-ops — PTY window-change is the
documented future step). The same security rules as the M5T3 automation
channel apply (SECURITY.md §8, DEVICE_ADAPTERS.md §6.1, M5T3 report):

- host-key pin-or-refuse: the pinned ``ssh_host_fingerprint`` is enforced at
  every connect through ``vrp.session.open_connection`` (asyncssh host-key
  hook) — a missing fingerprint refuses the connect (NO unpinned
  automation, and interactive terminal connections follow the SAME policy
  per the M5T4 brief);
- password authentication only (0.1.0 secret schema);
- connect timeout 10 s (DEVICE_ADAPTERS.md §8), mapped to the stable error
  vocabulary of ``errors.py``.

The session opens a raw interactive channel WITHOUT a PTY
(``encoding=None`` — the API moves raw bytes between the WebSocket and the
device; nothing is ever decoded, logged or recorded here).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh
from app.infrastructure.protocols.terminal.errors import TerminalTransportError
from app.infrastructure.protocols.vrp.errors import VrpError
from app.infrastructure.protocols.vrp.session import (
    VrpSshConfig,
    close_connection,
    open_connection,
)
from asyncssh import SSHReader, SSHWriter

CONNECT_TIMEOUT_SECONDS = 10.0


@dataclass
class InteractiveSsh:
    """One open interactive SSH channel (no PTY) plus the owning connection."""

    connection: asyncssh.SSHClientConnection
    writer: SSHWriter[bytes]
    reader: SSHReader[bytes]

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def read_chunk(self) -> bytes:
        """Next raw device chunk; b'' at EOF (like asyncio streams)."""
        return await self.reader.read(4096)

    def at_eof(self) -> bool:
        return self.reader.at_eof()

    def resize(self, cols: int, rows: int) -> None:
        # No PTY on the 0.1.0 interactive channel: window-change has no
        # device-side effect (guarded so a resize frame can never kill the
        # session). A future pty-based channel would send it here.
        del cols, rows

    async def close(self) -> None:
        self.writer.close()
        with _suppress:
            await self.writer.wait_closed()
        await close_connection(self.connection)


class _Suppress:
    def __enter__(self) -> _Suppress:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return True


_suppress = _Suppress()


async def open_interactive_ssh(
    config: VrpSshConfig,
    *,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
) -> InteractiveSsh:
    """Open an authenticated interactive SSH session (no PTY in 0.1.0).

    Fingerprint pin-or-refuse is enforced by ``open_connection``
    (``accept_unpinned=False`` — there is no first-connect capture on the
    terminal path; an unpinned device never gets a terminal ticket because
    the launch gates require the pinned fingerprint already). Raises
    ``TerminalTransportError`` with a stable code.
    """
    try:
        connection, _hook = await open_connection(config, connect_timeout=connect_timeout)
    except VrpError as exc:
        raise _map_connect_error(exc) from None
    try:
        writer, reader, _stderr = await asyncio.wait_for(
            connection.open_session(encoding=None),
            timeout=connect_timeout,
        )
    except TimeoutError as exc:
        with _suppress:
            await close_connection(connection)
        raise TerminalTransportError(
            "network_unreachable", "SSH 会话建立超时", detail="session_open_timeout"
        ) from exc
    except asyncssh.Error as exc:
        with _suppress:
            await close_connection(connection)
        raise TerminalTransportError(
            "protocol_error",
            f"SSH 会话建立失败：{str(exc)[:160]}",
            detail="session_open_failed",
        ) from exc
    return InteractiveSsh(connection=connection, writer=writer, reader=reader)


def _map_connect_error(exc: VrpError) -> TerminalTransportError:
    """VrpError -> terminal transport error (stable code + safe detail)."""
    if exc.code == "validation_failed":
        return TerminalTransportError(
            "validation_failed", exc.message, detail="host_key_mismatch"
        )
    return TerminalTransportError(exc.code, exc.message)
