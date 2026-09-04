"""Telnet variant of the VRP simulator (M5T4, tests only).

A plain TCP server speaking a minimal RFC 854 telnet dialect over the same
[sim] device state the SSH simulator serves (``VrpDevice``): IAC WILL ECHO /
IAC WILL SUPPRESS-GO-AHEAD on connect, a prompt-driven login
(``Username:`` / ``Password:``) against the fixed simulator credential
(``device.py`` SSH_USERNAME/SSH_PASSWORD — the M5T4 tests store the same
pair as the device's ``credentials.telnet``), then the interactive [sim]
CLI subset with line echo:

- typed characters are echoed (except CR/LF handling and the erase byte);
- CR executes the buffered line (a command subset: ``display version`` /
  ``display current-configuration`` / ``quit`` / ``exit``; anything else is
  the standard unknown-command error);
- wrong credentials answer ``Error: Authentication failed.`` and close.

This sim exists to prove the platform's telnet TERMINAL mechanics (login
conversation, IAC negotiation, weak-protocol path) — it is never hardware
evidence (tests/simulators/vrp/README.md, ADR-018).
"""

from __future__ import annotations

import asyncio
from typing import Any

from tests.simulators.vrp.device import (
    BANNER_LINES,
    ERR_CARET_LINE,
    ERR_UNKNOWN_COMMAND,
    SSH_PASSWORD,
    SSH_USERNAME,
    VrpDevice,
)

IAC = 0xFF
WILL = 0xFB
WONT = 0xFC
DO = 0xFD
DONT = 0xFE

OPT_ECHO = 1
OPT_SUPPRESS_GO_AHEAD = 3

CR = 0x0D
LF = 0x0A
DEL = 0x7F

LOGIN_PROMPT_USERNAME = b"Username: "
LOGIN_PROMPT_PASSWORD = b"Password: "
LOGIN_FAILED = b"\r\nError: Authentication failed.\r\n"
LOGIN_OK = b"\r\nInfo: Login succeeded.\r\n"

#: Interactive [sim] CLI subset (smoke terminals; full DSL stays SSH-only).
_SUPPORTED_COMMANDS = ("display version", "display current-configuration")


def _iac(*options: int) -> bytes:
    return bytes([IAC]) + bytes(options)


def _send(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)


class _TelnetClientState:
    """Server-side negotiation state (echo negotiated by the client)."""

    def __init__(self) -> None:
        self.echo_on = False

    def handle(self, command: int, option: int, writer: asyncio.StreamWriter) -> None:
        """Answer one client IAC option (3-byte sequence already consumed)."""
        if command == DO:
            # The client asks US to echo / suppress-go-ahead: we echo and
            # agree to SG-A when the client supports it.
            if option == OPT_ECHO:
                self.echo_on = True
                _send(writer, _iac(WILL, OPT_ECHO))
            elif option == OPT_SUPPRESS_GO_AHEAD:
                _send(writer, _iac(WILL, OPT_SUPPRESS_GO_AHEAD))
            else:
                _send(writer, _iac(WONT, option))
        elif command == DONT:
            self.echo_on = False
            _send(writer, _iac(WONT, option))
        elif command == WILL:
            # The client wants to echo locally / negotiate SG-A: allowed
            # only for SG-A; echo stays with the server (we refuse).
            if option == OPT_SUPPRESS_GO_AHEAD:
                _send(writer, _iac(DO, option))
            elif option == OPT_ECHO:
                _send(writer, _iac(DO, OPT_ECHO))
            else:
                _send(writer, _iac(DONT, option))
        elif command == WONT:
            if option == OPT_ECHO:
                self.echo_on = False
            _send(writer, _iac(DONT, option))


async def _read_telnet_byte(
    reader: asyncio.StreamReader, state: _TelnetClientState, writer: asyncio.StreamWriter
) -> int | None:
    """One negotiated byte (IAC sequences consumed); None at EOF."""
    byte = await reader.readexactly(1)
    if byte[0] != IAC:
        return byte[0]
    command = (await reader.readexactly(1))[0]
    if command in (DO, DONT, WILL, WONT):
        option = (await reader.readexactly(1))[0]
        state.handle(command, option, writer)
        await writer.drain()
        return await _read_telnet_byte(reader, state, writer)
    # IAC SB ... IAC SE (sub-negotiation) is discarded; bare IAC/other
    # commands are ignored (the sim never uses them).
    if command == 0xFA:  # SB
        while True:
            token = await reader.readexactly(1)
            if token[0] == IAC and (await reader.readexactly(1))[0] == 0xF0:  # IAC SE
                break
    return await _read_telnet_byte(reader, state, writer)


async def _read_login_line(
    reader: asyncio.StreamReader,
    state: _TelnetClientState,
    writer: asyncio.StreamWriter,
) -> bytes | None:
    """One CR/LF-terminated line (no echo) during the login phase.

    IAC negotiations arriving mid-login (e.g. the client's own offer replies)
    are consumed by the option handler, never treated as credential text.
    """
    line = bytearray()
    while True:
        try:
            byte = await asyncio.wait_for(
                _read_telnet_byte(reader, state, writer), timeout=30.0
            )
        except (asyncio.IncompleteReadError, TimeoutError):
            return None
        if byte is None:
            return None
        if byte in (CR, LF):
            if line or byte == LF:
                return bytes(line)
            continue
        line.append(byte)
        if len(line) > 512:
            return bytes(line)


async def _authenticate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: _TelnetClientState,
) -> bool:
    """Username/Password conversation against the fixed sim credential."""
    _send(writer, LOGIN_PROMPT_USERNAME)
    await writer.drain()
    username = await _read_login_line(reader, state, writer)
    if username is None:
        return False
    _send(writer, LOGIN_PROMPT_PASSWORD)
    await writer.drain()
    password = await _read_login_line(reader, state, writer)
    if password is None:
        return False
    if username.decode("utf-8", "ignore") != SSH_USERNAME or password.decode(
        "utf-8", "ignore"
    ) != SSH_PASSWORD:
        _send(writer, LOGIN_FAILED)
        await writer.drain()
        await asyncio.sleep(0.05)  # let the client read the failure line
        return False
    _send(writer, LOGIN_OK)
    return True


async def _cli_subset(device: VrpDevice, text: str) -> bytes:
    """The interactive [sim] command subset -> response bytes."""
    lowered = text.lower()
    if lowered.startswith("display version"):
        return (device.version_text() + "\n").encode("utf-8")
    if lowered.startswith("display current-configuration"):
        return (device.current_config_text() + "\n").encode("utf-8")
    return (ERR_UNKNOWN_COMMAND + "\n" + ERR_CARET_LINE + "\n").encode("utf-8")


async def _interactive(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    device: VrpDevice,
    state: _TelnetClientState,
) -> None:
    """Line-oriented interactive session with per-character echo."""
    prompt = f"<{device.sysname}> ".encode()
    line = bytearray()

    async def write(text: bytes) -> None:
        _send(writer, text)
        await writer.drain()

    async def execute_line() -> None:
        command = bytes(line)
        del line[:]
        if not command.strip():
            return
        lowered = command.strip().decode("utf-8", "ignore").lower()
        if lowered in ("quit", "exit"):
            writer.close()
            return
        response = await _cli_subset(device, command.decode("utf-8", "ignore"))
        await write(response + prompt)

    await write(prompt)
    while True:
        byte = await _read_telnet_byte(reader, state, writer)
        if byte is None:
            return
        if byte in (CR, LF):
            # Enter: echo a CRLF pair (NVT line end) then run the command.
            await write(b"\r\n")
            if line:
                await execute_line()
            else:
                await write(prompt)
            continue
        if byte == DEL:
            if line:
                del line[-1:]
            continue
        if 32 <= byte <= 126:
            line.append(byte)
            if state.echo_on:
                _send(writer, bytes([byte]))
                await writer.drain()
        elif state.echo_on and byte == 8:  # backspace (0x08)
            _send(writer, b"\b \b")
            await writer.drain()


async def telnet_session(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, device: VrpDevice
) -> None:
    """One telnet connection: negotiate, authenticate, serve the CLI."""
    state = _TelnetClientState()
    # Server offers echo + suppress-go-ahead up front (like telnetd).
    _send(writer, _iac(WILL, OPT_ECHO, WILL, OPT_SUPPRESS_GO_AHEAD))
    try:
        if not await _authenticate(reader, writer, state):
            writer.close()
            return
        state.echo_on = True  # echo starts once logged in
        await writer.drain()
        banner = ("\r\n".join(BANNER_LINES) + "\r\n").encode("utf-8")
        _send(writer, banner)
        await _interactive(reader, writer, device, state)
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
        with _suppress:
            await writer.wait_closed()


class _Suppress:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_exc: object) -> bool:
        return True


_suppress = _Suppress()


async def start_telnet_server(device: VrpDevice) -> Any:
    """Start the telnet listener on 127.0.0.1 with an OS-assigned port."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await telnet_session(reader, writer, device)

    return await asyncio.start_server(handler, host="127.0.0.1", port=0)
