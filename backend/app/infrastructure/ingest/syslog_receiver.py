"""Syslog UDP/TCP receiver (M5T1 event-ingest; ARCHITECTURE.md §3.4).

Two asyncio datagram/stream servers on non-privileged ports (deployment maps
UDP 514/TCP 514 to the configured ports; config.py ``syslog_udp_port`` /
``syslog_tcp_port`` / ``ingest_bind_host``). Every datagram/line is parsed
with the tolerant RFC3164/5424 parser; the handler receives
``(parsed, peer_ip, raw)`` — ``parsed`` is None for lines that are not
syslog (the caller counts them; nothing fabricated is stored).

TCP framing (RFC 6587): non-transparent LF-delimited lines are the baseline;
octet-counting frames (``<count> <message>``) are detected and unwrapped so
rsyslog-style senders work too.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import cast

import structlog
from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage, parse_syslog_line

SyslogHandler = Callable[[ParsedSyslogMessage | None, str, str], None]

MAX_DATAGRAM_BYTES = 65535


def _decode_datagram(data: bytes) -> str | None:
    """syslog text is ASCII/UTF-8; latin-1 keeps single-byte encodings readable."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def parse_octet_counting_frame(payload: str) -> str | None:
    """Unwrap one RFC 6587 octet-counting frame; None when not a frame."""
    parts = payload.split(" ", 1)
    if len(parts) == 2 and parts[0].isdigit():
        declared = int(parts[0])
        body = parts[1]
        if len(body) == declared:
            return body
    return None


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._receiver._udp_transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int] | str) -> None:
        peer_ip = addr[0] if isinstance(addr, tuple) else str(addr)
        self._receiver._on_payload(data, peer_ip)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - OS path
        self._receiver._log.warning("syslog.udp.error", error=type(exc).__name__)


class _TcpProtocol(asyncio.Protocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver
        self._buffer = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        peer = self._transport.get_extra_info("peername")
        self._peer_ip = peer[0] if isinstance(peer, tuple) else str(peer)

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                break
            line = self._buffer[:newline]
            self._buffer = self._buffer[newline + 1 :]
            self._receiver._on_line(line, self._peer_ip)

    def eof_received(self) -> bool | None:
        if self._buffer:
            self._receiver._on_line(self._buffer, self._peer_ip)
            self._buffer = b""
        return None


class SyslogReceiver:
    """UDP + TCP syslog servers sharing one handler."""

    def __init__(
        self,
        *,
        host: str,
        udp_port: int,
        tcp_port: int,
        handler: SyslogHandler,
        logger: structlog.BoundLogger | None = None,
    ) -> None:
        self._host = host
        self._configured_udp_port = udp_port
        self._configured_tcp_port = tcp_port
        self._handler = handler
        self._log = logger if logger is not None else structlog.get_logger("warden.ingest.syslog")
        self.udp_port: int | None = None
        self.tcp_port: int | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self._started = False

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self),
            local_addr=(self._host, self._configured_udp_port),
        )
        sock = self._udp_transport.get_extra_info("sockname")
        self.udp_port = sock[1] if isinstance(sock, tuple) else self._configured_udp_port
        self._tcp_server = await loop.create_server(
            lambda: _TcpProtocol(self),
            host=self._host,
            port=self._configured_tcp_port,
        )
        if self._tcp_server.sockets:
            sock = self._tcp_server.sockets[0].getsockname()
            self.tcp_port = sock[1] if isinstance(sock, tuple) else self._configured_tcp_port
        self._started = True
        self._log.info(
            "syslog.receiver.started",
            host=self._host,
            udp_port=self.udp_port,
            tcp_port=self.tcp_port,
        )

    async def stop(self) -> None:
        if not self._started:
            return
        if self._udp_transport is not None:
            self._udp_transport.close()
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        self._started = False
        self._log.info("syslog.receiver.stopped")

    def _on_payload(self, data: bytes, peer_ip: str) -> None:
        text = _decode_datagram(data)
        if text is None:
            self._handler(None, peer_ip, "")
            return
        self._on_text(text, peer_ip)

    def _on_line(self, line: bytes, peer_ip: str) -> None:
        text = _decode_datagram(line)
        if text is None:
            self._handler(None, peer_ip, "")
            return
        self._on_text(text, peer_ip)

    def _on_text(self, text: str, peer_ip: str) -> None:
        unwrapped = parse_octet_counting_frame(text.strip())
        if unwrapped is not None:
            text = unwrapped
        self._handler(parse_syslog_line(text), peer_ip, text)
