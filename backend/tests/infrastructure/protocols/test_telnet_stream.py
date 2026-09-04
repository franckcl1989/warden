"""Telnet stream chunk-boundary unit tests (M5T4 review fix).

A real telnet peer may split IAC command sequences and sub-negotiations
across TCP segments; the RFC 854 driver must handle sequences that straddle
reads (previously a truncated ``IAC`` at the end of a chunk was dropped —
losing the sequence AND mis-parsing the next chunk's leading bytes as
terminal content). Pure-protocol reads must also never look like EOF to the
stream consumer.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from app.infrastructure.protocols.terminal.telnet import (
    DO,
    IAC,
    SB,
    SE,
    WILL,
    TelnetConnection,
    _OptionState,
)


class _FakeWriter:
    """Records negotiation replies written by the driver."""

    def __init__(self) -> None:
        self.written = bytearray()

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None


class _ChunkedReader:
    """Serves pre-split chunks, then b'' at EOF."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    async def read(self, n: int) -> bytes:
        del n
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


def _connection(reader: _ChunkedReader, writer: _FakeWriter) -> TelnetConnection:
    return TelnetConnection(
        reader=reader,  # type: ignore[arg-type]
        writer=writer,  # type: ignore[arg-type]
        options=_OptionState(),
    )


@pytest.mark.unit
async def test_truncated_iac_will_across_two_reads_is_buffered_and_replied() -> None:
    writer = _FakeWriter()
    connection = _connection(_ChunkedReader([b"\x01\x02\xff\xfb", b"\x01rest"]), writer)
    # The first read carries visible bytes plus a truncated ``IAC WILL``
    # (2 of 3 bytes); the driver must hold the tail and complete the
    # negotiation when the option byte (ECHO = 1) arrives.
    first = await connection.read_raw_chunk()
    assert first == b"\x01\x02"
    second = await connection.read_raw_chunk()
    assert second == b"rest"
    assert bytes(writer.written) == bytes([IAC, DO, 1])
    assert not connection._partial_command  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_truncated_iac_at_chunk_end_keeps_next_content_clean() -> None:
    # Old behavior: the trailing ``IAC`` byte was dropped and the next
    # chunk's leading ``0xFB`` (the WILL of IAC WILL 0x03) mis-parsed as
    # terminal content garbage.
    writer = _FakeWriter()
    connection = _connection(_ChunkedReader([b"a\xff", b"\xfb\x03b"]), writer)
    assert await connection.read_raw_chunk() == b"a"
    assert await connection.read_raw_chunk() == b"b"
    assert bytes(writer.written) == bytes([IAC, DO, 3])
    assert not connection._partial_command  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_subnegotiation_spanning_reads_is_discarded_without_content_loss() -> None:
    writer = _FakeWriter()
    # IAC SB 0x01 ... split mid-subnegotiation, terminated in a later chunk
    # that also carries visible bytes after IAC SE.
    connection = _connection(
        _ChunkedReader([b"x\xff\xfa\x01", b"\x02\x03", b"\xff\xf0y", b"z"]),
        writer,
    )
    assert await connection.read_raw_chunk() == b"x"
    assert await connection.read_raw_chunk() == b"y"
    assert await connection.read_raw_chunk() == b"z"
    assert not connection._in_subnegotiation  # noqa: SLF001 - unit-visible state
    assert connection._subnegotiation_dropped == 0  # noqa: SLF001


@pytest.mark.unit
async def test_escaped_iac_pair_inside_subnegotiation_does_not_end_it() -> None:
    writer = _FakeWriter()
    # The payload contains an escaped 0xFF (IAC IAC) before the real SE —
    # only the IAC SE pair terminates the sub-negotiation.
    connection = _connection(
        _ChunkedReader([bytes([IAC, SB, 1, IAC, IAC, 2]), bytes([IAC, SE]) + b"end"]),
        writer,
    )
    assert await connection.read_raw_chunk() == b"end"
    assert await connection.read_raw_chunk() == b""
    assert not connection._in_subnegotiation  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_subnegotiation_se_split_across_reads_still_terminates() -> None:
    writer = _FakeWriter()
    # The chunk ends with the IAC of the terminating ``IAC SE`` pair; the
    # SE byte arrives with the next chunk — without buffering that trailing
    # IAC the sub-negotiation would swallow the session forever.
    connection = _connection(
        _ChunkedReader([bytes([IAC, SB, 1, 0x02]) + b"x\xff", b"\xf0visible"]),
        writer,
    )
    assert await connection.read_raw_chunk() == b"visible"
    assert not connection._in_subnegotiation  # noqa: SLF001 - unit-visible state
    assert not connection._partial_command  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_pure_protocol_read_never_looks_like_eof() -> None:
    # A read that contains ONLY negotiation bytes must not surface as b''
    # (the bridge would treat it as device_connection_lost); the driver
    # drains internally until real data or EOF.
    writer = _FakeWriter()
    connection = _connection(_ChunkedReader([bytes([IAC, WILL, 1]), b"data"]), writer)
    assert await connection.read_raw_chunk() == b"data"
    assert await connection.read_raw_chunk() == b""
    assert bytes(writer.written) == bytes([IAC, DO, 1])


@pytest.mark.unit
async def test_unterminated_subnegotiation_is_bounded_by_the_cap() -> None:
    writer = _FakeWriter()
    # The peer opens IAC SB and never sends IAC SE: the driver drops the
    # payload up to its cap, then stops swallowing so the session survives.
    flood = bytes([IAC, SB, 0x01]) + b"\x00" * 4097
    connection = _connection(_ChunkedReader([flood, b"tail"]), writer)
    assert await connection.read_raw_chunk() == b"tail"
    assert not connection._in_subnegotiation  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_pending_login_tail_with_partial_iac_is_buffered() -> None:
    writer = _FakeWriter()
    connection = replace(
        _connection(_ChunkedReader([b"\x01"]), writer),
        pending=b"banner \xff\xfb",
    )
    # The pending login tail ends with a truncated IAC WILL; the option
    # byte arrives with the next socket read.
    assert await connection.read_raw_chunk() == b"banner "
    assert await connection.read_raw_chunk() == b""
    assert bytes(writer.written) == bytes([IAC, DO, 1])
    assert not connection._partial_command  # noqa: SLF001 - unit-visible state


@pytest.mark.unit
async def test_wont_and_dont_are_accepted_without_reply() -> None:
    writer = _FakeWriter()
    connection = _connection(
        _ChunkedReader([bytes([IAC, 0xFC, 1, IAC, 0xFE, 3]) + b"ok"]),
        writer,
    )
    assert await connection.read_raw_chunk() == b"ok"
    assert bytes(writer.written) == b""
