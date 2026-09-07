"""Syslog + trap receiver integration tests over real UDP/TCP (M5T1).

pytest-asyncio in-process receivers on ephemeral ports; the syslog side is
raw sockets, the trap side uses the pysnmp notification-originator machinery
(the same engine pair the switch simulator uses). Engine boots state is
isolated per test through the shared ``isolated_snmp_boots`` fixture so USM
time-window semantics are deterministic.
"""

from __future__ import annotations

import asyncio
import datetime

import structlog
from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage
from app.infrastructure.ingest.syslog_receiver import SyslogReceiver, parse_octet_counting_frame
from app.infrastructure.ingest.trap_receiver import TrapReceiver, TrapUser
from app.infrastructure.ingest.trap_types import ParsedTrap
from pyasn1.type.univ import OctetString
from pysnmp.entity import config
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    NotificationType,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    sendNotification,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import rfc1902

UTC = datetime.UTC

RECEIVER_ENGINE_ID = "77617264656e2d747261702d72656376"
SENDER_ENGINE_ID = "73353733322d73696d2d30303031"

AUTH_KEY = "auth-pass-1"
PRIV_KEY = "priv-pass-1"


async def _send_v3_trap(port: int, *, if_index: int, community: str = "public") -> None:
    del community
    sender = SnmpEngine(snmpEngineID=OctetString(hexValue=SENDER_ENGINE_ID))
    config.addV3User(
        sender,
        "monitor",
        config.usmHMACSHAAuthProtocol,
        AUTH_KEY,
        config.usmAesCfb128Protocol,
        PRIV_KEY,
    )
    try:
        result = await sendNotification(
            sender,
            UsmUserData("monitor", AUTH_KEY, PRIV_KEY, usmHMACSHAAuthProtocol, usmAesCfb128Protocol),
            UdpTransportTarget(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.3")).addVarBinds(
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1"), rfc1902.Integer32(if_index))
            ),
        )
    finally:
        # Windows proactor (M6T2b): a trap send is fire-and-forget: the
        # sender may return while the UDP write is still in flight. Closing
        # the dispatcher then stalls the transport finalization forever and
        # its __del__ ResourceWarning fires at an arbitrary later cyclic GC.
        # Wait out the write, close, and drain the close callbacks while this
        # loop is still alive.
        await asyncio.sleep(0.05)
        sender.transportDispatcher.closeDispatcher()
        await asyncio.sleep(0)
    assert result[0] is None, result[0]


async def _send_v2c_trap(port: int, *, trap_oid: str, community: str = "public") -> None:
    engine = SnmpEngine()
    try:
        result = await sendNotification(
            engine,
            CommunityData(community, mpModel=1),  # noqa: S508 - v2c receiver tests
            UdpTransportTarget(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(trap_oid)),
        )
    finally:
        await asyncio.sleep(0.05)  # proactor write drain (M6T2b), see _send_v3_trap
        engine.transportDispatcher.closeDispatcher()
        await asyncio.sleep(0)
    assert result[0] is None, result[0]


class TestSyslogReceiver:
    async def test_udp_datagram_parsed_and_delivered_with_peer(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        received: list[tuple[ParsedSyslogMessage | None, str, str]] = []
        receiver = SyslogReceiver(
            host="127.0.0.1",
            udp_port=0,
            tcp_port=0,
            handler=lambda parsed, peer, raw: received.append((parsed, peer, raw)),
            logger=structlog.get_logger("test"),
        )
        await receiver.start()
        assert receiver.udp_port is not None
        transport = await _udp_sender(receiver.udp_port)
        payload = b"<190>Aug  4 2026 14:22:01 s5732-1 %%01IFNET/4/LINK_STATE(l): msg"
        transport.sendto(payload, ("127.0.0.1", receiver.udp_port))
        await asyncio.sleep(0.3)
        assert len(received) == 1
        parsed, peer, _raw = received[0]
        assert isinstance(parsed, ParsedSyslogMessage)
        assert parsed.tag == "%%01IFNET/4/LINK_STATE(l)"
        assert peer == "127.0.0.1"
        transport.close()
        await receiver.stop()

    async def test_tcp_line_framing(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        received: list[ParsedSyslogMessage | None] = []
        receiver = SyslogReceiver(
            host="127.0.0.1",
            udp_port=0,
            tcp_port=0,
            handler=lambda parsed, _peer, _raw: received.append(parsed),
        )
        await receiver.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", receiver.tcp_port or 0)
        writer.write(b"<190>Aug  4 2026 14:22:01 host %%01IFNET/4/LINK_STATE(l): line1\n")
        writer.write(b"<190>Aug  4 2026 14:22:02 host tag: line2\n")
        await writer.drain()
        await asyncio.sleep(0.3)
        assert len(received) == 2
        assert received[0] is not None and received[0].message == "line1"
        assert received[1] is not None and received[1].message == "line2"
        writer.close()
        await writer.wait_closed()
        await receiver.stop()

    async def test_tcp_octet_counting_framing(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        received: list[ParsedSyslogMessage | None] = []
        receiver = SyslogReceiver(
            host="127.0.0.1", udp_port=0, tcp_port=0,
            handler=lambda parsed, _peer, _raw: received.append(parsed),
        )
        await receiver.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", receiver.tcp_port or 0)
        body = b"<14>Aug  4 14:22:01 host tag: octet framed"
        writer.write(f"{len(body)} ".encode("ascii") + body + b"\n")
        await writer.drain()
        await asyncio.sleep(0.3)
        assert len(received) == 1
        assert received[0] is not None
        assert received[0].message == "octet framed"
        writer.close()
        await writer.wait_closed()
        await receiver.stop()

    async def test_garbage_datagram_delivered_as_none(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        received: list[ParsedSyslogMessage | None] = []
        receiver = SyslogReceiver(
            host="127.0.0.1", udp_port=0, tcp_port=0,
            handler=lambda parsed, _peer, _raw: received.append(parsed),
        )
        await receiver.start()
        transport = await _udp_sender(receiver.udp_port or 0)
        transport.sendto(b"\xff\xfe\x00garbage", ("127.0.0.1", receiver.udp_port or 0))
        await asyncio.sleep(0.3)
        assert len(received) == 1
        assert received[0] is None
        transport.close()
        await receiver.stop()


def test_octet_counting_parser() -> None:
    body = "<14>Aug  4 14:22:01 host tag: msg"
    frame = f"{len(body)} {body}"
    assert parse_octet_counting_frame(frame) == body
    assert parse_octet_counting_frame("<14>Aug  4 14:22:01 host tag: msg") is None
    assert parse_octet_counting_frame("4 xyz") is None


class TestTrapReceiver:
    async def test_v3_auth_priv_trap_decoded_with_peer(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        received: list[tuple[ParsedTrap, str]] = []
        receiver = TrapReceiver(
            host="127.0.0.1",
            port=0,
            handler=lambda trap, peer: received.append((trap, peer)),
            engine_id_hex=RECEIVER_ENGINE_ID,
        )
        receiver.set_users(
            [
                TrapUser(
                    username="monitor",
                    engine_id_hex=SENDER_ENGINE_ID,
                    auth_key=AUTH_KEY,
                    privacy_key=PRIV_KEY,
                )
            ]
        )
        await receiver.start()
        assert receiver.port is not None
        await _send_v3_trap(receiver.port, if_index=24)
        await asyncio.sleep(0.5)
        assert len(received) == 1
        trap, peer = received[0]
        assert peer == "127.0.0.1"
        assert trap.security_model == 3
        assert trap.security_name == "monitor"
        assert trap.security_level == 3
        assert trap.varbind("1.3.6.1.6.3.1.1.4.1.0") is not None
        assert trap.varbind("1.3.6.1.6.3.1.1.4.1.0") is not None
        assert str(trap.varbind("1.3.6.1.6.3.1.1.4.1.0").value) == "1.3.6.1.6.3.1.1.5.3"
        await receiver.stop()

    async def test_v2c_trap_decoded_with_community(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        received: list[ParsedTrap] = []
        receiver = TrapReceiver(
            host="127.0.0.1",
            port=0,
            handler=lambda trap, _peer: received.append(trap),
            engine_id_hex=RECEIVER_ENGINE_ID,
        )
        receiver.set_communities(["public"])
        await receiver.start()
        await _send_v2c_trap(receiver.port or 0, trap_oid="1.3.6.1.6.3.1.1.5.4", community="public")
        await asyncio.sleep(0.5)
        assert len(received) == 1
        trap = received[0]
        assert trap.security_model == 2
        assert trap.community == "public"
        await receiver.stop()

    async def test_garbage_datagram_never_reaches_handler(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        received: list[ParsedTrap] = []
        receiver = TrapReceiver(
            host="127.0.0.1",
            port=0,
            handler=lambda trap, _peer: received.append(trap),
            engine_id_hex=RECEIVER_ENGINE_ID,
        )
        await receiver.start()
        transport = await _udp_sender(receiver.port or 0)
        transport.sendto(b"\x30\x03\x02\x01\x00garbage", ("127.0.0.1", receiver.port or 0))
        await asyncio.sleep(0.3)
        assert received == []
        transport.close()
        await receiver.stop()


async def _udp_sender(port: int) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _NullProtocol(),
        remote_addr=("127.0.0.1", port),
    )
    return transport


class _NullProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int] | str) -> None:
        pass
