"""SNMP Trap v1/v2c/v3 receiver (M5T1 event-ingest; ARCHITECTURE.md §3.4).

A pysnmp ``SnmpEngine`` decodes messages the receiver feeds it from its own
asyncio UDP endpoint (non-privileged port; deployment maps UDP 162). The
engine provides real SNMPv3 USM handling (auth + AES decryption) and the
v1/v2c proxy; the receiver's own PDU registration converts v1 traps onto
their v2c form (RFC 2576: sysUpTime.0 + snmpTrapOID.0 synthesized) and hands
every decoded trap to the handler as a ``ParsedTrap`` with the PEER ADDRESS
intact (source-IP attribution needs it; pysnmp's built-in receiver callback
does not expose the peer).

USM user rows must be registered per (device engine id, user) BEFORE the
device's traps can decode: registration happens through ``set_users`` and is
keyed by the authoritative engine id of the sender (the switch). pysnmp
drops v3 messages it cannot authenticate/decrypt at the USM layer — that is
the honest security boundary: a wrong-key trap never reaches the handler
(documented: the receiver counts nothing for USM-level drops; the v2c
community check happens at the platform layer because v2c authenticates
nothing).
"""

from __future__ import annotations

import asyncio
import datetime
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast

import structlog
from app.infrastructure.ingest.trap_types import ParsedTrap, TrapVarBind
from pyasn1.compat.octets import null as _null_octets
from pyasn1.type.univ import OctetString
from pysnmp.entity import config, engine
from pysnmp.proto.api import v1 as _pv1
from pysnmp.proto.api import v2c as _pv2c
from pysnmp.proto.proxy import rfc2576

TrapHandler = Callable[[ParsedTrap, str], None]

_AUTH_PROTOCOLS: dict[str, Any] = {
    "none": config.usmNoAuthProtocol,
    "md5": config.usmHMACMD5AuthProtocol,
    "sha": config.usmHMACSHAAuthProtocol,
}
_PRIVACY_PROTOCOLS: dict[str, Any] = {
    "none": config.usmNoPrivProtocol,
    "des": config.usmDESPrivProtocol,
    "aes128": config.usmAesCfb128Protocol,
}


@dataclass(frozen=True)
class TrapUser:
    """One SNMPv3 USM user row to register (plaintext inside this boundary only).

    ``engine_id_hex`` is the AUTHORITATIVE engine id of the sender (the
    device), because the switch stamps its own engine id + boots/time into
    its traps (RFC 3414 §3.2 semantics as implemented by pysnmp).
    """

    username: str
    engine_id_hex: str
    auth_protocol: str = "sha"
    auth_key: str | None = None
    privacy_protocol: str = "aes128"
    privacy_key: str | None = None


class _TrapPduRegistration:
    """PDU dispatch registration: v1/v2c/v3 traps -> sink callback.

    Mirrors pysnmp's ``NotificationReceiver`` registration (RFC 3412 4.3.x)
    but keeps the security fields AND the wire community so the platform can
    attribute and (for v2c) verify the community at its own layer.
    """

    pdu_types = (_pv1.TrapPDU.tagSet, _pv2c.SNMPv2TrapPDU.tagSet)

    def __init__(self, snmp_engine: engine.SnmpEngine, sink: Callable[[dict[str, object]], None]) -> None:
        self._sink = sink
        self._community = b""
        snmp_engine.msgAndPduDsp.registerContextEngineId(_null_octets, self.pdu_types, self.process_pdu)

        def store_community(
            _snmpEngine: Any,
            _execpoint: str,
            variables: dict[str, object],
            _cbCtx: object,
        ) -> None:
            community = variables.get("communityName")
            if community is not None:
                if isinstance(community, bytes):
                    self._community = community
                else:
                    self._community = str(community).encode("latin-1")

        snmp_engine.observer.registerObserver(store_community, "rfc2576.processIncomingMsg")

    def process_pdu(
        self,
        snmp_engine: engine.SnmpEngine,
        message_processing_model: int,
        security_model: int,
        security_name: Any,
        security_level: Any,
        context_engine_id: Any,
        context_name: Any,
        pdu_version: Any,
        pdu: Any,
        max_size_response_scoped_pdu: int,
        state_reference: Any,
    ) -> None:
        del snmp_engine, context_engine_id, context_name, pdu_version
        del max_size_response_scoped_pdu, state_reference
        if message_processing_model == 0:
            pdu = rfc2576.v1ToV2(pdu, self._community)
        var_binds = [
            (str(name), value)
            for name, value in _pv2c.apiPDU.getVarBinds(pdu)
        ]
        self._sink(
            {
                "mp_model": int(message_processing_model),
                "security_model": int(security_model),
                "security_name": str(security_name),
                "security_level": int(security_level),
                "community": self._community.decode("latin-1") if self._community else None,
                "var_binds": var_binds,
            }
        )


class _TrapDatagramProtocol(asyncio.DatagramProtocol):
    """Feeds raw datagrams + peer address into the engine's decoder."""

    def __init__(self, receiver: TrapReceiver) -> None:
        self._receiver = receiver

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._receiver._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int] | str) -> None:
        peer_ip = addr[0] if isinstance(addr, tuple) else str(addr)
        self._receiver._on_datagram(bytes(data), peer_ip)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - OS path
        self._receiver._log.warning("trap.udp.error", error=type(exc).__name__)


class TrapReceiver:
    """Decodes SNMP traps from its own UDP endpoint through a pysnmp engine."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        handler: TrapHandler,
        engine_id_hex: str,
        logger: structlog.BoundLogger | None = None,
    ) -> None:
        self._host = host
        self._configured_port = port
        self._handler = handler
        self._engine_id_hex = engine_id_hex
        self._log = logger if logger is not None else structlog.get_logger("warden.ingest.trap")
        self.port: int | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._snmp_engine: engine.SnmpEngine | None = None
        self._registration: _TrapPduRegistration | None = None
        self._users: dict[tuple[str, str], TrapUser] = {}
        self._communities: tuple[str, ...] = ()
        self._current_peer: str = ""
        self._started = False

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        self._snmp_engine = engine.SnmpEngine(snmpEngineID=OctetString(hexValue=self._engine_id_hex))
        self._registration = _TrapPduRegistration(self._snmp_engine, self._on_decoded)
        for user in self._users.values():
            self._register_user(user)
        for community in self._communities:
            config.addV1System(self._snmp_engine, f"v2c-{community}", communityName=community)
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _TrapDatagramProtocol(self),
            local_addr=(self._host, self._configured_port),
        )
        sock = self._transport.get_extra_info("sockname")
        self.port = sock[1] if isinstance(sock, tuple) else self._configured_port
        self._started = True
        self._log.info("trap.receiver.started", host=self._host, port=self.port)

    async def stop(self) -> None:
        if not self._started:
            return
        if self._transport is not None:
            self._transport.close()
        if self._snmp_engine is not None and self._snmp_engine.transportDispatcher is not None:
            self._snmp_engine.transportDispatcher.closeDispatcher()
        self._started = False
        self._log.info("trap.receiver.stopped")

    def set_users(self, users: Sequence[TrapUser]) -> None:
        """Replace the USM user rows (delta-applied against the engine)."""
        wanted = {(user.username, user.engine_id_hex): user for user in users}
        removed = set(self._users) - set(wanted)
        added = {key: user for key, user in wanted.items() if key not in self._users}
        for key in removed:
            self._remove_user(key[0], key[1])
        for user in added.values():
            self._register_user(user)
        self._users = wanted

    def set_communities(self, communities: Sequence[str]) -> None:
        """Replace the accepted v2c community rows.

        pysnmp's v2c receive path maps each community to a security name via
        the community MIB (RFC 2576): a community without a row is dropped by
        the engine. The WIRE community is still handed to the platform in
        ``ParsedTrap.community`` so the dispatcher can verify it against the
        attributed device's configuration (v2c authenticates nothing).
        """
        wanted = dict.fromkeys(communities)
        if self._snmp_engine is not None:
            for community in set(self._communities) - set(wanted):
                config.delV1System(self._snmp_engine, f"v2c-{community}")
            for community in set(wanted) - set(self._communities):
                config.addV1System(
                    self._snmp_engine,
                    f"v2c-{community}",
                    communityName=community,
                )
        self._communities = tuple(communities)

    def _register_user(self, user: TrapUser) -> None:
        if self._snmp_engine is None:
            return
        config.addV3User(
            self._snmp_engine,
            user.username,
            _AUTH_PROTOCOLS[user.auth_protocol],
            user.auth_key,
            _PRIVACY_PROTOCOLS[user.privacy_protocol],
            user.privacy_key,
            securityEngineId=OctetString(hexValue=user.engine_id_hex),
        )

    def _remove_user(self, username: str, engine_id_hex: str) -> None:
        if self._snmp_engine is None:
            return
        config.delV3User(
            self._snmp_engine,
            username,
            securityEngineId=OctetString(hexValue=engine_id_hex),
        )

    # -- decode path --------------------------------------------------------

    def _on_datagram(self, data: bytes, peer_ip: str) -> None:
        if self._snmp_engine is None:
            return
        self._current_peer = peer_ip
        # Synchronous decode: USM + MPD + the PDU dispatch all run inside
        # receiveMessage, so _current_peer is per-message (single-threaded
        # asyncio loop, no awaits in between). The transport domain tuple
        # only identifies the carrier type (RFC 3417 snmpUDPDomain).
        self._snmp_engine.msgAndPduDsp.receiveMessage(
            self._snmp_engine,
            (1, 3, 6, 1, 6, 1, 1),
            (peer_ip, 0),
            bytes(data),
        )
        self._current_peer = ""

    def _on_decoded(self, decoded: dict[str, object]) -> None:
        community = decoded.get("community")
        var_binds = tuple(
            TrapVarBind(name=str(name), value=value)
            for name, value in cast(Sequence[tuple[object, object]], decoded.get("var_binds", ()))
        )
        trap = ParsedTrap(
            received_at=datetime.datetime.now(datetime.UTC),
            message_processing_model=int(cast(int, decoded["mp_model"])),
            security_model=int(cast(int, decoded["security_model"])),
            security_name=str(decoded["security_name"]),
            security_level=int(cast(int, decoded["security_level"])),
            community=str(community) if community is not None else None,
            varbinds=var_binds,
        )
        self._handler(trap, self._current_peer)
