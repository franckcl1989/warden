"""Switch simulator SYSLOG + TRAP emitters (test-only, real UDP).

TEST-DEVICE SIMULATOR — not evidence of hardware support. The emitters send
real UDP syslog datagrams and SNMP traps to a receiver so ingest tests and
M5T2+ adapter tests exercise genuine wire behaviour.

Syslog wording is the fixture-DSL counterpart of the platform's [sim]
classification rows (app/infrastructure/ingest/dispatcher.py): both sides are
declared together and marked [sim] until real VRP log wording is archived
during hardware certification. The trap OIDs are the RFC-standard
notifications (coldStart/warmStart/linkDown/linkUp/authenticationFailure).

The v1/v2c/v3 trap senders are pysnmp engines with fixed per-profile engine
ids (v3 USM needs the receiver to know the authoritative engine id + keys,
exactly like a real switch configured to send authPriv traps to Warden).
"""

from __future__ import annotations

import datetime
import warnings
from dataclasses import dataclass

import structlog
from pyasn1.type.univ import OctetString
from pysnmp.entity import config, engine
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

# --- syslog line builders (fixture DSL wording, [sim]) ----------------------


def vrp_link_state_line(
    *,
    hostname: str,
    interface: str,
    direction: str,  # "up" | "down"
    when: datetime.datetime | None = None,
    rfc5424: bool = False,
    priority: int = 190,
) -> str:
    """One VRP-style LINK_STATE syslog line the platform classifies as flap."""
    if direction == "down":
        state = "The protocol state of the link turned from UP to DOWN."
    elif direction == "up":
        state = "The protocol state of the link turned from DOWN to UP."
    else:
        raise ValueError(f"unknown flap direction {direction!r}")
    moment = when if when is not None else datetime.datetime.now(datetime.UTC)
    content = f"{interface}: {state}"
    return _format_line(hostname, "%%01IFNET/4/LINK_STATE(l)", content, moment, rfc5424, priority)


def vrp_restart_line(
    *,
    hostname: str,
    when: datetime.datetime | None = None,
    rfc5424: bool = False,
    priority: int = 190,
) -> str:
    """One device-restart syslog line (classifies event.device_restart)."""
    moment = when if when is not None else datetime.datetime.now(datetime.UTC)
    return _format_line(hostname, "%%01SYS/5/RESTART(l)", "System restarted", moment, rfc5424, priority)


def vrp_auth_failure_line(
    *,
    hostname: str,
    when: datetime.datetime | None = None,
    rfc5424: bool = False,
    priority: int = 190,
) -> str:
    """One login-failure syslog line (classifies event.auth_failure)."""
    moment = when if when is not None else datetime.datetime.now(datetime.UTC)
    return _format_line(
        hostname, "%%01SECE/4/AUTH_FAIL(l)", "Authentication failed for user", moment, rfc5424, priority
    )


def generic_line(
    *,
    hostname: str,
    content: str,
    when: datetime.datetime | None = None,
    rfc5424: bool = False,
    priority: int = 190,
) -> str:
    """Any other line (classifies to nothing -> counted drop in tests)."""
    moment = when if when is not None else datetime.datetime.now(datetime.UTC)
    return _format_line(hostname, "%%01SHELL/5/CMD(l)", content, moment, rfc5424, priority)


def _format_line(
    hostname: str,
    tag: str,
    content: str,
    when: datetime.datetime,
    rfc5424: bool,
    priority: int,
) -> str:
    if rfc5424:
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return f"<{priority}>1 {stamp} {hostname} warden-sim 0 - - {content}"
    # RFC3164 / VRP style with a year: "Aug  4 2026 14:22:01"
    month = when.strftime("%b")
    day = when.day
    stamp = when.strftime("%H:%M:%S")
    return f"<{priority}>{month} {day:>2} {when.year} {stamp} {hostname} {tag}: {content}"


# --- trap emitter -----------------------------------------------------------


@dataclass(frozen=True)
class TrapCredentials:
    """Trap emitter credentials: v2c community and/or v3 USM user."""

    community: str | None = "public"
    username: str | None = None
    auth_key: str | None = None
    privacy_key: str | None = None


class TrapEmitter:
    """Sends RFC-standard traps to one receiver address over real UDP."""

    def __init__(
        self,
        *,
        profile_engine_id_hex: str,
        host: str = "127.0.0.1",
        port: int,
        credentials: TrapCredentials | None = None,
        logger: structlog.BoundLogger | None = None,
    ) -> None:
        self._engine_id_hex = profile_engine_id_hex
        self._host = host
        self._port = port
        self._credentials = credentials if credentials is not None else TrapCredentials()
        self._log = logger if logger is not None else structlog.get_logger("sim.switch-trap-emitter")
        self._engine: engine.SnmpEngine | None = None

    def _ensure_engine(self) -> engine.SnmpEngine:
        if self._engine is not None:
            return self._engine
        credentials = self._credentials
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._engine = engine.SnmpEngine(snmpEngineID=OctetString(hexValue=self._engine_id_hex))
        if credentials.username is not None:
            config.addV3User(
                self._engine,
                credentials.username,
                config.usmHMACSHAAuthProtocol,
                credentials.auth_key,
                config.usmAesCfb128Protocol,
                credentials.privacy_key,
            )
        return self._engine

    def _target(self) -> UdpTransportTarget:
        return UdpTransportTarget((self._host, self._port), timeout=2, retries=0)

    async def send_v3(self, trap_oid: str, *, if_index: int | None = None) -> None:
        """One authPriv v3 trap (SHA/AES-128; the M5T1 default level)."""
        credentials = self._credentials
        if credentials.username is None:
            msg = "v3 trap requires v3 credentials on the emitter"
            raise ValueError(msg)
        engine_obj = self._ensure_engine()
        notification = NotificationType(ObjectIdentity(trap_oid))
        if if_index is not None:
            notification = notification.addVarBinds(
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1"), rfc1902.Integer32(if_index))
            )
        error_indication, error_status, error_index, _varbinds = await sendNotification(
            engine_obj,
            UsmUserData(
                credentials.username,
                credentials.auth_key,
                credentials.privacy_key,
                usmHMACSHAAuthProtocol,
                usmAesCfb128Protocol,
            ),
            self._target(),
            ContextData(),
            "trap",
            notification,
        )
        if error_indication is not None:
            self._log.warning("sim.trap-emitter.send-failed", error=str(error_indication))
        if error_status:
            self._log.warning("sim.trap-emitter.error-status", status=int(error_status))
        del error_index

    async def send_v2c(self, trap_oid: str, *, if_index: int | None = None) -> None:
        """One v2c trap with the configured community."""
        credentials = self._credentials
        community = credentials.community
        if community is None:
            msg = "v2c trap requires a community on the emitter"
            raise ValueError(msg)
        notification = NotificationType(ObjectIdentity(trap_oid))
        if if_index is not None:
            notification = notification.addVarBinds(
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1"), rfc1902.Integer32(if_index))
            )
        engine_obj = SnmpEngine()
        try:
            error_indication, error_status, _error_index, _varbinds = await sendNotification(
                engine_obj,
                CommunityData(community, mpModel=1),  # noqa: S508 - simulator v2c fixture
                self._target(),
                ContextData(),
                "trap",
                notification,
            )
        finally:
            engine_obj.transportDispatcher.closeDispatcher()
        if error_indication is not None:
            self._log.warning("sim.trap-emitter.send-failed", error=str(error_indication))
        if error_status:
            self._log.warning("sim.trap-emitter.error-status", status=int(error_status))

    async def close(self) -> None:
        if self._engine is not None and self._engine.transportDispatcher is not None:
            self._engine.transportDispatcher.closeDispatcher()
        self._engine = None


# RFC-standard notification OIDs (dispatcher [rfc-3418]/[rfc-2863] rows).
TRAP_COLD_START = "1.3.6.1.6.3.1.1.5.1"
TRAP_WARM_START = "1.3.6.1.6.3.1.1.5.2"
TRAP_LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
TRAP_LINK_UP = "1.3.6.1.6.3.1.1.5.4"
TRAP_AUTH_FAILURE = "1.3.6.1.6.3.1.1.5.5"
