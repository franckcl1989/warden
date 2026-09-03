"""Huawei-switch simulator SNMP AGENT (real SNMPv1/v2c/v3 over UDP).

TEST-DEVICE SIMULATOR — not evidence of hardware support (see README.md in
this package). The agent is a pysnmp command responder serving a dict-backed
OID tree: the M5T1 seed set (SNMPv2-MIB system group + IF-MIB ifTable
columns, all RFC-based — app/infrastructure/protocols/snmp/oid.py) populated
from a model profile. The responder machinery (USM auth/decrypt, VACM, GET/
NEXT/BULK, v1 proxy) is pysnmp's real implementation, so the client exercises
genuine protocol behaviour over real UDP:

- v3 users and v2c communities are accepted exactly as configured; a request
  with unknown/wrong credentials gets NO response (v3 USM refuses it, v2c
  community mismatch is silent — the honest wire behaviour);
- every read of a counter leaf advances it by its configured step, so rate
  tests observe monotonic growth;
- walking a subtree terminates at its edge (endOfMibView).

hwEntity / PoE / vendor OIDs are NOT served yet: those OIDs must come from
the M5T2 MIB table with a citable basis ([huawei-doc-url] or [sim]) — nothing
is invented here (M5T1 brief: never guessed OIDs). ``register_oid`` is the
extension point M5T2 uses to mount those trees.
"""

from __future__ import annotations

import socket
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog
from app.infrastructure.protocols.snmp.oid import parse_oid
from pyasn1.type.univ import OctetString
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902
from pysnmp.smi import exval

from tests.simulators.switch.profiles import SwitchProfile

_AGENT_AUTH: dict[str, Any] = {
    "none": config.usmNoAuthProtocol,
    "md5": config.usmHMACMD5AuthProtocol,
    "sha": config.usmHMACSHAAuthProtocol,
}
_AGENT_PRIV: dict[str, Any] = {
    "none": config.usmNoPrivProtocol,
    "des": config.usmDESPrivProtocol,
    "aes128": config.usmAesCfb128Protocol,
}

# IF-MIB ifType 6 = ethernetCsmacd (RFC 2863); ifAdminStatus/ifOperStatus 1
# = up (RFC 2863); sim ports start up unless a knob flips oper status.
_IF_TYPE_ETHERNET_CSMACD = 6
_IF_ADMIN_UP = 1
_IF_OPER_UP = 1


@dataclass(frozen=True)
class AgentCredential:
    """One accepted v3 USM credential (simulator DSL; test-only)."""

    username: str = "monitor"
    auth_protocol: str = "sha"
    auth_key: str | None = None
    privacy_protocol: str = "aes128"
    privacy_key: str | None = None


@dataclass(frozen=True)
class AgentConfig:
    """Agent construction config."""

    profile: SwitchProfile
    host: str = "127.0.0.1"
    port: int = 0  # 0 = pick a free port; the bound port is on SwitchAgent.port
    community: str = "public"  # the accepted v2c community
    v3_user: AgentCredential | None = None  # None = no v3 user accepted
    counter_step_if_in_octets: int = 125_000
    counter_step_if_out_octets: int = 125_000
    counter_step_if_errors: int = 0


class CounterState:
    """Monotonic counter leaf: advances ``step`` on every read (rate tests)."""

    __slots__ = ("value", "step", "kind")

    def __init__(self, kind: str, step: int) -> None:
        self.kind = kind  # counter | counter64
        self.value = 0
        self.step = step

    def read(self) -> int:
        self.value += self.step
        return self.value


def _to_value(raw: object) -> Any:
    """Tree leaf -> typed pysnmp ASN.1 value (tag fidelity matters).

    Accepted leaves: ``int`` -> Integer32; ``str``/``bytes`` -> OctetString;
    tuples ``("ip", text)``; ``("ticks", n)`` -> TimeTicks; ``CounterState``
    -> Counter32/Counter64 advancing one step per read.
    """
    if isinstance(raw, int):
        return rfc1902.Integer32(raw)
    if isinstance(raw, str):
        return rfc1902.OctetString(raw)
    if isinstance(raw, bytes):
        return rfc1902.OctetString(raw)
    if isinstance(raw, CounterState):
        value = raw.read()
        if raw.kind == "counter64":
            return rfc1902.Counter64(value)
        return rfc1902.Counter32(value)
    if isinstance(raw, tuple):
        if raw[0] == "ip":
            return rfc1902.IpAddress(str(raw[1]))
        if raw[0] == "ticks":
            return rfc1902.TimeTicks(int(raw[1]))
    raise TypeError(f"unsupported simulator tree leaf {raw!r}")


def _free_udp_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


class SwitchAgent:
    """One in-process switch simulator speaking real SNMP over UDP."""

    def __init__(
        self,
        config: AgentConfig,
        *,
        logger: structlog.BoundLogger | None = None,
    ) -> None:
        self._config = config
        self._log = logger if logger is not None else structlog.get_logger("sim.switch-agent")
        self.port: int | None = None
        self._engine: engine.SnmpEngine | None = None
        self._snmp_context: context.SnmpContext | None = None
        self._tree: dict[tuple[int, ...], object] = {}
        self._started = False

    # -- OID tree -----------------------------------------------------------

    def register_oid(self, oid: str, leaf: object) -> None:
        """Mount one leaf (M5T2 extension point for the Huawei trees)."""
        self._tree[parse_oid(oid)] = leaf

    def _build_tree(self) -> None:
        profile = self._config.profile
        self._tree = {}
        self.register_oid("1.3.6.1.2.1.1.1.0", profile.sys_descr)  # sysDescr
        self.register_oid("1.3.6.1.2.1.1.5.0", profile.sys_name)  # sysName
        self.register_oid("1.3.6.1.2.1.1.3.0", ("ticks", 1_000_000))  # sysUpTime
        ports = profile.ge_port_count + profile.xge_port_count
        self.register_oid("1.3.6.1.2.1.2.1.0", ports)  # ifNumber
        for index in range(1, ports + 1):
            self.register_oid(f"1.3.6.1.2.1.2.2.1.1.{index}", index)  # ifIndex
            self.register_oid(f"1.3.6.1.2.1.2.2.1.2.{index}", self._port_name(index))  # ifDescr
            self.register_oid(f"1.3.6.1.2.1.2.2.1.3.{index}", _IF_TYPE_ETHERNET_CSMACD)  # ifType
            self.register_oid(f"1.3.6.1.2.1.2.2.1.7.{index}", _IF_ADMIN_UP)  # ifAdminStatus
            self.register_oid(f"1.3.6.1.2.1.2.2.1.8.{index}", _IF_OPER_UP)  # ifOperStatus
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.10.{index}",
                CounterState("counter", self._config.counter_step_if_in_octets),
            )  # ifInOctets
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.16.{index}",
                CounterState("counter", self._config.counter_step_if_out_octets),
            )  # ifOutOctets
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.14.{index}",
                CounterState("counter", self._config.counter_step_if_errors),
            )  # ifInErrors
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.20.{index}",
                CounterState("counter", self._config.counter_step_if_errors),
            )  # ifOutErrors

    def _port_name(self, index: int) -> str:
        profile = self._config.profile
        if index <= profile.ge_port_count:
            return f"GigabitEthernet0/0/{index}"
        return f"XGigabitEthernet0/0/{index - profile.ge_port_count}"

    # -- knobs --------------------------------------------------------------

    def set_link_state(self, index: int, *, up: bool) -> None:
        """Flip ifOperStatus for one port (1=up, 2=down; RFC 2863)."""
        oid = parse_oid(f"1.3.6.1.2.1.2.2.1.8.{index}")
        if oid not in self._tree:
            msg = f"unknown simulator port index {index}"
            raise ValueError(msg)
        self._tree[oid] = _IF_OPER_UP if up else 2

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        profile = self._config.profile
        self._build_tree()
        port = self._config.port or _free_udp_port(self._config.host)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._engine = engine.SnmpEngine(snmpEngineID=OctetString(hexValue=profile.engine_id_hex))
        config.addTransport(
            self._engine,
            udp.domainName,
            udp.UdpTransport().openServerMode((self._config.host, port)),
        )
        config.addV1System(self._engine, "v2c-area", communityName=self._config.community)
        config.addVacmUser(self._engine, 2, "v2c-area", "noAuthNoPriv", (1, 3, 6))
        user = self._config.v3_user
        if user is not None:
            config.addV3User(
                self._engine,
                user.username,
                _AGENT_AUTH[user.auth_protocol],
                user.auth_key,
                _AGENT_PRIV[user.privacy_protocol],
                user.privacy_key,
            )
            config.addVacmUser(self._engine, 3, user.username, "authPriv", (1, 3, 6))
        self._snmp_context = context.SnmpContext(self._engine)
        # The payload tree is the dict tree (all requests answer from it);
        # USM/MPD keep the engine's own MIB controller for auth/engine state.
        self._snmp_context.contextNames[b""] = _DictInstrumentation(self._tree)
        cmdrsp.GetCommandResponder(self._engine, self._snmp_context)
        cmdrsp.NextCommandResponder(self._engine, self._snmp_context)
        cmdrsp.BulkCommandResponder(self._engine, self._snmp_context)
        self.port = port
        self._started = True
        self._log.info(
            "sim.switch-agent.started",
            profile=profile.profile_key,
            model=profile.model,
            port=self.port,
        )

    async def stop(self) -> None:
        if not self._started:
            return
        if self._engine is not None and self._engine.transportDispatcher is not None:
            self._engine.transportDispatcher.closeDispatcher()
        self._started = False

    @property
    def profile(self) -> SwitchProfile:
        return self._config.profile


class _DictInstrumentation:
    """Pseudo MIB instrumentation over the dict tree (sync read contract)."""

    def __init__(self, tree: Mapping[tuple[int, ...], object]) -> None:
        self._tree = tree

    def _next_key(self, name: tuple[int, ...]) -> tuple[int, ...] | None:
        for key in sorted(self._tree):
            if key > name:
                return key
        return None

    def readVars(self, varBinds: list[Any], acInfo: tuple[Any, Any] = (None, None)) -> list[Any]:
        del acInfo
        out: list[Any] = []
        for var_bind in varBinds:
            name = tuple(int(part) for part in var_bind[0])
            if name not in self._tree:
                out.append((var_bind[0], exval.noSuchInstance))
                continue
            out.append((var_bind[0], _to_value(self._tree[name])))
        return out

    def readNextVars(self, varBinds: list[Any], acInfo: tuple[Any, Any] = (None, None)) -> list[Any]:
        del acInfo
        out: list[Any] = []
        for var_bind in varBinds:
            name = tuple(int(part) for part in var_bind[0])
            next_key = self._next_key(name)
            if next_key is None:
                out.append((var_bind[0], exval.endOfMib))
                continue
            dotted = ".".join(str(part) for part in next_key)
            out.append((rfc1902.ObjectName(dotted), _to_value(self._tree[next_key])))
        return out

    def writeVars(self, varBinds: list[Any], acInfo: tuple[Any, Any] = (None, None)) -> list[Any]:
        del varBinds, acInfo
        raise exval.NoSuchObjectError(idx=0)
