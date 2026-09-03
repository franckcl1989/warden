"""Huawei-switch simulator SNMP AGENT (real SNMPv1/v2c/v3 over UDP).

TEST-DEVICE SIMULATOR — not evidence of hardware support (see README.md in
this package). The agent is a pysnmp command responder serving a dict-backed
OID tree populated from a model profile:

- the M5T1 seed set (SNMPv2-MIB system group + IF-MIB ifTable columns, all
  RFC-based — app/infrastructure/protocols/snmp/oid.py);
- the M5T2 Huawei trees mounted from the adapter ledger
  (app/adapters/huawei/oids.py — every row carries its [basis] tag; the
  Huawei subtree rows are [sim] DSL served exactly as declared there,
  never invented in this module): CPU/memory scalars, hwEntityStateTable,
  hwOpticalModuleInfoTable, hwPoEPortTable + hwPoEDeviceTable scalars,
  loop/broadcast scalars, hwStpPortTable, hwPortCrcErrorsTable and the
  RFC-2863 ifXTable 64-bit HC counters + discard counters the adapter's
  rate derivation reads.

The responder machinery (USM auth/decrypt, VACM, GET/NEXT/BULK, v1 proxy)
is pysnmp's real implementation, so the client exercises genuine protocol
behaviour over real UDP:

- v3 users and v2c communities are accepted exactly as configured; a request
  with unknown/wrong credentials gets NO response (v3 USM refuses it, v2c
  community mismatch is silent — the honest wire behaviour);
- every read of a counter leaf advances it by its configured step, so rate
  tests observe monotonic growth (``CounterState``; an optional ``wrap_at``
  rolls the value back to a small base to exercise the adapter's
  counter_reset partial-quality path). To keep those per-pass advances
  DETERMINISTIC, GETBULK/GETNEXT continuations terminate at registered
  column/scalar REGION edges (endOfMibView) instead of serving into the
  next table — real agents return the foreign rows too but their counters
  do not move on reads; here a foreign tail read would advance another
  table's counters, so the responder bounds each continuation to its
  region. Walking a subtree therefore returns exactly its own rows.
- walking a subtree terminates at its edge (endOfMibView).

Model profiles define the per-model MIB shapes (entity slots, optics
presence, PoE layout, static CPU/memory utilizations); knobs (methods on
``SwitchAgent``) flip device state for the honest-state tests (fan fault,
PoE budget removal, HC wrap, transceiver removal, per-port admin/oper/STP/
PoE states, loop/broadcast detection).
"""

from __future__ import annotations

import socket
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog
from app.adapters.huawei import oids as huawei_oids
from app.infrastructure.protocols.snmp import oid as snmp_oid_module
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

# [sim] hwEntityStateTable semantics (adapter ledger, app/adapters/huawei):
# type 1=psu 2=fan 3=temperature; present 1=present 2=absent;
# status 1=normal 2=fault 3=unknown.
_ENTITY_TYPE_PSU = 1
_ENTITY_TYPE_FAN = 2
_ENTITY_TYPE_TEMP = 3
_ENTITY_PRESENT_YES = 1
_ENTITY_STATUS_NORMAL = 1
# [sim] PoE port states: 1=on 2=off 3=denied 4=fault 5=unknown.
_POE_ON = 1
# [sim] PoE device alarm: 1=normal 2=warning 3=critical.
_POE_ALARM_NORMAL = 1
# [sim] loop/broadcast + STP: normal/detected; forwarding state.
_LAYER2_NORMAL = 1
_STP_FORWARDING = 4
# RFC 2863 ifAdmin/ifOper "down" literals.
_IF_DOWN = 2


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
    counter_step_if_discards: int = 0
    counter_step_crc: int = 0
    #: When set, the 64-bit HC octet counters roll back to a small base once
    #: they reach this value (exercises the adapter's counter_reset partial
    #: quality path; values in octets).
    hc_wrap_at: int | None = None
    #: Per-test identity override: when set, sysDescr serves this text
    #: instead of the profile's (cross-model rejection probes).
    sys_descr_override: str | None = None


class CounterState:
    """Monotonic counter leaf: advances ``step`` on every read (rate tests).

    ``wrap_at`` (optional): once the value reaches it, the next read rolls
    back to ``step`` and keeps ascending — a device restart/rollover
    simulation for the adapter's counter_reset partial-quality path.
    """

    __slots__ = ("value", "step", "kind", "wrap_at", "reads")

    def __init__(self, kind: str, step: int, wrap_at: int | None = None) -> None:
        self.kind = kind  # counter | counter64
        self.value = 0
        self.step = step
        self.wrap_at = wrap_at
        self.reads = 0

    def read(self) -> int:
        self.reads += 1
        if self.wrap_at is not None and self.value >= self.wrap_at:
            self.value = self.step
        else:
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


def _registered_regions() -> tuple[tuple[int, ...], ...]:
    """Every registered scalar leaf or table-column prefix as a region.

    GETBULK/GETNEXT continuations must not cross a region edge (module
    docstring: counter side effects must stay per-pass deterministic).
    """
    regions: set[tuple[int, ...]] = set()
    for row in snmp_oid_module.SEED_SYSTEM:
        regions.add(parse_oid(str(row["oid"])))
    for row in snmp_oid_module.SEED_IFTABLE_COLUMNS:
        regions.add(parse_oid(str(row["oid"])))
    for row in huawei_oids.ROWS:
        regions.add(parse_oid(str(row["oid"])))
    return tuple(sorted(regions))


# --- per-profile MIB shapes ([sim] DSL, declared once per profile) ------------
# hwEntityStateTable rows per profile: (slot arc, name, type, present,
# status, value). value = fan rpm / temp*10; None = the leaf is not served
# for that row (walk returns the other rows).
_PROFILE_ENTITIES: dict[str, tuple[tuple[int, str, int, int, int, int | None], ...]] = {
    "core_s5732": (
        (1, "PSU1", _ENTITY_TYPE_PSU, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, None),
        (2, "PSU2", _ENTITY_TYPE_PSU, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, None),
        (3, "FAN1", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 6200),
        (4, "FAN2", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 6100),
        (5, "FAN3", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 6000),
        (6, "FAN4", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 5900),
        (7, "SystemTemp", _ENTITY_TYPE_TEMP, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 342),
    ),
    "core_s5731s": (
        (1, "PSU1", _ENTITY_TYPE_PSU, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, None),
        # PSU2 slot installed-but-absent: exercises the absent-entity path.
        (2, "PSU2", _ENTITY_TYPE_PSU, 2, _ENTITY_STATUS_NORMAL, None),
        (3, "FAN1", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 5200),
        (4, "FAN2", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 5100),
        (5, "SystemTemp", _ENTITY_TYPE_TEMP, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 352),
    ),
    "access_s5735": (
        (1, "PSU1", _ENTITY_TYPE_PSU, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, None),
        (2, "FAN1", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 4800),
        (3, "FAN2", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 4700),
        (4, "FAN3", _ENTITY_TYPE_FAN, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 4600),
        (5, "SystemTemp", _ENTITY_TYPE_TEMP, _ENTITY_PRESENT_YES, _ENTITY_STATUS_NORMAL, 365),
    ),
}

# CPU (5s/1min/5min) + memory utilization per profile (percent, [sim] DSL).
_PROFILE_UTILIZATION: dict[str, tuple[int, int, int, int]] = {
    "core_s5732": (12, 10, 9, 41),
    "core_s5731s": (8, 7, 6, 33),
    "access_s5735": (5, 4, 4, 28),
}

# PoE per-port default (state, power_mw) tri-state map for the access
# profile ([sim]): 16 powered ports x 5000 mW = 80000 mW of a 400000 mW
# budget -> total_power_percent 20.0.
_PROFILE_POE_TOTAL_MW = 80_000
_PROFILE_POE_BUDGET_MW = 400_000


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

    def _register_octet_counter_pair(self, prefix: str, step: int, wrap_at: int | None = None) -> None:
        """64-bit HC octet counters for the ifXTable columns (RFC 2863).

        One CounterState PER port leaf (the ifTable octet counters follow
        the same pattern) so every port advances exactly ``step`` per
        collect pass — deterministic rate tests. ``wrap_at`` rolls each
        port's counter back to ``step`` once it reaches the boundary (the
        adapter's counter_reset partial-quality path).
        """
        for index in range(1, self._port_count() + 1):
            for suffix in (6, 10):
                self.register_oid(
                    f"{prefix}.{suffix}.{index}",
                    CounterState("counter64", step, wrap_at=wrap_at),
                )

    def _port_count(self) -> int:
        profile = self._config.profile
        return profile.ge_port_count + profile.xge_port_count

    def _xge_start_index(self) -> int:
        return self._config.profile.ge_port_count + 1

    def _build_tree(self) -> None:
        profile = self._config.profile
        self._tree = {}
        override = self._config.sys_descr_override
        sys_descr = override if override is not None else profile.sys_descr
        self.register_oid(huawei_oids.OID_SYS_DESCR, sys_descr)  # sysDescr
        self.register_oid("1.3.6.1.2.1.1.5.0", profile.sys_name)  # sysName
        self.register_oid("1.3.6.1.2.1.1.3.0", ("ticks", 1_000_000))  # sysUpTime
        self.register_oid(huawei_oids.OID_SNMP_ENGINE_ID, profile.engine_id_hex)  # snmpEngineID [rfc-3411]
        ports = self._port_count()
        self.register_oid("1.3.6.1.2.1.2.1.0", ports)  # ifNumber
        for index in range(1, ports + 1):
            name = self._port_name(index)
            self.register_oid(f"1.3.6.1.2.1.2.2.1.1.{index}", index)  # ifIndex
            self.register_oid(f"1.3.6.1.2.1.2.2.1.2.{index}", name)  # ifDescr
            self.register_oid(f"1.3.6.1.2.1.2.2.1.3.{index}", _IF_TYPE_ETHERNET_CSMACD)  # ifType
            self.register_oid(f"1.3.6.1.2.1.2.2.1.7.{index}", _IF_ADMIN_UP)  # ifAdminStatus
            self.register_oid(f"1.3.6.1.2.1.2.2.1.8.{index}", _IF_OPER_UP)  # ifOperStatus
            self.register_oid(f"1.3.6.1.2.1.31.1.1.1.1.{index}", name)  # ifName [rfc-2863]
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.10.{index}",
                CounterState("counter", self._config.counter_step_if_in_octets),
            )  # ifInOctets
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.16.{index}",
                CounterState("counter", self._config.counter_step_if_out_octets),
            )  # ifOutOctets
            # One CounterState PER leaf so per-pass deltas are deterministic
            # (the M5T2 sums errors/discards over both direction leaves).
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.14.{index}",
                CounterState("counter", self._config.counter_step_if_errors),
            )  # ifInErrors
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.20.{index}",
                CounterState("counter", self._config.counter_step_if_errors),
            )  # ifOutErrors
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.13.{index}",
                CounterState("counter", self._config.counter_step_if_discards),
            )  # ifInDiscards
            self.register_oid(
                f"1.3.6.1.2.1.2.2.1.19.{index}",
                CounterState("counter", self._config.counter_step_if_discards),
            )  # ifOutDiscards
            self.register_oid(
                f"{huawei_oids.COL_CRC_ERRORS}.{index}",
                CounterState("counter", self._config.counter_step_crc),
            )  # hwPortCrcErrors [sim]
        # 64-bit HC counters (ifXTable) advance per read with the octet step.
        self._register_octet_counter_pair(
            "1.3.6.1.2.1.31.1.1.1",
            self._config.counter_step_if_in_octets,
            wrap_at=self._config.hc_wrap_at,
        )
        self._register_m5t2_trees()
        self._log.info(
            "sim.switch-agent.tree",
            profile=profile.profile_key,
            rows=len(self._tree),
        )

    def _register_m5t2_trees(self) -> None:
        """Mount the M5T2 Huawei tables ([sim] DSL per profile layout)."""
        profile = self._config.profile
        util = _PROFILE_UTILIZATION[profile.profile_key]
        self.register_oid(huawei_oids.OID_CPU_UTIL_5S, util[0])
        self.register_oid(huawei_oids.OID_CPU_UTIL_1MIN, util[1])
        self.register_oid(huawei_oids.OID_CPU_UTIL_5MIN, util[2])
        self.register_oid(huawei_oids.OID_MEM_UTIL, util[3])
        for slot, name, etype, present, status, value in _PROFILE_ENTITIES[profile.profile_key]:
            self.register_oid(f"{huawei_oids.COL_ENTITY_NAME}.{slot}", name)
            self.register_oid(f"{huawei_oids.COL_ENTITY_TYPE}.{slot}", etype)
            self.register_oid(f"{huawei_oids.COL_ENTITY_PRESENT}.{slot}", present)
            self.register_oid(f"{huawei_oids.COL_ENTITY_STATUS}.{slot}", status)
            if value is not None:
                self.register_oid(f"{huawei_oids.COL_ENTITY_VALUE}.{slot}", value)
        # Optical modules on the uplink ports (ifIndex 49..52 = XGE SFP+).
        optics_values: dict[str, int] = {
            "rx": -250,  # -2.50 dBm
            "tx": -180,  # -1.80 dBm
            "temp": 3500,  # 35.00 C
            "volt": 3300,  # 3.300 V
            "current": 7200,  # 7.200 mA
        }
        for if_index in range(self._xge_start_index(), self._port_count() + 1):
            self.register_oid(f"{huawei_oids.COL_OPTICS_RX}.{if_index}", optics_values["rx"])
            self.register_oid(f"{huawei_oids.COL_OPTICS_TX}.{if_index}", optics_values["tx"])
            self.register_oid(f"{huawei_oids.COL_OPTICS_TEMP}.{if_index}", optics_values["temp"])
            self.register_oid(f"{huawei_oids.COL_OPTICS_VOLT}.{if_index}", optics_values["volt"])
            self.register_oid(f"{huawei_oids.COL_OPTICS_CURRENT}.{if_index}", optics_values["current"])
        if profile.profile_key == "access_s5735":
            # PoE on the 48 GE downlink ports ([sim] layout described at the
            # _PROFILE_POE_* constants).
            for if_index in range(1, profile.ge_port_count + 1):
                if if_index <= 16:
                    state, power_mw = _POE_ON, 5000
                elif if_index == 17:
                    state, power_mw = 3, 0  # denied
                elif if_index == 18:
                    state, power_mw = 4, 0  # fault
                else:
                    state, power_mw = 2, 0  # off
                self.register_oid(f"{huawei_oids.COL_POE_STATE}.{if_index}", state)
                self.register_oid(f"{huawei_oids.COL_POE_POWER_MW}.{if_index}", power_mw)
            self.register_oid(huawei_oids.OID_POE_TOTAL_MW, _PROFILE_POE_TOTAL_MW)
            self.register_oid(huawei_oids.OID_POE_BUDGET_MW, _PROFILE_POE_BUDGET_MW)
            self.register_oid(huawei_oids.OID_POE_ALARM, _POE_ALARM_NORMAL)
        if profile.device_type == "core_switch":
            # Layer2 + STP trees only on core profiles (the core adapter maps
            # CORE-MON-05; the access adapter never reads them).
            self.register_oid(huawei_oids.OID_LOOP_STATUS, _LAYER2_NORMAL)
            self.register_oid(huawei_oids.OID_STORM_STATUS, _LAYER2_NORMAL)
            for if_index in range(1, self._port_count() + 1):
                self.register_oid(f"{huawei_oids.COL_STP_STATE}.{if_index}", _STP_FORWARDING)

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
        self._tree[oid] = _IF_OPER_UP if up else _IF_DOWN

    def set_admin_state(self, index: int, *, up: bool) -> None:
        """Flip ifAdminStatus for one port (1=up, 2=down; RFC 2863)."""
        oid = parse_oid(f"1.3.6.1.2.1.2.2.1.7.{index}")
        if oid not in self._tree:
            msg = f"unknown simulator port index {index}"
            raise ValueError(msg)
        self._tree[oid] = _IF_ADMIN_UP if up else _IF_DOWN

    def _require_leaf(self, oid: str) -> tuple[tuple[int, ...], object]:
        parsed = parse_oid(oid)
        if parsed not in self._tree:
            msg = f"unknown simulator leaf {oid}"
            raise ValueError(msg)
        return parsed, self._tree[parsed]

    def set_fan_fault(self, slot: int, *, fault: bool) -> None:
        """Flip one fan entity slot's status (1 normal / 2 fault, [sim])."""
        parsed, _ = self._require_leaf(f"{huawei_oids.COL_ENTITY_STATUS}.{slot}")
        self._tree[parsed] = 2 if fault else _ENTITY_STATUS_NORMAL

    def set_psu_present(self, slot: int, *, present: bool) -> None:
        """Flip one PSU entity slot's present state (1/2, [sim])."""
        parsed, _ = self._require_leaf(f"{huawei_oids.COL_ENTITY_PRESENT}.{slot}")
        self._tree[parsed] = _ENTITY_PRESENT_YES if present else 2

    def set_transceiver_present(self, if_index: int, *, present: bool) -> None:
        """Install/remove the optical-module rows of one uplink port.

        Removing a module leaves the port WITHOUT transceiver rows (the
        adapter must produce no point/component for it, never a 0).
        """
        if present:
            for column, raw in (
                (huawei_oids.COL_OPTICS_RX, -250),
                (huawei_oids.COL_OPTICS_TX, -180),
                (huawei_oids.COL_OPTICS_TEMP, 3500),
                (huawei_oids.COL_OPTICS_VOLT, 3300),
                (huawei_oids.COL_OPTICS_CURRENT, 7200),
            ):
                self._tree[parse_oid(f"{column}.{if_index}")] = raw
        else:
            for column in (
                huawei_oids.COL_OPTICS_RX,
                huawei_oids.COL_OPTICS_TX,
                huawei_oids.COL_OPTICS_TEMP,
                huawei_oids.COL_OPTICS_VOLT,
                huawei_oids.COL_OPTICS_CURRENT,
            ):
                self._tree.pop(parse_oid(f"{column}.{if_index}"), None)

    def set_poe_port_state(self, if_index: int, state: int) -> None:
        """Set one PoE port's state literal (1=on 2=off 3=denied 4=fault
        5=unknown, [sim])."""
        parsed, _ = self._require_leaf(f"{huawei_oids.COL_POE_STATE}.{if_index}")
        self._tree[parsed] = state

    def set_poe_port_power_mw(self, if_index: int, power_mw: int) -> None:
        parsed, _ = self._require_leaf(f"{huawei_oids.COL_POE_POWER_MW}.{if_index}")
        self._tree[parsed] = power_mw

    def set_poe_budget_present(self, present: bool) -> None:
        """Mount/remove the PoE budget leaf (the no_budget_denominator
        knob: with no budget the adapter must never fake a percent)."""
        if present:
            self._tree[parse_oid(huawei_oids.OID_POE_BUDGET_MW)] = _PROFILE_POE_BUDGET_MW
        else:
            self._tree.pop(parse_oid(huawei_oids.OID_POE_BUDGET_MW), None)

    def set_poe_alarm_state(self, code: int) -> None:
        """Set the device PoE alarm state literal (1=normal 2=warning
        3=critical, [sim])."""
        parsed, _ = self._require_leaf(huawei_oids.OID_POE_ALARM)
        self._tree[parsed] = code

    def set_loop_detected(self, detected: bool) -> None:
        parsed, _ = self._require_leaf(huawei_oids.OID_LOOP_STATUS)
        self._tree[parsed] = 2 if detected else _LAYER2_NORMAL

    def set_storm_detected(self, detected: bool) -> None:
        parsed, _ = self._require_leaf(huawei_oids.OID_STORM_STATUS)
        self._tree[parsed] = 2 if detected else _LAYER2_NORMAL

    def set_stp_state(self, if_index: int, code: int) -> None:
        """Set one port's STP state literal (1=disabled 2=discarding
        3=learning 4=forwarding 5=broken, [sim])."""
        parsed, _ = self._require_leaf(f"{huawei_oids.COL_STP_STATE}.{if_index}")
        self._tree[parsed] = code

    def set_crc_step(self, step: int) -> None:
        """Replace every hwPortCrcErrors leaf state with the new step
        (post-boot knob so error-counter tests stay deterministic)."""
        prefix = tuple(parse_oid(huawei_oids.COL_CRC_ERRORS))
        for oid in list(self._tree):
            if len(oid) == len(prefix) + 1 and oid[: len(prefix)] == prefix:
                self._tree[oid] = CounterState("counter", step)

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
        self._snmp_context.contextNames[b""] = _DictInstrumentation(self._tree, _registered_regions())
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

    def __init__(self, tree: Mapping[tuple[int, ...], object], regions: tuple[tuple[int, ...], ...]) -> None:
        self._tree = tree
        self._regions = regions

    def _region_of(self, oid: tuple[int, ...]) -> tuple[int, ...] | None:
        """The registered column/scalar region the OID belongs to (or None).

        The tree is a flat dict of registered column rows + scalars; a
        GETBULK/GETNEXT continuation must not cross a region edge (see
        _build_tree docs on counter side effects)."""
        for width in range(len(oid), 0, -1):
            if oid[:width] in self._regions:
                return oid[:width]
        return None

    def _next_key(self, name: tuple[int, ...]) -> tuple[int, ...] | None:
        region = self._region_of(name)
        for key in sorted(self._tree):
            if key <= name:
                continue
            if region is not None and self._region_of(key) != region:
                return None
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
