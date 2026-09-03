"""Huawei VRP switch MIB table (M5T2) — every OID with a [basis] tag.

docs/DEVICE_ADAPTERS.md §6.2-6.4 maps CORE-MON-01..05 / ACCESS-MON-01..05
to Huawei SNMP sources. This module is the adapter's OID ledger (the M5T2
owner of the Huawei trees; the SNMP client registry in
app/infrastructure/protocols/snmp/oid.py keeps the RFC seed set):

- RFC leaves and table columns are cited to their RFC
  ([rfc-3411] SNMP-FRAMEWORK-MIB snmpEngineID, [rfc-2863] IF-MIB ifXTable
  ifName/ifHCInOctets/ifHCOutOctets + ifTable discard counters,
  [rfc-3418] SNMPv2-MIB sysDescr);
- the Huawei enterprise prefix ``1.3.6.1.4.1.2011`` is cited to the IANA
  Private Enterprise Numbers registry (the Huawei Technologies PEN);
- EVERYTHING under the Huawei prefix is [sim] DSL in this build: a
  Huawei-support MIB reference fetch was attempted (2026-09-04,
  support.huawei.com/enterprise) and the environment could not reach a
  citable page — the same outcome M5T1 recorded. The subtree numbers,
  table names and enum semantics below are simulator-declared fixtures that
  hardware certification must replace with per-model/VRP MIB evidence
  (ADR-018; docs/DEVICE_ADAPTERS.md §6). No OID here is claimed to be a
  real Huawei MIB object, and no row without a citable basis exists.

The simulator (tests/simulators/switch) serves exactly the leaves of this
ledger (honesty cross-test), so adapter and simulator can never drift.
"""

from __future__ import annotations

# --- basis tags (cited sources) ---------------------------------------------
RFC_2863 = "[rfc-2863]"  # RFC 2863 IF-MIB (ifXTable / discard counters)
RFC_3411 = "[rfc-3411]"  # RFC 3411 SNMP-FRAMEWORK-MIB (snmpEngineID)
RFC_3418 = "[rfc-3418]"  # RFC 3418 SNMPv2-MIB (system group)
# IANA Private Enterprise Numbers registry (Huawei Technologies = 2011):
# https://www.iana.org/assignments/enterprise-numbers (fetched 2026-09-04).
IANA_ENTERPRISE = "[iana-enterprise-numbers]"
# Simulator DSL: subtree structure/columns/enums declared by the TEST-DEVICE
# simulator (tests/simulators/switch/README.md); not hardware evidence.
SIM = "[sim]"

# Huawei private enterprise subtree (IANA PEN 2011 — prefix only; the rest
# of the tree under it is simulator-declared, see module docstring).
HUAWEI_PEN = "1.3.6.1.4.1.2011"
# Simulator-declared monitoring subtree (root for every [sim] row below).
SIM_MONITOR_ROOT = f"{HUAWEI_PEN}.5.25.31"

# --- scalars the adapter reads directly (exported for simulator + tests) -----
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"  # sysDescr [rfc-3418]
OID_SNMP_ENGINE_ID = "1.3.6.1.6.3.10.2.1.1.0"  # snmpEngineID [rfc-3411]
# hwCpuDevTable analog, device row 1 ([sim]).
OID_CPU_UTIL_5S = f"{SIM_MONITOR_ROOT}.1.1.1"  # hwCpuDevUtilization5s (%, mapped)
OID_CPU_UTIL_1MIN = f"{SIM_MONITOR_ROOT}.1.1.2"  # hwCpuDevUtilization1min (%)
OID_CPU_UTIL_5MIN = f"{SIM_MONITOR_ROOT}.1.1.3"  # hwCpuDevUtilization5min (%)
OID_MEM_UTIL = f"{SIM_MONITOR_ROOT}.1.2.1"  # hwMemoryDevUtilization (%)

# --- table column prefixes ([sim] unless noted) ------------------------------
# hwEntityStateTable columns; rows are entity slots; types 1=psu 2=fan
# 3=temperature-sensor; present 1=present 2=absent; status 1=normal 2=fault
# 3=unknown; value = fan rpm / 0.1 Cel for the matching type.
COL_ENTITY_NAME = f"{SIM_MONITOR_ROOT}.3.2"
COL_ENTITY_TYPE = f"{SIM_MONITOR_ROOT}.3.3"
COL_ENTITY_PRESENT = f"{SIM_MONITOR_ROOT}.3.4"
COL_ENTITY_STATUS = f"{SIM_MONITOR_ROOT}.3.5"
COL_ENTITY_VALUE = f"{SIM_MONITOR_ROOT}.3.6"
# hwOpticalModuleInfoTable columns; rows are optics-bearing port ifIndexes.
# Scaled integers: rx/tx power dBm x100; temperature 0.01 Cel; voltage V
# x1000; current mA x1000. Ports without a module have NO row.
COL_OPTICS_RX = f"{SIM_MONITOR_ROOT}.4.2"  # hwTransceiverRxPower
COL_OPTICS_TX = f"{SIM_MONITOR_ROOT}.4.3"  # hwTransceiverTxPower
COL_OPTICS_TEMP = f"{SIM_MONITOR_ROOT}.4.4"  # hwTransceiverTemperatureC
COL_OPTICS_VOLT = f"{SIM_MONITOR_ROOT}.4.5"  # hwTransceiverVoltageV
COL_OPTICS_CURRENT = f"{SIM_MONITOR_ROOT}.4.6"  # hwTransceiverCurrentMa
# hwPoEPortTable columns; rows are PoE-capable port ifIndexes. State
# 1=on 2=off 3=denied 4=fault 5=unknown ([sim]); power is measured mW.
COL_POE_STATE = f"{SIM_MONITOR_ROOT}.5.2"
COL_POE_POWER_MW = f"{SIM_MONITOR_ROOT}.5.3"
# Device-level PoE scalars: measured total mW / budget mW / the device's OWN
# alarm state 1=normal 2=warning 3=critical.
OID_POE_TOTAL_MW = f"{SIM_MONITOR_ROOT}.6.1"
OID_POE_BUDGET_MW = f"{SIM_MONITOR_ROOT}.6.2"
OID_POE_ALARM = f"{SIM_MONITOR_ROOT}.6.3"
# Layer2 device scalars: loop/broadcast-storm detection 1=normal 2=detected.
OID_LOOP_STATUS = f"{SIM_MONITOR_ROOT}.7.1"
OID_STORM_STATUS = f"{SIM_MONITOR_ROOT}.7.2"
# hwStpPortTable rows: STP-running port ifIndexes; state 1=disabled
# 2=discarding 3=learning 4=forwarding 5=broken ([sim], IEEE 802.1D mirror).
COL_STP_STATE = f"{SIM_MONITOR_ROOT}.8.2"
# Per-port CRC error counter (CORE-MON-02 crc_errors source).
COL_CRC_ERRORS = f"{SIM_MONITOR_ROOT}.9.1"

# --- rows ledger --------------------------------------------------------------
# Row shape: (oid, label, kind, basis, is_column).
# ``kind`` mirrors the SNMP value class: integer | string | counter |
# counter64 (Counter64 must keep the 64-bit tag for wrap arithmetic).

RFC_ROWS: tuple[dict[str, str | bool], ...] = (
    {
        "oid": OID_SYS_DESCR,
        "label": "sysDescr",
        "kind": "string",
        "basis": RFC_3418,
        "is_column": False,
    },
    {
        "oid": OID_SNMP_ENGINE_ID,
        "label": "snmpEngineID",
        "kind": "string",
        "basis": RFC_3411,
        "is_column": False,
    },
    # IF-MIB ifXTable (RFC 2863): 64-bit HC counters + ifName. Instances are
    # ifIndex arcs, identical to the ifTable rows the client seeds.
    {
        "oid": "1.3.6.1.2.1.31.1.1.1.1",
        "label": "ifName",
        "kind": "string",
        "basis": RFC_2863,
        "is_column": True,
    },
    {
        "oid": "1.3.6.1.2.1.31.1.1.1.6",
        "label": "ifHCInOctets",
        "kind": "counter64",
        "basis": RFC_2863,
        "is_column": True,
    },
    {
        "oid": "1.3.6.1.2.1.31.1.1.1.10",
        "label": "ifHCOutOctets",
        "kind": "counter64",
        "basis": RFC_2863,
        "is_column": True,
    },
    # IF-MIB ifTable discard counters (RFC 2863) — the platform
    # ``interface.drops`` source (ifInDiscards + ifOutDiscards).
    {
        "oid": "1.3.6.1.2.1.2.2.1.13",
        "label": "ifInDiscards",
        "kind": "counter",
        "basis": RFC_2863,
        "is_column": True,
    },
    {
        "oid": "1.3.6.1.2.1.2.2.1.19",
        "label": "ifOutDiscards",
        "kind": "counter",
        "basis": RFC_2863,
        "is_column": True,
    },
)

# Every [sim] row: {oid, label, kind, basis, is_column} — declared from the
# exported constants above so the ledger and the code cannot drift.
_SIM_LEAF_ROWS: tuple[dict[str, str | bool], ...] = (
    {"oid": OID_CPU_UTIL_5S, "label": "hwCpuDevUtilization5s", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_CPU_UTIL_1MIN, "label": "hwCpuDevUtilization1min", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_CPU_UTIL_5MIN, "label": "hwCpuDevUtilization5min", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_MEM_UTIL, "label": "hwMemoryDevUtilization", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_POE_TOTAL_MW, "label": "hwPoEDeviceTotalPowerMw", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_POE_BUDGET_MW, "label": "hwPoEDeviceBudgetMw", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_POE_ALARM, "label": "hwPoEDeviceAlarmState", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_LOOP_STATUS, "label": "hwLoopDetectionStatus", "kind": "integer", "basis": SIM, "is_column": False},
    {"oid": OID_STORM_STATUS, "label": "hwBroadcastStormStatus", "kind": "integer", "basis": SIM, "is_column": False},
)
_SIM_COLUMN_ROWS: tuple[dict[str, str | bool], ...] = (
    {"oid": COL_ENTITY_NAME, "label": "hwEntityName", "kind": "string", "basis": SIM, "is_column": True},
    {"oid": COL_ENTITY_TYPE, "label": "hwEntityType", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_ENTITY_PRESENT, "label": "hwEntityPresent", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_ENTITY_STATUS, "label": "hwEntityStatus", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_ENTITY_VALUE, "label": "hwEntityValue", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_OPTICS_RX, "label": "hwTransceiverRxPower", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_OPTICS_TX, "label": "hwTransceiverTxPower", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_OPTICS_TEMP, "label": "hwTransceiverTemperatureC", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_OPTICS_VOLT, "label": "hwTransceiverVoltageV", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_OPTICS_CURRENT, "label": "hwTransceiverCurrentMa", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_POE_STATE, "label": "hwPoEPortState", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_POE_POWER_MW, "label": "hwPoEPortPowerMw", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_STP_STATE, "label": "hwStpPortState", "kind": "integer", "basis": SIM, "is_column": True},
    {"oid": COL_CRC_ERRORS, "label": "hwPortCrcErrors", "kind": "counter", "basis": SIM, "is_column": True},
)
HUAWEI_SIM_ROWS: tuple[dict[str, str | bool], ...] = _SIM_LEAF_ROWS + _SIM_COLUMN_ROWS

ROWS: tuple[dict[str, str | bool], ...] = RFC_ROWS + HUAWEI_SIM_ROWS

_OIDS: frozenset[str] | None = None


def oids() -> frozenset[str]:
    """Every registered OID (exact leaf or table-column prefix)."""
    global _OIDS
    if _OIDS is None:
        _OIDS = frozenset(str(row["oid"]) for row in ROWS)
    return _OIDS
