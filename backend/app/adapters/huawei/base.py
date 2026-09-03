"""Huawei VRP switch adapter — probe/discover/collect base (M5T2).

docs/DEVICE_ADAPTERS.md §6.2-6.4 maps CORE-MON-01..05 and ACCESS-MON-01..05
to Huawei SNMP sources; this base implements the shared machinery and both
subclasses pin the certified model set + per-requirement metric mapping:

- ``switch.huawei_vrp_core`` — S5732-H48XUM2CC, S5731S-S48P4X-A
- ``switch.huawei_vrp_access`` — S5735-L48P4S-A1

(exact model strings from contracts/hardware-targets.json; probe identity
requires an EXACT certified-model match in sysDescr + a parseable VRP
version — a cross-model device is refused at the identity stage so a device
can never be saved under the wrong adapter (prevent cross-registration,
exact_model scope)).

SNMP-only in this milestone (CLI/SSH paths are M5T3); events
(CORE-MON-06) flow through the M5T1 syslog/trap ingest path, never through
collect. Monitoring semantics follow contracts/metrics.json + the M5T2
brief decisions:

- rates (interface.in_bps/out_bps) are derived BY THE ADAPTER from two
  64-bit ifHCInOctets/ifHCOutOctets samples. The adapter keeps an in-memory
  LRU sample cache keyed by (device_id, interface). A cache miss (first
  collect, or after a platform restart wiped the process-local cache) is an
  ObservationError — NEVER a fabricated bps value; a platform restart loses
  one rate interval (documented decision, M5T2 brief). A sample that went
  backwards (device restart/counter rollover) derives an unsigned 64-bit
  delta marked quality=partial per contracts/metrics.json counter_reset
  (never negative);
- PoE ``total_power_percent`` is computed ONLY when the device reports the
  budget denominator (mirrors the DSM share rule + ADR-016/025; a missing
  budget is an ObservationError ``no_budget_denominator``, never a fake
  percent); ``total_power_alarm`` comes ONLY from the device's own alarm
  state leaf;
- every OID row lives in ``oids.py`` with a [basis] tag ([rfc-*] cited
  RFCs, [iana-enterprise-numbers] for the Huawei PEN, [sim] for the
  simulator-declared Huawei subtree — no guessed OIDs, ADR-018 spirit);
- absent components (a port without an optical module, an absent PSU slot)
  produce no point and no fabricated zero; enum literals the certified
  mapping cannot translate are ObservationErrors, device-reported
  "unknown" states map to the contract "unknown" sentinel;
- per-family device failures become per-key ObservationErrors so one broken
  family never hides the rest of the batch; only auth/network failures fail
  the whole run (AdapterError), mirroring the DSM/Redfish boundary.

Connection conventions (API_CONTRACT.md §4.1/§4.3): the SNMP version lives
in ``connection_config.snmp_version`` (v3 default), the v3 USM user/keys or
the v2c community live in ``credentials.snmp``, ``credentials.ssh`` is
declared now for M5T3. ``connection_config.snmp_engine_id`` (device USM
engine id, hex) is consumed by the M5T1 ingest worker for v3 trap
registration — the onboarding client supplies it; see the M5T2 report for
the wizard follow-up note.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from app.adapters.huawei.oids import (
    COL_CRC_ERRORS,
    COL_ENTITY_NAME,
    COL_ENTITY_PRESENT,
    COL_ENTITY_STATUS,
    COL_ENTITY_TYPE,
    COL_ENTITY_VALUE,
    COL_OPTICS_CURRENT,
    COL_OPTICS_RX,
    COL_OPTICS_TEMP,
    COL_OPTICS_TX,
    COL_OPTICS_VOLT,
    COL_POE_POWER_MW,
    COL_POE_STATE,
    COL_STP_STATE,
    OID_CPU_UTIL_5S,
    OID_LOOP_STATUS,
    OID_MEM_UTIL,
    OID_POE_ALARM,
    OID_POE_BUDGET_MW,
    OID_POE_TOTAL_MW,
    OID_STORM_STATUS,
    OID_SYS_DESCR,
)
from app.domain.adapter import (
    EVENT_SOURCE_IPS_CONFIG_KEY,
    EVENT_SOURCE_IPS_SCHEMA,
    AdapterError,
    CapabilitySupport,
    CollectionRequest,
    ComponentObserved,
    ConnectionProfile,
    DeviceSession,
    DiscoveryResult,
    LaunchDescriptor,
    Observation,
    ObservationBatch,
    ObservationError,
    OperationProgress,
    OperationResult,
    PreflightResult,
    ProbeResult,
    ProbeStage,
    Quality,
    VerificationResult,
)
from app.domain.operation_plan import DeviceSnapshot, OperationPlan, OperationRequest
from app.generated.capabilities import REQUIREMENTS
from app.generated.metrics import METRIC_DEFINITIONS
from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection
from app.infrastructure.protocols.snmp.errors import SnmpError
from app.infrastructure.protocols.snmp.values import SnmpKind, SnmpValue

_2_64 = 2**64

# --- certified model identity -------------------------------------------------
# EXACT hardware-targets.json declared model strings (certification scope
# exact_model); the probe identity stage matches sysDescr against the
# adapter's certified set and refuses everything else (cross-model
# rejection prevents registering a device under the wrong adapter).
MODEL_S5732_H48XUM2CC = "S5732-H48XUM2CC"
MODEL_S5731S_S48P4X_A = "S5731S-S48P4X-A"
MODEL_S5735_L48P4S_A1 = "S5735-L48P4S-A1"

# Tolerant VRP sysDescr parse: ``... VRP (R) software, Version <token>``.
# The VRP marker must be present (proves VRP identity); the version token is
# any non-space token (V200R021C10SPC600, 8.180, ...).
_VRP_VERSION_RE = re.compile(r"VRP\s*\(\s*R\s*\)\s*software.*?Version\s+([0-9A-Za-z_.+-]+)", re.IGNORECASE)

# --- certified device enum tables (basis per row family) ----------------------
# ifAdminStatus (RFC 2863): up(1) down(2) testing(3).
IF_ADMIN: dict[int, str] = {1: "up", 2: "down", 3: "testing"}
# ifOperStatus (RFC 2863): up(1) down(2) testing(3) unknown(4) dormant(5)
# notPresent(6) lowerLayerDown(7) — RFC 2863 itself defines the "unknown"
# state, which maps to the contract's unknown sentinel.
IF_OPER: dict[int, str] = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}
# [sim] hwEntityStateTable semantics: type 1=psu 2=fan 3=temperature;
# present 1=present 2=absent; status 1=normal 2=fault 3=unknown.
ENTITY_TYPE: dict[int, str] = {1: "psu", 2: "fan", 3: "temperature"}
ENTITY_PRESENT: dict[int, str] = {1: "present", 2: "absent"}
ENTITY_STATUS: dict[int, str] = {1: "ok", 2: "critical", 3: "unknown"}
# [sim] hwLoopDetectionStatus/hwBroadcastStormStatus: 1=normal 2=detected.
LAYER2_STATUS: dict[int, str] = {1: "normal", 2: "detected"}
# [sim] hwStpPortState codes mirror IEEE 802.1D states + the contract
# stp_port_state enum (5=broken for error-disabled ports).
STP_STATE: dict[int, str] = {1: "disabled", 2: "discarding", 3: "learning", 4: "forwarding", 5: "broken"}
# [sim] hwPoEPortState: 1=on 2=off 3=denied 4=fault 5=unknown (the device
# literally reports unknown -> the contract's unknown sentinel).
POE_STATE: dict[int, str] = {1: "on", 2: "off", 3: "denied", 4: "fault", 5: "unknown"}
# [sim] hwPoEDeviceAlarmState: the device's OWN PoE alarm state.
POE_ALARM: dict[int, str] = {1: "normal", 2: "warning", 3: "critical"}

# SNMP errors that fail the whole run (reachability/auth semantics); other
# device-side answers degrade to per-key ObservationErrors
# (DEVICE_ADAPTERS.md §7, mirror of the DSM/Redfish boundary).
FATAL_SNMP_CODES: frozenset[str] = frozenset({"network_unreachable", "authentication_failed"})

# --- evidence strings (the [basis] tag travels with every observation) --------
_EV_CPU = "[sim] hwCpuDevUtilization5s（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_MEM = "[sim] hwMemoryDevUtilization（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_IF_ADMIN = "[rfc-2863] ifAdminStatus"
_EV_IF_OPER = "[rfc-2863] ifOperStatus"
_EV_IF_BPS = "[rfc-2863] ifHCInOctets/ifHCOutOctets 64 位计数器派生（适配器双采样）"
_EV_IF_ERRORS = "[rfc-2863] ifInErrors+ifOutErrors"
_EV_IF_DROPS = "[rfc-2863] ifInDiscards+ifOutDiscards"
_EV_IF_CRC = "[sim] hwPortCrcErrors（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_OPTICS = "[sim] hwOpticalModuleInfoTable（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_ENTITY = "[sim] hwEntityStateTable（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_POE = "[sim] hwPoEPortTable/hwPoEDeviceTable（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_LOOP = "[sim] hwLoopDetectionStatus（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_STORM = "[sim] hwBroadcastStormStatus（模拟器 DSL；真机 MIB OID 认证时记录）"
_EV_STP = "[sim] hwStpPortState（模拟器 DSL；真机 MIB OID 认证时记录）"

# Component status for inventory rows the device reports no status object
# for (interfaces, optics, PoE ports): honest unknown, never inferred.
STATUS_UNKNOWN = "unknown"

# Composite counters are the sum of both directions (documented mapping).
# OID prefixes for the RFC 2863 ifTable/ifXTable columns the interface
# reader walks (they are part of the client's RFC seed; declared here as
# read-site literals — every value is covered by the oids() ledger scan:
# the RFC rows are listed in ``oids.RFC_ROWS``).
_OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
_OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
_OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"
_OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
_OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
_OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
_OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
_OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
_OID_IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"


def _component(kind: str, native_id: str, name: str, status: str) -> ComponentObserved:
    return ComponentObserved(kind=kind, native_id=native_id, name=name, status=status)


def _add_or_none(first: int | None, second: int | None) -> int | None:
    if first is None or second is None:
        return None
    return first + second


def _snmp_int(value: object) -> int | None:
    if isinstance(value, SnmpValue) and value.kind in (SnmpKind.INTEGER, SnmpKind.UNSIGNED, SnmpKind.COUNTER):
        return int(value.value)
    return None


def _instance_arc(oid: str, column: str) -> int | None:
    """Instance arc int of ``oid`` under the ``column`` prefix (or None)."""
    if not (oid == column or oid.startswith(column + ".")):
        return None
    suffix = oid[len(column) :].lstrip(".")
    if not suffix.isdigit():
        return None
    return int(suffix)


def walk_int_rows(client: SnmpClient, column: str) -> tuple[dict[int, int], bool]:
    """Walk one integer table column -> {instance: value}.

    Missing markers are skipped; ``truncated`` mirrors the client's walk
    contract (the page guard fired mid-subtree — callers treat a truncated
    walk as partial evidence, never a fabricated full table).
    """
    rows: dict[int, int] = {}
    walked, truncated = client.walk(column)
    for value in walked:
        if not isinstance(value, SnmpValue):
            continue
        if value.kind not in (SnmpKind.INTEGER, SnmpKind.UNSIGNED, SnmpKind.COUNTER):
            continue
        arc = _instance_arc(value.oid, column)
        if arc is None:
            continue
        rows[arc] = int(value.value)
    return rows, truncated


def walk_string_rows(client: SnmpClient, column: str) -> tuple[dict[int, str], bool]:
    """Walk one string table column -> {instance: text} (same contract)."""
    rows: dict[int, str] = {}
    walked, truncated = client.walk(column)
    for value in walked:
        if not isinstance(value, SnmpValue) or value.kind is not SnmpKind.STRING:
            continue
        arc = _instance_arc(value.oid, column)
        if arc is None:
            continue
        rows[arc] = str(value.value)
    return rows, truncated


def _safe_snmp_exc(exc: SnmpError) -> str:
    return exc.message if exc.detail_safe is None else exc.detail_safe


def _safe_config_error(exc: ValueError) -> str:
    return str(exc).replace("snmp ", "")


def _raise_fatal_snmp(exc: SnmpError, *, stage: str) -> None:
    """Re-raise auth/network failures as a run-level AdapterError."""
    raise AdapterError(exc.code, exc.message, stage=exc.stage or stage)


def parse_sys_descr(
    sys_descr: str, certified_models: tuple[str, ...]
) -> tuple[str | None, str | None, tuple[str, ...]]:
    """Parse sysDescr -> (model, vrp_version, failures).

    The model must EXACTLY match a certified model token of the adapter and
    the text must carry a VRP software marker with a parseable version.
    Returns human-readable Chinese failures instead of raising so the probe
    can phrase stage details.
    """
    failures: list[str] = []
    found_model: str | None = None
    for model in certified_models:
        if re.search(rf"(?<![\w-]){re.escape(model)}(?![\w-])", sys_descr) is not None:
            found_model = model
            break
    if found_model is None:
        expected = "、".join(certified_models)
        failures.append(
            f"sysDescr 未包含本适配器认证的型号（期望精确型号 {expected}），"
            f"设备自述 {sys_descr[:120]!r} — 防止跨型号注册（exact_model）"
        )
    version_match = _VRP_VERSION_RE.search(sys_descr)
    vrp_version = version_match.group(1) if version_match is not None else None
    if vrp_version is None:
        failures.append("sysDescr 未包含可解析的 VRP 软件版本（VRP (R) software, Version ...）")
    return found_model, vrp_version, tuple(failures)


# --- rate cache (in-memory, process-local; M5T2 brief decision) ---------------


@dataclass(frozen=True)
class CounterSample:
    """One raw 64-bit counter sample (octets) at a collection time."""

    at: datetime
    in_octets: int
    out_octets: int


class RateSampleCache:
    """Process-local LRU of the last raw HC-octets sample per interface.

    The adapter is stateless per collect and contracts/metrics.json has no
    raw-octet key the platform could hold, so the previous sample lives in
    an in-memory LRU keyed by (device_id, interface native id)
    (M5T2 brief decision, documented): a cache miss (first collect or after
    a platform/worker restart) yields ObservationErrors for in_bps/out_bps
    — a restart loses one rate interval, never a fabricated rate.
    """

    def __init__(self, maxlen: int = 8192) -> None:
        self._maxlen = maxlen
        self._samples: OrderedDict[tuple[object, str], CounterSample] = OrderedDict()
        self._lock = Lock()

    def get(self, device_id: object, interface: str) -> CounterSample | None:
        key = (device_id, interface)
        with self._lock:
            sample = self._samples.get(key)
            if sample is not None:
                self._samples.move_to_end(key)
            return sample

    def store(self, device_id: object, interface: str, sample: CounterSample) -> None:
        key = (device_id, interface)
        with self._lock:
            self._samples[key] = sample
            self._samples.move_to_end(key)
            while len(self._samples) > self._maxlen:
                self._samples.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._samples.clear()


def derive_rate_bps(previous: int, current: int) -> tuple[int, bool]:
    """Unsigned 64-bit octet delta between two HC samples.

    ``(delta_octets, reset)`` — ``reset=True`` when the counter went
    backwards (device restart / rollover): the unsigned wrap delta is still
    non-negative and correct for a true 64-bit wrap, but per
    contracts/metrics.json counter_reset the first derived point after a
    restart/rollover is marked quality partial — never a negative rate.
    """
    if current >= previous:
        return current - previous, False
    return current + (_2_64 - previous), True


# --- raw row DTOs --------------------------------------------------------------


@dataclass(frozen=True)
class EntityRow:
    """One hwEntityStateTable slot row ([sim] DSL semantics)."""

    slot: int
    name: str
    kind: str  # psu | fan | temperature | unknown
    present: int | None  # 1 present / 2 absent
    status: int | None  # 1 normal / 2 fault / 3 unknown
    value: int | None  # fan rpm / temp x10 (type-dependent)


@dataclass(frozen=True)
class InterfaceRow:
    """One interface row (RFC 2863 ifTable + ifXTable + [sim] CRC)."""

    if_index: int
    name: str
    admin_raw: int | None  # ifAdminStatus (RFC 2863)
    oper_raw: int | None  # ifOperStatus (RFC 2863)
    hc_in: int | None  # ifHCInOctets Counter64
    hc_out: int | None  # ifHCOutOctets Counter64
    in_errors: int | None  # ifInErrors
    out_errors: int | None  # ifOutErrors
    in_discards: int | None  # ifInDiscards
    out_discards: int | None  # ifOutDiscards
    crc: int | None  # [sim] hwPortCrcErrors


class _Bundle:
    """Collect/discover accumulator (mirrors the DSM/Redfish bundles)."""

    def __init__(self) -> None:
        self.observations: list[Observation] = []
        self.components: list[ComponentObserved] = []
        self.errors: list[ObservationError] = []

    def obs(
        self,
        key: str,
        value: object,
        *,
        now: datetime,
        unit: str | None = None,
        quality: Quality = Quality.GOOD,
        kind: str | None = None,
        native: str | None = None,
        evidence: str,
    ) -> None:
        definition = METRIC_DEFINITIONS.get(key)
        self.observations.append(
            Observation(
                metric_key=key,
                value=value,  # type: ignore[arg-type]
                observed_at=now,
                quality=quality,
                unit=unit if unit is not None else (definition.unit if definition is not None else None),
                source="poll",
                component_kind=kind,
                component_native_id=native,
                evidence=evidence,
            )
        )

    def err(
        self,
        key: str | None,
        *,
        detail: str,
        error_code: str = "protocol_error",
        stage: str = "parse",
        kind: str | None = None,
        native: str | None = None,
    ) -> None:
        self.errors.append(
            ObservationError(
                key=key,
                error_code=error_code,
                stage=stage,
                component_kind=kind,
                component_native_id=native,
                detail=detail,
            )
        )


def _not_executed_stages(names: tuple[str, ...]) -> tuple[ProbeStage, ...]:
    return tuple(ProbeStage(stage=name, ok=False, detail_safe="前置阶段失败，未执行") for name in names)


def _identity_hint(model: str) -> dict[str, str]:
    return {"vendor": "Huawei", "model": model}


def _requirement_keys(requirement: object) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    keys.extend((key, "metric") for key in requirement.metrics)  # type: ignore[attr-defined]
    keys.extend((key, "event") for key in requirement.events)  # type: ignore[attr-defined]
    keys.extend((operation[0], "operation") for operation in requirement.operations)  # type: ignore[attr-defined]
    return keys


def _device_type_keys(device_type: str) -> list[tuple[str, str, str]]:
    """All (requirement_id, key, kind) rows for a device type (unique keys)."""
    rows: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != device_type:
            continue
        for key, kind in _requirement_keys(requirement):
            if key in seen:
                continue
            seen.add(key)
            rows.append((requirement.id, key, kind))
    return rows


def _translate(table: dict[int, str], raw: int) -> str | None:
    """Map one certified device literal; None = unmapped (error path). A
    device literal outside the certified table is never silently guessed
    (ADR-018)."""
    return table.get(raw)


# --- Huawei adapter base -------------------------------------------------------


class HuaweiVrpAdapter:
    """Huawei VRP switch adapter base (probe/discover/collect, M5T2)."""

    adapter_key = "switch.huawei_vrp_base"  # overridden by subclasses
    supported_device_types: frozenset[str] = frozenset()
    adapter_version = "0.1.0"
    secret_schema_version = 1
    certified_models: tuple[str, ...] = ()
    #: Event keys wired to the platform ingest path (CORE-MON-06).
    event_keys: tuple[str, ...] = ()
    #: {family: metric keys} per adapter (DEVICE_ADAPTERS.md §6.2/§6.4).
    family_keys: dict[str, tuple[str, ...]] = {}

    secret_schema: dict[str, object] = {
        "type": "object",
        "required": ["snmp"],
        "additionalProperties": False,
        "properties": {
            "snmp": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    # v3 USM (default; the version lives in connection_config.snmp_version)
                    "username": {"type": "string", "minLength": 1},
                    "auth_protocol": {"type": "string", "enum": ["none", "md5", "sha"]},
                    "auth_key": {"type": "string", "minLength": 1},
                    "privacy_protocol": {"type": "string", "enum": ["none", "des", "aes128"]},
                    "privacy_key": {"type": "string", "minLength": 1},
                    # v2c community (explicit v2c choice only)
                    "community": {"type": "string", "minLength": 1},
                },
            },
            # SSH credentials are NOT used by M5T2 (SNMP-only); the schema is
            # declared now for the M5T3 CLI/SSH milestone.
            "ssh": {
                "type": "object",
                "required": ["username", "password"],
                "additionalProperties": False,
                "properties": {
                    "username": {"type": "string", "minLength": 1},
                    "password": {"type": "string", "minLength": 1},
                },
            },
        },
    }
    connection_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "snmp_version": {"type": "string", "enum": ["v3", "v2c"]},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "snmp_engine_id": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-fA-F]{10,64}$",
            },
            # M5T3 (SSH) fields declared now; unused in M5T2.
            "ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "verify_tls": {"type": "boolean"},
            EVENT_SOURCE_IPS_CONFIG_KEY: dict(EVENT_SOURCE_IPS_SCHEMA),
        },
    }

    def __init__(self) -> None:
        #: Process-local previous-HC-sample cache (see RateSampleCache docs).
        self._rate_samples = RateSampleCache()

    # -- operation protocol (M5T3) -------------------------------------------
    # The M5T2 milestone is SNMP monitoring only (CORE-ACT/ACCESS-ACT rows are
    # discovered unsupported with mapping_missing, so the platform never calls
    # these). They exist so the adapter still conforms to the DeviceAdapter
    # protocol; the SSH/CLI implementations arrive in M5T3 — until then every
    # call is an honest unsupported_capability, never a stub success.

    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
        del snapshot, request
        raise AdapterError(
            "unsupported_capability",
            "交换机操作（CORE-ACT/ACCESS-ACT）的 SSH/CLI 适配路径在 M5T3 交付",
            stage="plan",
        )

    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult:
        del session, plan
        raise AdapterError(
            "unsupported_capability",
            "交换机操作（CORE-ACT/ACCESS-ACT）的 SSH/CLI 适配路径在 M5T3 交付",
            stage="preflight",
        )

    def execute_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        progress: OperationProgress,
    ) -> OperationResult:
        del session, plan, progress
        raise AdapterError(
            "unsupported_capability",
            "交换机操作（CORE-ACT/ACCESS-ACT）的 SSH/CLI 适配路径在 M5T3 交付",
            stage="execute",
        )

    def verify_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        result: OperationResult | None,
    ) -> VerificationResult:
        del session, plan, result
        raise AdapterError(
            "unsupported_capability",
            "交换机操作（CORE-ACT/ACCESS-ACT）的 SSH/CLI 适配路径在 M5T3 交付",
            stage="verify",
        )

    def create_launch(self, session: DeviceSession, capability: str) -> LaunchDescriptor:
        del session, capability
        raise AdapterError(
            "unsupported_capability",
            "交换机连接能力（console.ssh/telnet/web）在 M5T3 交付",
            stage="launch",
        )

    @property
    def implemented_metric_keys(self) -> frozenset[str]:
        keys: set[str] = set()
        for family_keys in self.family_keys.values():
            keys.update(family_keys)
        return frozenset(keys)

    def reset_rate_cache(self) -> None:
        """Test hook: simulate a platform restart (empty sample state)."""
        self._rate_samples.clear()

    # -- connection ---------------------------------------------------------

    def _snmp_connection(self, source: DeviceSession | ConnectionProfile) -> SnmpConnection:
        """SnmpConnection from a session/profile (credentials stay inside the
        call boundary). Raises ValueError on an inconsistent v3/v2c branch
        (the runtime enforcement the JSON schema cannot express); the probe
        maps it to a network-stage validation_failed.

        The SNMP port is the probe request port (ConnectionProfile) or the
        saved ``connection_config.port`` (DeviceSession — the platform merges
        the effective port into the stored config at onboarding); both fall
        back to the SNMP default 161."""
        host = source.resolved_ip if source.resolved_ip is not None else source.management_endpoint
        config = dict(source.connection_config)
        if isinstance(source, ConnectionProfile):
            port = source.port
        else:
            raw_port = config.get("port")
            port = int(raw_port) if isinstance(raw_port, int) else 161
        version = str(config.get("snmp_version", "v3"))
        credentials = dict(source.credentials)
        snmp_section = credentials.get("snmp")
        snmp = dict(snmp_section) if isinstance(snmp_section, dict) else {}
        return SnmpConnection(
            host=str(host),
            port=port,
            version=version if version in ("v3", "v2c") else "v3",
            community=str(snmp["community"]) if snmp.get("community") else None,
            username=str(snmp["username"]) if snmp.get("username") else None,
            auth_protocol=str(snmp.get("auth_protocol", "sha")),
            auth_key=str(snmp["auth_key"]) if snmp.get("auth_key") else None,
            privacy_protocol=str(snmp.get("privacy_protocol", "aes128")),
            privacy_key=str(snmp["privacy_key"]) if snmp.get("privacy_key") else None,
        )

    def _client(self, source: DeviceSession | ConnectionProfile) -> SnmpClient:
        return SnmpClient(self._snmp_connection(source))

    def _sys_descr(self, client: SnmpClient) -> str:
        raw = client.get(OID_SYS_DESCR)
        if not isinstance(raw, SnmpValue) or raw.kind is not SnmpKind.STRING:
            raise AdapterError("protocol_error", "设备未返回可解析的 sysDescr", stage="collect")
        return str(raw.value)

    # -- probe --------------------------------------------------------------

    def probe(self, profile: ConnectionProfile) -> ProbeResult:
        """Staged probe: network -> auth -> identity -> capabilities.

        SNMP has no TLS stage (UDP datagrams): ``network`` covers
        reachability and protocol sanity; ``auth`` covers the SNMPv3 USM
        refusal (v2c carries no protocol authentication — the stage passes
        on an answered request with the documented weak-protocol note);
        ``identity`` gates the EXACT certified model in sysDescr plus a
        parseable VRP version (cross-model devices are refused here, before
        any capability claim); ``capabilities`` proves the monitoring
        mapping answers. Stages after a failure are not executed (never
        fabricated as ok).
        """
        try:
            client = self._client(profile)
        except ValueError as exc:
            return ProbeResult(
                stages=(
                    ProbeStage(
                        stage="network",
                        ok=False,
                        error_code="validation_failed",
                        detail_safe=f"SNMP 连接配置不一致：{_safe_config_error(exc)}",
                    ),
                )
                + _not_executed_stages(("auth", "identity", "capabilities"))
            )
        try:
            sys_descr = self._sys_descr(client)
        except AdapterError as exc:
            return ProbeResult(
                stages=(
                    ProbeStage(stage="network", ok=True),
                    ProbeStage(
                        stage="auth",
                        ok=False,
                        error_code=exc.code,
                        detail_safe=exc.message,
                    ),
                )
                + _not_executed_stages(("identity", "capabilities"))
            )
        except SnmpError as exc:
            if exc.code == "authentication_failed":
                return ProbeResult(
                    stages=(
                        ProbeStage(stage="network", ok=True),
                        ProbeStage(
                            stage="auth",
                            ok=False,
                            error_code="authentication_failed",
                            detail_safe="SNMPv3 USM 拒绝凭据（v2c 社区不匹配表现为静默超时）",
                        ),
                    )
                    + _not_executed_stages(("identity", "capabilities"))
                )
            return ProbeResult(
                stages=(
                    ProbeStage(
                        stage="network",
                        ok=False,
                        error_code=exc.code,
                        detail_safe=_safe_snmp_exc(exc),
                    ),
                )
                + _not_executed_stages(("auth", "identity", "capabilities"))
            )
        version_note = ""
        if str(profile.connection_config.get("snmp_version", "v3")) == "v2c":
            version_note = "（v2c 无协议认证 — 管理员显式选择；弱安全警告见界面）"
        auth = ProbeStage(stage="auth", ok=True, detail_safe=f"SNMP 请求被接受{version_note}")
        model, vrp_version, failures = parse_sys_descr(sys_descr, self.certified_models)
        if model is None or vrp_version is None:
            return ProbeResult(
                stages=(
                    ProbeStage(stage="network", ok=True),
                    auth,
                    ProbeStage(
                        stage="identity",
                        ok=False,
                        error_code="validation_failed",
                        detail_safe="；".join(failures),
                    ),
                )
                + _not_executed_stages(("capabilities",))
            )
        identity = ProbeStage(
            stage="identity",
            ok=True,
            detail_safe=f"已识别为 Huawei {model}（VRP {vrp_version}）",
        )
        capabilities = self._probe_capabilities(client)
        return ProbeResult(
            stages=(ProbeStage(stage="network", ok=True), auth, identity, capabilities),
            identity_hint=_identity_hint(model),
        )

    def _probe_capabilities(self, client: SnmpClient) -> ProbeStage:
        """Capabilities stage: the monitoring mapping answers SNMP reads."""
        try:
            cpu = client.get(OID_CPU_UTIL_5S)
            memory = client.get(OID_MEM_UTIL)
        except SnmpError as exc:
            return ProbeStage(
                stage="capabilities",
                ok=False,
                error_code=exc.code,
                detail_safe=_safe_snmp_exc(exc),
            )
        if isinstance(cpu, SnmpValue) and isinstance(memory, SnmpValue):
            return ProbeStage(
                stage="capabilities",
                ok=True,
                detail_safe="CPU/内存监控族应答（system.cpu_percent/system.memory_percent 可读）",
            )
        return ProbeStage(
            stage="capabilities",
            ok=False,
            error_code="unsupported_capability",
            detail_safe="设备未应答 CPU/内存监控族（能力阶段未通过，不做能力声明）",
        )

    # -- discover -----------------------------------------------------------

    def discover(self, profile: ConnectionProfile) -> DiscoveryResult:
        """Identity + component inventory + capability rows for EVERY
        capability key of the device type (supported / unsupported /
        not_configured with honest reasons — ADR-014/ADR-018)."""
        try:
            client = self._client(profile)
            sys_descr = self._sys_descr(client)
        except SnmpError as exc:
            raise AdapterError(exc.code, exc.message, stage=exc.stage or "discover") from exc
        model, vrp_version, failures = parse_sys_descr(sys_descr, self.certified_models)
        if model is None or vrp_version is None:
            raise AdapterError("validation_failed", "；".join(failures), stage="discover")
        evidence = self._discovery_evidence(client)
        return DiscoveryResult(
            vendor="Huawei",
            model=model,
            serial_number=None,
            firmware_version=vrp_version,
            capabilities=self._capability_rows(
                evidence,
                source_endpoint=profile.management_endpoint,
                connection_config=profile.connection_config,
            ),
            components=self._inventory_components(evidence),
            secrets_schema=self.secret_schema,
            secrets_schema_version=self.secret_schema_version,
        )

    def _discovery_evidence(self, client: SnmpClient) -> dict[str, object]:
        """One read pass per family -> raw rows for capability + inventory.

        ``{family: raw}`` — families keep the same rows the collect mapping
        uses so capability support derives from the SAME device answers. A
        family read error raises (discover fails honestly rather than
        claiming capability absence).
        """
        cpu = client.get(OID_CPU_UTIL_5S)
        memory = client.get(OID_MEM_UTIL)
        evidence: dict[str, object] = {
            "system": {
                "cpu": cpu if isinstance(cpu, SnmpValue) else None,
                "memory": memory if isinstance(memory, SnmpValue) else None,
            },
            "interfaces": self._read_interfaces(client),
            "entities": self._read_entities(client),
            "optics": self._read_optics(client),
        }
        if "layer2" in self.family_keys:
            evidence["layer2"] = self._read_layer2(client)
        if "poe" in self.family_keys:
            evidence["poe"] = self._read_poe(client)
        return evidence

    def _capability_rows(
        self, evidence: dict[str, object], *, source_endpoint: str, connection_config: Mapping[str, object]
    ) -> tuple[CapabilitySupport, ...]:
        rows: list[CapabilitySupport] = []
        for requirement_id, key, kind in _device_type_keys(next(iter(self.supported_device_types))):
            state, reason_code, detail = self._capability_decision(
                requirement_id, key, kind, evidence, source_endpoint, connection_config
            )
            rows.append(
                CapabilitySupport(
                    capability_key=key,
                    support_state=state,
                    requirement_id=requirement_id,
                    discovery_method=self.adapter_key,
                    reason_code=reason_code,
                    detail=detail,
                )
            )
        return tuple(rows)

    def _event_sources_declared(self, source_endpoint: str, connection_config: Mapping[str, object]) -> bool:
        """Event keys are supported only when syslog/trap sources can be
        attributed: the management endpoint is an IP literal or
        ``event_source_ips`` is declared (RISK R-14 — the ingest layer
        attributes exactly this way)."""
        try:
            ipaddress.ip_address(source_endpoint)
            return True
        except ValueError:
            pass
        declared = connection_config.get(EVENT_SOURCE_IPS_CONFIG_KEY)
        return isinstance(declared, list) and len(declared) > 0

    def _family_of_metric_key(self, key: str) -> str | None:
        for family, keys in self.family_keys.items():
            if key in keys:
                return family
        return None

    def _capability_decision(
        self,
        requirement_id: str,
        key: str,
        kind: str,
        evidence: dict[str, object],
        source_endpoint: str,
        connection_config: Mapping[str, object],
    ) -> tuple[str, str | None, str]:
        """(support_state, reason_code, detail) for one capability key.

        - metric keys the mapping implements: supported when the family
          evidence answered on THIS device, unsupported (device source
          missing) otherwise;
        - event keys: supported when event sources can be attributed (the
          ingest path itself is wired since M5T1; the device-side push
          channel cannot be verified over SNMP and is a runtime matter);
        - operation keys: unsupported adapter-side gap — the SSH/CLI paths
          arrive in M5T3 (never a device claim).
        """
        if kind == "operation":
            return (
                "unsupported",
                "mapping_missing",
                f"{requirement_id} 的操作键 {key} 的 SSH/CLI 适配路径在 M5T3 交付"
                "（适配器侧缺口，不是设备不支持；本适配器未接线）",
            )
        if kind == "event":
            if key not in self.event_keys:
                return (
                    "unsupported",
                    "mapping_missing",
                    f"事件键 {key} 没有为本适配器接线的 ingest 分类（适配器侧缺口）",
                )
            if self._event_sources_declared(source_endpoint, connection_config):
                return (
                    "supported",
                    None,
                    "事件源可归因（管理端点 IP 或 event_source_ips 声明）；syslog/trap 由平台 ingest 接收（M5T1）",
                )
            return (
                "not_configured",
                "event_source_unconfigured",
                "未声明事件源：syslog/trap 来源 IP 无法归因到设备（RISK R-14）— "
                "声明 event_source_ips 或使用 IP 管理端点后事件能力可用",
            )
        family = self._family_of_metric_key(key)
        if family is None:
            return (
                "unsupported",
                "mapping_missing",
                f"指标键 {key} 不在本适配器的监控映射中（适配器侧缺口，不是设备不支持）",
            )
        if self._family_answered(family, evidence):
            return (
                "supported",
                None,
                f"来源 {self._family_table_label(family)} 在设备上应答（{self._family_basis(family)}）",
            )
        return (
            "unsupported",
            "device_source_missing",
            f"设备未应答 {self._family_table_label(family)}（无该表/无数据行）— 能力行保持不支持，不臆测设备能力",
        )

    def _family_answered(self, family: str, evidence: dict[str, object]) -> bool:
        rows = evidence.get(family)
        if family == "system":
            if not isinstance(rows, dict):
                return False
            return isinstance(rows.get("cpu"), SnmpValue) or isinstance(rows.get("memory"), SnmpValue)
        if family == "interfaces":
            return isinstance(rows, list) and len(rows) > 0
        if family == "entities":
            return isinstance(rows, list) and len(rows) > 0
        if family == "optics":
            return isinstance(rows, dict) and len(rows) > 0
        if family == "layer2":
            if not isinstance(rows, dict):
                return False
            loop = rows.get("loop")
            storm = rows.get("storm")
            stp = rows.get("stp")
            return isinstance(loop, SnmpValue) or isinstance(storm, SnmpValue) or bool(stp)
        if family == "poe":
            if not isinstance(rows, dict):
                return False
            return isinstance(rows.get("states"), dict) and len(rows["states"]) > 0
        return False

    def _family_table_label(self, family: str) -> str:
        labels = {
            "system": "hwCpuDevTable/hwMemoryDevTable",
            "interfaces": "IF-MIB ifTable/ifXTable + hwPortCrcErrorsTable",
            "entities": "hwEntityStateTable",
            "optics": "hwOpticalModuleInfoTable",
            "layer2": "hwLoopDetection/hwBroadcastStorm + hwStpPortTable",
            "poe": "hwPoEPortTable/hwPoEDeviceTable",
        }
        return labels[family]

    def _family_basis(self, family: str) -> str:
        if family == "interfaces":
            return "[rfc-2863] + [sim]"
        return "[sim]"

    # -- family readers (pure SNMP reads; never touch the rate cache) --------

    def _read_interfaces(self, client: SnmpClient) -> list[InterfaceRow]:
        name_rows, _truncated = walk_string_rows(client, _OID_IF_NAME)
        admin_rows, _truncated = walk_int_rows(client, _OID_IF_ADMIN)
        oper_rows, _truncated = walk_int_rows(client, _OID_IF_OPER)
        hc_in, _truncated = walk_int_rows(client, _OID_IF_HC_IN)
        hc_out, _truncated = walk_int_rows(client, _OID_IF_HC_OUT)
        in_errors, _truncated = walk_int_rows(client, _OID_IF_IN_ERRORS)
        out_errors, _truncated = walk_int_rows(client, _OID_IF_OUT_ERRORS)
        in_discards, _truncated = walk_int_rows(client, _OID_IF_IN_DISCARDS)
        out_discards, _truncated = walk_int_rows(client, _OID_IF_OUT_DISCARDS)
        crc_rows, _truncated = walk_int_rows(client, COL_CRC_ERRORS)
        rows: list[InterfaceRow] = []
        for if_index in sorted(name_rows):
            rows.append(
                InterfaceRow(
                    if_index=if_index,
                    name=name_rows[if_index],
                    admin_raw=admin_rows.get(if_index),
                    oper_raw=oper_rows.get(if_index),
                    hc_in=hc_in.get(if_index),
                    hc_out=hc_out.get(if_index),
                    in_errors=in_errors.get(if_index),
                    out_errors=out_errors.get(if_index),
                    in_discards=in_discards.get(if_index),
                    out_discards=out_discards.get(if_index),
                    crc=crc_rows.get(if_index),
                )
            )
        return rows

    def _read_entities(self, client: SnmpClient) -> list[EntityRow]:
        names, _truncated = walk_string_rows(client, COL_ENTITY_NAME)
        kinds, _truncated = walk_int_rows(client, COL_ENTITY_TYPE)
        present, _truncated = walk_int_rows(client, COL_ENTITY_PRESENT)
        status, _truncated = walk_int_rows(client, COL_ENTITY_STATUS)
        values, _truncated = walk_int_rows(client, COL_ENTITY_VALUE)
        rows: list[EntityRow] = []
        for slot in sorted(kinds):
            kind_raw = kinds[slot]
            rows.append(
                EntityRow(
                    slot=slot,
                    name=names.get(slot, f"slot-{slot}"),
                    kind=ENTITY_TYPE.get(kind_raw, "unknown"),
                    present=present.get(slot),
                    status=status.get(slot),
                    value=values.get(slot),
                )
            )
        return rows

    def _read_optics(self, client: SnmpClient) -> dict[int, dict[str, int | None]]:
        """{if_index: {column: int|None}} for optics-bearing ports only.

        A port WITHOUT a module has no row — a missing module is an absent
        component, never a fabricated 0. Scale factors ([sim] DSL):
        rx/tx power dBm x100; temperature 0.01 Cel; voltage V x1000;
        current mA x1000.
        """
        columns: dict[str, str] = {
            "rx_dbm": COL_OPTICS_RX,
            "tx_dbm": COL_OPTICS_TX,
            "temperature_c": COL_OPTICS_TEMP,
            "voltage_v": COL_OPTICS_VOLT,
            "current_ma": COL_OPTICS_CURRENT,
        }
        read: dict[str, dict[int, int]] = {}
        for key, column in columns.items():
            read[key], _truncated = walk_int_rows(client, column)
        rows: dict[int, dict[str, int | None]] = {}
        for if_index in sorted(read["rx_dbm"]):
            rows[if_index] = {key: values.get(if_index) for key, values in read.items()}
        return rows

    def _read_layer2(self, client: SnmpClient) -> dict[str, object]:
        loop = client.get(OID_LOOP_STATUS)
        storm = client.get(OID_STORM_STATUS)
        stp_rows, _truncated = walk_int_rows(client, COL_STP_STATE)
        return {
            "loop": loop if isinstance(loop, SnmpValue) else None,
            "storm": storm if isinstance(storm, SnmpValue) else None,
            "stp": stp_rows,
        }

    def _read_poe(self, client: SnmpClient) -> dict[str, object]:
        states, _truncated = walk_int_rows(client, COL_POE_STATE)
        powers, _truncated = walk_int_rows(client, COL_POE_POWER_MW)
        total = client.get(OID_POE_TOTAL_MW)
        budget = client.get(OID_POE_BUDGET_MW)
        alarm = client.get(OID_POE_ALARM)
        return {
            "states": states,
            "powers": powers,
            "total": total if isinstance(total, SnmpValue) else None,
            "budget": budget if isinstance(budget, SnmpValue) else None,
            "alarm": alarm if isinstance(alarm, SnmpValue) else None,
        }

    def _read_scalar_int(self, client: SnmpClient, oid: str) -> int | None:
        """One integer scalar; NOT_PRESENT/non-integer -> None (never 0)."""
        return _snmp_int(client.get(oid))

    # -- collect -------------------------------------------------------------

    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch:
        if request.collection_type not in ("reachability", "health", "metrics", "logs", "discovery"):
            raise AdapterError("protocol_error", f"未知的采集类型 {request.collection_type}", stage="prepare")
        client = self._client(session)
        if request.collection_type in ("reachability", "health"):
            # Prove the agent answers WITHOUT touching any counter leaf (the
            # 64-bit rate derivation samples once per metrics run — see
            # RateSampleCache docs). Reachability is tracked by run success;
            # a failure raises AdapterError below.
            self._identity_read(client)
            return ObservationBatch()
        if request.collection_type != "metrics":
            # logs: switch events flow through the M5T1 syslog/trap ingest
            # path (CORE-MON-06) — there is no poll source in M5T2;
            # discovery-type runs carry no collect payload either.
            return ObservationBatch()
        bundle = _Bundle()
        self._run_metrics(bundle, client, request)
        return ObservationBatch(
            observations=tuple(bundle.observations),
            components=tuple(bundle.components),
            errors=tuple(bundle.errors),
        )

    def _identity_read(self, client: SnmpClient) -> None:
        try:
            self._sys_descr(client)
        except SnmpError as exc:
            if exc.code in FATAL_SNMP_CODES:
                _raise_fatal_snmp(exc, stage="collect")
            raise AdapterError("protocol_error", exc.message, stage=exc.stage or "collect") from exc

    def _run_metrics(self, bundle: _Bundle, client: SnmpClient, request: CollectionRequest) -> None:
        """One metrics pass: every implemented family, read+map per family.

        Per-family error isolation (DSM/Redfish boundary): an auth/network
        SnmpError fails the whole run (AdapterError); any other device-side
        answer degrades to per-key ObservationErrors so one broken family
        never hides the rest of the batch. Mapping is pure (no device I/O),
        so only the reads sit inside the guards. The interface pass runs
        first and yields the ifIndex->ifName map the optics/layer2/poe
        mappings attach their components to.
        """
        if "system" in self.family_keys:
            keys = self.family_keys["system"]
            try:
                self._collect_system(bundle, client, request.now)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
        names: dict[int, str] = {}
        if "interfaces" in self.family_keys:
            keys = self.family_keys["interfaces"]
            iface_rows: list[InterfaceRow] | None = None
            try:
                iface_rows = self._read_interfaces(client)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
            if iface_rows is not None:
                self._map_interfaces(bundle, iface_rows, request)
                names = {row.if_index: row.name for row in iface_rows}
        if "entities" in self.family_keys:
            keys = self.family_keys["entities"]
            entity_rows: list[EntityRow] | None = None
            try:
                entity_rows = self._read_entities(client)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
            if entity_rows is not None:
                self._map_entities(bundle, entity_rows, request.now)
        if "optics" in self.family_keys:
            keys = self.family_keys["optics"]
            optics_rows: dict[int, dict[str, int | None]] | None = None
            try:
                optics_rows = self._read_optics(client)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
            if optics_rows is not None:
                self._map_optics(bundle, optics_rows, names, request)
        if "layer2" in self.family_keys:
            keys = self.family_keys["layer2"]
            layer2_rows: dict[str, object] | None = None
            try:
                layer2_rows = self._read_layer2(client)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
            if layer2_rows is not None:
                self._map_layer2(bundle, layer2_rows, names, request.now)
        if "poe" in self.family_keys:
            keys = self.family_keys["poe"]
            poe_rows: dict[str, object] | None = None
            try:
                poe_rows = self._read_poe(client)
            except SnmpError as exc:
                self._family_failure(bundle, keys, exc)
            if poe_rows is not None:
                self._map_poe(bundle, poe_rows, names, request)

    def _family_failure(self, bundle: _Bundle, keys: tuple[str, ...], exc: SnmpError) -> None:
        """One family read failed: auth/network fail the run, other device
        answers degrade to per-key ObservationErrors."""
        if exc.code in FATAL_SNMP_CODES:
            _raise_fatal_snmp(exc, stage="collect")
        detail = f"族读取失败：{_safe_snmp_exc(exc)}"
        for key in keys:
            bundle.err(key, detail=detail, error_code=exc.code, stage="collect")

    # -- collect mappings (points + components + errors) ----------------------

    def _collect_system(self, bundle: _Bundle, client: SnmpClient, now: datetime) -> None:
        cpu = self._read_scalar_int(client, OID_CPU_UTIL_5S)
        memory = self._read_scalar_int(client, OID_MEM_UTIL)
        if cpu is None:
            bundle.err("system.cpu_percent", detail="hwCpuDevUtilization5s 缺失或不可解析（不写 0）")
        else:
            bundle.obs("system.cpu_percent", cpu, now=now, evidence=_EV_CPU)
        if memory is None:
            bundle.err("system.memory_percent", detail="hwMemoryDevUtilization 缺失或不可解析（不写 0）")
        else:
            bundle.obs("system.memory_percent", memory, now=now, evidence=_EV_MEM)

    def _map_interfaces(self, bundle: _Bundle, rows: list[InterfaceRow], request: CollectionRequest) -> None:
        """admin/oper/counters/bps per port; components kind=interface with
        native_id = ifName (matches the ingest syslog flap component ids)."""
        keys = self.family_keys.get("interfaces", ())
        for row in rows:
            native = row.name
            bundle.components.append(_component("interface", native, native, STATUS_UNKNOWN))
            if row.admin_raw is not None:
                mapped = _translate(IF_ADMIN, row.admin_raw)
                if mapped is not None:
                    bundle.obs(
                        "interface.admin_status",
                        mapped,
                        now=request.now,
                        kind="interface",
                        native=native,
                        evidence=_EV_IF_ADMIN,
                    )
                else:
                    bundle.err(
                        "interface.admin_status",
                        detail=f"ifAdminStatus 字面量 {row.admin_raw!r} 无认证映射（RFC 2863）",
                        kind="interface",
                        native=native,
                    )
            else:
                bundle.err("interface.admin_status", detail="ifAdminStatus 缺失", kind="interface", native=native)
            if row.oper_raw is not None:
                mapped = _translate(IF_OPER, row.oper_raw)
                if mapped is not None:
                    bundle.obs(
                        "interface.oper_status",
                        mapped,
                        now=request.now,
                        kind="interface",
                        native=native,
                        evidence=_EV_IF_OPER,
                    )
                else:
                    bundle.err(
                        "interface.oper_status",
                        detail=f"ifOperStatus 字面量 {row.oper_raw!r} 无认证映射（RFC 2863）",
                        kind="interface",
                        native=native,
                    )
            else:
                bundle.err("interface.oper_status", detail="ifOperStatus 缺失", kind="interface", native=native)
            if "interface.crc_errors" in keys:
                if row.crc is not None:
                    bundle.obs(
                        "interface.crc_errors",
                        row.crc,
                        now=request.now,
                        kind="interface",
                        native=native,
                        evidence=_EV_IF_CRC,
                    )
                else:
                    bundle.err("interface.crc_errors", detail="hwPortCrcErrors 缺失", kind="interface", native=native)
            if "interface.errors" in keys:
                errors = _add_or_none(row.in_errors, row.out_errors)
                if errors is not None:
                    bundle.obs(
                        "interface.errors",
                        errors,
                        now=request.now,
                        kind="interface",
                        native=native,
                        evidence=_EV_IF_ERRORS,
                    )
                else:
                    bundle.err(
                        "interface.errors",
                        detail="ifInErrors/ifOutErrors 缺失",
                        kind="interface",
                        native=native,
                    )
            if "interface.drops" in keys:
                drops = _add_or_none(row.in_discards, row.out_discards)
                if drops is not None:
                    bundle.obs(
                        "interface.drops",
                        drops,
                        now=request.now,
                        kind="interface",
                        native=native,
                        evidence=_EV_IF_DROPS,
                    )
                else:
                    bundle.err(
                        "interface.drops",
                        detail="ifInDiscards/ifOutDiscards 缺失",
                        kind="interface",
                        native=native,
                    )
            self._map_interface_rates(bundle, row, request)

    def _map_interface_rates(self, bundle: _Bundle, row: InterfaceRow, request: CollectionRequest) -> None:
        """in_bps/out_bps from two 64-bit samples (RateSampleCache docs).

        Cache miss -> ObservationError (never a fabricated value; a platform
        restart loses one rate interval, documented). A sample that went
        backwards (restart/rollover) derives the unsigned 64-bit delta and
        marks the point partial per contracts/metrics.json counter_reset.
        """
        keys = self.family_keys.get("interfaces", ())
        if "interface.in_bps" not in keys or "interface.out_bps" not in keys:
            return
        native = row.name
        if row.hc_in is None or row.hc_out is None:
            for key in ("interface.in_bps", "interface.out_bps"):
                bundle.err(key, detail="ifHCInOctets/ifHCOutOctets 缺失，无法计算速率", kind="interface", native=native)
            return
        previous = self._rate_samples.get(request.device_id, native)
        current = CounterSample(at=request.now, in_octets=row.hc_in, out_octets=row.hc_out)
        self._rate_samples.store(request.device_id, native, current)
        if previous is None:
            for key in ("interface.in_bps", "interface.out_bps"):
                bundle.err(
                    key,
                    detail=(
                        "rate_unavailable_first_sample：无上一 64 位计数采样，无法派生速率"
                        "（首次采集或平台重启后丢失一个速率区间 — M5T2 决策，不伪造速率）"
                    ),
                    error_code="not_configured",
                    stage="collect",
                    kind="interface",
                    native=native,
                )
            return
        delta_seconds = (request.now - previous.at).total_seconds()
        if delta_seconds <= 0:
            for key in ("interface.in_bps", "interface.out_bps"):
                bundle.err(key, detail="采样时间未前进，无法派生速率", kind="interface", native=native)
            return
        in_delta, in_reset = derive_rate_bps(previous.in_octets, row.hc_in)
        out_delta, out_reset = derive_rate_bps(previous.out_octets, row.hc_out)
        quality = Quality.PARTIAL if (in_reset or out_reset) else Quality.GOOD
        if in_reset or out_reset:
            evidence = _EV_IF_BPS + "（计数器回绕/重启，首个派生点 partial — counter_reset 规则，无负速率）"
        else:
            evidence = _EV_IF_BPS
        bundle.obs(
            "interface.in_bps",
            in_delta * 8.0 / delta_seconds,
            now=request.now,
            quality=quality,
            kind="interface",
            native=native,
            evidence=evidence,
        )
        bundle.obs(
            "interface.out_bps",
            out_delta * 8.0 / delta_seconds,
            now=request.now,
            quality=quality,
            kind="interface",
            native=native,
            evidence=evidence,
        )

    def _map_entities(self, bundle: _Bundle, rows: list[EntityRow], now: datetime) -> None:
        keys = self.family_keys.get("entities", ())
        for row in rows:
            if row.kind == "psu":
                self._map_psu(bundle, row, now, keys)
            elif row.kind == "fan":
                self._map_fan(bundle, row, now, keys)
            elif row.kind == "temperature":
                self._map_temperature(bundle, row, now, keys)
            else:
                bundle.err(
                    None,
                    detail=f"hwEntityType 字面量（slot {row.slot}）无认证映射",
                    error_code="protocol_error",
                    stage="parse",
                )

    def _map_psu(self, bundle: _Bundle, row: EntityRow, now: datetime, keys: tuple[str, ...]) -> None:
        native = row.name
        bundle.components.append(_component("psu", native, native, self._psu_component_status(row)))
        if "psu.present" in keys:
            if row.present is not None:
                mapped = _translate(ENTITY_PRESENT, row.present)
                if mapped is not None:
                    bundle.obs("psu.present", mapped, now=now, kind="psu", native=native, evidence=_EV_ENTITY)
                else:
                    bundle.err(
                        "psu.present",
                        detail=f"hwEntityPresent 字面量 {row.present!r} 无认证映射",
                        kind="psu",
                        native=native,
                    )
            else:
                bundle.err("psu.present", detail="hwEntityPresent 缺失", kind="psu", native=native)
        if "psu.status" in keys:
            if row.present is not None and ENTITY_PRESENT.get(row.present) == "absent":
                bundle.obs("psu.status", "absent", now=now, kind="psu", native=native, evidence=_EV_ENTITY)
            elif row.status is not None:
                mapped = _translate(ENTITY_STATUS, row.status)
                if mapped is not None:
                    bundle.obs("psu.status", mapped, now=now, kind="psu", native=native, evidence=_EV_ENTITY)
                else:
                    bundle.err(
                        "psu.status",
                        detail=f"hwEntityStatus 字面量 {row.status!r} 无认证映射",
                        kind="psu",
                        native=native,
                    )
            else:
                bundle.err("psu.status", detail="hwEntityStatus 缺失", kind="psu", native=native)

    def _psu_component_status(self, row: EntityRow) -> str:
        if row.present is not None and ENTITY_PRESENT.get(row.present) == "absent":
            return "absent"
        if row.status is not None:
            mapped = ENTITY_STATUS.get(row.status)
            if mapped is not None:
                return mapped
        return STATUS_UNKNOWN

    def _map_fan(self, bundle: _Bundle, row: EntityRow, now: datetime, keys: tuple[str, ...]) -> None:
        native = row.name
        absent = row.present is not None and ENTITY_PRESENT.get(row.present) == "absent"
        if absent:
            bundle.components.append(_component("fan", native, native, "absent"))
            return  # absent fan: no rpm/status fabrications for a missing unit
        status_mapped = _translate(ENTITY_STATUS, row.status) if row.status is not None else None
        if row.status is not None:
            bundle.components.append(
                _component("fan", native, native, status_mapped if status_mapped is not None else STATUS_UNKNOWN)
            )
            if status_mapped is not None:
                bundle.obs("fan.status", status_mapped, now=now, kind="fan", native=native, evidence=_EV_ENTITY)
            else:
                bundle.err(
                    "fan.status",
                    detail=f"hwEntityStatus 字面量 {row.status!r} 无认证映射",
                    kind="fan",
                    native=native,
                )
        else:
            bundle.components.append(_component("fan", native, native, STATUS_UNKNOWN))
            bundle.err("fan.status", detail="hwEntityStatus 缺失", kind="fan", native=native)
        if row.value is not None:
            bundle.obs("fan.rpm", row.value, now=now, kind="fan", native=native, evidence=_EV_ENTITY)
        else:
            bundle.err("fan.rpm", detail="hwEntityValue（转速）缺失", kind="fan", native=native)

    def _map_temperature(self, bundle: _Bundle, row: EntityRow, now: datetime, keys: tuple[str, ...]) -> None:
        del keys
        native = row.name
        absent = row.present is not None and ENTITY_PRESENT.get(row.present) == "absent"
        if absent:
            return  # absent sensor: no component, no point
        status_mapped = _translate(ENTITY_STATUS, row.status) if row.status is not None else None
        if row.status is not None:
            bundle.components.append(
                _component("sensor", native, native, status_mapped if status_mapped is not None else STATUS_UNKNOWN)
            )
            if status_mapped is None:
                bundle.err(
                    "temperature.system",
                    detail=f"hwEntityStatus 字面量 {row.status!r} 无认证映射",
                    kind="sensor",
                    native=native,
                )
        else:
            bundle.components.append(_component("sensor", native, native, STATUS_UNKNOWN))
        if row.value is not None:
            bundle.obs(
                "temperature.system",
                row.value / 10.0,
                now=now,
                kind="sensor",
                native=native,
                evidence=_EV_ENTITY,
            )
        else:
            bundle.err("temperature.system", detail="hwEntityValue（温度）缺失", kind="sensor", native=native)

    def _map_optics(
        self,
        bundle: _Bundle,
        rows: dict[int, dict[str, int | None]],
        names: dict[int, str],
        request: CollectionRequest,
    ) -> None:
        """Optical modules per port; a port WITHOUT a module has no row -> no
        component, no point (never a fabricated 0). Native id = the port's
        interface ifName."""
        keys = self.family_keys.get("optics", ())
        # Metric key suffix == the raw column name (rx_dbm/tx_dbm/
        # temperature_c/voltage_v/current_ma); the scale divisor converts
        # the [sim] scaled integers to the contract units.
        optic_scale: dict[str, tuple[str, float]] = {
            "rx_dbm": ("hwTransceiverRxPower", 100.0),
            "tx_dbm": ("hwTransceiverTxPower", 100.0),
            "temperature_c": ("hwTransceiverTemperatureC", 100.0),
            "voltage_v": ("hwTransceiverVoltageV", 1000.0),
            "current_ma": ("hwTransceiverCurrentMa", 1000.0),
        }
        for if_index, values in rows.items():
            native = names.get(if_index)
            if native is None:
                bundle.err(
                    None,
                    detail=f"hwOpticalModuleInfoTable 行引用了未知接口（ifIndex {if_index}）",
                    kind="transceiver",
                    native=str(if_index),
                )
                continue
            bundle.components.append(_component("transceiver", native, native, STATUS_UNKNOWN))
            for key in keys:
                column = key.split(".", 1)[1]
                entry = optic_scale.get(column)
                if entry is None:
                    continue
                leaf_label, divisor = entry
                raw_value = values.get(column)
                if raw_value is not None:
                    bundle.obs(
                        key,
                        raw_value / divisor,
                        now=request.now,
                        kind="transceiver",
                        native=native,
                        evidence=_EV_OPTICS,
                    )
                else:
                    bundle.err(key, detail=f"{leaf_label} 缺失", kind="transceiver", native=native)

    def _map_layer2(self, bundle: _Bundle, layer2: dict[str, object], names: dict[int, str], now: datetime) -> None:
        loop = layer2.get("loop")
        if isinstance(loop, SnmpValue):
            loop_int = _snmp_int(loop)
            mapped = _translate(LAYER2_STATUS, loop_int) if loop_int is not None else None
            if mapped is not None:
                bundle.obs("loop.status", mapped, now=now, evidence=_EV_LOOP)
            else:
                bundle.err("loop.status", detail=f"hwLoopDetectionStatus 字面量 {loop.value!r} 无认证映射")
        else:
            bundle.err("loop.status", detail="hwLoopDetectionStatus 缺失")
        storm = layer2.get("storm")
        if isinstance(storm, SnmpValue):
            storm_int = _snmp_int(storm)
            mapped = _translate(LAYER2_STATUS, storm_int) if storm_int is not None else None
            if mapped is not None:
                bundle.obs("broadcast_storm.status", mapped, now=now, evidence=_EV_STORM)
            else:
                bundle.err("broadcast_storm.status", detail=f"hwBroadcastStormStatus 字面量 {storm.value!r} 无认证映射")
        else:
            bundle.err("broadcast_storm.status", detail="hwBroadcastStormStatus 缺失")
        stp = layer2.get("stp")
        if not isinstance(stp, dict):
            stp = {}
        for if_index, state_raw in stp.items():
            if not isinstance(if_index, int) or not isinstance(state_raw, int):
                continue
            name = names.get(if_index)
            if name is None:
                continue  # STP row for an unknown interface: not attributable
            mapped = _translate(STP_STATE, state_raw)
            if mapped is not None:
                bundle.obs("stp.port_state", mapped, now=now, kind="interface", native=name, evidence=_EV_STP)
            else:
                bundle.err(
                    "stp.port_state",
                    detail=f"hwStpPortState 字面量 {state_raw!r} 无认证映射",
                    kind="interface",
                    native=name,
                )

    def _map_poe(
        self,
        bundle: _Bundle,
        poe: dict[str, object],
        names: dict[int, str],
        request: CollectionRequest,
    ) -> None:
        """PoE per-port state/power + device total/budget/percent/alarm."""
        now = request.now
        keys = self.family_keys.get("poe", ())
        states = poe.get("states")
        powers = poe.get("powers")
        if not isinstance(states, dict) or not isinstance(powers, dict):
            states = {}
            powers = {}
        for if_index in sorted(states):
            if not isinstance(if_index, int):
                continue
            native = names.get(if_index)
            if native is None:
                continue
            bundle.components.append(_component("poe_port", native, native, STATUS_UNKNOWN))
            state_raw = states.get(if_index)
            if isinstance(state_raw, int) and "poe.port.status" in keys:
                mapped = _translate(POE_STATE, state_raw)
                if mapped is not None:
                    bundle.obs("poe.port.status", mapped, now=now, kind="poe_port", native=native, evidence=_EV_POE)
                else:
                    bundle.err(
                        "poe.port.status",
                        detail=f"hwPoEPortState 字面量 {state_raw!r} 无认证映射",
                        kind="poe_port",
                        native=native,
                    )
            elif "poe.port.status" in keys:
                bundle.err("poe.port.status", detail="hwPoEPortState 缺失", kind="poe_port", native=native)
            power_mw = powers.get(if_index)
            if isinstance(power_mw, int) and "poe.port.power_w" in keys:
                bundle.obs(
                    "poe.port.power_w",
                    power_mw / 1000.0,
                    now=now,
                    kind="poe_port",
                    native=native,
                    evidence=_EV_POE,
                )
            elif "poe.port.power_w" in keys:
                bundle.err("poe.port.power_w", detail="hwPoEPortPowerMw 缺失", kind="poe_port", native=native)
        total = poe.get("total")
        budget = poe.get("budget")
        total_mw = _snmp_int(total) if isinstance(total, SnmpValue) else None
        budget_mw = _snmp_int(budget) if isinstance(budget, SnmpValue) else None
        if "poe.total_power_w" in keys:
            if total_mw is not None:
                bundle.obs("poe.total_power_w", total_mw / 1000.0, now=now, evidence=_EV_POE)
            else:
                bundle.err("poe.total_power_w", detail="hwPoEDeviceTotalPowerMw 缺失")
        if "poe.power_budget_w" in keys:
            if budget_mw is not None:
                bundle.obs("poe.power_budget_w", budget_mw / 1000.0, now=now, evidence=_EV_POE)
            else:
                bundle.err("poe.power_budget_w", detail="hwPoEDeviceBudgetMw 缺失")
        if "poe.total_power_percent" in keys:
            if total_mw is not None and budget_mw is not None and budget_mw > 0:
                bundle.obs("poe.total_power_percent", total_mw / budget_mw * 100.0, now=now, evidence=_EV_POE)
            elif budget_mw is not None and budget_mw <= 0:
                bundle.err(
                    "poe.total_power_percent",
                    detail=(
                        f"no_budget_denominator：设备 PoE 预算为 {budget_mw} mW（0），"
                        "缺少分母不以瓦数冒充百分比（ADR-016/025）"
                    ),
                    error_code="not_configured",
                )
            else:
                bundle.err(
                    "poe.total_power_percent",
                    detail="no_budget_denominator：设备未提供总功耗或预算（缺失分母），不伪造百分比（ADR-016/025）",
                    error_code="not_configured",
                )
        if "poe.total_power_alarm" in keys:
            alarm = poe.get("alarm")
            alarm_int = _snmp_int(alarm) if isinstance(alarm, SnmpValue) else None
            if alarm_int is not None:
                mapped = _translate(POE_ALARM, alarm_int)
                if mapped is not None:
                    bundle.obs("poe.total_power_alarm", mapped, now=now, evidence=_EV_POE)
                else:
                    bundle.err(
                        "poe.total_power_alarm",
                        detail=f"hwPoEDeviceAlarmState 字面量 {alarm_int!r} 无认证映射（告警只取设备自身状态）",
                    )
            else:
                bundle.err("poe.total_power_alarm", detail="设备未提供 PoE 告警状态（不伪造 normal）")

    # -- inventory (discover) --------------------------------------------------

    def _inventory_components(self, evidence: dict[str, object]) -> tuple[ComponentObserved, ...]:
        components: list[ComponentObserved] = []
        by_index: dict[int, str] = {}
        ifaces = evidence.get("interfaces")
        if isinstance(ifaces, list):
            for row in ifaces:
                if isinstance(row, InterfaceRow):
                    components.append(_component("interface", row.name, row.name, STATUS_UNKNOWN))
                    by_index[row.if_index] = row.name
        optics = evidence.get("optics")
        if isinstance(optics, dict):
            for if_index in sorted(optics):
                native = by_index.get(if_index)
                if native is not None:
                    components.append(_component("transceiver", native, native, STATUS_UNKNOWN))
        entities = evidence.get("entities")
        if isinstance(entities, list):
            for row in entities:
                if not isinstance(row, EntityRow):
                    continue
                if row.kind == "psu":
                    components.append(_component("psu", row.name, row.name, self._psu_component_status(row)))
                elif row.kind == "fan":
                    absent = row.present is not None and ENTITY_PRESENT.get(row.present) == "absent"
                    if absent:
                        continue
                    mapped = ENTITY_STATUS.get(row.status) if row.status is not None else None
                    components.append(
                        _component("fan", row.name, row.name, mapped if mapped is not None else STATUS_UNKNOWN)
                    )
                elif row.kind == "temperature":
                    absent = row.present is not None and ENTITY_PRESENT.get(row.present) == "absent"
                    if absent:
                        continue
                    mapped = ENTITY_STATUS.get(row.status) if row.status is not None else None
                    components.append(
                        _component("sensor", row.name, row.name, mapped if mapped is not None else STATUS_UNKNOWN)
                    )
        poe = evidence.get("poe")
        if isinstance(poe, dict) and isinstance(poe.get("states"), dict):
            for if_index in sorted(poe["states"]):
                native = by_index.get(if_index)
                if native is not None:
                    components.append(_component("poe_port", native, native, STATUS_UNKNOWN))
        return tuple(components)
