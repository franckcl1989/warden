"""Common Redfish adapter — probe/discover/collect (docs/DEVICE_ADAPTERS.md §2/§4).

Registration: ``adapter_key=server.redfish``, a REAL registered adapter for
devices of device_type ``server`` (DEVICE_ADAPTERS.md §3 registry is
registry-driven, so onboarding accepts it). It is the shared BASE the five
certification-target vendor adapters (server.dell_idrac, server.inspur_ibmc,
server.xfusion_ibmc, server.lenovo_xcc, server.huawei_ibmc) subclass in M3T5.
``server.redfish`` itself is NOT a hardware certification target: it exists so
the M3 probe/discover/collect flows are exercisable against the test-device
simulator (tests/simulators/redfish) — never 真机 evidence
(HARDWARE_CERTIFICATION.md §3). No vendor-specific behavior lives in this
module beyond certified-fixture comments; vendor overlays own vendor shapes.

Transport rules (SECURITY.md §6/§7, DEVICE_ADAPTERS.md §8):

- The connection host is the policy-resolved address: probe/discover use
  ``ConnectionProfile.resolved_ip`` (set by the platform's SSRF policy before
  any adapter call) and connect to that IP, never a re-resolved hostname.
  When ``resolved_ip`` is absent the endpoint must itself be an IP literal
  (tests construct such sessions directly) — a hostname is refused.
- ``connection_config.protocol``: ``https`` (default, certificate-validated
  via the system CA store when ``verify_tls`` is true) or ``http``.
  Plain HTTP is a dev/test-only weak protocol (the simulator runs on http);
  carrying credentials over http is never allowed outside that explicit
  operator configuration (audited as security.config_changed by the
  platform). ``tls_fingerprint_sha256`` pinning cannot run inside httpx
  (infrastructure/tls.py): a configured pin fails the probe tls stage with
  ``not_configured`` until vendor overlay wiring (M3T5) — never a silent
  downgrade to unverified TLS.

Collect semantics (DEVICE_ADAPTERS.md §2.3, ADR-014): every mapped metric key
yields an ``Observation`` ONLY when the device provided the value; anything
missing/unparseable is an explicit ``ObservationError`` (never 0/normal/
passed). Status mapping tables are one-directional device→contract; a device
value with no certified mapping is an error, and an explicitly unknown device
value maps to the contract ``unknown``. No thresholds are invented
(ADR-025): temperatures/fan speeds are device-reported display values and
statuses come from device Status blocks only.

Per-collection-type content (ARCHITECTURE.md §8, TRACEABILITY.md §2.1):

- ``reachability``/``health``: the health subset (SRV-MON-01/07) — every
  batch carries ``health.overall`` so the platform's batch-scoped device
  health never degrades to unknown between metrics runs;
- ``metrics``: health subset + thermal/power/storage/memory/fan mappings
  (SRV-MON-02..07) + the full component inventory observed this pass;
- ``logs``: health subset + SEL entries (SRV-MON-08). Entries are read from
  the oldest entry forward and only pages NEWER than the previous logs run
  are emitted (``CollectionRequest.last_run_at``); on the first run the full
  tail (bounded by the parse layer's page budget) is imported. Re-emitting
  already-known entries is harmless — the platform dedupes on the device
  native event id (DATA_MODEL.md §5.5);
- ``discovery``: the health subset (full re-discovery is probe/discover
  territory; collect never re-walks capability rows).

Component modeling (DATA_MODEL.md §4.4): ``native_id`` = the resource ``Id``
when present, else its ``Name``, else its ``MemberId``; temperature sensors
use ``temp-<MemberId>``; processors use ``cpu-<1-based index>`` from
ProcessorSummary.Count. Properties are minimal (model/capacity/speed/media
type) and documented per component type; component serials/asset data belong
to the asset surface (SRV-ACT-07 asset.refresh), never duplicated here.
Component statuses map through the same one-directional Status table; an
empty DIMM slot is a component with status ``absent`` and no memory points.

Certified-fixture comments (simulator origin only, never 真机): the generic
OEM blocks this common adapter parses — DIMM ``Oem.Vendor.ECCErrorCount``,
drive ``Oem.Vendor.SMARTStatus``/``PredictiveFailure``, volume
``Oem.Vendor.RAIDStatus`` — are shapes the M3T1/M3T2 test simulator emits and
their contract fixtures freeze; vendor overlays (M3T5) re-certify the real
per-vendor equivalents from sanitized 真机 fixtures before any vendor key is
declared supported.
"""

from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from app.domain.adapter import (
    AdapterError,
    CapabilitySupport,
    CollectionRequest,
    ComponentObserved,
    ConnectionProfile,
    DeviceSession,
    DiscoveryResult,
    EventObservation,
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
from app.domain.operation_plan import DeviceSnapshot, OperationPlan, OperationRequest, plan_operation
from app.generated.capabilities import REQUIREMENTS
from app.infrastructure.protocols.redfish.client import DEFAULT_BASE_PATH, RedfishClient, RedfishEndpoint
from app.infrastructure.protocols.redfish.errors import RedfishError
from app.infrastructure.protocols.redfish.parse import (
    MAX_COLLECTION_PAGES,
    FieldSentinel,
    RedfishResource,
    bool_field,
    datetime_field,
    follow,
    member_links,
    number_field,
    text_field,
    walk_collection,
)
from app.infrastructure.protocols.redfish.session import RedfishCredentials
from app.infrastructure.tls import build_ssl_context

OBSERVATION_SOURCE = "redfish"
SEL_EVENT_SOURCE = "redfish_sel"
CONNECT_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 30.0

_MISSING = FieldSentinel.MISSING
_UNPARSEABLE = FieldSentinel.UNPARSEABLE

# -- status mapping tables (one-directional device -> contract) ---------------
# Device values absent from a table are explicit ObservationErrors; values the
# device itself reports as unknown map to the contract "unknown" value.

_HEALTH_MAP: dict[str, str] = {
    "OK": "healthy",
    "Warning": "warning",
    "Critical": "critical",
    "Unknown": "unknown",
}

_COMPONENT_HEALTH_MAP: dict[str, str] = {
    "OK": "ok",
    "Warning": "warning",
    "Critical": "critical",
    "Unknown": "unknown",
}

# System/Chassis IndicatorLED -> indicator_state. "Off" on a server panel is
# the normal (no-problem) state; blinking marks the critical panel alarm the
# simulator certifies for SRV-MON-01/07. Vendor-specific LED semantics are
# overlay territory (M3T5).
_INDICATOR_MAP: dict[str, str] = {
    "Off": "normal",
    "Lit": "warning",
    "Blinking": "critical",
    "Unknown": "unknown",
}

# DSP2046 PhysicalSecurity.IntrusionSensor -> condition_state.
_INTRUSION_MAP: dict[str, str] = {
    "Normal": "normal",
    "HardwareIntrusionDetected": "detected",
    "TamperingDetected": "detected",
    "IntrusionDetected": "detected",
    "Unknown": "unknown",
}

# DSP2046 Thermal Temperatures PhysicalContext -> SRV-MON-02 metric key.
_TEMP_CONTEXT_TO_METRIC: dict[str, str] = {
    "CPU": "temperature.cpu",
    "Memory": "temperature.memory",
    "Intake": "temperature.inlet",
    "Board": "temperature.board",
}

# OEM SMART member (generic SMARTStatus, simulator-certified shape) ->
# smart_status. Absent member is an ObservationError, never "passed".
_SMART_MAP: dict[str, str] = {
    "OK": "passed",
    "Warning": "warning",
    "Failed": "failed",
    "Unknown": "unknown",
}

# OEM RAID member (generic RAIDStatus, simulator-certified shape) is the
# device's own RAID semantic and wins over the Volume Status block.
_OEM_RAID_MAP: dict[str, str] = {
    "Optimal": "optimal",
    "Degraded": "degraded",
    "Rebuilding": "rebuilding",
    "Failed": "failed",
    "Unknown": "unknown",
}

# Volume Status.Health fallback -> raid_status (used when no OEM RAID member).
_VOLUME_HEALTH_MAP: dict[str, str] = {
    "OK": "optimal",
    "Warning": "degraded",
    "Critical": "failed",
    "Unknown": "unknown",
}

# Redfish LogEntry Severity -> event severity (events.json normalization).
_SEVERITY_MAP: dict[str, str] = {
    "OK": "info",
    "Informational": "info",
    "Warning": "warning",
    "Critical": "critical",
    "Fatal": "critical",
    "Unknown": "unknown",
}

# Health-state severity ranking for aggregating System + Chassis Status.
_HEALTH_RANK: dict[str, int] = {"healthy": 0, "unknown": 1, "warning": 2, "critical": 3}

# OEM member names normalized (lowercase, [-_ ] stripped) for generic matching.
_ECC_AGGREGATE_NAMES = frozenset({"eccerrorcount", "totaleccerrorcount"})
_SMART_MEMBER_NAMES = frozenset({"smartstatus"})
_PREDICTIVE_MEMBER_NAMES = frozenset({"predictivefailure"})
_RAID_MEMBER_NAMES = frozenset({"raidstatus"})
_TIMESTAMP_MEMBER_NAMES = frozenset({"timestamp"})

# Unsupported-capability reason codes (stable snake_case; adapter-owned
# vocabulary, DeviceCapability.reason_code / detail on the API).
REASON_CODES: dict[str, str] = {
    "health.overall": "no_system_status",
    "indicator.led": "no_indicator_led",
    "temperature.cpu": "no_cpu_context_sensor",
    "temperature.memory": "no_memory_context_sensor",
    "temperature.inlet": "no_intake_context_sensor",
    "temperature.board": "no_board_context_sensor",
    "memory.status": "no_populated_memory",
    "memory.ecc_errors": "no_ecc_counter_member",
    "drive.status": "no_storage_drives",
    "drive.smart": "no_drive_smart_member",
    "drive.predictive_failure": "no_drive_predictive_member",
    "raid.status": "no_raid_volume",
    "psu.present": "no_power_supplies",
    "psu.status": "no_power_supplies",
    "psu.load_w": "no_power_supplies",
    "psu.voltage_v": "no_power_supplies",
    "fan.rpm": "no_fans",
    "fan.status": "no_fans",
    "chassis.intrusion": "no_physical_security",
    "event.sel": "no_sel_log_service",
    "manager.reset": "no_manager_reset_action",
    "power.on": "no_system_reset_action",
    "power.off": "no_system_reset_action",
    "power.cycle": "no_system_reset_action",
    "console.kvm.open": "no_graphical_console",
    "logs.support_bundle.collect": "no_sel_log_service",
    "virtual_media.mount": "no_virtual_media_service",
    "virtual_media.unmount": "no_virtual_media_service",
    "firmware.query": "no_firmware_inventory",
    "firmware.update": "no_update_service",
    "asset.refresh": "no_system_resource",
}

_DETAIL_CN: dict[str, str] = {
    "no_system_status": "设备未返回 ComputerSystem.Status",
    "no_indicator_led": "系统与机箱均未提供 IndicatorLED",
    "no_cpu_context_sensor": "Thermal 中不存在 CPU 上下文温度传感器",
    "no_memory_context_sensor": "Thermal 中不存在 Memory 上下文温度传感器",
    "no_intake_context_sensor": "Thermal 中不存在 Intake 上下文温度传感器",
    "no_board_context_sensor": "Thermal 中不存在 Board 上下文温度传感器",
    "no_populated_memory": "未发现已安装内存条",
    "no_ecc_counter_member": "内存未提供明确的 ECC 计数器成员",
    "no_storage_drives": "未发现 Storage/Drives",
    "no_drive_smart_member": "硬盘未提供 SMART OEM 成员",
    "no_drive_predictive_member": "硬盘未提供预测故障 OEM 成员",
    "no_raid_volume": "未发现 RAID 卷",
    "no_power_supplies": "未发现 Power/PowerSupplies",
    "no_fans": "未发现 Thermal Fans",
    "no_physical_security": "机箱未提供 PhysicalSecurity",
    "no_sel_log_service": "管理卡未提供 SEL LogService",
    "no_manager_reset_action": "管理卡未提供 Manager Reset 动作",
    "no_system_reset_action": "服务器未提供 ComputerSystem Reset 动作",
    "no_graphical_console": "管理卡未提供图形控制台",
    "no_virtual_media_service": "管理卡未提供 VirtualMedia 服务",
    "no_firmware_inventory": "UpdateService 未提供固件清单",
    "no_update_service": "未提供 UpdateService",
    "no_system_resource": "未发现 ComputerSystem 资源",
}

_COMPONENT_PROPERTIES: dict[str, frozenset[str]] = {
    # Documented minimal property sets per component kind (DATA_MODEL §4.4).
    "processor": frozenset({"model", "total_cores"}),
    "memory": frozenset({"device_type", "capacity_mib", "speed_mhz", "slot"}),
    "drive": frozenset({"media_type", "model", "capacity_bytes", "revision"}),
    "raid": frozenset({"raid_type", "volume_type", "capacity_bytes"}),
    "psu": frozenset({"capacity_w"}),
    "fan": frozenset(),
    "sensor": frozenset({"physical_context"}),
}


def _norm_name(value: str) -> str:
    """OEM member key normalized for generic matching (case/separator-free)."""
    return re.sub(r"[-_\s]", "", value).lower()


def _oem_blocks(resource: RedfishResource | Mapping[str, Any]) -> list[dict[str, Any]]:
    """The dict values of a resource's ``Oem`` object (vendor namespaces)."""
    oem = resource.get("Oem")
    if not isinstance(oem, Mapping):
        return []
    blocks: list[dict[str, Any]] = []
    for block in oem.values():
        if isinstance(block, Mapping):
            blocks.append(dict(block))
    return blocks


def _member_value(blocks: Sequence[dict[str, Any]], names: frozenset[str]) -> tuple[str, Any] | None:
    """First ``(member_name, value)`` inside any OEM block whose normalized
    name matches ``names``; None when absent."""
    for block in blocks:
        for member_name, value in block.items():
            if _norm_name(str(member_name)) in names:
                return member_name, value
    return None


def _status_absent(state: object) -> bool:
    return isinstance(state, str) and state == "Absent"


def _component_status(status: object) -> str | FieldSentinel:
    """One Status block -> contracts component_status (documented table:
    State Absent -> absent; else Health OK/Warning/Critical/Unknown map
    directly; a missing/unparseable block stays a sentinel."""
    if status is None:
        return _MISSING
    if not isinstance(status, Mapping):
        return _UNPARSEABLE
    state = status.get("State")
    if state is not None:
        if not isinstance(state, str):
            return _UNPARSEABLE
        if _status_absent(state):
            return "absent"
    health = status.get("Health")
    if health is None:
        return _MISSING
    if not isinstance(health, str):
        return _UNPARSEABLE
    mapped = _COMPONENT_HEALTH_MAP.get(health)
    return mapped if mapped is not None else _UNPARSEABLE


def _status_to_text(status: object, fallback: str = "unknown") -> str:
    value = _component_status(status)
    return value if isinstance(value, str) else fallback


def _health_state(health: object) -> str | FieldSentinel:
    if health is None:
        return _MISSING
    if not isinstance(health, str):
        return _UNPARSEABLE
    mapped = _HEALTH_MAP.get(health)
    return mapped if mapped is not None else _UNPARSEABLE


def _worse_health(first: str, second: str) -> str:
    if _HEALTH_RANK[second] > _HEALTH_RANK[first]:
        return second
    return first


@dataclass(frozen=True)
class _Endpoint:
    host: str
    port: int
    scheme: str


def _endpoint_for(
    *,
    resolved_ip: IPv4Address | IPv6Address | None,
    management_endpoint: str,
    connection_config: dict[str, object],
    fallback_port: int | None = None,
) -> _Endpoint:
    """Resolved endpoint for a connection: the policy-validated IP when the
    platform provided one, else the management endpoint ITSELF must be an IP
    literal (no hostname resolution inside the adapter — SECURITY.md §7).
    Scheme/port come from the operator-declared ``connection_config``
    (protocol https default, port from config, then ``fallback_port``, then
    the scheme default)."""
    host = str(resolved_ip) if resolved_ip is not None else management_endpoint
    try:
        ip_address(host)
    except ValueError as exc:
        raise AdapterError(
            "not_configured",
            "未提供经 SSRF 策略解析的管理地址（resolved_ip）",
            stage="prepare",
        ) from exc
    scheme_raw = connection_config.get("protocol")
    scheme = scheme_raw if scheme_raw in ("http", "https") else "https"
    raw_port = connection_config.get("port")
    if not (isinstance(raw_port, int) and raw_port > 0):
        raw_port = fallback_port
    if not (isinstance(raw_port, int) and raw_port > 0):
        raw_port = 443 if scheme == "https" else 80
    return _Endpoint(host=host, port=raw_port, scheme=scheme)


def _build_http_client(endpoint: _Endpoint, *, verify_tls: bool, pinned_fingerprint: str | None) -> httpx.Client:
    """Policy-free transport construction at the adapter boundary.

    The platform resolves/validates endpoints before probe/discover; the
    collect pipeline currently passes no policy object into
    ``DeviceSession``, so the adapter honours the operator-declared
    ``connection_config`` (protocol/port/verify_tls). https verifies the CA
    chain (no permanent verify=false, SECURITY.md §6); a configured pin
    cannot run inside httpx and is refused here (callers map it to
    ``not_configured`` before any connection is attempted).
    """
    if endpoint.scheme == "https":
        context = build_ssl_context(verify_tls=verify_tls, pinned_fingerprint=None, ca_bundle_path=None)
        return httpx.Client(
            verify=context,
            base_url=f"https://{endpoint.host}:{endpoint.port}",
            timeout=httpx.Timeout(
                connect=CONNECT_TIMEOUT_SECONDS,
                read=REQUEST_TIMEOUT_SECONDS,
                write=REQUEST_TIMEOUT_SECONDS,
                pool=CONNECT_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
        )
    del pinned_fingerprint
    return httpx.Client(
        base_url=f"http://{endpoint.host}:{endpoint.port}",
        timeout=httpx.Timeout(
            connect=CONNECT_TIMEOUT_SECONDS,
            read=REQUEST_TIMEOUT_SECONDS,
            write=REQUEST_TIMEOUT_SECONDS,
            pool=CONNECT_TIMEOUT_SECONDS,
        ),
        follow_redirects=False,
    )


@contextmanager
def _redfish_client(
    http: httpx.Client,
    *,
    endpoint: _Endpoint,
    credentials: Mapping[str, object],
    auth_mode: str = "session",
) -> Iterator[RedfishClient]:
    """Wrap a transport in a RedfishClient and close both on exit (the device
    session is deleted on close). Plaintext credentials exist only inside this
    call boundary (SECURITY.md §5)."""
    username = credentials.get("username")
    password = credentials.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        raise AdapterError("not_configured", "设备凭据缺少用户名或密码", stage="prepare")
    client = RedfishClient(
        http=http,
        base_path=DEFAULT_BASE_PATH,
        endpoint=RedfishEndpoint(host=endpoint.host, port=endpoint.port, scheme=endpoint.scheme),
        auth_mode=auth_mode,
        credentials=RedfishCredentials(username=username, password=password),
        logger=None,
        backoff=lambda attempt: 0.0,
    )
    try:
        yield client
    finally:
        client.close()


def _probe_network(endpoint: _Endpoint) -> ProbeStage:
    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=CONNECT_TIMEOUT_SECONDS):
            return ProbeStage(stage="network", ok=True)
    except OSError:
        return ProbeStage(
            stage="network",
            ok=False,
            error_code="network_unreachable",
            detail_safe=f"TCP 连接 {endpoint.host}:{endpoint.port} 失败",
        )


def _probe_tls(endpoint: _Endpoint, *, verify_tls: bool, pinned_fingerprint: str | None) -> ProbeStage:
    """TLS/协议握手 stage. For https this is a real TLS handshake with CA
    validation (a pinned fingerprint is refused — M3T5 overlay wiring); for
    the dev/test http protocol it is an unauthenticated round-trip (an HTTP
    response is a protocol success — 401 is expected without credentials)."""
    if endpoint.scheme == "https":
        if pinned_fingerprint is not None:
            return ProbeStage(
                stage="tls",
                ok=False,
                error_code="not_configured",
                detail_safe="证书指纹固定需要专用 TLS 接线（M3T5 厂商 overlay）",
            )
        if not verify_tls:
            return ProbeStage(
                stage="tls",
                ok=False,
                error_code="not_configured",
                detail_safe="verify_tls=false 不允许；自签名证书请使用指纹固定（SECURITY.md §6）",
            )
        context = build_ssl_context(verify_tls=True, pinned_fingerprint=None, ca_bundle_path=None)
        try:
            with (
                socket.create_connection((endpoint.host, endpoint.port), timeout=CONNECT_TIMEOUT_SECONDS) as raw,
                context.wrap_socket(raw, server_hostname=endpoint.host) as tls_socket,
            ):
                tls_socket.settimeout(REQUEST_TIMEOUT_SECONDS)
                return ProbeStage(stage="tls", ok=True)
        except (OSError, ssl.SSLError):
            return ProbeStage(
                stage="tls",
                ok=False,
                error_code="tls_validation_failed",
                detail_safe="TLS 握手失败（证书校验或连接中断）",
            )
    try:
        with httpx.Client(
            base_url=f"http://{endpoint.host}:{endpoint.port}",
            timeout=httpx.Timeout(
                connect=CONNECT_TIMEOUT_SECONDS,
                read=REQUEST_TIMEOUT_SECONDS,
                write=REQUEST_TIMEOUT_SECONDS,
                pool=CONNECT_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
        ) as probe:
            probe.get(f"{DEFAULT_BASE_PATH}/")
    except httpx.TransportError:
        return ProbeStage(
            stage="tls",
            ok=False,
            error_code="network_unreachable",
            detail_safe="HTTP 协议握手失败（连接中断）",
        )
    return ProbeStage(stage="tls", ok=True)


def _stage_failure(stage: str, exc: RedfishError) -> ProbeStage:
    return ProbeStage(
        stage=stage,
        ok=False,
        error_code=exc.code,
        detail_safe=exc.detail_safe if exc.detail_safe is not None else exc.message,
    )


def _identity_hint(system: RedfishResource) -> dict[str, str]:
    hint: dict[str, str] = {}
    for key in ("Manufacturer", "Model"):
        value = text_field(system, key)
        if isinstance(value, str):
            hint[key.lower()] = value
    return hint


def _link_of(resource: RedfishResource, key: str) -> str | None:
    """Resolved @odata.id string of a link member (``{"@odata.id": ...}``)."""
    value = resource.get(key)
    if isinstance(value, Mapping):
        candidate = value.get("@odata.id")
        return candidate if isinstance(candidate, str) else None
    return None


def _first_collection_member(client: RedfishClient, collection_url: str) -> RedfishResource | None:
    page = follow(client, collection_url)
    if page is None:
        return None
    links = member_links(page)
    if not links:
        return None
    return follow(client, links[0])


def _resource_link(client: RedfishClient, url: str | None) -> RedfishResource | None:
    if url is None:
        return None
    return follow(client, url)


def _system_and_chassis(client: RedfishClient) -> tuple[RedfishResource, RedfishResource | None]:
    root = follow(client, f"{DEFAULT_BASE_PATH}/")
    if root is None:
        raise RedfishError("protocol_error", "ServiceRoot 返回了空响应", stage="parse")
    systems = _link_of(root, "Systems")
    if systems is None:
        raise RedfishError("protocol_error", "ServiceRoot 未提供 Systems 链接", stage="parse")
    system = _first_collection_member(client, systems)
    if system is None:
        raise RedfishError("protocol_error", "Systems 集合为空", stage="parse")
    chassis = None
    chassis_url = _link_of(root, "Chassis")
    if chassis_url is not None:
        chassis = _first_collection_member(client, chassis_url)
    return system, chassis


def _manager_of(client: RedfishClient) -> RedfishResource | None:
    root = follow(client, f"{DEFAULT_BASE_PATH}/")
    if root is None:
        return None
    managers_url = _link_of(root, "Managers")
    if managers_url is None:
        return None
    return _first_collection_member(client, managers_url)


def _service_root(client: RedfishClient) -> RedfishResource | None:
    return follow(client, f"{DEFAULT_BASE_PATH}/")


# -- discovery evidence -------------------------------------------------------


@dataclass
class _DiscoveryRead:
    """Everything one full read of the server surface collected (discover or
    a metrics collect). Any domain whose mapped resources are absent/errored
    keeps its containers empty — per-key ObservationError/unsupported rows
    explain the state."""

    root: RedfishResource | None = None
    system: RedfishResource | None = None
    chassis: RedfishResource | None = None
    manager: RedfishResource | None = None
    thermal: RedfishResource | None = None
    power: RedfishResource | None = None
    storage: RedfishResource | None = None
    memory_members: list[RedfishResource] = field(default_factory=list)
    drives: list[RedfishResource] = field(default_factory=list)
    volumes: list[RedfishResource] = field(default_factory=list)
    sel_service: RedfishResource | None = None


def _walk_collection_members(client: RedfishClient, url: str | None) -> list[RedfishResource]:
    """Full member resources of a link-style collection (bounded pagination)."""
    if url is None:
        return []
    resources: list[RedfishResource] = []
    try:
        members, _truncated = walk_collection(client, url)
    except RedfishError:
        return []
    for member in members:
        odata_id = member.odata_id
        if odata_id is None:
            continue
        full = follow(client, odata_id)
        if full is not None:
            resources.append(full)
    return resources


def _find_sel_service(client: RedfishClient, manager: RedfishResource | None) -> RedfishResource | None:
    """The manager LogService whose LogEntryType is SEL (SRV-MON-08)."""
    if manager is None:
        return None
    services_url = _link_of(manager, "LogServices")
    if services_url is None:
        return None
    collection = follow(client, services_url)
    if collection is None:
        return None
    for service in _walk_collection_members(client, collection.odata_id or services_url):
        entry_type = text_field(service, "LogEntryType")
        if entry_type == "SEL":
            return service
    return None


def _collect_discovery_read(client: RedfishClient) -> _DiscoveryRead:
    """One full read of the server surface (identity + capabilities evidence +
    component inventory). Core resources (ServiceRoot/Systems) failing raise
    ``RedfishError``; non-core domains degrade to empty containers."""
    read = _DiscoveryRead()
    root = follow(client, f"{DEFAULT_BASE_PATH}/")
    if root is None:
        raise RedfishError("protocol_error", "ServiceRoot 返回了空响应", stage="parse")
    read.root = root
    systems_url = _link_of(root, "Systems")
    if systems_url is None:
        raise RedfishError("protocol_error", "ServiceRoot 未提供 Systems 链接", stage="parse")
    read.system = _first_collection_member(client, systems_url)
    if read.system is None:
        raise RedfishError("protocol_error", "Systems 集合为空", stage="parse")
    chassis_url = _link_of(root, "Chassis")
    if chassis_url is not None:
        read.chassis = _first_collection_member(client, chassis_url)
    read.manager = _manager_of(client)
    read.thermal = _resource_link(client, _link_of(read.chassis, "Thermal") if read.chassis is not None else None)
    read.power = _resource_link(client, _link_of(read.chassis, "Power") if read.chassis is not None else None)
    storage_url = _link_of(read.system, "Storage")
    if storage_url is not None:
        # /Systems/1/Storage is a COLLECTION of Storage resources (one
        # controller here); the drives/volumes live under its first member.
        read.storage = _first_collection_member(client, storage_url)
    read.memory_members = _walk_collection_members(client, _link_of(read.system, "Memory"))
    if read.storage is not None:
        read.drives = _walk_collection_members(client, _link_of(read.storage, "Drives"))
        read.volumes = _walk_collection_members(client, _link_of(read.storage, "Volumes"))
    read.sel_service = _find_sel_service(client, read.manager)
    return read


def _evidence_of(client: RedfishClient, read: _DiscoveryRead) -> dict[str, object]:
    """Capability evidence flags derived from one discovery read.

    Values are booleans/frozensets consumed by ``_capability_support``; a
    non-core domain that could not be read counts as absent (the re-probe
    reconciles the capability rows; ADR-014 rows are a discovery snapshot).
    """
    system = read.system
    chassis = read.chassis
    manager = read.manager
    temp_members: list[Mapping[str, Any]] = []
    fan_members: list[Mapping[str, Any]] = []
    if read.thermal is not None:
        raw_temps = read.thermal.get("Temperatures")
        if isinstance(raw_temps, list):
            temp_members = [item for item in raw_temps if isinstance(item, Mapping)]
        raw_fans = read.thermal.get("Fans")
        if isinstance(raw_fans, list):
            fan_members = [item for item in raw_fans if isinstance(item, Mapping)]
    contexts: set[str] = set()
    for member in temp_members:
        context = member.get("PhysicalContext")
        if isinstance(context, str):
            contexts.add(context)
    supplies: list[Mapping[str, Any]] = []
    if read.power is not None:
        raw_supplies = read.power.get("PowerSupplies")
        if isinstance(raw_supplies, list):
            supplies = [item for item in raw_supplies if isinstance(item, Mapping)]
    dimms = read.memory_members
    ecc_seen = False
    for dimm in dimms:
        if _member_value(_oem_blocks(dimm), _ECC_AGGREGATE_NAMES) is not None:
            ecc_seen = True
    drive_smart_seen = False
    drive_predictive_seen = False
    for drive in read.drives:
        blocks = _oem_blocks(drive)
        if _member_value(blocks, _SMART_MEMBER_NAMES) is not None:
            drive_smart_seen = True
        if _member_value(blocks, _PREDICTIVE_MEMBER_NAMES) is not None:
            drive_predictive_seen = True
    return {
        "system_present": system is not None,
        "system_status": system is not None and isinstance(system.get("Status"), Mapping),
        "indicator_led": _indicator_present(system, chassis),
        "temp_contexts": frozenset(contexts),
        "has_fans": bool(fan_members),
        "dimms_populated": any(not _status_absent(dimm.get("Status", {}).get("State")) for dimm in dimms),
        "ecc_counter": ecc_seen,
        "has_drives": bool(read.drives),
        "drive_smart": drive_smart_seen,
        "drive_predictive": drive_predictive_seen,
        "raid_volume": bool(read.volumes),
        "power_supplies": bool(supplies),
        "physical_security": chassis is not None and isinstance(chassis.get("PhysicalSecurity"), Mapping),
        "sel_service": read.sel_service is not None,
        "manager_reset": _has_action(manager, "#Manager.Reset"),
        "system_reset": _has_action(system, "#ComputerSystem.Reset"),
        "graphical_console": _graphical_console_enabled(manager),
        "virtual_media": _link_of(manager, "VirtualMedia") is not None if manager is not None else False,
        "update_service": read.root is not None and _link_of(read.root, "UpdateService") is not None,
        "firmware_inventory": _firmware_inventory_present(client, read.root),
    }


def _indicator_present(system: RedfishResource | None, chassis: RedfishResource | None) -> bool:
    return any(
        resource is not None and isinstance(resource.get("IndicatorLED"), str)
        for resource in (system, chassis)
    )


def _has_action(resource: RedfishResource | None, action_key: str) -> bool:
    if resource is None:
        return False
    actions = resource.get("Actions")
    return isinstance(actions, Mapping) and isinstance(actions.get(action_key), Mapping)


def _graphical_console_enabled(manager: RedfishResource | None) -> bool:
    if manager is None:
        return False
    console = manager.get("GraphicalConsole")
    if not isinstance(console, Mapping):
        return False
    enabled = console.get("ServiceEnabled")
    return enabled is True


def _firmware_inventory_present(client: RedfishClient, root: RedfishResource | None) -> bool:
    if root is None:
        return False
    update_url = _link_of(root, "UpdateService")
    if update_url is None:
        return False
    update_service = _resource_link(client, update_url)
    if update_service is None:
        return False
    return _link_of(update_service, "FirmwareInventory") is not None


def _capability_support(
    key: str, requirement_id: str, evidence: Mapping[str, object], adapter_key: str
) -> CapabilitySupport:
    """One capability row from the evidence flags (state + reason + detail)."""
    supported = _key_supported(key, evidence)
    if supported:
        return CapabilitySupport(
            capability_key=key,
            support_state="supported",
            requirement_id=requirement_id,
            discovery_method=adapter_key,
        )
    reason = REASON_CODES[key]
    return CapabilitySupport(
        capability_key=key,
        support_state="unsupported",
        requirement_id=requirement_id,
        discovery_method=adapter_key,
        reason_code=reason,
        detail=_DETAIL_CN.get(reason, "设备未提供该能力对应的 Redfish 资源"),
    )


def _key_supported(key: str, evidence: Mapping[str, object]) -> bool:
    contexts = evidence.get("temp_contexts")
    context_set = contexts if isinstance(contexts, frozenset) else frozenset()
    mapping: dict[str, object] = {
        "health.overall": evidence.get("system_status"),
        "indicator.led": evidence.get("indicator_led"),
        "temperature.cpu": "CPU" in context_set,
        "temperature.memory": "Memory" in context_set,
        "temperature.inlet": "Intake" in context_set,
        "temperature.board": "Board" in context_set,
        "memory.status": evidence.get("dimms_populated"),
        "memory.ecc_errors": evidence.get("ecc_counter"),
        "drive.status": evidence.get("has_drives"),
        "drive.smart": evidence.get("drive_smart"),
        "drive.predictive_failure": evidence.get("drive_predictive"),
        "raid.status": evidence.get("raid_volume"),
        "psu.present": evidence.get("power_supplies"),
        "psu.status": evidence.get("power_supplies"),
        "psu.load_w": evidence.get("power_supplies"),
        "psu.voltage_v": evidence.get("power_supplies"),
        "fan.rpm": evidence.get("has_fans"),
        "fan.status": evidence.get("has_fans"),
        "chassis.intrusion": evidence.get("physical_security"),
        "event.sel": evidence.get("sel_service"),
        "manager.reset": evidence.get("manager_reset"),
        "power.on": evidence.get("system_reset"),
        "power.off": evidence.get("system_reset"),
        "power.cycle": evidence.get("system_reset"),
        "console.kvm.open": evidence.get("graphical_console"),
        "logs.support_bundle.collect": evidence.get("sel_service"),
        "virtual_media.mount": evidence.get("virtual_media"),
        "virtual_media.unmount": evidence.get("virtual_media"),
        "firmware.query": evidence.get("firmware_inventory"),
        "firmware.update": evidence.get("update_service"),
        "asset.refresh": evidence.get("system_present"),
    }
    return bool(mapping.get(key, False))


def _capability_rows(evidence: Mapping[str, object], adapter_key: str) -> tuple[CapabilitySupport, ...]:
    """One row per server capability key (shared keys: first requirement in
    the generated registry wins deterministically — same rule as fake.simple)."""
    rows: dict[str, CapabilitySupport] = {}
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != "server":
            continue
        for key in (
            *requirement.metrics,
            *requirement.events,
            *(operation[0] for operation in requirement.operations),
        ):
            if key in rows:
                continue
            rows[key] = _capability_support(key, requirement.id, evidence, adapter_key)
    return tuple(rows.values())


# -- component inventory ------------------------------------------------------


def _component(
    kind: str,
    native_id: str,
    name: str,
    status: str,
    properties: dict[str, object] | None = None,
) -> ComponentObserved:
    return ComponentObserved(kind=kind, native_id=native_id, name=name, status=status, properties=properties or {})


def _status_properties(resource: RedfishResource, kind: str) -> dict[str, object]:
    allowed = _COMPONENT_PROPERTIES[kind]
    properties: dict[str, object] = {}
    for member_name, target in (
        ("Model", "model"),
        ("MediaType", "media_type"),
        ("CapacityBytes", "capacity_bytes"),
        ("Revision", "revision"),
        ("MemoryDeviceType", "device_type"),
        ("CapacityMiB", "capacity_mib"),
        ("OperatingSpeedMhz", "speed_mhz"),
        ("DeviceLocator", "slot"),
        ("PowerCapacityWatts", "capacity_w"),
        ("RAIDType", "raid_type"),
        ("VolumeType", "volume_type"),
    ):
        if target not in allowed:
            continue
        value = resource.get(member_name)
        if value is not None:
            properties[target] = value
    return properties


def _native_id(resource: RedfishResource, fallback: str | None = None) -> str:
    for key in ("Id", "Name"):
        value = resource.get(key)
        if isinstance(value, str) and value:
            return value
    return fallback if fallback is not None else "unknown"


def _processor_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    system = read.system
    if system is None:
        return []
    summary = system.get("ProcessorSummary")
    if not isinstance(summary, Mapping):
        return []
    raw_count = summary.get("Count")
    if not isinstance(raw_count, int) or raw_count <= 0:
        return []
    status = _status_to_text(summary.get("Status"))
    model = summary.get("Model")
    properties: dict[str, object] = {}
    if isinstance(model, str):
        properties["model"] = model
    return [
        _component("processor", f"cpu-{index}", f"CPU {index}", status, properties)
        for index in range(1, raw_count + 1)
    ]


def _memory_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    components: list[ComponentObserved] = []
    for dimm in read.memory_members:
        native = _native_id(dimm)
        name = dimm.get("Name")
        components.append(
            _component(
                "memory",
                native,
                name if isinstance(name, str) else native,
                _status_to_text(dimm.get("Status")),
                _status_properties(dimm, "memory"),
            )
        )
    return components


def _drive_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    return [
        _component(
            "drive",
            _native_id(drive),
            str(drive.get("Name") or _native_id(drive)),
            _status_to_text(drive.get("Status")),
            _status_properties(drive, "drive"),
        )
        for drive in read.drives
    ]


def _raid_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    return [
        _component(
            "raid",
            _native_id(volume),
            str(volume.get("Name") or _native_id(volume)),
            _status_to_text(volume.get("Status")),
            _status_properties(volume, "raid"),
        )
        for volume in read.volumes
    ]


def _psu_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    if read.power is None:
        return []
    raw = read.power.get("PowerSupplies")
    if not isinstance(raw, list):
        return []
    components: list[ComponentObserved] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        supply = RedfishResource(item)
        native = _native_id(supply)
        name = supply.get("Name")
        components.append(
            _component(
                "psu",
                native,
                name if isinstance(name, str) else native,
                _status_to_text(supply.get("Status")),
                _status_properties(supply, "psu"),
            )
        )
    return components


def _fan_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    if read.thermal is None:
        return []
    raw = read.thermal.get("Fans")
    if not isinstance(raw, list):
        return []
    components: list[ComponentObserved] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            continue
        fan = RedfishResource(item)
        native = _native_id(fan, fallback=f"fan-{index}")
        components.append(
            _component("fan", native, native, _status_to_text(fan.get("Status")), {})
        )
    return components


def _sensor_components(read: _DiscoveryRead) -> list[ComponentObserved]:
    if read.thermal is None:
        return []
    raw = read.thermal.get("Temperatures")
    if not isinstance(raw, list):
        return []
    components: list[ComponentObserved] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            continue
        sensor = RedfishResource(item)
        member_id = sensor.get("MemberId")
        native = f"temp-{member_id}" if isinstance(member_id, str) and member_id else f"temp-{index}"
        name = sensor.get("Name")
        context = sensor.get("PhysicalContext")
        properties: dict[str, object] = {}
        if isinstance(context, str):
            properties["physical_context"] = context
        components.append(
            _component(
                "sensor",
                native,
                name if isinstance(name, str) else native,
                _status_to_text(sensor.get("Status")),
                properties,
            )
        )
    return components


def _inventory_components(read: _DiscoveryRead) -> tuple[ComponentObserved, ...]:
    components: list[ComponentObserved] = []
    components.extend(_processor_components(read))
    components.extend(_memory_components(read))
    components.extend(_drive_components(read))
    components.extend(_raid_components(read))
    components.extend(_psu_components(read))
    components.extend(_fan_components(read))
    components.extend(_sensor_components(read))
    return tuple(components)


# -- observation helpers ------------------------------------------------------


@dataclass
class _Bundle:
    """Mutable collector for one collect pass (deterministic ordering)."""

    observations: list[Observation] = field(default_factory=list)
    errors: list[ObservationError] = field(default_factory=list)
    components: list[ComponentObserved] = field(default_factory=list)
    events: list[EventObservation] = field(default_factory=list)


def _obs(
    bundle: _Bundle,
    key: str,
    value: bool | int | float | str,
    *,
    now: datetime,
    unit: str | None = None,
    kind: str | None = None,
    native: str | None = None,
    quality: Quality = Quality.GOOD,
) -> None:
    bundle.observations.append(
        Observation(
            metric_key=key,
            value=value,
            observed_at=now,
            quality=quality,
            unit=unit,
            source=OBSERVATION_SOURCE,
            component_kind=kind,
            component_native_id=native,
        )
    )


def _err(
    bundle: _Bundle,
    key: str | None,
    *,
    detail: str,
    error_code: str = "protocol_error",
    stage: str = "parse",
    kind: str | None = None,
    native: str | None = None,
) -> None:
    bundle.errors.append(
        ObservationError(
            key=key,
            error_code=error_code,
            stage=stage,
            component_kind=kind,
            component_native_id=native,
            detail=detail,
        )
    )


def _redfish_error_code(exc: RedfishError) -> str:
    if exc.code == "unsupported_capability":
        return "unsupported_capability"
    if exc.code == "permission_denied_by_device":
        return "permission_denied_by_device"
    if exc.code in ("network_unreachable", "rate_limited", "device_busy"):
        return exc.code
    return "protocol_error"


def _add_system_health(
    bundle: _Bundle, system: RedfishResource | None, chassis: RedfishResource | None, *, now: datetime
) -> None:
    """SRV-MON-01 health.overall: the ComputerSystem Status.Health is the
    primary source; a parseable Chassis Status.Health can only worsen the
    result (an unknown chassis state keeps the aggregate conservative). A
    missing System Status is an ObservationError — health is never inferred
    from absence."""
    if system is None:
        _err(bundle, "health.overall", detail="ComputerSystem 资源缺失")
        return
    status = system.get("Status")
    if not isinstance(status, Mapping):
        _err(bundle, "health.overall", detail="ComputerSystem 未返回 Status")
        return
    system_health = _health_state(status.get("Health"))
    if isinstance(system_health, FieldSentinel):
        _err(bundle, "health.overall", detail="ComputerSystem Status.Health 缺失或无法解析")
        return
    overall = system_health
    if chassis is not None:
        chassis_status = chassis.get("Status")
        if isinstance(chassis_status, Mapping):
            chassis_health = _health_state(chassis_status.get("Health"))
            if isinstance(chassis_health, str):
                overall = _worse_health(overall, chassis_health)
    _obs(bundle, "health.overall", overall, now=now)


def _add_indicator_led(
    bundle: _Bundle, system: RedfishResource | None, chassis: RedfishResource | None, *, now: datetime
) -> None:
    """SRV-MON-01/07 indicator.led: the System's own IndicatorLED when
    present, else the Chassis panel LED."""
    raw: object = None
    if system is not None:
        raw = system.get("IndicatorLED")
    if raw is None and chassis is not None:
        raw = chassis.get("IndicatorLED")
    if raw is None:
        _err(bundle, "indicator.led", detail="系统与机箱均未提供 IndicatorLED")
        return
    if not isinstance(raw, str):
        _err(bundle, "indicator.led", detail="IndicatorLED 值无法解析")
        return
    mapped = _INDICATOR_MAP.get(raw)
    if mapped is None:
        _err(bundle, "indicator.led", detail=f"IndicatorLED 值 {raw!r} 无认证映射")
        return
    _obs(bundle, "indicator.led", mapped, now=now)


def _add_chassis_intrusion(bundle: _Bundle, chassis: RedfishResource | None, *, now: datetime) -> None:
    """SRV-MON-07 chassis.intrusion from PhysicalSecurity.IntrusionSensor."""
    if chassis is None:
        _err(bundle, "chassis.intrusion", detail="机箱资源缺失")
        return
    security = chassis.get("PhysicalSecurity")
    if not isinstance(security, Mapping):
        _err(bundle, "chassis.intrusion", detail="机箱未提供 PhysicalSecurity")
        return
    sensor = security.get("IntrusionSensor")
    if sensor is None:
        _err(bundle, "chassis.intrusion", detail="PhysicalSecurity 未提供 IntrusionSensor")
        return
    if not isinstance(sensor, str):
        _err(bundle, "chassis.intrusion", detail="IntrusionSensor 值无法解析")
        return
    mapped = _INTRUSION_MAP.get(sensor)
    if mapped is None:
        _err(bundle, "chassis.intrusion", detail=f"IntrusionSensor 值 {sensor!r} 无认证映射")
        return
    _obs(bundle, "chassis.intrusion", mapped, now=now)


def _add_health_subset(
    bundle: _Bundle, system: RedfishResource | None, chassis: RedfishResource | None, *, now: datetime
) -> None:
    _add_system_health(bundle, system, chassis, now=now)
    _add_indicator_led(bundle, system, chassis, now=now)
    _add_chassis_intrusion(bundle, chassis, now=now)


def _sensor_component_for_temperature(
    read: _DiscoveryRead, sensor: RedfishResource, index: int
) -> tuple[str, str]:
    """The component a temperature reading attaches to: CPU-context sensors
    attach to the per-processor component (``cpu-<n>`` parsed from the sensor
    Name), a memory-context sensor naming an installed DIMM attaches to that
    DIMM, and every other classified sensor attaches to its own sensor
    component (``temp-<MemberId>``)."""
    member_id = sensor.get("MemberId")
    native = f"temp-{member_id}" if isinstance(member_id, str) and member_id else f"temp-{index}"
    name = sensor.get("Name")
    if isinstance(name, str):
        match = re.search(r"(?i)\bcpu\s*(\d+)\b", name)
        if match is not None:
            return "processor", f"cpu-{int(match.group(1))}"
    context = sensor.get("PhysicalContext")
    if context == "Memory" and isinstance(name, str):
        for dimm in read.memory_members:
            native_id = _native_id(dimm)
            if name == native_id or name == dimm.get("Name") or name == dimm.get("DeviceLocator"):
                return "memory", native_id
    return "sensor", native


def _add_temperatures(bundle: _Bundle, read: _DiscoveryRead, *, now: datetime) -> None:
    """SRV-MON-02 temperature classification by PhysicalContext. A sensor
    whose context is absent/unknown and whose name matches no certified
    heuristic is an explicit ObservationError — never a fabricated point."""
    if read.thermal is None:
        for key in ("temperature.cpu", "temperature.memory", "temperature.inlet", "temperature.board"):
            _err(bundle, key, error_code="unsupported_capability", detail="设备未提供 Thermal 资源")
        return
    raw_temps = read.thermal.get("Temperatures")
    if not isinstance(raw_temps, list):
        for key in ("temperature.cpu", "temperature.memory", "temperature.inlet", "temperature.board"):
            _err(bundle, key, detail="Thermal 未提供 Temperatures")
        return
    for index, item in enumerate(raw_temps):
        if not isinstance(item, Mapping):
            continue
        sensor = RedfishResource(item)
        context = sensor.get("PhysicalContext")
        metric_key = _TEMP_CONTEXT_TO_METRIC.get(context) if isinstance(context, str) else None
        if metric_key is None:
            # An unclassifiable temperature reading carries NO metric key: the
            # four temperature.* keys stay honest (no false attribution of a
            # CPU/memory/inlet/board failure to a sensor that is none of them).
            _err(
                bundle,
                None,
                detail=(
                    f"温度传感器 {sensor.get('Name')!r} 的 PhysicalContext 缺失/未知"
                    "且无认证启发式规则"
                ),
            )
            continue
        reading = number_field(sensor, "ReadingCelsius")
        if isinstance(reading, FieldSentinel):
            _err(
                bundle,
                metric_key,
                detail="温度传感器缺少 ReadingCelsius",
                kind=_sensor_component_for_temperature(read, sensor, index)[0],
                native=_sensor_component_for_temperature(read, sensor, index)[1],
            )
            continue
        kind, native = _sensor_component_for_temperature(read, sensor, index)
        _obs(bundle, metric_key, reading, now=now, unit="Cel", kind=kind, native=native)


def _add_fans(bundle: _Bundle, read: _DiscoveryRead, *, now: datetime) -> None:
    """SRV-MON-06: fan.rpm from the fan Reading (ReadingRPM or legacy Reading
    with ReadingUnits RPM); fan.status from the device Status.Health ONLY —
    never from invented thresholds (ADR-025)."""
    if read.thermal is None:
        _err(bundle, "fan.rpm", error_code="unsupported_capability", detail="设备未提供 Thermal 资源")
        _err(bundle, "fan.status", error_code="unsupported_capability", detail="设备未提供 Thermal 资源")
        return
    raw_fans = read.thermal.get("Fans")
    if not isinstance(raw_fans, list):
        _err(bundle, "fan.rpm", detail="Thermal 未提供 Fans")
        _err(bundle, "fan.status", detail="Thermal 未提供 Fans")
        return
    for index, item in enumerate(raw_fans):
        if not isinstance(item, Mapping):
            continue
        fan = RedfishResource(item)
        native = _native_id(fan, fallback=f"fan-{index}")
        rpm = number_field(fan, "ReadingRPM")
        if isinstance(rpm, FieldSentinel):
            legacy = number_field(fan, "Reading")
            if not isinstance(legacy, FieldSentinel):
                units = text_field(fan, "ReadingUnits")
                if isinstance(units, FieldSentinel) or str(units).lower() != "rpm":
                    _err(
                        bundle,
                        "fan.rpm",
                        detail="风扇 Reading 未声明 RPM 单位，无法换算",
                        kind="fan",
                        native=native,
                    )
                else:
                    _obs(bundle, "fan.rpm", legacy, now=now, unit="r/min", kind="fan", native=native)
            else:
                _err(bundle, "fan.rpm", detail="风扇缺少 Reading 读数", kind="fan", native=native)
        else:
            _obs(bundle, "fan.rpm", rpm, now=now, unit="r/min", kind="fan", native=native)
        status = _component_status(fan.get("Status"))
        if isinstance(status, FieldSentinel):
            _err(bundle, "fan.status", detail="风扇缺少可解析的 Status", kind="fan", native=native)
        else:
            _obs(bundle, "fan.status", status, now=now, kind="fan", native=native)


def _add_power(bundle: _Bundle, read: _DiscoveryRead, *, now: datetime) -> None:
    """SRV-MON-05 per PowerSupply: presence from Status.State; status from
    the Status block; load from OutputPowerWatts (LastPowerOutputWatts as the
    device's own fallback — never PowerCapacityWatts); voltage from
    OutputVoltage. An ABSENT supply reports presence/status absent and no
    readings (nothing to measure); a present supply without readings is an
    ObservationError."""
    if read.power is None:
        for key in ("psu.present", "psu.status", "psu.load_w", "psu.voltage_v"):
            _err(bundle, key, error_code="unsupported_capability", detail="设备未提供 Power 资源")
        return
    raw_supplies = read.power.get("PowerSupplies")
    if not isinstance(raw_supplies, list):
        for key in ("psu.present", "psu.status", "psu.load_w", "psu.voltage_v"):
            _err(bundle, key, detail="Power 未提供 PowerSupplies")
        return
    for index, item in enumerate(raw_supplies):
        if not isinstance(item, Mapping):
            continue
        supply = RedfishResource(item)
        native = _native_id(supply, fallback=f"psu-{index}")
        status = _component_status(supply.get("Status"))
        if isinstance(status, FieldSentinel):
            _err(bundle, "psu.status", detail="电源缺少可解析的 Status", kind="psu", native=native)
            presence: str | FieldSentinel = _MISSING
        else:
            presence = "absent" if status == "absent" else "present"
            _obs(bundle, "psu.status", status, now=now, kind="psu", native=native)
        if isinstance(presence, FieldSentinel):
            _err(bundle, "psu.present", detail="电源缺少可解析的 Status", kind="psu", native=native)
        else:
            _obs(bundle, "psu.present", presence, now=now, kind="psu", native=native)
        if presence == "absent":
            continue
        load = number_field(supply, "OutputPowerWatts")
        if isinstance(load, FieldSentinel):
            load = number_field(supply, "LastPowerOutputWatts")
        if isinstance(load, FieldSentinel):
            _err(bundle, "psu.load_w", detail="电源缺少输出功率读数", kind="psu", native=native)
        else:
            _obs(bundle, "psu.load_w", load, now=now, unit="W", kind="psu", native=native)
        voltage = number_field(supply, "OutputVoltage")
        if isinstance(voltage, FieldSentinel):
            _err(bundle, "psu.voltage_v", detail="电源缺少输出电压读数", kind="psu", native=native)
        else:
            _obs(bundle, "psu.voltage_v", voltage, now=now, unit="V", kind="psu", native=native)


def _add_memory(bundle: _Bundle, read: _DiscoveryRead, *, now: datetime) -> None:
    """SRV-MON-03 per DIMM: memory.status from the Status block; an empty
    slot (State Absent) is an absent component with no points at all;
    memory.ecc_errors ONLY from an explicit OEM ECC counter member — an
    absent counter is an ObservationError, never an inferred 0."""
    for dimm in read.memory_members:
        native = _native_id(dimm)
        status = _component_status(dimm.get("Status"))
        if status == "absent":
            continue
        if isinstance(status, FieldSentinel):
            _err(bundle, "memory.status", detail="内存条缺少可解析的 Status", kind="memory", native=native)
        else:
            _obs(bundle, "memory.status", status, now=now, kind="memory", native=native)
        blocks = _oem_blocks(dimm)
        ecc_member = _member_value(blocks, _ECC_AGGREGATE_NAMES)
        if ecc_member is None:
            explicit: list[tuple[str, Any]] = []
            for block in blocks:
                for member_name, value in block.items():
                    normalized = _norm_name(str(member_name))
                    if "ecc" in normalized and "count" in normalized:
                        explicit.append((str(member_name), value))
            if len(explicit) == 1:
                ecc_member = explicit[0]
        if ecc_member is None:
            _err(
                bundle,
                "memory.ecc_errors",
                detail="内存条未提供明确的 ECC 计数器成员",
                kind="memory",
                native=native,
            )
            continue
        counter = number_field({ecc_member[0]: ecc_member[1]}, ecc_member[0])
        if isinstance(counter, FieldSentinel):
            _err(bundle, "memory.ecc_errors", detail="ECC 计数器值无法解析", kind="memory", native=native)
            continue
        _obs(bundle, "memory.ecc_errors", counter, now=now, unit="1", kind="memory", native=native)


def _add_storage(bundle: _Bundle, read: _DiscoveryRead, *, now: datetime) -> None:
    """SRV-MON-04: per-drive status/SMART/predictive-failure + per-volume
    raid.status. raid.status is emitted ONLY when a RAID volume (or OEM RAID
    block) exists — a drive-only server is a valid state with no raid data.
    A drive without a SMART member is an ObservationError, never passed."""
    if read.storage is None:
        for key in ("drive.status", "drive.smart", "drive.predictive_failure"):
            _err(bundle, key, error_code="unsupported_capability", detail="设备未提供 Storage 资源")
        return
    for drive in read.drives:
        native = _native_id(drive)
        status = _component_status(drive.get("Status"))
        if isinstance(status, FieldSentinel):
            _err(bundle, "drive.status", detail="硬盘缺少可解析的 Status", kind="drive", native=native)
        else:
            _obs(bundle, "drive.status", status, now=now, kind="drive", native=native)
        blocks = _oem_blocks(drive)
        smart_member = _member_value(blocks, _SMART_MEMBER_NAMES)
        if smart_member is None:
            _err(bundle, "drive.smart", detail="硬盘未提供 SMART 状态成员", kind="drive", native=native)
        else:
            smart_value = smart_member[1]
            if not isinstance(smart_value, str):
                _err(bundle, "drive.smart", detail="SMART 状态值无法解析", kind="drive", native=native)
            else:
                mapped = _SMART_MAP.get(smart_value)
                if mapped is None:
                    _err(
                        bundle,
                        "drive.smart",
                        detail=f"SMART 状态值 {smart_value!r} 无认证映射",
                        kind="drive",
                        native=native,
                    )
                else:
                    _obs(bundle, "drive.smart", mapped, now=now, kind="drive", native=native)
        predictive_member = _member_value(blocks, _PREDICTIVE_MEMBER_NAMES)
        if predictive_member is None:
            _err(bundle, "drive.predictive_failure", detail="硬盘未提供预测故障成员", kind="drive", native=native)
        else:
            predictive = bool_field({predictive_member[0]: predictive_member[1]}, predictive_member[0])
            if isinstance(predictive, FieldSentinel):
                _err(bundle, "drive.predictive_failure", detail="预测故障值无法解析", kind="drive", native=native)
            else:
                _obs(bundle, "drive.predictive_failure", predictive, now=now, kind="drive", native=native)
    for volume in read.volumes:
        native = _native_id(volume)
        oem_raid = _member_value(_oem_blocks(volume), _RAID_MEMBER_NAMES)
        if oem_raid is not None and isinstance(oem_raid[1], str):
            mapped = _OEM_RAID_MAP.get(oem_raid[1])
            if mapped is None:
                _err(
                    bundle,
                    "raid.status",
                    detail=f"OEM RAID 状态 {oem_raid[1]!r} 无认证映射",
                    kind="raid",
                    native=native,
                )
                continue
            _obs(bundle, "raid.status", mapped, now=now, kind="raid", native=native)
            continue
        status = _component_status(volume.get("Status"))
        if isinstance(status, FieldSentinel):
            _err(bundle, "raid.status", detail="RAID 卷缺少可解析的 Status", kind="raid", native=native)
            continue
        if status == "absent":
            continue
        mapped = _VOLUME_HEALTH_MAP.get(status)
        if mapped is None:
            _err(bundle, "raid.status", detail=f"RAID 卷状态 {status!r} 无认证映射", kind="raid", native=native)
            continue
        _obs(bundle, "raid.status", mapped, now=now, kind="raid", native=native)


def _add_missing_memory_collection(bundle: _Bundle, read: _DiscoveryRead) -> None:
    """SRV-MON-03 source-level gaps: no Memory link, or an empty collection."""
    if read.memory_members:
        return
    system = read.system
    has_link = system is not None and _link_of(system, "Memory") is not None
    code = "unsupported_capability" if not has_link else "protocol_error"
    detail = "设备未提供 Memory 资源" if not has_link else "Memory 集合为空"
    for key in ("memory.status", "memory.ecc_errors"):
        _err(bundle, key, error_code=code, detail=detail)


def _add_missing_drives(bundle: _Bundle, read: _DiscoveryRead) -> None:
    """SRV-MON-04 source-level gaps: a Storage resource without Drives. Zero
    volumes is a valid drive-only state — raid.status has no data by design
    (and discovery declares it unsupported without a volume)."""
    if read.drives or read.storage is None:
        return
    for key in ("drive.status", "drive.smart", "drive.predictive_failure"):
        _err(bundle, key, detail="Storage 未提供可用的 Drives")


# -- collect ------------------------------------------------------------------


def _read_health_resources(client: RedfishClient) -> tuple[RedfishResource | None, RedfishResource | None]:
    try:
        return _system_and_chassis(client)
    except RedfishError:
        return None, None


def _collect_logs(bundle: _Bundle, client: RedfishClient, request: CollectionRequest) -> None:
    """SRV-MON-08: SEL entries as event.sel observations. Entries older than
    the previous logs run are skipped (SEL is time-ordered ascending); every
    entry missing a timestamp/message is an explicit ObservationError."""
    manager = _manager_of(client)
    service = _find_sel_service(client, manager)
    if service is None:
        _err(bundle, "event.sel", error_code="unsupported_capability", detail="管理卡未提供 SEL LogService")
        return
    entries_url = _link_of(service, "Entries")
    if entries_url is None:
        _err(bundle, "event.sel", error_code="unsupported_capability", detail="SEL LogService 未提供 Entries")
        return
    for member in _iter_sel_pages(client, entries_url, since=request.last_run_at):
        _add_sel_entry(bundle, member)


def _iter_sel_pages(
    client: RedfishClient, entries_url: str, since: datetime | None
) -> Iterator[RedfishResource]:
    """Yield LogEntry members newer than ``since`` (all when None), walking
    $skip pages within the parse layer's page budget. A whole page older than
    ``since`` stops the walk (time-ordered logs: the rest is older too)."""
    page_url = entries_url
    pages = 0
    collected = 0
    while pages < MAX_COLLECTION_PAGES:
        pages += 1
        page = follow(client, page_url)
        if page is None:
            raise RedfishError("protocol_error", "SEL Entries 返回了空响应", stage="parse")
        raw_members = page.get("Members")
        if not isinstance(raw_members, list):
            return
        page_entries = [member for member in raw_members if isinstance(member, Mapping)]
        if since is not None:
            page_has_newer = any(
                occurred is None or (since is not None and occurred > since)
                for occurred in (_entry_occurred_at(member) for member in page_entries)
            )
            if not page_has_newer:
                return
        for member in page_entries:
            occurred = _entry_occurred_at(member)
            if since is None or occurred is None or occurred > since:
                yield RedfishResource(member)
        collected += len(raw_members)
        total = page.get("Members@odata.count")
        if not isinstance(total, int) or collected >= total or not raw_members:
            return
        page_url = _with_skip(entries_url, collected)
    raise RedfishError("protocol_error", "SEL 分页超过预算", stage="parse")


def _entry_occurred_at(entry: Mapping[str, Any]) -> datetime | None:
    created = datetime_field(entry, "Created")
    if isinstance(created, datetime):
        return created
    for block in _oem_blocks(RedfishResource(entry)):
        member = _member_value([block], _TIMESTAMP_MEMBER_NAMES)
        if member is not None:
            parsed = datetime_field({member[0]: member[1]}, member[0])
            if isinstance(parsed, datetime):
                return parsed
    return None


def _add_sel_entry(bundle: _Bundle, entry: RedfishResource) -> None:
    """One SEL LogEntry -> event.sel (events.json required fields); an entry
    without a parseable timestamp or message is an explicit ObservationError
    (never a fabricated time or text)."""
    occurred_at = _entry_occurred_at(entry)
    if occurred_at is None:
        _err(bundle, "event.sel", detail="SEL 条目缺少可解析的时间戳（Created/OEM）")
        return
    severity_raw = entry.get("Severity")
    severity = _SEVERITY_MAP.get(severity_raw, "unknown") if isinstance(severity_raw, str) else "unknown"
    message = _entry_message(entry)
    if message is None:
        _err(bundle, "event.sel", detail="SEL 条目缺少可用的消息正文")
        return
    native_id = entry.get("Id")
    bundle.events.append(
        EventObservation(
            event_type="event.sel",
            severity=severity,
            message=message,
            occurred_at=occurred_at,
            source=SEL_EVENT_SOURCE,
            native_event_id=native_id if isinstance(native_id, str) else None,
            detail={},
        )
    )


def _entry_message(entry: Mapping[str, Any]) -> str | None:
    message = entry.get("Message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    args = entry.get("MessageArgs")
    if isinstance(args, list) and args and all(isinstance(arg, str) for arg in args):
        return " ".join(args)
    message_id = entry.get("MessageId")
    if isinstance(message_id, str) and message_id.strip():
        return message_id.strip()
    return None


def _with_skip(url: str, skip: int) -> str:
    from urllib.parse import parse_qsl

    parts = urlsplit(url)
    pairs = [
        f"{quote(key, safe='')}={quote(value, safe='')}"
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != "$skip"
    ]
    pairs.append(f"$skip={skip}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))


# -- adapter ------------------------------------------------------------------


class RedfishCommonAdapter:
    """Common Redfish adapter (adapter_key ``server.redfish``).

    Registration stance (module docstring): a real generic adapter for
    server-type devices that exercises the M3 probe/discover/collect flows;
    NOT a certification target — the five vendor keys arrive in M3T5 by
    subclassing this base, and hardware-targets.json stays untouched.
    """

    adapter_key = "server.redfish"
    supported_device_types = frozenset({"server"})
    adapter_version = "0.1.0"
    secret_schema_version = 1

    secret_schema: dict[str, object] = {
        "type": "object",
        "required": ["username", "password"],
        "additionalProperties": False,
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
        },
    }
    connection_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "protocol": {"type": "string", "enum": ["https", "http"]},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "verify_tls": {"type": "boolean"},
            "tls_fingerprint_sha256": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-fA-F]{64}$",
            },
        },
    }

    def _endpoint_and_client(self, session: DeviceSession) -> tuple[_Endpoint, httpx.Client]:
        config = dict(session.connection_config)
        endpoint = _endpoint_for(
            resolved_ip=session.resolved_ip,
            management_endpoint=session.management_endpoint,
            connection_config=config,
        )
        verify_tls = config.get("verify_tls", True)
        pinned = config.get("tls_fingerprint_sha256")
        pinned_value = pinned if isinstance(pinned, str) else None
        return endpoint, _build_http_client(endpoint, verify_tls=bool(verify_tls), pinned_fingerprint=pinned_value)

    def probe(self, profile: ConnectionProfile) -> ProbeResult:
        """Staged probe: network -> tls/auth/identity/capabilities. Each
        stage reports its own outcome; stages after a failure are not
        executed (never fabricated as ok)."""
        config = dict(profile.connection_config)
        try:
            endpoint = _endpoint_for(
                resolved_ip=profile.resolved_ip,
                management_endpoint=profile.management_endpoint,
                connection_config=config,
                fallback_port=profile.port,
            )
        except AdapterError as exc:
            failed = ProbeStage(stage="network", ok=False, error_code=exc.code, detail_safe=exc.message)
            return ProbeResult(stages=(failed,))
        network = _probe_network(endpoint)
        if not network.ok:
            return ProbeResult(
                stages=(network,)
                + tuple(
                    ProbeStage(stage=name, ok=False, detail_safe="前置阶段失败，未执行")
                    for name in ("tls", "auth", "identity", "capabilities")
                )
            )
        verify_tls = config.get("verify_tls", True)
        pinned = config.get("tls_fingerprint_sha256")
        pinned_value = pinned if isinstance(pinned, str) else None
        tls = _probe_tls(endpoint, verify_tls=bool(verify_tls), pinned_fingerprint=pinned_value)
        if not tls.ok:
            return ProbeResult(
                stages=(network, tls)
                + tuple(
                    ProbeStage(stage=name, ok=False, detail_safe="前置阶段失败，未执行")
                    for name in ("auth", "identity", "capabilities")
                )
            )
        http = _build_http_client(endpoint, verify_tls=bool(verify_tls), pinned_fingerprint=pinned_value)
        try:
            with _redfish_client(http, endpoint=endpoint, credentials=profile.credentials) as client:
                try:
                    root = follow(client, f"{DEFAULT_BASE_PATH}/")
                except RedfishError as exc:
                    auth = _stage_failure("auth", exc)
                    return ProbeResult(
                        stages=(network, tls, auth)
                        + tuple(
                            ProbeStage(stage=name, ok=False, detail_safe="前置阶段失败，未执行")
                            for name in ("identity", "capabilities")
                        )
                    )
                auth = ProbeStage(stage="auth", ok=True)
                try:
                    system, _chassis = _system_and_chassis(client)
                except RedfishError as exc:
                    identity = _stage_failure("identity", exc)
                    return ProbeResult(
                        stages=(network, tls, auth, identity)
                        + (ProbeStage(stage="capabilities", ok=False, detail_safe="前置阶段失败，未执行"),)
                    )
                hint = _identity_hint(system)
                identity = ProbeStage(
                    stage="identity",
                    ok=True,
                    detail_safe=(
                        f"已识别为 {hint.get('manufacturer', '未知厂商')} {hint.get('model', '未知型号')}"
                    ),
                )
                try:
                    detail_safe = _capability_probe_summary(client, root)
                except RedfishError as exc:
                    capabilities = _stage_failure("capabilities", exc)
                else:
                    capabilities = ProbeStage(stage="capabilities", ok=True, detail_safe=detail_safe)
                return ProbeResult(stages=(network, tls, auth, identity, capabilities), identity_hint=hint or None)
        finally:
            http.close()

    def discover(self, profile: ConnectionProfile) -> DiscoveryResult:
        """Full discovery: identity + component inventory + capability rows
        for ALL server requirement keys (supported / unsupported-with-reason
        per the evidence mapping tables in this module)."""
        config = dict(profile.connection_config)
        endpoint = _endpoint_for(
            resolved_ip=profile.resolved_ip,
            management_endpoint=profile.management_endpoint,
            connection_config=config,
            fallback_port=profile.port,
        )
        verify_tls = config.get("verify_tls", True)
        pinned = config.get("tls_fingerprint_sha256")
        http = _build_http_client(
            endpoint, verify_tls=bool(verify_tls), pinned_fingerprint=pinned if isinstance(pinned, str) else None
        )
        try:
            with _redfish_client(http, endpoint=endpoint, credentials=profile.credentials) as client:
                read = _collect_discovery_read(client)
                evidence = _evidence_of(client, read)
                capabilities = _capability_rows(evidence, self.adapter_key)
                vendor = self._identity_text(read.system, "Manufacturer")
                model = self._identity_text(read.system, "Model")
                serial = self._identity_text(read.system, "SerialNumber")
                firmware = self._identity_text(read.manager, "FirmwareVersion")
                return DiscoveryResult(
                    vendor=vendor,
                    model=model,
                    serial_number=serial or None,
                    firmware_version=firmware or None,
                    capabilities=capabilities,
                    components=_inventory_components(read),
                    secrets_schema=self.secret_schema,
                    secrets_schema_version=self.secret_schema_version,
                )
        except RedfishError as exc:
            raise AdapterError(
                _redfish_error_code(exc),
                exc.message,
                stage=exc.stage if exc.stage is not None else "discover",
            ) from exc
        finally:
            http.close()

    @staticmethod
    def _identity_text(resource: RedfishResource | None, key: str) -> str:
        if resource is None:
            return ""
        value = text_field(resource, key)
        return value if isinstance(value, str) else ""

    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch:
        """One collect pass (per-type content mapping in the module docstring).
        Adapter-level failures (connection/TLS/auth) raise ``AdapterError``;
        missing device values become per-key ``ObservationError`` entries."""
        if request.collection_type not in ("reachability", "health", "metrics", "logs", "discovery"):
            raise AdapterError("protocol_error", f"未知的采集类型 {request.collection_type}", stage="prepare")
        endpoint, http = self._endpoint_and_client(session)
        try:
            with _redfish_client(http, endpoint=endpoint, credentials=session.credentials) as client:
                bundle = _Bundle()
                system, chassis = _read_health_resources(client)
                _add_health_subset(bundle, system, chassis, now=request.now)
                if request.collection_type == "metrics":
                    self._collect_metrics(bundle, client, request)
                elif request.collection_type == "logs":
                    _collect_logs(bundle, client, request)
                if request.collection_type == "metrics":
                    return ObservationBatch(
                        observations=tuple(bundle.observations),
                        events=tuple(bundle.events),
                        components=tuple(bundle.components),
                        errors=tuple(bundle.errors),
                    )
                return ObservationBatch(
                    observations=tuple(bundle.observations),
                    events=tuple(bundle.events),
                    errors=tuple(bundle.errors),
                )
        except RedfishError as exc:
            raise AdapterError(
                _redfish_error_code(exc),
                exc.message,
                stage=exc.stage if exc.stage is not None else "collect",
            ) from exc
        finally:
            http.close()

    def _collect_metrics(self, bundle: _Bundle, client: RedfishClient, request: CollectionRequest) -> None:
        now = request.now
        read = _collect_discovery_read(client)
        bundle.components.extend(_inventory_components(read))
        _add_temperatures(bundle, read, now=now)
        _add_fans(bundle, read, now=now)
        _add_power(bundle, read, now=now)
        _add_memory(bundle, read, now=now)
        _add_storage(bundle, read, now=now)
        _add_missing_memory_collection(bundle, read)
        _add_missing_drives(bundle, read)

    # -- operation protocol (M3T5 owns real device-side operation wiring) -----

    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
        """Planning is contract-driven and shared with the domain planner
        (same as fake.simple): no device I/O, safe for any adapter."""
        return plan_operation(snapshot, request)

    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult:
        del session, plan
        return PreflightResult(
            ok=False,
            error_code="unsupported_capability",
            detail="通用 Redfish 适配器尚未实现设备端操作（M3T5 厂商 overlay）",
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
            "通用 Redfish 适配器尚未实现设备端操作（M3T5 厂商 overlay）",
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
            "通用 Redfish 适配器尚未实现设备端操作（M3T5 厂商 overlay）",
            stage="verify",
        )


def _capability_probe_summary(client: RedfishClient, root: RedfishResource | None) -> str:
    """Discover-lite for the probe capabilities stage: which mapped services
    exist. Errors here fail the stage (never fabricated presence)."""
    presence: list[str] = []
    system = _system_and_chassis(client)[0] if root is not None else None
    actions = system.get("Actions") if system is not None else None
    if isinstance(actions, Mapping) and isinstance(actions.get("#ComputerSystem.Reset"), Mapping):
        presence.append("系统 Reset")
    chassis_url = _link_of(root, "Chassis") if root is not None else None
    chassis = None
    if chassis_url is not None:
        chassis = _first_collection_member(client, chassis_url)
    if chassis is not None:
        for key in ("Thermal", "Power"):
            if _link_of(chassis, key) is not None:
                presence.append(key)
    manager = _manager_of(client)
    if manager is not None:
        if _has_action(manager, "#Manager.Reset"):
            presence.append("管理卡 Reset")
        if _link_of(manager, "LogServices") is not None:
            presence.append("LogServices")
        if _link_of(manager, "VirtualMedia") is not None:
            presence.append("VirtualMedia")
    if root is not None and _link_of(root, "UpdateService") is not None:
        presence.append("UpdateService")
    summary = "能力发现完成" if presence else "能力发现完成（无标准服务）"
    return f"{summary}：{', '.join(presence)}"
