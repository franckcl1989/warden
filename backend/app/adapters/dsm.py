"""Synology NAS adapter — ``nas.synology_dsm`` (M4T2 collect + M4T3 ops).

Registered device_type ``synology_nas`` for the two hardware-targets
certification units (contracts/hardware-targets.json: nas.synology_ds224plus
DS224+ and nas.synology_ds225plus DS225+, certification_scope=exact_model).
M4T2 wires probe/discover/collect (NAS-MON-01..06); M4T3 wires the NAS-ACT
operation surface through ``dsm_operations.py`` (power restart/shutdown,
console.dsm.open, logs.support_bundle.collect, disk.smart_test quick/full,
backup.status.refresh, firmware.update, snmp.configure — 9 profiles, all
verification strategies from contracts/operations.json).

Honesty ledger (docs/DEVICE_ADAPTERS.md §5/§10, ADR-018 — every row with an
explicit basis; the simulator is a TEST DEVICE, never 真机 evidence):

- **Doc sources consulted 2026-09-03** (both reachable, HTTP 200):
  - DSM Login Web API Guide:
    https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf
    — documents SYNO.API.Info (query.cgi, v1) and SYNO.API.Auth (entry.cgi,
    v6 login/logout) only. SYNO.FileStation.*/SYNO.VideoStation.* appear as
    walkthrough examples; the FileStation.List ``list_share`` sample returns
    shares with name/path/isdir and documents NO usage/quota member, so no
    share-usage field below is guide-backed.
  - Synology DiskStation MIB Guide:
    https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_DiskStation_MIB_Guide.pdf
    — documents the SNMP side: System MIB .1.3.6.1.4.1.6574.1 (temperature,
    systemFanStatus/cpuFanStatus, powerStatus), Disk MIB (.6574.2), RAID MIB
    (.6574.3), UPS MIB (.6574.4), SMART MIB (.6574.5). It documents NO fan
    rpm OID and no redundant-PSU OID for consumer units, and states DSM does
    not support SNMP traps.
- **Source decision per metric (this milestone: WebAPI only; SNMP reading
  is NOT implemented — DEVICE_ADAPTERS.md §5 "SNMP 用于补充监控", §5.1):**
  every NAS-MON metric maps to a certified DSM WebAPI row where one exists;
  metrics whose only documented source would be SNMP stay unsupported-with-
  reason (never a silent SNMPv2c fallback):
  - disk.* / storage_pool.* / raid.* / volume.usage_percent →
    SYNO.Storage.CGI.Storage load_info [sim];
  - shared_folder.usage_percent → SYNO.Core.Share list [sim] (invented
    placeholder — see below);
  - temperature.system / fan.* → SYNO.Core.System info [sim] (MIB fan/
    temperature OIDs exist but SNMP reading is not implemented in M4T2);
  - ups.status → SYNO.Core.UPS get [sim];
  - event.system_log → SYNO.Core.System.Log list [sim];
  - psu.status → **unsupported, no certified source**: the certified WebAPI
    list has no power-supply family, and the official MIB guide documents no
    consumer-unit PSU OID beyond the System-MIB ``powerStatus`` (a
    supplement-monitoring row SNMP is not implemented in this milestone).
    DS224+/DS225+ use external power adapters. Collect emits NOTHING for
    psu.status (no fake) and discovery says unsupported with reason
    ``no_webapi_source``.
- **Simulator-DSL rows**: SYNO.Core.System/Storage.CGI.Storage/Share/UPS/
  System.Log/Upgrade API names and value vocabularies (disk/pool/UPS/fan
  literals, share usage/quota members, log levels) are simulator-invented
  placeholders (tests/simulators/dsm/README.md basis table), fixture-
  certified in M4T2 against the Warden DSM test simulator ONLY. Real-DSM
  certification (target model + DSM version, sanitized fixtures + 真机
  behavior) is pending per ADR-018; nothing here is hardware evidence.
- **Per-call (api, version) ledger (ADR-018)**: the only callable API names
  are the certified rows below (client ``CERTIFIED_API_VERSIONS`` refuses
  anything else); DSMClient records every call's exact
  (api, method, path, version) basis on its call ledger, and each discovery
  capability row's detail carries the mapping's api+version so the archived
  device_capabilities rows ARE the per-capability discovery evidence.
- **No invented thresholds (ADR-025)**: fan rpm 0 is DEVICE-REPORTED data
  and is stored as-is (quality good) only when the API returns 0; it never
  becomes an alert (fan.rpm alert_policy=none — display only). Statuses come
  exclusively from device-reported state text via the certified parse
  tables; missing/unparseable values are ObservationErrors, never
  0/normal/passed (metrics.json rule missing_value, ADR-014).
- **Usage-percent denominator rule (ADR-016 / DEVICE_ADAPTERS.md §5.1)**:
  volume/shared-folder percentages are computed from used bytes over a
  capacity/quota denominator; a missing or non-positive denominator is an
  ObservationError (``no_quota_denominator`` detail), never bytes-as-percent.
- **Component modeling** (DATA_MODEL.md §4.4, kinds open-ended): disk,
  storage_pool, volume, shared_folder, fan, ups, sensor. A component's
  ``status`` is the adapter-certified projection of the device-reported
  state onto the platform's component_status scale (disk/fan reuse the
  parse tables; pool/volume/ups projections are documented below); the
  sensor row carries ``unknown`` because DSM reports no health member for a
  temperature sensor ("没有异常不等于健康" — the value itself is DATA via
  temperature.system). ups components appear ONLY while a UPS is connected
  (ups_absent → no point, no component); ups.status itself is device-scoped
  per contracts/metrics.json.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address

import httpx

from app.adapters.dsm_operations import SynologyDsmOperationsMixin
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
    ProbeResult,
    ProbeStage,
    Quality,
)
from app.generated.capabilities import REQUIREMENTS
from app.infrastructure.protocols.dsm.client import DSMClient, DSMEndpoint
from app.infrastructure.protocols.dsm.discovery import AUTH_API_NAME, INFO_API_NAME
from app.infrastructure.protocols.dsm.errors import DSMError
from app.infrastructure.protocols.dsm.parse import (
    UNKNOWN,
    disk_smart,
    disk_status,
    fan_status,
    float_value,
    int_value,
    log_severity,
    pool_status,
    text_value,
    ups_status,
    usage_percent,
)
from app.infrastructure.protocols.dsm.session import DSMCredentials
from app.infrastructure.tls import build_ssl_context

BASE_PATH = "/webapi"

OBSERVATION_SOURCE = "dsm"
LOG_EVENT_SOURCE = "dsm_log"

CONNECT_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 30.0

MAX_LOG_PAGES = 25  # bounded DSM log page walk (parse-layer budget, honest error beyond)

# --- certified API list (ADR-018; every entry with its basis) -----------------
# The ONLY DSM APIs this adapter maps. Rows marked [guide] are documented by
# the DSM Login Web API guide; [sim] rows are simulator-DSL placeholders for
# the DSM vendor_private management families (DEVICE_ADAPTERS.md §5: 官方登录
# 指南只证明 API 发现/认证流程；每个非公开管理 API 必须标记 vendor_private
# 并以 fixture + 真机认证形成证据) — fixture-certified in M4T2/M4T3,
# real-DSM certification pending. Versions are enforced by the client ledger
# (CERTIFIED_API_VERSIONS); this module documents the mapping-level basis.
API_BASIS: dict[str, str] = {
    INFO_API_NAME: "[guide] DSM Login Web API guide（discovery，query.cgi v1）",
    AUTH_API_NAME: "[guide] DSM Login Web API guide（login/logout，entry.cgi v6）",
    "SYNO.Core.System": "[sim] DSM Control-Panel 系统族占位 API（info v2，fixture 认证；真机待认证）",
    "SYNO.Storage.CGI.Storage": ("[sim] DSM Storage Manager 族占位 API（load_info v1，fixture 认证；真机待认证）"),
    "SYNO.Core.Share": (
        "[sim] DSM 共享文件夹配额族占位 API（list v1，fixture 认证；真机待认证；"
        "Login guide 的 FileStation list_share 示例不携带 usage/quota 成员）"
    ),
    "SYNO.Core.UPS": "[sim] DSM UPS 族占位 API（get v1，fixture 认证；真机待认证）",
    "SYNO.Core.System.Log": "[sim] DSM 日志中心族占位 API（list v1，fixture 认证；真机待认证）",
    "SYNO.Core.Upgrade": (
        "[sim] DSM 更新族占位 API（upgrade/update_task_status v1，fixture 认证；真机待认证；"
        "NAS-ACT-06 固件升级用）"
    ),
    "SYNO.Core.Support": (
        "[sim] DSM 支持中心/日志导出族占位 API（export v1，fixture 认证；真机待认证；"
        "NAS-ACT-03 支持包导出用）"
    ),
    "SYNO.Core.Backup": (
        "[sim] DSM Hyper Backup/快照复制状态族占位 API（list v1，fixture 认证；真机待认证；"
        "NAS-ACT-05 备份/快照任务状态用）"
    ),
    "SYNO.Core.Network.SNMP": (
        "[sim] DSM 控制面板 SNMP/Trap 配置族占位 API（get/set v1，fixture 认证；真机待认证；"
        "NAS-ACT-06 snmp.configure 用；MIB Guide 声称 DSM 不支持 SNMP trap，最终映射以真机认证为准）"
    ),
}

# --- capability evidence vocabulary -------------------------------------------
# Stable unsupported/not_configured reason codes (adapter-owned snake_case,
# String(32) column — DeviceCapability.reason_code; detail is the display-safe
# Chinese explanation). Device-side negotiation reasons mirror
# dsm/discovery.py; adapter-side gaps are labeled as adapter gaps, never
# blamed on the device.
REASON_API_NOT_DISCOVERED = "api_not_discovered"
REASON_NO_CERTIFIED_VERSION = "no_certified_version"
REASON_DEVICE_TOO_OLD = "device_too_old"
REASON_RANGE_MISMATCH = "range_mismatch"
REASON_NO_WEBAPI_SOURCE = "no_webapi_source"
REASON_MAPPING_MISSING = "adapter_mapping_missing"

# Metric/event key -> the certified API name that serves it. Keys whose only
# possible source is not in the certified list (psu.status) are marked
# MISSING_CERTIFIED_API and NEVER supported (no silent SNMPv2c fallback).
MISSING_CERTIFIED_API = ""

KEY_API: dict[str, str] = {
    "disk.status": "SYNO.Storage.CGI.Storage",
    "disk.smart": "SYNO.Storage.CGI.Storage",
    "disk.bad_sectors": "SYNO.Storage.CGI.Storage",
    "storage_pool.status": "SYNO.Storage.CGI.Storage",
    "raid.status": "SYNO.Storage.CGI.Storage",
    "raid.rebuild_progress": "SYNO.Storage.CGI.Storage",
    "volume.usage_percent": "SYNO.Storage.CGI.Storage",
    "temperature.system": "SYNO.Core.System",
    "fan.rpm": "SYNO.Core.System",
    "fan.status": "SYNO.Core.System",
    "psu.status": MISSING_CERTIFIED_API,
    "shared_folder.usage_percent": "SYNO.Core.Share",
    "ups.status": "SYNO.Core.UPS",
    "connectivity.management": "SYNO.Core.System",
    "event.system_log": "SYNO.Core.System.Log",
}

# Operation key -> the certified API name that serves it (M4T3 NAS-ACT
# profiles from contracts/operations.json). ``console.dsm.open`` is the
# launch-channel exception: its target IS the validated DSM management
# origin, so the certified surface it depends on is the authenticated
# SYNO.Core.System row (any device that logs in serves DSM on that origin).
OPERATION_KEY_API: dict[str, str] = {
    "power.restart": "SYNO.Core.System",
    "power.shutdown": "SYNO.Core.System",
    "console.dsm.open": "SYNO.Core.System",
    "logs.support_bundle.collect": "SYNO.Core.Support",
    "disk.smart_test.quick": "SYNO.Storage.CGI.Storage",
    "disk.smart_test.full": "SYNO.Storage.CGI.Storage",
    "backup.status.refresh": "SYNO.Core.Backup",
    "firmware.update": "SYNO.Core.Upgrade",
    "snmp.configure": "SYNO.Core.Network.SNMP",
}

# Per-operation basis notes appended to the discovery row detail (method
# families actually mapped — the client ledger enforces (api, version), the
# per-call method evidence is recorded in the execution evidence).
OPERATION_METHOD_BASIS: dict[str, str] = {
    "power.restart": "SYNO.Core.System restart",
    "power.shutdown": "SYNO.Core.System shutdown",
    "console.dsm.open": "DSM 管理来源 URL（不带凭据）",
    "logs.support_bundle.collect": "SYNO.Core.Support export",
    "disk.smart_test.quick": "SYNO.Storage.CGI.Storage smart_test(type=quick)",
    "disk.smart_test.full": "SYNO.Storage.CGI.Storage smart_test(type=full)",
    "backup.status.refresh": "SYNO.Core.Backup list",
    "firmware.update": "SYNO.Core.Upgrade upgrade",
    "snmp.configure": "SYNO.Core.Network.SNMP set/get",
}

# --- certified component-status projections (simulator-DSL rows) --------------
# Component inventory rows carry the platform's component_status-scale text.
# disk/fan components reuse the parse tables (disk_status()/fan_status() are
# already component_status projections). The pool/volume/ups tables below are
# the certified projections of the DSM native state text for INVENTORY DISPLAY
# ONLY — alert semantics never read component rows; they come solely from the
# metric values + contracts/alert-rules.json. Severity projections mirror the
# alert value maps so a component chip can never contradict an active
# status.problem alert of the same component.

# storage_pool component status: pool state text -> component_status
# (rebuilding is an active maintenance state the alert map rates warning).
POOL_COMPONENT_STATUS: Mapping[str, str] = {
    "Normal": "ok",  # [sim]
    "Degraded": "warning",  # [sim]
    "Rebuilding": "warning",  # [sim] alert map: rebuilding -> warning
    "Failed": "critical",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# volume component status: volume state text -> component_status.
VOLUME_COMPONENT_STATUS: Mapping[str, str] = {
    "Normal": "ok",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# ups component status: UPS state text -> component_status (alert-map
# severity projection of the UPS state vocabulary).
UPS_COMPONENT_STATUS: Mapping[str, str] = {
    "Normal": "ok",  # [sim]
    "On Battery": "warning",  # [sim] alert map: on_battery -> warning
    "Low Battery": "critical",  # [sim] alert map: low_battery -> critical
    "Comms Lost": "warning",  # [sim] alert map: communication_lost -> warning
    "Fault": "critical",  # [sim] alert map: fault -> critical
    "Unknown": "unknown",  # [sim]
}


def _component_status_of(table: Mapping[str, str], raw: object) -> str:
    if isinstance(raw, str) and raw.strip() in table:
        return table[raw.strip()]
    return UNKNOWN


def _native_id_value(raw: object) -> str | None:
    """Component native id from a DSM member: a non-empty string or integer
    (DSM member ids may be numeric, e.g. fan 1/2); anything else is None
    (never coerced from floats/bools)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        return stripped or None
    return None


# --- identity gate ------------------------------------------------------------
# Registered targets are the exact consumer units DS224+/DS225+; a device that
# does not self-identify as one of them fails the probe identity stage instead
# of silently cross-registering (DEVICE_ADAPTERS.md §3). Normalization strips
# spaces and lowercases so real firmware strings like "DS224+" match; the
# simulator serves "DS224+ (simulated)"/"DS225+ (simulated)".
CERTIFIED_MODEL_MARKERS = ("ds224+", "ds225+")


def _identity_failures(model_raw: object) -> tuple[str, ...]:
    model = model_raw if isinstance(model_raw, str) else ""
    normalized = "".join(model.split()).lower()
    if any(marker in normalized for marker in CERTIFIED_MODEL_MARKERS):
        return ()
    return (
        f"设备自述型号 {model or '(缺失)'} 不在认证目标 DS224+/DS225+ 中"
        "（hardware-targets.json exact_model 范围；不得以适配器名义跨型号注册）",
    )


# --- bundle / observation helpers ------------------------------------------------


class _Bundle:
    """Mutable collector for one collect pass (deterministic ordering)."""

    def __init__(self) -> None:
        self.observations: list[Observation] = []
        self.errors: list[ObservationError] = []
        self.components: list[ComponentObserved] = []
        self.events: list[EventObservation] = []


def _obs(
    bundle: _Bundle,
    key: str,
    value: bool | int | float | str,
    *,
    now: datetime,
    unit: str | None = None,
    kind: str | None = None,
    native: str | None = None,
    evidence: str,
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
            evidence=evidence,
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


# DSM error codes that are run-level failures (reachability/auth/TLS); every
# other device-side answer degrades to per-key ObservationErrors so one
# broken family never hides the rest of a batch (DEVICE_ADAPTERS.md §2.3).
FATAL_DSM_CODES = frozenset({"authentication_failed", "network_unreachable", "tls_validation_failed"})

_PER_KEY_DSM_CODES = frozenset(
    {
        "permission_denied_by_device",
        "unsupported_capability",
        "not_configured",
        "device_busy",
        "validation_failed",
        "rate_limited",
        "operation_failed",
        "protocol_error",
        "ambiguous_result",
    }
)


def _raise_fatal(exc: DSMError) -> None:
    if exc.code in FATAL_DSM_CODES:
        raise AdapterError(exc.code, exc.message, stage=exc.stage if exc.stage is not None else "collect") from exc


def _error_code_of(exc: DSMError) -> str:
    if exc.code in _PER_KEY_DSM_CODES:
        return exc.code
    return "protocol_error"


def _safe_error_text(exc: DSMError) -> str:
    return exc.detail_safe if exc.detail_safe is not None else exc.message


def _stage_failure(stage: str, exc: DSMError) -> ProbeStage:
    return ProbeStage(
        stage=stage,
        ok=False,
        error_code=exc.code,
        detail_safe=exc.detail_safe if exc.detail_safe is not None else exc.message,
    )


# --- endpoint / transport ----------------------------------------------------------


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
    the scheme default). Mirrors the Redfish adapter's boundary rules.
    """
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
    """Policy-free transport construction at the adapter boundary (mirrors
    the Redfish adapter: the platform resolves endpoints before
    probe/discover; the collect pipeline currently passes no policy object
    into DeviceSession, so the adapter honours the operator-declared
    connection_config). https verifies the CA chain (no permanent
    verify=false, SECURITY.md §6); a configured pin cannot run inside httpx
    and is refused by the probe TLS stage before any connection is attempted.
    """
    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=REQUEST_TIMEOUT_SECONDS,
        write=REQUEST_TIMEOUT_SECONDS,
        pool=CONNECT_TIMEOUT_SECONDS,
    )
    if endpoint.scheme == "https":
        context = build_ssl_context(verify_tls=verify_tls, pinned_fingerprint=None, ca_bundle_path=None)
        return httpx.Client(
            verify=context,
            base_url=f"https://{endpoint.host}:{endpoint.port}",
            timeout=timeout,
            follow_redirects=False,
        )
    del pinned_fingerprint
    return httpx.Client(
        base_url=f"http://{endpoint.host}:{endpoint.port}",
        timeout=timeout,
        follow_redirects=False,
    )


def _dsm_client(
    http: httpx.Client,
    *,
    endpoint: _Endpoint,
    credentials: Mapping[str, object],
) -> DSMClient:
    """Wrap the transport in a DSMClient (login on first call, logout on close)."""
    username = credentials.get("username")
    password = credentials.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        raise AdapterError("not_configured", "设备凭据缺少用户名或密码", stage="prepare")
    return DSMClient(
        http=http,
        base_path=BASE_PATH,
        endpoint=DSMEndpoint(host=endpoint.host, port=endpoint.port, base_path=BASE_PATH, scheme=endpoint.scheme),
        credentials=DSMCredentials(username=username, password=password),
        logger=None,
        backoff=lambda attempt: 0.0,
    )


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
    """TLS/协议握手 stage: https does a real CA-validated handshake (a
    pinned fingerprint is refused — dedicated TLS wiring is not implemented);
    the dev/test http protocol does an anonymous SYNO.API.Info.Query
    round-trip (the documented discovery call — any HTTP answer proves the
    WebAPI surface answers)."""
    if endpoint.scheme == "https":
        if pinned_fingerprint is not None:
            return ProbeStage(
                stage="tls",
                ok=False,
                error_code="not_configured",
                detail_safe="证书指纹固定需要专用 TLS 接线（尚未实现；请使用 CA 验证）",
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
            probe.get(
                f"{BASE_PATH}/query.cgi",
                params={
                    "api": INFO_API_NAME,
                    "version": "1",
                    "method": "query",
                    "query": "all",
                },
            )
    except httpx.TransportError:
        return ProbeStage(
            stage="tls",
            ok=False,
            error_code="network_unreachable",
            detail_safe="HTTP 协议握手失败（连接中断）",
        )
    return ProbeStage(stage="tls", ok=True)


# --- family reads -------------------------------------------------------------------


def _family_data(
    client: DSMClient, api_name: str, method: str, *, params: Mapping[str, object] | None = None
) -> object:
    """One certified safe read; raises DSMError (handled by the caller)."""
    return client.call(api_name, method, safe=True, params=params)


def _rows_of(payload: object, key: str) -> list[dict[str, object]] | None:
    """The member list of a family data member; None when the shape is wrong
    (the caller turns that into an honest per-family error)."""
    if not isinstance(payload, dict):
        return None
    raw = payload.get(key)
    if isinstance(raw, list):
        result: list[dict[str, object]] = []
        for item in raw:
            if isinstance(item, dict):
                result.append(item)
        return result
    return None


# --- system mapping (NAS-MON-03 temperature/fan + NAS-MON-06 connectivity) ---------


SYSTEM_EVIDENCE = "[sim] SYNO.Core.System v2 info（fixture 认证；真机待认证）"


def _read_system(client: DSMClient) -> tuple[object | None, str | None]:
    """One SYNO.Core.System info read.

    Returns (payload, None) on success; (None, detail) on a non-fatal
    DSMError (fatal codes raise AdapterError). The SAME read drives
    connectivity.management and the system member mappings (one call per
    pass)."""
    try:
        return _family_data(client, "SYNO.Core.System", "info"), None
    except DSMError as exc:
        _raise_fatal(exc)
        return None, _safe_error_text(exc)


def _add_connectivity(bundle: _Bundle, payload: object, *, now: datetime, detail: str | None) -> bool:
    """connectivity.management from the System read outcome: ok -> true
    (quality good); a reachable-but-broken management answer -> false
    (quality good). Auth/network/TLS failures already raised AdapterError and
    NEVER produce a fabricated false (the platform reachability layer handles
    offline)."""
    if detail is not None or not isinstance(payload, dict):
        _obs(
            bundle,
            "connectivity.management",
            False,
            now=now,
            evidence="[guide] SYNO.API.Auth 登录 + " + SYSTEM_EVIDENCE,
        )
        return False
    _obs(
        bundle,
        "connectivity.management",
        True,
        now=now,
        evidence="[guide] SYNO.API.Auth 登录 + " + SYSTEM_EVIDENCE,
    )
    return True


def _add_system_mapping(bundle: _Bundle, payload: object, *, now: datetime) -> None:
    """temperature.system/fan.* from the already-read System payload."""
    if not isinstance(payload, dict):
        _err(bundle, "temperature.system", detail="System API 未返回数据成员")
        _err(bundle, "fan.rpm", detail="System API 未返回数据成员")
        _err(bundle, "fan.status", detail="System API 未返回数据成员")
        return
    # temperature.system: the member whose id is "system" is the certified
    # reading. Members with other ids (e.g. per-disk temps) are unmapped data
    # (no contract metric key exists) and are ignored, never guessed.
    raw_temps = payload.get("temperature")
    system_temp: dict[str, object] | None = None
    if isinstance(raw_temps, list):
        for item in raw_temps:
            if isinstance(item, dict) and text_value(item.get("id")) == "system":
                system_temp = item
                break
    if system_temp is None:
        _err(bundle, "temperature.system", detail="System API 未提供 system 温度读数")
    else:
        value = float_value(system_temp.get("temp_c"))
        if value is None:
            _err(bundle, "temperature.system", detail="system 温度读数无法解析")
        else:
            bundle.components.append(_component("sensor", "system", "System", UNKNOWN))
            _obs(
                bundle,
                "temperature.system",
                value,
                now=now,
                unit="Cel",
                kind="sensor",
                native="system",
                evidence=SYSTEM_EVIDENCE,
            )
    # fans: component per fan member; rpm only from the device member (0 IS
    # device-reported data); status only from the device text (never rpm-
    # derived thresholds, ADR-025).
    raw_fans = payload.get("fan")
    fans = _rows_of({"fan": raw_fans}, "fan")
    if fans is None:
        _err(bundle, "fan.rpm", detail="System API 未提供风扇列表")
        _err(bundle, "fan.status", detail="System API 未提供风扇列表")
        return
    for fan in fans:
        native_id = _native_id_value(fan.get("id"))
        name = text_value(fan.get("name"))
        native = native_id if native_id is not None else (name or "unknown")
        display = name if name is not None else native
        bundle.components.append(_component("fan", native, display, fan_status(fan.get("status"))))
        rpm = int_value(fan.get("rpm"))
        if rpm is None:
            _err(bundle, "fan.rpm", detail="风扇缺少可解析的转速读数", kind="fan", native=native)
        else:
            _obs(
                bundle,
                "fan.rpm",
                float(rpm),
                now=now,
                unit="r/min",
                kind="fan",
                native=native,
                evidence=SYSTEM_EVIDENCE,
            )
        mapped = fan_status(fan.get("status"))
        if mapped == UNKNOWN:
            _err(bundle, "fan.status", detail="风扇状态字面量未认证或缺失", kind="fan", native=native)
        else:
            _obs(bundle, "fan.status", mapped, now=now, kind="fan", native=native, evidence=SYSTEM_EVIDENCE)


def _component(
    kind: str,
    native_id: str,
    name: str,
    status: str,
    properties: dict[str, object] | None = None,
) -> ComponentObserved:
    return ComponentObserved(
        kind=kind,
        native_id=native_id,
        name=name,
        status=status,
        properties=properties or {},
    )


# --- storage mapping (NAS-MON-01/02/04 volumes) -------------------------------------


STORAGE_EVIDENCE = "[sim] SYNO.Storage.CGI.Storage v1 load_info（fixture 认证；真机待认证）"
STORAGE_KEYS = (
    "disk.status",
    "disk.smart",
    "disk.bad_sectors",
    "storage_pool.status",
    "raid.status",
    "raid.rebuild_progress",
    "volume.usage_percent",
)


def _add_storage_mapping(bundle: _Bundle, client: DSMClient, *, now: datetime) -> None:
    """SYNO.Storage.CGI.Storage load_info -> disks/pools/volumes mappings."""
    try:
        payload = _family_data(client, "SYNO.Storage.CGI.Storage", "load_info")
    except DSMError as exc:
        _raise_fatal(exc)
        for key in STORAGE_KEYS:
            _err(
                bundle,
                key,
                detail=f"存储 API 读取失败：{_safe_error_text(exc)}",
                error_code=_error_code_of(exc),
                stage="collect",
            )
        return
    disks = _rows_of(payload, "disk")
    pools = _rows_of(payload, "pool")
    volumes = _rows_of(payload, "volume")
    if disks is None and pools is None and volumes is None:
        for key in STORAGE_KEYS:
            _err(bundle, key, detail="存储 API 未返回 disk/pool/volume 成员")
        return
    for disk in disks or []:
        _add_disk(bundle, disk, now=now)
    for pool in pools or []:
        _add_pool(bundle, pool, now=now)
    for volume in volumes or []:
        _add_volume(bundle, volume, now=now)


def _add_disk(bundle: _Bundle, disk: Mapping[str, object], *, now: datetime) -> None:
    native_id = _native_id_value(disk.get("id"))
    name = text_value(disk.get("name"))
    native = native_id if native_id is not None else (name or "unknown")
    display = name if name is not None else native
    # disk_status() is the certified DSM text -> component_status projection
    # (Healthy/Cached -> ok, Degraded -> warning, Broken -> critical).
    bundle.components.append(_component("disk", native, display, disk_status(disk.get("status"))))
    mapped_status = disk_status(disk.get("status"))
    if mapped_status == UNKNOWN:
        _err(bundle, "disk.status", detail="磁盘状态字面量未认证或缺失", kind="disk", native=native)
    else:
        _obs(bundle, "disk.status", mapped_status, now=now, kind="disk", native=native, evidence=STORAGE_EVIDENCE)
    mapped_smart = disk_smart(disk.get("smart"))
    if mapped_smart == UNKNOWN:
        _err(bundle, "disk.smart", detail="磁盘 SMART 字面量未认证或缺失", kind="disk", native=native)
    else:
        _obs(bundle, "disk.smart", mapped_smart, now=now, kind="disk", native=native, evidence=STORAGE_EVIDENCE)
    bad = int_value(disk.get("bad_sectors"))
    if bad is None or bad < 0:
        _err(bundle, "disk.bad_sectors", detail="磁盘缺少可解析的坏扇区计数", kind="disk", native=native)
    else:
        # 0 bad sectors is DEVICE-REPORTED data and is stored as-is.
        _obs(bundle, "disk.bad_sectors", bad, now=now, unit="1", kind="disk", native=native, evidence=STORAGE_EVIDENCE)


def _add_pool(bundle: _Bundle, pool: Mapping[str, object], *, now: datetime) -> None:
    """One DSM storage pool -> storage_pool.status/raid.status (the pool IS
    the RAID unit on the certified consumer models; raid_type is recorded as
    a property) + raid.rebuild_progress ONLY while the device reports the
    pool rebuilding (never read otherwise — no invented state)."""
    native_id = _native_id_value(pool.get("id"))
    name = text_value(pool.get("name"))
    native = native_id if native_id is not None else (name or "unknown")
    display = name if name is not None else native
    raid_type = text_value(pool.get("raid_type"))
    properties: dict[str, object] = {}
    if raid_type is not None:
        properties["raid_type"] = raid_type
    bundle.components.append(
        _component(
            "storage_pool",
            native,
            display,
            _component_status_of(POOL_COMPONENT_STATUS, pool.get("status")),
            properties,
        )
    )
    mapped = pool_status(pool.get("status"))
    if mapped == UNKNOWN:
        detail = "存储池状态字面量未认证或缺失"
        _err(bundle, "storage_pool.status", detail=detail, kind="storage_pool", native=native)
        _err(bundle, "raid.status", detail=detail, kind="storage_pool", native=native)
        return
    _obs(bundle, "storage_pool.status", mapped, now=now, kind="storage_pool", native=native, evidence=STORAGE_EVIDENCE)
    _obs(bundle, "raid.status", mapped, now=now, kind="storage_pool", native=native, evidence=STORAGE_EVIDENCE)
    if mapped == "rebuilding":
        # rebuild_progress only exists while rebuilding: read the device
        # member then, and only then (a missing/unparseable member while
        # rebuilding is an ObservationError, never a fabricated value).
        progress = int_value(pool.get("rebuild_progress"))
        if progress is None or progress < 0 or progress > 100:
            _err(
                bundle,
                "raid.rebuild_progress",
                detail="重建中存储池缺少可解析的重建进度（0-100）",
                kind="storage_pool",
                native=native,
            )
        else:
            _obs(
                bundle,
                "raid.rebuild_progress",
                float(progress),
                now=now,
                unit="%",
                kind="storage_pool",
                native=native,
                evidence=STORAGE_EVIDENCE,
            )


def _add_volume(bundle: _Bundle, volume: Mapping[str, object], *, now: datetime) -> None:
    """volume.usage_percent from used/total bytes (ADR-016: percentage only
    from a real denominator — missing/non-positive/overshoot totals are an
    ObservationError, never bytes-as-percent)."""
    native_id = _native_id_value(volume.get("id"))
    name = text_value(volume.get("name"))
    native = native_id if native_id is not None else (name or "unknown")
    display = name if name is not None else native
    bundle.components.append(
        _component("volume", native, display, _component_status_of(VOLUME_COMPONENT_STATUS, volume.get("status")))
    )
    percent = usage_percent(used=volume.get("used_bytes"), total=volume.get("total_bytes"))
    if percent is None:
        _err(
            bundle,
            "volume.usage_percent",
            detail=(
                "卷缺少可用的容量分母（used/total 缺失或超账）— no_quota_denominator"
                " 语义，不以字节数冒充百分比（ADR-016）"
            ),
            kind="volume",
            native=native,
        )
        return
    _obs(
        bundle,
        "volume.usage_percent",
        percent,
        now=now,
        unit="%",
        kind="volume",
        native=native,
        evidence=STORAGE_EVIDENCE,
    )


# --- share mapping (NAS-MON-04 shared folders) --------------------------------------


SHARE_EVIDENCE = "[sim] SYNO.Core.Share v1 list（fixture 认证；真机待认证）"


def _add_share_mapping(bundle: _Bundle, client: DSMClient, *, now: datetime) -> None:
    """SYNO.Core.Share list -> shared_folder.usage_percent per share.

    The quota member is the denominator; quota 0/无配额 or a missing member
    is an ObservationError carrying the ``no_quota_denominator`` marker
    (ADR-016) — never bytes-as-percent.
    """
    try:
        payload = _family_data(client, "SYNO.Core.Share", "list")
    except DSMError as exc:
        _raise_fatal(exc)
        _err(
            bundle,
            "shared_folder.usage_percent",
            detail=f"共享文件夹 API 读取失败：{_safe_error_text(exc)}",
            error_code=_error_code_of(exc),
            stage="collect",
        )
        return
    shares = _rows_of(payload, "shares")
    if shares is None:
        _err(bundle, "shared_folder.usage_percent", detail="共享文件夹 API 未返回 shares 成员")
        return
    for share in shares:
        native_id = _native_id_value(share.get("id"))
        name = text_value(share.get("name"))
        native = native_id if native_id is not None else (name or "unknown")
        display = name if name is not None else native
        bundle.components.append(_component("shared_folder", native, display, UNKNOWN))
        used = int_value(share.get("used_bytes"))
        quota = int_value(share.get("quota_bytes"))
        if quota is None or quota <= 0:
            _err(
                bundle,
                "shared_folder.usage_percent",
                detail=(
                    "共享文件夹未设置配额（quota 0/缺失）— no_quota_denominator，"
                    "缺少使用率分母，不以字节数冒充百分比（ADR-016）"
                ),
                error_code="not_configured",
                kind="shared_folder",
                native=native,
            )
            continue
        percent = usage_percent(used=used, total=quota)
        if percent is None:
            _err(
                bundle,
                "shared_folder.usage_percent",
                detail="共享文件夹用量/配额超账或无法解析 — no_quota_denominator 语义（ADR-016）",
                kind="shared_folder",
                native=native,
            )
            continue
        _obs(
            bundle,
            "shared_folder.usage_percent",
            percent,
            now=now,
            unit="%",
            kind="shared_folder",
            native=native,
            evidence=SHARE_EVIDENCE,
        )


# --- UPS mapping (NAS-MON-05) --------------------------------------------------------


UPS_EVIDENCE = "[sim] SYNO.Core.UPS v1 get（fixture 认证；真机待认证）"


def _add_ups_mapping(bundle: _Bundle, client: DSMClient, *, now: datetime) -> None:
    """SYNO.Core.UPS get -> ups.status (device-scoped per contracts).

    No UPS connected (data.ups is None) -> NO point and NO component (the
    batch component lifecycle retires a previously seen ups component).
    ups.status maps ONLY device-reported state text through the certified
    ups_state table; unknown text is an ObservationError.
    """
    try:
        payload = _family_data(client, "SYNO.Core.UPS", "get")
    except DSMError as exc:
        _raise_fatal(exc)
        _err(
            bundle,
            "ups.status",
            detail=f"UPS API 读取失败：{_safe_error_text(exc)}",
            error_code=_error_code_of(exc),
            stage="collect",
        )
        return
    if not isinstance(payload, dict):
        _err(bundle, "ups.status", detail="UPS API 返回了无法解析的数据成员")
        return
    ups = payload.get("ups")
    if ups is None:
        return  # no UPS connected: no point, no component (device data)
    if not isinstance(ups, dict):
        _err(bundle, "ups.status", detail="UPS API 返回了无法解析的 ups 成员")
        return
    ups_id = _native_id_value(ups.get("id"))
    name = text_value(ups.get("name"))
    native = ups_id if ups_id is not None else (name or "ups")
    display = name if name is not None else native
    bundle.components.append(
        _component("ups", native, display, _component_status_of(UPS_COMPONENT_STATUS, ups.get("status")))
    )
    mapped = ups_status(ups.get("status"))
    if mapped == UNKNOWN:
        _err(bundle, "ups.status", detail="UPS 状态字面量未认证或缺失")
        return
    _obs(bundle, "ups.status", mapped, now=now, evidence=UPS_EVIDENCE)


# --- logs mapping (NAS-MON-06 event.system_log) --------------------------------------


def _iter_log_entries(client: DSMClient, *, since: datetime | None) -> Iterator[tuple[int, Mapping[str, object]]]:
    """Yield (1-based index, entry) for log entries not older than ``since``.

    DSM log pages are offset/limit walks with a ``total`` member. NO
    ordering assumption is made (M3T2 SEL fix semantics): the walk goes to
    the true collection end (total reached / empty page) within the page
    budget, and per-entry ``occurred_at >= since`` filtering happens AFTER
    the read, so a newer tail after an all-old head page is never silently
    omitted. Entries at exactly ``since`` are re-emitted on purpose (they may
    have appeared mid-read of the previous run); the platform dedupes on the
    native event id.
    """
    offset = 0
    page_limit = 20
    pages = 0
    while pages < MAX_LOG_PAGES:
        pages += 1
        payload = _family_data(client, "SYNO.Core.System.Log", "list", params={"offset": offset, "limit": page_limit})
        if not isinstance(payload, dict):
            raise DSMError("protocol_error", "日志 API 返回了无法解析的数据成员", stage="parse")
        total = payload.get("total")
        raw_entries = payload.get("log")
        entries = raw_entries if isinstance(raw_entries, list) else []
        for index, entry in enumerate(entries, start=offset + 1):
            if not isinstance(entry, dict):
                continue
            occurred_at = _entry_occurred_at(entry)
            if since is None or occurred_at is None or occurred_at >= since:
                yield index, entry
        collected = offset + len(entries)
        if not isinstance(total, int) or collected >= total or not entries:
            return
        offset = collected
    raise DSMError("protocol_error", "日志分页超过预算", stage="parse")


def _entry_occurred_at(entry: Mapping[str, object]) -> datetime | None:
    epoch = float_value(entry.get("time"))
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _add_log_mapping(bundle: _Bundle, client: DSMClient, request: CollectionRequest) -> None:
    """event.system_log entries (delta since the previous logs run)."""
    try:
        for index, entry in _iter_log_entries(client, since=request.last_run_at):
            message = entry.get("message")
            if not isinstance(message, str) or not message.strip():
                _err(bundle, "event.system_log", detail=f"日志条目 {index} 缺少可用的消息正文", stage="collect")
                continue
            occurred_at = _entry_occurred_at(entry)
            if occurred_at is None:
                _err(bundle, "event.system_log", detail=f"日志条目 {index} 缺少可解析的时间戳", stage="collect")
                continue
            native_id = entry.get("id")
            bundle.events.append(
                EventObservation(
                    event_type="event.system_log",
                    severity=log_severity(entry.get("level")),
                    message=message.strip(),
                    occurred_at=occurred_at,
                    source=LOG_EVENT_SOURCE,
                    native_event_id=str(native_id) if native_id is not None else None,
                    detail={},
                )
            )
    except DSMError as exc:
        _err(
            bundle,
            "event.system_log",
            detail=f"日志 API 读取失败：{_safe_error_text(exc)}",
            error_code=_error_code_of(exc),
            stage="collect",
        )


# --- discovery evidence ---------------------------------------------------------------


def _callable_reason(client: DSMClient, api_name: str) -> str | None:
    """Negotiation reason when ``api_name`` is NOT callable on this device."""
    reason = client.negotiation_reason(api_name)
    if reason is not None:
        return reason
    if client.call_spec(api_name) is not None:
        return None
    return "not_discovered"


def _api_reason_detail(reason: str, api_name: str) -> tuple[str, str]:
    """(reason_code, detail) for an uncallable certified API (ADR-014 rows)."""
    if reason == "not_discovered":
        return REASON_API_NOT_DISCOVERED, f"设备 API 映射未包含 {api_name}（不猜测路径）"
    if reason == "not_certified":
        return REASON_NO_CERTIFIED_VERSION, f"平台没有 {api_name} 的认证版本行（ADR-018）"
    if reason == "device_too_old":
        return REASON_DEVICE_TOO_OLD, f"设备 {api_name} maxVersion 低于认证版本（ADR-018）"
    return REASON_RANGE_MISMATCH, f"设备 {api_name} 版本范围与认证版本不匹配（ADR-018）"


def _api_basis(api_name: str) -> str:
    return API_BASIS.get(api_name, "[sim] api " + api_name)


def _capability_rows(client: DSMClient, adapter_key: str) -> tuple[CapabilitySupport, ...]:
    """One row per synology_nas capability key (24 unique keys across
    NAS-MON-01..06 + NAS-ACT-01..06). A row is supported when its certified
    source API is callable on the discovered device AND the adapter
    implements the mapping; missing/unnegotiable API rows stay unsupported
    with the honest reason (api_not_discovered / no_certified_version /
    device_too_old / range_mismatch) — never guessed paths."""
    rows: list[CapabilitySupport] = []
    seen: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != "synology_nas":
            continue
        for key, kind in _requirement_keys(requirement):
            if key in seen:
                continue
            seen.add(key)
            rows.append(_one_capability_row(client, adapter_key, requirement.id, key, kind))
    return tuple(rows)


def _requirement_keys(requirement: object) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for key in requirement.metrics:  # type: ignore[attr-defined]
        keys.append((key, "metric"))
    for key in requirement.events:  # type: ignore[attr-defined]
        keys.append((key, "event"))
    for operation in requirement.operations:  # type: ignore[attr-defined]
        keys.append((operation[0], "operation"))
    return keys


def _one_capability_row(
    client: DSMClient,
    adapter_key: str,
    requirement_id: str,
    key: str,
    kind: str,
) -> CapabilitySupport:
    if kind == "operation":
        return _operation_capability_row(client, adapter_key, requirement_id, key)
    api_name = KEY_API.get(key, MISSING_CERTIFIED_API)
    if api_name == MISSING_CERTIFIED_API:
        return CapabilitySupport(
            capability_key=key,
            support_state="unsupported",
            requirement_id=requirement_id,
            discovery_method=adapter_key,
            reason_code=REASON_NO_WEBAPI_SOURCE,
            detail=(
                "认证 WebAPI 列表无电源状态来源（官方 MIB Guide 仅有 System-MIB powerStatus "
                "补充监控 OID；SNMP 读取未在本里程碑实现）— psu.status 不产生采集值"
            ),
        )
    reason = _callable_reason(client, api_name)
    if reason is None:
        spec = client.call_spec(api_name)
        version = spec.version if spec is not None else "?"
        return CapabilitySupport(
            capability_key=key,
            support_state="supported",
            requirement_id=requirement_id,
            discovery_method=adapter_key,
            detail=f"来源 {api_name} v{version}（{_api_basis(api_name)}）",
        )
    reason_code, detail = _api_reason_detail(reason, api_name)
    return CapabilitySupport(
        capability_key=key,
        support_state="unsupported",
        requirement_id=requirement_id,
        discovery_method=adapter_key,
        reason_code=reason_code,
        detail=detail,
    )


def _operation_capability_row(
    client: DSMClient,
    adapter_key: str,
    requirement_id: str,
    key: str,
) -> CapabilitySupport:
    """One NAS-ACT operation capability row (M4T3).

    ``console.dsm.open`` (launch channel) depends on the authenticated DSM
    management surface — the same SYNO.Core.System row every other call
    needs; all other NAS-ACT profiles map to their certified source API. A
    callable certified API -> supported with the (api, version) + method
    basis; an uncallable one -> unsupported with the honest negotiation
    reason. Platform-side prerequisites (e.g. a configured trap receiver for
    snmp.configure) are runtime preflight items, never discovery claims.
    """
    api_name = OPERATION_KEY_API.get(key, MISSING_CERTIFIED_API)
    if api_name == MISSING_CERTIFIED_API:
        return CapabilitySupport(
            capability_key=key,
            support_state="unsupported",
            requirement_id=requirement_id,
            discovery_method=adapter_key,
            reason_code=REASON_MAPPING_MISSING,
            detail="该 NAS-ACT 能力键没有已接线的适配路径（适配器侧缺口，不是设备不支持）",
        )
    reason = _callable_reason(client, api_name)
    method_note = OPERATION_METHOD_BASIS.get(key, "")
    if reason is None:
        spec = client.call_spec(api_name)
        version = spec.version if spec is not None else "?"
        return CapabilitySupport(
            capability_key=key,
            support_state="supported",
            requirement_id=requirement_id,
            discovery_method=adapter_key,
            detail=f"来源 {api_name} v{version}（{_api_basis(api_name)}；{method_note}）",
        )
    reason_code, detail = _api_reason_detail(reason, api_name)
    return CapabilitySupport(
        capability_key=key,
        support_state="unsupported",
        requirement_id=requirement_id,
        discovery_method=adapter_key,
        reason_code=reason_code,
        detail=detail,
    )


def _inventory_components(client: DSMClient) -> tuple[ComponentObserved, ...]:
    """Component inventory from the current device surface (discovery and the
    metrics pass share this read: disks/pools/volumes/shares/fans/ups + the
    system temperature sensor). Only components the certified APIs actually
    report are returned; psu components NEVER appear (no source)."""
    now = datetime.now(UTC)
    bundle = _Bundle()
    payload, _detail = _read_system(client)
    _add_system_mapping(bundle, payload, now=now)
    _add_storage_mapping(bundle, client, now=now)
    _add_share_mapping(bundle, client, now=now)
    _add_ups_mapping(bundle, client, now=now)
    return tuple(bundle.components)


def _capability_probe_summary(client: DSMClient) -> str:
    """Discover-lite for the probe capabilities stage: which certified
    monitoring families are callable on this device. Errors here fail the
    stage (never fabricated presence)."""
    presence: list[str] = []
    for api_name in (
        "SYNO.Core.System",
        "SYNO.Storage.CGI.Storage",
        "SYNO.Core.Share",
        "SYNO.Core.UPS",
        "SYNO.Core.System.Log",
    ):
        if _callable_reason(client, api_name) is None:
            presence.append(api_name.replace("SYNO.", ""))
    summary = "能力发现完成" if presence else "能力发现完成（无可用监控族）"
    return f"{summary}：{', '.join(presence)}"


# --- adapter ---------------------------------------------------------------------------


class SynologyDsmAdapter(SynologyDsmOperationsMixin):
    """Synology NAS DSM WebAPI adapter (adapter_key ``nas.synology_dsm``).

    probe/discover/collect implement NAS-MON-01..06 against the certified
    DSM WebAPI rows at the top of this module (docs/DEVICE_ADAPTERS.md §5.1
    mapping table — EXACT keys/units from contracts/metrics.json and
    contracts/events.json; missing device values are ObservationErrors,
    never 0/normal). The NAS-ACT operation surface (M4T3) lives in
    ``dsm_operations.py``: plan/preflight/execute/verify per profile and the
    console.dsm.open launch descriptor (``create_launch``), all driven by
    contracts/operations.json profiles and DEVICE_ADAPTERS.md §7/§9.
    """

    adapter_key = "nas.synology_dsm"
    supported_device_types = frozenset({"synology_nas"})
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

    # -- connection ---------------------------------------------------------

    @staticmethod
    def _endpoint_and_http(
        source: DeviceSession | ConnectionProfile,
    ) -> tuple[_Endpoint, httpx.Client]:
        """Endpoint + transport for a session (collect) or a profile (probe/
        discover). See the module-level transport notes for the boundary."""
        config = dict(source.connection_config)
        if isinstance(source, ConnectionProfile):
            endpoint = _endpoint_for(
                resolved_ip=source.resolved_ip,
                management_endpoint=source.management_endpoint,
                connection_config=config,
                fallback_port=source.port,
            )
        else:
            endpoint = _endpoint_for(
                resolved_ip=source.resolved_ip,
                management_endpoint=source.management_endpoint,
                connection_config=config,
            )
        verify_tls = config.get("verify_tls", True)
        pinned = config.get("tls_fingerprint_sha256")
        return endpoint, _build_http_client(
            endpoint,
            verify_tls=bool(verify_tls),
            pinned_fingerprint=pinned if isinstance(pinned, str) else None,
        )

    # -- probe ---------------------------------------------------------------

    def probe(self, profile: ConnectionProfile) -> ProbeResult:
        """Staged probe: network -> tls -> auth -> identity -> capabilities.

        auth proves the DSM login on the discovered device (discovery + one
        authenticated System read — the same read feeds identity); identity
        verifies the device self-reports a certified model (DS224+/DS225+ —
        exact_model scope); capabilities proves the monitoring families are
        callable. Stages after a failure are not executed (never fabricated
        as ok)."""
        try:
            endpoint, http = self._endpoint_and_http(profile)
        except AdapterError as exc:
            failed = ProbeStage(stage="network", ok=False, error_code=exc.code, detail_safe=exc.message)
            return ProbeResult(stages=(failed,))
        try:
            network = _probe_network(endpoint)
            if not network.ok:
                return ProbeResult(
                    stages=(network,) + _not_executed_stages(("tls", "auth", "identity", "capabilities"))
                )
            config = dict(profile.connection_config)
            verify_tls = config.get("verify_tls", True)
            pinned = config.get("tls_fingerprint_sha256")
            tls = _probe_tls(
                endpoint,
                verify_tls=bool(verify_tls),
                pinned_fingerprint=pinned if isinstance(pinned, str) else None,
            )
            if not tls.ok:
                return ProbeResult(stages=(network, tls) + _not_executed_stages(("auth", "identity", "capabilities")))
            with _dsm_client(http, endpoint=endpoint, credentials=profile.credentials) as client:
                # auth stage: API discovery + one authenticated System read
                # (login happens on that read); its payload feeds identity.
                try:
                    client.discover()
                    payload = client.call("SYNO.Core.System", "info", safe=True)
                except DSMError as exc:
                    return ProbeResult(
                        stages=(network, tls, _stage_failure("auth", exc))
                        + _not_executed_stages(("identity", "capabilities"))
                    )
                auth = ProbeStage(stage="auth", ok=True)
                # identity stage: model gate against the certified targets.
                model = payload.get("model") if isinstance(payload, dict) else None
                failures = _identity_failures(model)
                hint = _identity_hint(model if isinstance(model, str) else "")
                if not isinstance(payload, dict) or failures:
                    detail = "；".join(failures) if failures else "System API 未返回身份数据"
                    return ProbeResult(
                        stages=(
                            network,
                            tls,
                            auth,
                            ProbeStage(
                                stage="identity",
                                ok=False,
                                error_code="validation_failed" if failures else "protocol_error",
                                detail_safe=detail,
                            ),
                        )
                        + _not_executed_stages(("capabilities",))
                    )
                identity = ProbeStage(
                    stage="identity",
                    ok=True,
                    detail_safe=f"已识别为 Synology {model if isinstance(model, str) else '未知型号'}",
                )
                # capabilities stage: certified monitoring families callable.
                try:
                    capabilities = ProbeStage(
                        stage="capabilities",
                        ok=True,
                        detail_safe=_capability_probe_summary(client),
                    )
                except DSMError as exc:
                    capabilities = _stage_failure("capabilities", exc)
                return ProbeResult(stages=(network, tls, auth, identity, capabilities), identity_hint=hint or None)
        finally:
            http.close()

    # -- discover ------------------------------------------------------------

    def discover(self, profile: ConnectionProfile) -> DiscoveryResult:
        """Full discovery: identity + component inventory + capability rows
        for ALL synology_nas keys (supported / unsupported-with-reason per
        the certified API list + the discovered API map; ADR-018 per-call
        (api, version) basis recorded on the row details)."""
        endpoint, http = self._endpoint_and_http(profile)
        try:
            with _dsm_client(http, endpoint=endpoint, credentials=profile.credentials) as client:
                client.discover()
                payload = client.call("SYNO.Core.System", "info", safe=True)
                if not isinstance(payload, dict):
                    raise DSMError("protocol_error", "System API 未返回身份数据", stage="parse")
                model = payload.get("model")
                failures = _identity_failures(model)
                if failures:
                    raise AdapterError("validation_failed", "；".join(failures), stage="discover")
                return DiscoveryResult(
                    vendor="Synology",
                    model=model if isinstance(model, str) else "",
                    serial_number=text_value(payload.get("serial")),
                    firmware_version=text_value(payload.get("firmware")),
                    capabilities=_capability_rows(client, self.adapter_key),
                    components=_inventory_components(client),
                    secrets_schema=self.secret_schema,
                    secrets_schema_version=self.secret_schema_version,
                )
        except DSMError as exc:
            raise AdapterError(
                exc.code,
                exc.message,
                stage=exc.stage if exc.stage is not None else "discover",
            ) from exc
        finally:
            http.close()

    # -- collect -------------------------------------------------------------

    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch:
        """One collect pass. Per-run semantics (module docstring + §5.1):

        - EVERY run proves management connectivity (login + one lightweight
          SYNO.Core.System read) and emits connectivity.management: ok ->
          true; a reachable-but-broken management answer -> false (quality
          good); auth/network/TLS failures raise ``AdapterError`` so the
          platform's reachability layer handles offline (a false is NEVER
          fabricated for those);
        - metrics runs add the NAS-MON-01..05 mappings; logs runs add the
          event.system_log delta; psu.status is NEVER emitted (no source —
          discovery row unsupported);
        - per-family device failures become per-key ObservationErrors so one
          broken family never hides the rest of the batch; only
          auth/network/TLS failures fail the whole run.
        """
        if request.collection_type not in ("reachability", "health", "metrics", "logs", "discovery"):
            raise AdapterError("protocol_error", f"未知的采集类型 {request.collection_type}", stage="prepare")
        endpoint, http = self._endpoint_and_http(session)
        try:
            with _dsm_client(http, endpoint=endpoint, credentials=session.credentials) as client:
                bundle = _Bundle()
                payload, detail = _read_system(client)
                _add_connectivity(bundle, payload, now=request.now, detail=detail)
                if request.collection_type == "metrics":
                    _add_system_mapping(bundle, payload, now=request.now)
                    _add_storage_mapping(bundle, client, now=request.now)
                    _add_share_mapping(bundle, client, now=request.now)
                    _add_ups_mapping(bundle, client, now=request.now)
                elif request.collection_type == "logs":
                    _add_log_mapping(bundle, client, request)
                return ObservationBatch(
                    observations=tuple(bundle.observations),
                    events=tuple(bundle.events),
                    components=tuple(bundle.components),
                    errors=tuple(bundle.errors),
                )
        except DSMError as exc:
            raise AdapterError(
                exc.code,
                exc.message,
                stage=exc.stage if exc.stage is not None else "collect",
            ) from exc
        finally:
            http.close()

    # -- operation protocol -------------------------------------------------
    # plan/preflight/execute/verify + create_launch come from the M4T3
    # operations mixin (dsm_operations.py) — NAS-ACT-01..06 profiles from
    # contracts/operations.json.


def _not_executed_stages(names: tuple[str, ...]) -> tuple[ProbeStage, ...]:
    return tuple(ProbeStage(stage=name, ok=False, detail_safe="前置阶段失败，未执行") for name in names)


def _identity_hint(model: str) -> dict[str, str]:
    return {"vendor": "Synology", "model": model}
