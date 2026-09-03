"""Common Redfish operation methods (M3T3): power, manager reset, support
bundles, virtual media, firmware, asset refresh.

Serves contracts/operations.json profiles SRV-ACT-01/02/04/05/06/07 for
``server`` devices (docs/DEVICE_ADAPTERS.md §4.2, §2.4, §7, §9). The five
vendor adapters (M3T5) subclass ``RedfishCommonAdapter`` (which inherits
``RedfishOperationsMixin``) and overlay vendor-specific cold-reset /
TSR / OEM-job semantics there; nothing vendor-specific lives here. Certified
fixture shapes are simulator-origin (module README rule).

Device-side semantics per profile (the ONLY authority — contracts/
operations.json):

- power.on/off/cycle (SRV-ACT-02): ComputerSystem.Reset with ResetType
  On / GracefulShutdown / cycle mapping; power.off NEVER falls back to
  ForceOff (profile prohibition, ADR-016 no_transform). power.cycle carries
  the forced-restart requirement: the common adapter sends ForceRestart when
  the device advertises it, else PowerCycle, and records which mapping it
  used in the execution evidence (the per-model certified overlay lands in
  M3T5). Verification is a deadline-bounded PowerState read-back
  (power_state_readback / power_transition_and_readback): a 204 response is
  acceptance ONLY — success requires the read-back (never 204-as-success).
- manager.reset (SRV-ACT-01): Manager.Reset with ResetType=GracefulRestart
  when advertised (cold-reset semantics are vendor-specific; common adapter
  refuses unadvertised types). expected_disconnect=true: verification polls
  reachability and then compares Manager UUID/System serial over a FRESH
  session (disconnect_reconnect_identity).
- logs.support_bundle.collect (SRV-ACT-04): bounded SEL + manager LogService
  export + a system snapshot JSON, returned as one zip artifact descriptor.
  The adapter yields BYTES ONLY; the worker stores/encrypts/links the file
  (boundary documented in the module + M3T3 report). Verification is the
  artifact_manifest strategy: manifest self-consistency (every source
  included-with-hash or explicitly unavailable) plus the platform's stored
  artifact proof merged into the result evidence by the worker.
- virtual_media.mount/unmount (SRV-ACT-05): InsertMedia/EjectMedia. The Image
  URL is ALWAYS the platform-issued device-pull ticket URL carried in the
  plan runtime context — the adapter never accepts a user-supplied URL and
  the simulator rejects foreign URLs. Verify reads the slot back
  (mounted_media_readback).
- firmware.query (SRV-ACT-06): walk UpdateService FirmwareInventory (+ the
  manager firmware version) into normalized items; the worker persists the
  device row + firmware components (inventory_persisted).
- firmware.update (SRV-ACT-06): POST UpdateService.SimpleUpdate with
  ImageURI = the platform ticket URL and Targets = [<target inventory id>];
  a 202 task is polled by the worker via the persisted device_job_id;
  verification is job_and_version_readback: terminal job success AND the
  target inventory version equals the platform-declared package version
  (runtime context; image parsing is the worker's, never the adapter's).
- asset.refresh (SRV-ACT-07): walk System/Chassis/Manager FRU fields into an
  InventorySnapshot (serial/model/firmware + fru components); the worker
  persists device identity + components (inventory_persisted).

Error mapping (DEVICE_ADAPTERS.md §7): device HTTP errors map through the
Redfish error layer to stable codes; execute/preflight raise ``AdapterError``
with the same code (400 ActionNotSupported -> unsupported_capability, 401 ->
authentication_failed via the client re-login, ...). Read-back verification
reports explicit results: explicit device failures -> failed (never retried),
unprovable outcomes (job vanished, state never reached, identity unreadable)
-> VerificationResult(ambiguous=True) so the executor parks the task in
verification_required (AGENTS.md: 不得把不确定的结果伪装成成功).

Budgets (documented caps; overlays re-certify per-vendor timings in M3T5):
a single verify call may poll the PowerState for at most
POWER_READBACK_CAP_SECONDS (90 s), reconnect after a job-less manager reset
for RECONNECT_CAP_SECONDS (120 s) and read back a job-less firmware version
for VERSION_READBACK_CAP_SECONDS (60 s). When the worker put the task
``timeout_at`` into the runtime context the budget shrinks to the remaining
task time. 202-task flows poll per worker poll interval (no internal long
loops): each verify call performs ONE job read.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.domain.adapter import (
    AdapterError,
    ArtifactDescriptor,
    ComponentObserved,
    DeviceSession,
    FirmwareItem,
    InventorySnapshot,
    OperationProgress,
    OperationResult,
    PreflightResult,
    VerificationResult,
)
from app.domain.operation_plan import (
    DeviceSnapshot,
    OperationPlan,
    OperationRequest,
    plan_operation,
)
from app.infrastructure.protocols.redfish.client import DEFAULT_BASE_PATH, RedfishClient
from app.infrastructure.protocols.redfish.errors import RedfishError, RedfishHttpError
from app.infrastructure.protocols.redfish.parse import (
    RedfishResource,
    datetime_field,
    follow,
    member_links,
    resolve_odata_id,
    text_field,
)

# -- documented single-call verification budgets (see module docstring) ------
POWER_READBACK_CAP_SECONDS = 90.0
RECONNECT_CAP_SECONDS = 120.0
VERSION_READBACK_CAP_SECONDS = 60.0
JOBLESS_RETRY_INTERVAL = 0.25
SEL_EXPORT_PAGE_BUDGET = 200
FIRMWARE_MEMBER_BUDGET = 50
BUNDLE_MESSAGE_MAX_CHARS = 2000


# -- runtime-context contract (worker fills; adapter consumes) ---------------
# Keys (all optional, JSON-safe):
#   "ticket":      {"url": ..., "id": ...}            (mount / firmware.update)
#   "file":        {"file_id", "file_type", "sha256", "expected_model",
#                   "expected_target", "expected_version"}  (mount/update/query)
#   "task_timeout_at": ISO-8601 task deadline          (budget shrinking)
#   "slot_id":     mounted slot evidence for unmount pre-checks
def _ctx_value(plan: OperationPlan, key: str) -> object | None:
    return plan.runtime_context.get(key)


def _ctx_dict(plan: OperationPlan, key: str) -> dict[str, object]:
    value = plan.runtime_context.get(key)
    return value if isinstance(value, dict) else {}


def _ctx_text(plan: OperationPlan, key: str) -> str | None:
    value = _ctx_dict(plan, key).get("url") if key == "ticket" else None
    return value if isinstance(value, str) else None


def _budget_remaining(plan: OperationPlan, cap: float) -> float:
    """Remaining single-call budget: the task deadline wins when present."""
    raw = plan.runtime_context.get("task_timeout_at")
    if isinstance(raw, str):
        try:
            deadline = datetime.fromisoformat(raw)
        except ValueError:
            deadline = None
        if deadline is not None:
            remaining = (deadline - datetime.now(UTC)).total_seconds() - 1.0
            if remaining < cap:
                return max(0.0, remaining)
    return cap


def _evidence_get(evidence: Mapping[str, object] | None, key: str) -> object | None:
    """Read an evidence value tolerating both flat and ``execution`` nesting.

    The run path passes the raw execution evidence; the crash-recovery path
    reconstructs the result from the persisted task evidence (which nests the
    execution evidence under ``execution``).
    """
    if not evidence:
        return None
    if key in evidence:
        return evidence[key]
    nested = evidence.get("execution")
    if isinstance(nested, Mapping) and key in nested:
        return nested[key]  # type: ignore[no-any-return]
    return None


def _text_of(resource: RedfishResource | Mapping[str, Any], key: str) -> str | None:
    value = text_field(resource, key)
    return value if isinstance(value, str) else None


def _status_of(resource: RedfishResource | Mapping[str, Any]) -> str | None:
    status = resource.get("Status")
    if not isinstance(status, Mapping):
        return None
    value = text_field(status, "Health")
    return value if isinstance(value, str) else None


@dataclass(frozen=True)
class _EndpointPath:
    root_url: str
    systems_url: str | None
    chassis_url: str | None
    managers_url: str | None
    update_url: str | None


def _service_links(client: RedfishClient) -> _EndpointPath:
    root = follow_or_raise(client, f"{DEFAULT_BASE_PATH}/", "ServiceRoot")
    return _EndpointPath(
        root_url=root.odata_id or f"{DEFAULT_BASE_PATH}/",
        systems_url=_link_of(root, "Systems"),
        chassis_url=_link_of(root, "Chassis"),
        managers_url=_link_of(root, "Managers"),
        update_url=_link_of(root, "UpdateService"),
    )


def follow_or_raise(client: RedfishClient, url: str, what: str) -> RedfishResource:
    resource = follow(client, url)
    if resource is None:
        raise RedfishError("protocol_error", f"{what} 返回了空响应", stage="parse")
    return resource


def _link_of(resource: RedfishResource | Mapping[str, Any], key: str) -> str | None:
    value = resource.get(key)
    return resolve_odata_id(value)


def _first_member(client: RedfishClient, collection_url: str | None) -> RedfishResource | None:
    if collection_url is None:
        return None
    page = follow(client, collection_url)
    if page is None:
        return None
    links = member_links(page)
    if not links:
        return None
    return follow(client, links[0])


def _system(client: RedfishClient) -> RedfishResource:
    links = _service_links(client)
    system = _first_member(client, links.systems_url)
    if system is None:
        raise RedfishError("protocol_error", "Systems 集合为空或不可读", stage="parse")
    return system


def _manager(client: RedfishClient) -> RedfishResource | None:
    return _first_member(client, _service_links(client).managers_url)


def _reset_action(
    resource: RedfishResource | None, action_key: str
) -> dict[str, object] | None:
    if resource is None:
        return None
    actions = resource.get("Actions")
    if not isinstance(actions, Mapping):
        return None
    entry = actions.get(action_key)
    return dict(entry) if isinstance(entry, Mapping) else None


def _allowable_values(action: Mapping[str, object] | None) -> frozenset[str] | None:
    if action is None:
        return None
    raw = action.get("ResetType@Redfish.AllowableValues")
    if isinstance(raw, list):
        values = {item for item in raw if isinstance(item, str)}
        return frozenset(values)
    return None


def _action_target(action: Mapping[str, object] | None) -> str | None:
    if action is None:
        return None
    target = action.get("target")
    return target if isinstance(target, str) else None


def _redfish_exception_to_adapter(exc: RedfishError, stage: str) -> AdapterError:
    return AdapterError(exc.code, exc.message, stage=exc.stage if exc.stage is not None else stage)


@contextmanager
def _open_session(session: DeviceSession) -> Iterator[RedfishClient]:
    """One Redfish session boundary for an operation call (same connection
    semantics as the M3T2 collect path: policy-resolved IP from the session or
    an IP-literal endpoint, protocol/port from ``connection_config``)."""
    from app.adapters.redfish.common import _build_http_client, _endpoint_for, _redfish_client

    config = dict(session.connection_config)
    endpoint = _endpoint_for(
        resolved_ip=session.resolved_ip,
        management_endpoint=session.management_endpoint,
        connection_config=config,
    )
    verify_tls = bool(config.get("verify_tls", True))
    pinned = config.get("tls_fingerprint_sha256")
    pinned_value = pinned if isinstance(pinned, str) else None
    http = _build_http_client(endpoint, verify_tls=verify_tls, pinned_fingerprint=pinned_value)
    try:
        with _redfish_client(http, endpoint=endpoint, credentials=session.credentials) as client:
            yield client
    finally:
        http.close()


def _system_identity(client: RedfishClient) -> dict[str, object]:
    """Device identity evidence used by manager-reset verification."""
    system = _system(client)
    manager = _manager(client)
    serial = _text_of(system, "SerialNumber")
    manager_uuid = _text_of(manager, "UUID") if manager is not None else None
    return {
        "system_serial": serial,
        "manager_uuid": manager_uuid,
        "model": _text_of(system, "Model"),
    }


# -- plan --------------------------------------------------------------------


def plan_operation_method(snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
    """Planning mirrors the shared domain planner (DEVICE_ADAPTERS.md §2.4):
    profiles only come from contracts/operations.json via the registry."""
    return plan_operation(snapshot, request)


# -- preflight ---------------------------------------------------------------


def _power_preflight(system: RedfishResource, plan: OperationPlan) -> PreflightResult:
    action = _reset_action(system, "#ComputerSystem.Reset")
    if action is None:
        return PreflightResult(
            ok=False,
            error_code="unsupported_capability",
            detail="服务器未提供 ComputerSystem Reset 动作",
        )
    allowable = _allowable_values(action)
    power_state = _text_of(system, "PowerState")
    if power_state is None:
        return PreflightResult(
            ok=False,
            error_code="protocol_error",
            detail="无法读取系统电源状态（PowerState 缺失）",
        )
    key = plan.capability_key
    if key == "power.on":
        if power_state != "Off":
            return PreflightResult(
                ok=False,
                error_code="validation_failed",
                detail=f"系统电源状态为 {power_state}，开机前置要求为关机（状态漂移）",
            )
        if allowable is not None and "On" not in allowable:
            return PreflightResult(
                ok=False,
                error_code="unsupported_capability",
                detail="设备未明确通告 On 复位类型",
            )
        return PreflightResult(ok=True)
    if key == "power.off":
        if power_state != "On":
            return PreflightResult(
                ok=False,
                error_code="validation_failed",
                detail=f"系统电源状态为 {power_state}，关机前置要求为开机（状态漂移）",
            )
        # Profile prohibition: graceful only, NEVER ForceOff (ADR-016).
        if allowable is not None and "GracefulShutdown" not in allowable:
            return PreflightResult(
                ok=False,
                error_code="unsupported_capability",
                detail="设备未通告优雅关机（GracefulShutdown），且禁止回退 ForceOff",
            )
        return PreflightResult(ok=True)
    # power.cycle
    if power_state != "On":
        return PreflightResult(
            ok=False,
            error_code="validation_failed",
            detail=f"系统电源状态为 {power_state}，重启前置要求为开机（状态漂移）",
        )
    if allowable is not None and not allowable.intersection({"ForceRestart", "PowerCycle"}):
        return PreflightResult(
            ok=False,
            error_code="unsupported_capability",
            detail="设备未通告 ForceRestart 或 PowerCycle 重启类型",
        )
    return PreflightResult(ok=True)


def preflight_operation_method(session: DeviceSession, plan: OperationPlan) -> PreflightResult:
    """Real-time read-only preflight per profile preconditions (no side effects)."""
    key = plan.capability_key
    if key in ("power.on", "power.off", "power.cycle"):
        with _open_session(session) as client:
            return _power_preflight(_system(client), plan)
    if key == "manager.reset":
        with _open_session(session) as client:
            manager = _manager(client)
            action = _reset_action(manager, "#Manager.Reset")
            if action is None:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="管理卡未提供 Manager Reset 动作",
                )
            allowable = _allowable_values(action)
            if allowable is not None and "GracefulRestart" not in allowable:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="管理卡未通告 GracefulRestart（冷复位类型由厂商 overlay 定义）",
                )
            return PreflightResult(ok=True)
    if key == "logs.support_bundle.collect":
        with _open_session(session) as client:
            sel = _find_sel_service(client)
            if sel is None:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="管理卡未提供 SEL LogService，无法组成支持包",
                )
            return PreflightResult(ok=True)
    if key == "virtual_media.mount":
        with _open_session(session) as client:
            slots = _virtual_media_slots(client)
            if not slots:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="管理卡未提供 VirtualMedia 服务或可用槽位",
                )
            kind = _media_kind(plan)
            if not _compatible_slot(slots, kind):
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail=f"未发现兼容 {kind} 的可用虚拟介质槽位",
                )
            if _ctx_text(plan, "ticket") is None:
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未提供设备拉取票据，无法挂载虚拟介质",
                )
            return PreflightResult(ok=True)
    if key == "virtual_media.unmount":
        slot_id = plan.normalized_parameters.get("slot_id")
        with _open_session(session) as client:
            record = _virtual_media_slot(client, slot_id if isinstance(slot_id, str) else None)
            if record is None:
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail="目标虚拟介质槽位不存在",
                )
            if not record.get("inserted"):
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail=f"槽位 {slot_id} 当前未插入介质（状态漂移）",
                )
            return PreflightResult(ok=True)
    if key == "firmware.update":
        with _open_session(session) as client:
            update = _update_service(client)
            if update is None:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="未提供 UpdateService",
                )
            action = _reset_action(update, "#UpdateService.SimpleUpdate")
            if action is None and _link_of(update, "HttpPushUri") is None:
                return PreflightResult(
                    ok=False,
                    error_code="unsupported_capability",
                    detail="UpdateService 未提供 SimpleUpdate 或 HttpPushUri 更新路径",
                )
            target_id = plan.normalized_parameters.get("target_id")
            if action is not None and isinstance(target_id, str) and not _firmware_target_exists(client, target_id):
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail=f"固件清单中不存在目标 {target_id}",
                )
            system = _system(client)
            if _text_of(system, "PowerState") != "On":
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail="系统当前非开机状态，无法执行固件升级",
                )
            return PreflightResult(ok=True)
    if key in ("firmware.query", "asset.refresh"):
        with _open_session(session) as client:
            if key == "firmware.query":
                update = _update_service(client)
                if update is None or _link_of(update, "FirmwareInventory") is None:
                    return PreflightResult(
                        ok=False,
                        error_code="unsupported_capability",
                        detail="UpdateService 未提供固件清单",
                    )
            else:
                try:
                    _system(client)
                except RedfishError as exc:
                    return PreflightResult(
                        ok=False,
                        error_code=exc.code,
                        detail="无法读取资产资源（ComputerSystem 缺失）",
                    )
            return PreflightResult(ok=True)
    return PreflightResult(
        ok=False,
        error_code="unsupported_capability",
        detail=f"通用 Redfish 适配器未实现操作 {key}",
    )


# -- execute ----------------------------------------------------------------


def _reset_type_for(system: RedfishResource, plan: OperationPlan) -> tuple[str, str]:
    """(reset_type, mapping note) for a power plan.

    power.on -> On; power.off -> GracefulShutdown (NEVER ForceOff); power.cycle
    -> ForceRestart when advertised else PowerCycle (common mapping rule; the
    certified per-model overlay lands in M3T5).
    """
    action = _reset_action(system, "#ComputerSystem.Reset")
    allowable = _allowable_values(action)
    key = plan.capability_key
    if key == "power.on":
        return "On", "On（开机）"
    if key == "power.off":
        return "GracefulShutdown", "GracefulShutdown（优雅关机，禁止 ForceOff 回退）"
    if allowable is not None and "ForceRestart" in allowable:
        return "ForceRestart", "ForceRestart（设备通告，通用映射规则）"
    return "PowerCycle", "PowerCycle（设备未通告 ForceRestart，通用映射规则）"


def _post_action(
    client: RedfishClient,
    plan: OperationPlan,
    progress: OperationProgress,
    *,
    action_target: str,
    body: dict[str, object],
    stage: str,
) -> OperationResult:
    try:
        reply = client.post(action_target, json_body=body)
    except RedfishError as exc:
        raise _redfish_exception_to_adapter(exc, stage) from exc
    progress(60, "动作已被设备接受")
    evidence: dict[str, object] = {"command": body, "http_status": reply.status_code}
    location = reply.headers.get("location")
    if reply.status_code == 202 and location:
        job_uri = location.strip()
        return OperationResult(ok=True, evidence=evidence, device_job_id=job_uri or None)
    return OperationResult(ok=True, evidence=evidence)


def _power_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    with _open_session(session) as client:
        system = _system(client)
        action = _reset_action(system, "#ComputerSystem.Reset")
        action_target = _action_target(action)
        if action_target is None:
            raise AdapterError(
                "unsupported_capability", "服务器未提供 ComputerSystem Reset 动作", stage="execute"
            )
        reset_type, mapping_note = _reset_type_for(system, plan)
        progress(20, f"执行电源动作（{mapping_note}）")
        result = _post_action(
            client,
            plan,
            progress,
            action_target=action_target,
            body={"ResetType": reset_type},
            stage="execute",
        )
        evidence = dict(result.evidence)
        evidence["reset_type"] = reset_type
        evidence["mapping"] = mapping_note
        return OperationResult(
            ok=result.ok,
            evidence=evidence,
            device_job_id=result.device_job_id,
            error_code=result.error_code,
            error_detail=result.error_detail,
        )


def _manager_reset_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    with _open_session(session) as client:
        manager = _manager(client)
        action = _reset_action(manager, "#Manager.Reset")
        action_target = _action_target(action)
        if action_target is None:
            raise AdapterError(
                "unsupported_capability", "管理卡未提供 Manager Reset 动作", stage="execute"
            )
        allowable = _allowable_values(action)
        if allowable is not None and "GracefulRestart" not in allowable:
            raise AdapterError(
                "unsupported_capability",
                "管理卡未通告 GracefulRestart（冷复位类型由厂商 overlay 定义）",
                stage="execute",
            )
        # Identity BEFORE the reset (read over the pre-reset session) — the
        # verification compares it over a fresh post-reset session.
        identity = _system_identity(client)
        progress(20, "执行管理卡复位（GracefulRestart）")
        result = _post_action(
            client,
            plan,
            progress,
            action_target=action_target,
            body={"ResetType": "GracefulRestart"},
            stage="execute",
        )
        evidence = dict(result.evidence)
        evidence["reset_type"] = "GracefulRestart"
        evidence["identity_before"] = identity
        return OperationResult(
            ok=result.ok,
            evidence=evidence,
            device_job_id=result.device_job_id,
            error_code=result.error_code,
            error_detail=result.error_detail,
        )


def _find_sel_service(client: RedfishClient) -> RedfishResource | None:
    manager = _manager(client)
    if manager is None:
        return None
    services_url = _link_of(manager, "LogServices")
    if services_url is None:
        return None
    for service in _walk_member_resources(client, services_url, budget=20):
        if _text_of(service, "LogEntryType") == "SEL":
            return service
    return None


def _log_services(client: RedfishClient) -> list[RedfishResource]:
    manager = _manager(client)
    if manager is None:
        return []
    services_url = _link_of(manager, "LogServices")
    if services_url is None:
        return []
    return _walk_member_resources(client, services_url, budget=20)


def _walk_collection_pages(
    client: RedfishClient, collection_url: str, page_budget: int
) -> tuple[list[dict[str, Any]], bool]:
    """Page-walk a Redfish collection (nextLink or $skip counting).

    Returns (raw page member payload dicts, truncated). Truncation (device
    stopped short with no continuation) is reported honestly — never a
    fabricated full result.
    """
    from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

    def _with_skip(url: str, skip: int) -> str:
        parts = urlsplit(url)
        pairs = [
            f"{quote(key, safe='')}={quote(value, safe='')}"
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key != "$skip"
        ]
        pairs.append(f"$skip={skip}")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))

    page_url = collection_url
    resources: list[dict[str, Any]] = []
    collected = 0
    seen: set[str] = set()
    while True:
        if page_url in seen or len(seen) >= page_budget:
            return resources, True
        seen.add(page_url)
        try:
            page = follow(client, page_url)
        except RedfishError as exc:
            raise RedfishError(exc.code, exc.message, stage="parse") from exc
        if page is None:
            raise RedfishError("protocol_error", "日志集合返回了空响应", stage="parse")
        raw_members = page.get("Members")
        if not isinstance(raw_members, list):
            break
        for member in raw_members:
            if isinstance(member, Mapping):
                resources.append(dict(member))
            elif isinstance(member, str):
                resources.append({"@odata.id": member})
        collected += len(raw_members)
        count = page.get("Members@odata.count")
        next_link = page.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link:
            page_url = next_link
            continue
        if isinstance(count, int) and collected < count:
            page_url = _with_skip(page_url, collected)
            continue
        break
    return resources, False


def _walk_member_resources(
    client: RedfishClient, collection_url: str, budget: int
) -> list[RedfishResource]:
    """Member RESOURCES of a link-style collection (bounded)."""
    page = follow(client, collection_url)
    if page is None:
        return []
    members: list[RedfishResource] = []
    for member in page.get("Members", []) if isinstance(page.get("Members"), list) else []:
        if not isinstance(member, Mapping):
            continue
        odata_id = resolve_odata_id(member)
        if odata_id is None:
            continue
        full = follow(client, odata_id)
        if full is not None:
            members.append(full)
        if len(members) >= budget:
            break
    return members


def _normalized_log_entry(entry: Mapping[str, Any], index: int) -> dict[str, object] | None:
    entry_id = entry.get("Id")
    if not isinstance(entry_id, str) or not entry_id:
        return None
    message = entry.get("Message")
    message_text = message if isinstance(message, str) else ""
    occurred = datetime_field(entry, "Created")
    occurred_iso = occurred.isoformat() if isinstance(occurred, datetime) else None
    severity = entry.get("Severity")
    return {
        "id": entry_id,
        "index": index + 1,
        "occurred_at": occurred_iso,
        "severity": severity if isinstance(severity, str) else None,
        "message": message_text[:BUNDLE_MESSAGE_MAX_CHARS],
    }


def _source_bytes(name: str, entries: Sequence[dict[str, object]]) -> bytes:
    payload = {"source": name, "entries": list(entries)}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _system_snapshot(client: RedfishClient) -> dict[str, object]:
    system = _system(client)
    manager = _manager(client)
    return {
        "id": _text_of(system, "Id") or "1",
        "name": _text_of(system, "Name"),
        "manufacturer": _text_of(system, "Manufacturer"),
        "model": _text_of(system, "Model"),
        "serial_number": _text_of(system, "SerialNumber"),
        "sku": _text_of(system, "SKU"),
        "bios_version": _text_of(system, "BiosVersion"),
        "power_state": _text_of(system, "PowerState"),
        "system_status": _status_of(system),
        "manager_firmware_version": _text_of(manager, "FirmwareVersion") if manager is not None else None,
        "manager_uuid": _text_of(manager, "UUID") if manager is not None else None,
    }


def _support_bundle_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    with _open_session(session) as client:
        progress(10, "导出 SEL/系统日志")
        services = _log_services(client)
        sel_service = next((s for s in services if _text_of(s, "LogEntryType") == "SEL"), None)
        export_sources: list[dict[str, object]] = []
        unavailable: list[dict[str, object]] = []
        files: list[tuple[str, str, bytes]] = []
        walked_any = False
        for service in services:
            service_id = _text_of(service, "Id") or "log"
            entries_url = _link_of(service, "Entries")
            if entries_url is None:
                unavailable.append({"name": service_id, "reason": "no_entries_link"})
                continue
            try:
                raw_members, truncated = _walk_collection_pages(
                    client, entries_url, SEL_EXPORT_PAGE_BUDGET
                )
            except RedfishError:
                unavailable.append({"name": service_id, "reason": "entries_unreadable"})
                continue
            if truncated:
                unavailable.append({"name": service_id, "reason": "entries_truncated"})
                continue
            entries: list[dict[str, object]] = []
            skipped = 0
            for index, member in enumerate(raw_members):
                normalized = _normalized_log_entry(member, index)
                if normalized is None:
                    skipped += 1
                    continue
                entries.append(normalized)
            if not entries:
                unavailable.append({"name": service_id, "reason": "no_parseable_entries"})
                continue
            walked_any = True
            blob = _source_bytes(service_id, entries)
            name = f"log-{service_id}.json"
            files.append((name, service_id, blob))
            export_sources.append(
                {
                    "name": service_id,
                    "log_type": _text_of(service, "LogEntryType"),
                    "entries": len(entries),
                    "skipped_unparseable": skipped,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                }
            )
        progress(50, "整理系统快照")
        snapshot = _system_snapshot(client)
        snapshot_blob = _source_bytes("system_snapshot", [snapshot])
        files.append(("system.json", "system_snapshot", snapshot_blob))
        export_sources.append(
            {
                "name": "system_snapshot",
                "entries": 1,
                "sha256": hashlib.sha256(snapshot_blob).hexdigest(),
            }
        )
        if sel_service is None:
            unavailable.append({"name": "SEL", "reason": "no_sel_log_service"})
        if not walked_any:
            raise AdapterError(
                "operation_failed", "没有可导出的日志来源，支持包内容为空", stage="execute"
            )
        manifest: dict[str, object] = {
            "format": "warden-support-bundle/1",
            "created_at": datetime.now(UTC).isoformat(),
            "sources": export_sources,
            "unavailable": unavailable,
        }
        progress(80, "打包支持包产物")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2)
            )
            for name, _service_id, blob in files:
                archive.writestr(name, blob)
        content = buffer.getvalue()
        progress(95, "支持包打包完成")
        artifact = ArtifactDescriptor(
            file_type="support_bundle",
            filename="support-bundle.zip",
            content_bytes=content,
            mime_type="application/zip",
            manifest=manifest,
        )
        evidence: dict[str, object] = {
            "artifact_manifest": manifest,
            "artifact_sha256": hashlib.sha256(content).hexdigest(),
            "artifact_bytes": len(content),
        }
        return OperationResult(ok=True, evidence=evidence, artifacts=(artifact,))


def _media_kind(plan: OperationPlan) -> str:
    kind = plan.normalized_parameters.get("media_kind")
    return kind if kind in ("iso", "usb_image") else "iso"


def _virtual_media_slots(client: RedfishClient) -> list[dict[str, Any]]:
    manager = _manager(client)
    if manager is None:
        return []
    collection_url = _link_of(manager, "VirtualMedia")
    if collection_url is None:
        return []
    members = _walk_member_resources(client, collection_url, budget=16)
    slots: list[dict[str, Any]] = []
    for member in members:
        media_types = member.get("MediaTypes")
        slot: dict[str, Any] = {
            "id": _text_of(member, "Id"),
            "name": _text_of(member, "Name"),
            "inserted": member.get("Inserted") is True,
            "image": member.get("Image"),
            "insert_target": _action_target(
                _reset_action(member, "#VirtualMedia.InsertMedia")
            ),
            "eject_target": _action_target(
                _reset_action(member, "#VirtualMedia.EjectMedia")
            ),
        }
        if isinstance(media_types, list):
            slot["media_types"] = [item for item in media_types if isinstance(item, str)]
        else:
            slot["media_types"] = []
        slots.append(slot)
    return slots


def _virtual_media_slot(client: RedfishClient, slot_id: str | None) -> dict[str, Any] | None:
    for slot in _virtual_media_slots(client):
        if slot["id"] == slot_id:
            return slot
    return None


def _compatible_slot(slots: Sequence[dict[str, Any]], kind: str) -> dict[str, Any] | None:
    wanted = {"CD", "DVD"} if kind == "iso" else {"USB"}
    for slot in slots:
        if slot.get("inserted"):
            continue
        types = slot.get("media_types")
        if types is None or wanted.intersection(types):
            return slot
    return None


def _virtual_media_mount_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    ticket_url = _ctx_text(plan, "ticket")
    if ticket_url is None:
        raise AdapterError("not_configured", "平台未提供设备拉取票据，无法挂载虚拟介质", stage="execute")
    kind = _media_kind(plan)
    with _open_session(session) as client:
        slots = _virtual_media_slots(client)
        target = _compatible_slot(slots, kind)
        if target is None:
            raise AdapterError(
                "unsupported_capability",
                f"未发现兼容 {kind} 的空闲虚拟介质槽位",
                stage="execute",
            )
        insert_target = target["insert_target"]
        if insert_target is None:
            raise AdapterError(
                "unsupported_capability",
                f"槽位 {target['id']} 未提供 InsertMedia 动作",
                stage="execute",
            )
        progress(40, f"向槽位 {target['id']} 插入虚拟介质")
        body: dict[str, object] = {
            "Image": ticket_url,
            "Inserted": True,
            "WriteProtected": True,
        }
        result = _post_action(
            client, plan, progress, action_target=insert_target, body=body, stage="execute"
        )
        evidence = dict(result.evidence)
        evidence["slot_id"] = target["id"]
        evidence["slot_name"] = target["name"]
        evidence["media_kind"] = kind
        return OperationResult(
            ok=result.ok,
            evidence=evidence,
            device_job_id=result.device_job_id,
            error_code=result.error_code,
            error_detail=result.error_detail,
        )


def _virtual_media_unmount_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    slot_id = plan.normalized_parameters.get("slot_id")
    if not isinstance(slot_id, str):
        raise AdapterError("validation_failed", "缺少 slot_id 参数", stage="execute")
    with _open_session(session) as client:
        slot = _virtual_media_slot(client, slot_id)
        if slot is None:
            raise AdapterError("validation_failed", f"虚拟介质槽位 {slot_id} 不存在", stage="execute")
        eject_target = slot["eject_target"]
        if eject_target is None:
            raise AdapterError(
                "unsupported_capability",
                f"槽位 {slot_id} 未提供 EjectMedia 动作",
                stage="execute",
            )
        progress(40, f"弹出槽位 {slot_id} 中的虚拟介质")
        result = _post_action(
            client,
            plan,
            progress,
            action_target=eject_target,
            body={},
            stage="execute",
        )
        evidence = dict(result.evidence)
        evidence["slot_id"] = slot_id
        return OperationResult(
            ok=result.ok,
            evidence=evidence,
            device_job_id=result.device_job_id,
            error_code=result.error_code,
            error_detail=result.error_detail,
        )


def _update_service(client: RedfishClient) -> RedfishResource | None:
    update_url = _service_links(client).update_url
    if update_url is None:
        return None
    return follow(client, update_url)


def _firmware_inventory_items(client: RedfishClient) -> list[FirmwareItem]:
    update = _update_service(client)
    if update is None:
        return []
    inventory_url = _link_of(update, "FirmwareInventory")
    if inventory_url is None:
        return []
    members = _walk_member_resources(client, inventory_url, budget=FIRMWARE_MEMBER_BUDGET)
    items: list[FirmwareItem] = []
    for member in members:
        target = _text_of(member, "Id")
        if not target:
            odata = member.odata_id
            target = odata.rsplit("/", 1)[-1] if odata else ""
        name = _text_of(member, "Name") or target
        version = _text_of(member, "Version")
        items.append(FirmwareItem(target=target, name=name, version=version))
    return items


def _firmware_target_exists(client: RedfishClient, target_id: str) -> bool:
    return any(item.target == target_id for item in _firmware_inventory_items(client))


def _firmware_query_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    with _open_session(session) as client:
        progress(20, "读取固件清单")
        items = _firmware_inventory_items(client)
        if not items:
            raise AdapterError(
                "unsupported_capability", "UpdateService 固件清单为空", stage="execute"
            )
        manager = _manager(client)
        manager_version = _text_of(manager, "FirmwareVersion") if manager is not None else None
        evidence: dict[str, object] = {
            "firmware_items": [
                {"target": item.target, "name": item.name, "version": item.version}
                for item in items
            ],
            "manager_firmware_version": manager_version,
            "observed_at": datetime.now(UTC).isoformat(),
        }
        inventory = InventorySnapshot(
            observed_at=datetime.now(UTC),
            firmware_version=manager_version,
            firmware_items=tuple(items),
        )
        progress(100, "固件清单读取完成")
        return OperationResult(ok=True, evidence=evidence, inventory=inventory)


def _firmware_update_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    ticket_url = _ctx_text(plan, "ticket")
    if ticket_url is None:
        raise AdapterError("not_configured", "平台未提供设备拉取票据，无法升级固件", stage="execute")
    file_ctx = _ctx_dict(plan, "file")
    expected_version = file_ctx.get("expected_version")
    if not isinstance(expected_version, str) or not expected_version:
        raise AdapterError(
            "validation_failed", "平台未提供固件包目标版本，无法执行升级", stage="execute"
        )
    with _open_session(session) as client:
        update = _update_service(client)
        if update is None:
            raise AdapterError("unsupported_capability", "未提供 UpdateService", stage="execute")
        action = _reset_action(update, "#UpdateService.SimpleUpdate")
        if action is None and _link_of(update, "HttpPushUri") is None:
            raise AdapterError(
                "unsupported_capability",
                "UpdateService 未提供 SimpleUpdate 或 HttpPushUri 更新路径",
                stage="execute",
            )
        target_id = plan.normalized_parameters.get("target_id")
        items = _firmware_inventory_items(client)
        match = next((item for item in items if item.target == target_id), None)
        if match is None:
            raise AdapterError(
                "validation_failed",
                f"固件清单中不存在目标 {target_id}",
                stage="execute",
            )
        target_url = None
        update_res = update
        inventory_url = _link_of(update_res, "FirmwareInventory")
        if inventory_url is not None and match is not None:
            collection = follow(client, inventory_url)
            if collection is not None:
                for member in collection.get("Members", []) if isinstance(collection.get("Members"), list) else []:
                    if not isinstance(member, Mapping):
                        continue
                    odata_id = resolve_odata_id(member)
                    if odata_id is not None and odata_id.rsplit("/", 1)[-1] == match.target:
                        target_url = odata_id
                        break
        if target_url is None:
            raise AdapterError(
                "validation_failed",
                f"无法解析目标 {target_id} 的清单 URI",
                stage="execute",
            )
        action_target = _action_target(action)
        if action_target is None:
            raise AdapterError(
                "unsupported_capability", "UpdateService 未提供 SimpleUpdate 动作", stage="execute"
            )
        progress(20, f"提交固件升级任务（目标 {target_id}）")
        result = _post_action(
            client,
            plan,
            progress,
            action_target=action_target,
            body={"ImageURI": ticket_url, "Targets": [target_url]},
            stage="execute",
        )
        evidence = dict(result.evidence)
        evidence["target_id"] = target_id
        evidence["expected_version"] = expected_version
        evidence["file_sha256"] = file_ctx.get("sha256")
        evidence["mapping"] = "UpdateService.SimpleUpdate"
        return OperationResult(
            ok=result.ok,
            evidence=evidence,
            device_job_id=result.device_job_id,
            error_code=result.error_code,
            error_detail=result.error_detail,
        )


def _asset_refresh_execute(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    with _open_session(session) as client:
        progress(20, "读取资产/FRU 资源")
        system = _system(client)
        manager = _manager(client)
        chassis = _first_member(client, _service_links(client).chassis_url)
        serial = _text_of(system, "SerialNumber")
        model = _text_of(system, "Model")
        manager_version = _text_of(manager, "FirmwareVersion") if manager is not None else None
        now = datetime.now(UTC)
        components: list[ComponentObserved] = []
        if chassis is not None:
            components.append(
                ComponentObserved(
                    kind="fru",
                    native_id="chassis-1",
                    name=_text_of(chassis, "Name") or "机箱 FRU",
                    status="ok",
                    properties={
                        "manufacturer": _text_of(chassis, "Manufacturer"),
                        "model": _text_of(chassis, "Model"),
                        "serial_number": _text_of(chassis, "SerialNumber"),
                        "part_number": _text_of(chassis, "PartNumber"),
                    },
                )
            )
        if manager is not None:
            components.append(
                ComponentObserved(
                    kind="fru",
                    native_id="manager-1",
                    name=_text_of(manager, "Name") or "管理卡 FRU",
                    status="ok",
                    properties={
                        "manufacturer": _text_of(manager, "Manufacturer"),
                        "model": _text_of(manager, "Model"),
                        "serial_number": _text_of(manager, "SerialNumber"),
                        "part_number": _text_of(manager, "PartNumber"),
                        "firmware_version": manager_version,
                    },
                )
            )
        evidence: dict[str, object] = {
            "serial_number": serial,
            "model": model,
            "manager_firmware_version": manager_version,
            "fru_parts": [
                {
                    "native_id": component.native_id,
                    "name": component.name,
                    "properties": component.properties,
                }
                for component in components
            ],
            "observed_at": now.isoformat(),
        }
        inventory = InventorySnapshot(
            observed_at=now,
            serial_number=serial,
            model=model,
            firmware_version=manager_version,
            components=tuple(components),
        )
        progress(100, "资产读取完成")
        return OperationResult(ok=True, evidence=evidence, inventory=inventory)


def execute_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    """Execute a device-side operation (called only AFTER the dispatch fence)."""
    key = plan.capability_key
    if key in ("power.on", "power.off", "power.cycle"):
        return _power_execute(session, plan, progress)
    if key == "manager.reset":
        return _manager_reset_execute(session, plan, progress)
    if key == "logs.support_bundle.collect":
        return _support_bundle_execute(session, plan, progress)
    if key == "virtual_media.mount":
        return _virtual_media_mount_execute(session, plan, progress)
    if key == "virtual_media.unmount":
        return _virtual_media_unmount_execute(session, plan, progress)
    if key == "firmware.query":
        return _firmware_query_execute(session, plan, progress)
    if key == "firmware.update":
        return _firmware_update_execute(session, plan, progress)
    if key == "asset.refresh":
        return _asset_refresh_execute(session, plan, progress)
    raise AdapterError(
        "unsupported_capability", f"通用 Redfish 适配器未实现操作 {key}", stage="execute"
    )


# -- verification ------------------------------------------------------------


@dataclass(frozen=True)
class _JobRead:
    state: str  # running / completed / failed / interrupted / vanished
    error_code: str | None = None


def _read_job(client: RedfishClient, job_uri: str) -> _JobRead:
    """One bounded read of a Redfish task resource (single poll).

    404 -> vanished (unprovable, ambiguous); Exception/Killed -> failed;
    Interrupted/Cancelled -> interrupted (ambiguous); anything else
    non-terminal -> running; unknown TaskState -> protocol_error.
    """
    try:
        reply = client.request("GET", job_uri)
    except RedfishHttpError as exc:
        if exc.status == 404:
            return _JobRead(state="vanished", error_code="ambiguous_result")
        raise
    if reply.payload is None:
        raise RedfishError("protocol_error", "设备作业返回了空响应", stage="verify")
    payload = RedfishResource(reply.payload)
    state = text_field(payload, "TaskState")
    if not isinstance(state, str):
        raise RedfishError("protocol_error", "设备作业缺少 TaskState", stage="verify")
    if state == "Completed":
        return _JobRead(state="completed")
    if state in ("Exception", "Killed"):
        return _JobRead(state="failed", error_code="operation_failed")
    if state in ("Interrupted", "Cancelled"):
        return _JobRead(state="interrupted", error_code="ambiguous_result")
    if state in (
        "New",
        "Starting",
        "Running",
        "Suspended",
        "Pending",
        "Stopping",
        "Cancelling",
        "Resuming",
    ):
        return _JobRead(state="running")
    raise RedfishError("protocol_error", f"设备作业状态 {state!r} 无法解析", stage="verify")


def _readback_target_state(plan: OperationPlan) -> str | None:
    if plan.capability_key == "power.on":
        return "On"
    if plan.capability_key == "power.off":
        return "Off"
    if plan.capability_key == "power.cycle":
        return "On"
    return None


_OFFLINE_CODES = frozenset(
    {
        "network_unreachable",
        "operation_failed",
        "protocol_error",
        "rate_limited",
        "device_busy",
    }
)


def _is_offline_code(code: str) -> bool:
    """Codes meaning 'the manager/session is not back yet' (boot window)."""
    return code in _OFFLINE_CODES


def _power_verify_inner(
    client: RedfishClient,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """Read the PowerState until the profile target, deadline-bounded.

    power.cycle (power_transition_and_readback) additionally requires
    observing the Off transition before the final On — a restart that cannot
    be proven to have happened is ambiguous, never success. A 202 job is
    polled once per call: still running -> ``pending`` (the worker keeps
    polling with lease renewals); a vanished/interrupted job falls through to
    the state read-back, which may still prove the target state.
    """
    target = _readback_target_state(plan)
    if target is None:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={"reason": "unknown power target"},
        )
    job = result.device_job_id if result is not None else None
    job_outcome: str | None = None
    if job is not None:
        try:
            job_read = _read_job(client, job)
        except RedfishError:
            # Job unreadable right after acceptance (device busy/booting):
            # fall through to the state read-back, which retries until the
            # deadline — never a fabricated verdict.
            job_outcome = "unreadable"
        else:
            if job_read.state == "running":
                return VerificationResult(
                    succeeded=False, pending=True, evidence={"job_state": "running"}
                )
            if job_read.state == "failed":
                return VerificationResult(
                    succeeded=False,
                    error_code="operation_failed",
                    evidence={"job_state": "failed", "job_error": job_read.error_code},
                )
            if job_read.state in ("interrupted", "vanished"):
                job_outcome = job_read.state
    deadline = time.monotonic() + _budget_remaining(plan, POWER_READBACK_CAP_SECONDS)
    observed: list[str] = []
    saw_off = False
    saw_on = False
    while time.monotonic() < deadline:
        try:
            state = _text_of(_system(client), "PowerState")
        except RedfishError:
            time.sleep(JOBLESS_RETRY_INTERVAL)
            continue
        if state not in ("On", "Off"):
            time.sleep(JOBLESS_RETRY_INTERVAL)
            continue
        observed.append(state)
        if state == "Off":
            saw_off = True
        if state == "On":
            saw_on = True
        if plan.capability_key == "power.cycle":
            if saw_off and saw_on:
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "target_state": "On",
                        "observed_states": observed,
                        "transition_observed": True,
                        "job_outcome": job_outcome,
                        "strategy": plan.verification_strategy,
                    },
                )
        elif state == target:
            return VerificationResult(
                succeeded=True,
                evidence={
                    "target_state": target,
                    "observed_states": observed,
                    "job_outcome": job_outcome,
                    "strategy": plan.verification_strategy,
                },
            )
        time.sleep(JOBLESS_RETRY_INTERVAL)
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={
            "target_state": target,
            "observed_states": observed,
            "job_outcome": job_outcome,
            "reason": "read-back deadline reached without the target state",
            "strategy": plan.verification_strategy,
        },
    )


def _identity_readable(client: RedfishClient) -> dict[str, object] | None:
    try:
        return _system_identity(client)
    except RedfishError:
        return None


def _manager_reset_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """disconnect_reconnect_identity: reachability poll, then identity check.

    With a persisted job (202 reset) each call is ONE cheap poll: a device
    still down/booting or a job still running returns ``pending`` and the
    worker re-polls with lease renewals. A job-less reset (204) runs the
    bounded reconnect loop inside the call.
    """
    identity_before = _evidence_get(evidence, "identity_before")
    before = identity_before if isinstance(identity_before, Mapping) else {}
    job = result.device_job_id if result is not None else None
    deadline = time.monotonic() + _budget_remaining(plan, RECONNECT_CAP_SECONDS)
    while time.monotonic() < deadline:
        try:
            with _open_session(session) as client:
                if job is not None:
                    try:
                        job_read = _read_job(client, job)
                    except RedfishError as exc:
                        if _is_offline_code(exc.code) and plan.expected_disconnect:
                            # The manager is still restarting: known
                            # in-progress, never ambiguous (expected_disconnect).
                            return VerificationResult(
                                succeeded=False, pending=True, evidence={"job_state": "device_offline"}
                            )
                        return VerificationResult(
                            succeeded=False,
                            ambiguous=True,
                            error_code="ambiguous_result",
                            evidence={"reason": f"job unreadable ({exc.code})"},
                        )
                    if job_read.state == "running":
                        return VerificationResult(
                            succeeded=False, pending=True, evidence={"job_state": "running"}
                        )
                    if job_read.state == "failed":
                        return VerificationResult(
                            succeeded=False,
                            error_code="operation_failed",
                            evidence={"job_state": "failed"},
                        )
                    if job_read.state == "interrupted":
                        return VerificationResult(
                            succeeded=False,
                            ambiguous=True,
                            error_code="ambiguous_result",
                            evidence={"job_state": "interrupted"},
                        )
                    # completed / vanished (a reset wipes its own task): the
                    # identity check decides below.
                current = _identity_readable(client)
                if current is None:
                    if job is not None and plan.expected_disconnect:
                        return VerificationResult(
                            succeeded=False, pending=True, evidence={"job_state": "device_offline"}
                        )
                    time.sleep(JOBLESS_RETRY_INTERVAL)
                    continue
                same_identity = (
                    before.get("manager_uuid") is None
                    or before.get("manager_uuid") == current.get("manager_uuid")
                ) and (
                    before.get("system_serial") is None
                    or before.get("system_serial") == current.get("system_serial")
                )
                if not same_identity:
                    return VerificationResult(
                        succeeded=False,
                        error_code="operation_failed",
                        evidence={
                            "reason": "identity_changed_after_reset",
                            "identity_before": before,
                            "identity_after": current,
                        },
                    )
                if not before:
                    # No pre-reset identity evidence (crash recovery): the
                    # manager is back but identity cannot be PROVEN unchanged.
                    return VerificationResult(
                        succeeded=False,
                        ambiguous=True,
                        error_code="ambiguous_result",
                        evidence={
                            "reason": "no_pre_reset_identity_evidence",
                            "identity_after": current,
                        },
                    )
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "strategy": plan.verification_strategy,
                        "identity_verified": current,
                        "disconnect_observed": True,
                    },
                )
        except RedfishError as exc:
            if _is_offline_code(exc.code) and plan.expected_disconnect:
                if job is not None:
                    return VerificationResult(
                        succeeded=False, pending=True, evidence={"job_state": "device_offline"}
                    )
                time.sleep(JOBLESS_RETRY_INTERVAL)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"reconnect failed ({exc.code})"},
            )
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": "reconnect deadline reached without the manager returning"},
    )


def _support_bundle_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """artifact_manifest: manifest self-consistency + stored artifact proof.

    The stored-artifact proof (file row ready + encrypted + SHA-256) is merged
    into the evidence by the worker right after it persists the artifact;
    the adapter verifies the manifest lists every source included-with-hash
    or explicitly unavailable, and that the device still reports a readable
    SEL (a vanished SEL after the export makes the outcome unprovable).
    """
    manifest = _evidence_get(evidence, "artifact_manifest")
    if not isinstance(manifest, Mapping):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_artifact_manifest_in_evidence"},
        )
    sources = manifest.get("sources")
    unavailable = manifest.get("unavailable")
    if not isinstance(sources, list) or not sources:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "artifact_manifest_has_no_included_sources"},
        )
    for source in sources:
        if not isinstance(source, Mapping):
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={"reason": "artifact_manifest_source_unparseable"},
            )
        sha = source.get("sha256")
        if not (isinstance(sha, str) and len(sha) == 64):
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={"reason": "artifact_manifest_source_missing_hash", "source": source},
            )
    if isinstance(unavailable, list):
        for source in unavailable:
            if not isinstance(source, Mapping) or not isinstance(source.get("name"), str):
                return VerificationResult(
                    succeeded=False,
                    error_code="operation_failed",
                    evidence={"reason": "artifact_manifest_unavailable_source_unparseable"},
                )
    stored = _evidence_get(evidence, "artifact_stored")
    if not isinstance(stored, Mapping) or stored.get("status") != "ready":
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "artifact_not_stored_ready"},
        )
    expected_sha = _evidence_get(evidence, "artifact_sha256")
    if expected_sha is not None and stored.get("sha256") != expected_sha:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={"reason": "artifact_hash_mismatch"},
        )
    with _open_session(session) as client:
        try:
            sel = _find_sel_service(client)
        except RedfishError:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "sel_unreadable_during_verify"},
            )
        if sel is None:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "sel_missing_during_verify"},
            )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "artifact_stored": stored,
            "sources": len(sources),
            "unavailable": len(unavailable) if isinstance(unavailable, list) else 0,
        },
    )


def _mounted_media_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """mounted_media_readback: the slot reports the expected inserted state."""
    del result
    slot_id: object | None = None
    if plan.capability_key == "virtual_media.unmount":
        slot_id = plan.normalized_parameters.get("slot_id")
    else:
        slot_id = _evidence_get(evidence, "slot_id")
    if not isinstance(slot_id, str):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_slot_id_for_verification"},
        )
    with _open_session(session) as client:
        try:
            slot = _virtual_media_slot(client, slot_id)
        except RedfishError:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "slot_unreadable_during_verify"},
            )
        if slot is None:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "slot_missing_during_verify"},
            )
        if plan.capability_key == "virtual_media.mount":
            expected_image = _ctx_text(plan, "ticket")
            inserted = slot.get("inserted") is True
            image = slot.get("image")
            if not inserted:
                return VerificationResult(
                    succeeded=False,
                    ambiguous=True,
                    error_code="ambiguous_result",
                    evidence={"slot_id": slot_id, "reason": "media_not_inserted"},
                )
            if expected_image is not None and image != expected_image:
                return VerificationResult(
                    succeeded=False,
                    error_code="operation_failed",
                    evidence={
                        "slot_id": slot_id,
                        "reason": "inserted_image_does_not_match_ticket",
                    },
                )
            return VerificationResult(
                succeeded=True,
                evidence={
                    "slot_id": slot_id,
                    "inserted": True,
                    "image_matches_ticket": image == expected_image,
                    "strategy": plan.verification_strategy,
                },
            )
        # unmount
        if slot.get("inserted") is True:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"slot_id": slot_id, "reason": "media_still_inserted"},
            )
        revoked = _evidence_get(evidence, "ticket_revoked")
        return VerificationResult(
            succeeded=True,
            evidence={
                "slot_id": slot_id,
                "inserted": False,
                "ticket_revoked": isinstance(revoked, str),
                "strategy": plan.verification_strategy,
            },
        )


def _inventory_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """inventory_persisted (firmware.query / asset.refresh): re-read the same
    inventory surface and confirm the platform persistence proof is present."""
    del result
    persisted = _evidence_get(evidence, "inventory_persisted")
    if not isinstance(persisted, Mapping):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "inventory_not_persisted"},
        )
    with _open_session(session) as client:
        try:
            if plan.capability_key == "firmware.query":
                items = _firmware_inventory_items(client)
                expected = persisted.get("firmware_items")
                if isinstance(expected, list) and len(items) != len(expected):
                    return VerificationResult(
                        succeeded=False,
                        error_code="operation_failed",
                        evidence={"reason": "firmware_inventory_changed"},
                    )
                if not items:
                    return VerificationResult(
                        succeeded=False,
                        error_code="operation_failed",
                        evidence={"reason": "firmware_inventory_empty_on_readback"},
                    )
            else:
                system = _system(client)
                serial = _text_of(system, "SerialNumber")
                if serial != persisted.get("serial_number"):
                    return VerificationResult(
                        succeeded=False,
                        error_code="operation_failed",
                        evidence={"reason": "asset_serial_changed"},
                    )
        except RedfishError:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "inventory_unreadable_during_verify"},
            )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "persisted": persisted,
            "readback_consistent": True,
        },
    )


def _firmware_update_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """job_and_version_readback: job terminal + target version == expected.

    With a persisted job each call is ONE cheap poll: running/offline ->
    ``pending`` (worker re-polls with lease renewals). After the job is
    terminal (or for a job-less update) the target inventory version is read
    back and compared against the platform-declared package version.
    """
    file_ctx = _ctx_dict(plan, "file")
    expected_version = file_ctx.get("expected_version")
    if not isinstance(expected_version, str):
        raw = _evidence_get(evidence, "expected_version")
        expected_version = raw if isinstance(raw, str) else None
    target_id = plan.normalized_parameters.get("target_id")
    if not isinstance(target_id, str) or not expected_version:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_expected_version_or_target_in_context"},
        )
    job = result.device_job_id if result is not None else None
    deadline = time.monotonic() + _budget_remaining(plan, VERSION_READBACK_CAP_SECONDS)
    job_state_seen: str | None = None
    while time.monotonic() < deadline:
        try:
            with _open_session(session) as client:
                if job is not None:
                    try:
                        job_read = _read_job(client, job)
                    except RedfishError as exc:
                        if plan.expected_disconnect and _is_offline_code(exc.code):
                            return VerificationResult(
                                succeeded=False,
                                pending=True,
                                evidence={"job_state": "device_offline"},
                            )
                        return VerificationResult(
                            succeeded=False,
                            ambiguous=True,
                            error_code="ambiguous_result",
                            evidence={"reason": f"job unreadable ({exc.code})"},
                        )
                    job_state_seen = job_read.state
                    if job_read.state == "running":
                        return VerificationResult(
                            succeeded=False, pending=True, evidence={"job_state": "running"}
                        )
                    if job_read.state == "failed":
                        return VerificationResult(
                            succeeded=False,
                            error_code="operation_failed",
                            evidence={"job_state": "failed", "job_error": job_read.error_code},
                        )
                    if job_read.state == "interrupted":
                        return VerificationResult(
                            succeeded=False,
                            ambiguous=True,
                            error_code="ambiguous_result",
                            evidence={"job_state": "interrupted"},
                        )
                    # completed / vanished -> version read-back decides.
                items = _firmware_inventory_items(client)
                match = next((item for item in items if item.target == target_id), None)
                if match is not None and match.version == expected_version:
                    return VerificationResult(
                        succeeded=True,
                        evidence={
                            "strategy": plan.verification_strategy,
                            "target_id": target_id,
                            "expected_version": expected_version,
                            "readback_version": match.version,
                            "job_state": job_state_seen,
                        },
                    )
                time.sleep(JOBLESS_RETRY_INTERVAL)
        except RedfishError as exc:
            if plan.expected_disconnect and _is_offline_code(exc.code):
                if job is not None:
                    return VerificationResult(
                        succeeded=False, pending=True, evidence={"job_state": "device_offline"}
                    )
                time.sleep(JOBLESS_RETRY_INTERVAL)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"version read-back failed ({exc.code})"},
            )
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={
            "reason": "version read-back deadline reached",
            "target_id": target_id,
            "expected_version": expected_version,
        },
    )


def verify_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult | None,
) -> VerificationResult:
    """Read-back verification per the profile's verification strategy."""
    evidence: Mapping[str, object] = result.evidence if result is not None else {}
    key = plan.capability_key
    if key in ("power.on", "power.off", "power.cycle"):
        with _open_session(session) as client:
            return _power_verify_inner(client, plan, evidence, result)
    if key == "manager.reset":
        return _manager_reset_verify(session, plan, evidence, result)
    if key == "logs.support_bundle.collect":
        return _support_bundle_verify(session, plan, evidence, result)
    if key in ("virtual_media.mount", "virtual_media.unmount"):
        return _mounted_media_verify(session, plan, evidence, result)
    if key == "firmware.update":
        return _firmware_update_verify(session, plan, evidence, result)
    if key in ("firmware.query", "asset.refresh"):
        return _inventory_verify(session, plan, evidence, result)
    raise AdapterError(
        "unsupported_capability", f"通用 Redfish 适配器未实现操作验证 {key}", stage="verify"
    )


class RedfishOperationsMixin:
    """Operation protocol methods shared by the common adapter (and the M3T5
    vendor subclasses, which overlay vendor specifics per profile)."""

    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
        return plan_operation_method(snapshot, request)

    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult:
        return preflight_operation_method(session, plan)

    def execute_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        progress: OperationProgress,
    ) -> OperationResult:
        return execute_operation_method(session, plan, progress)

    def verify_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        result: OperationResult | None,
    ) -> VerificationResult:
        return verify_operation_method(session, plan, result)
