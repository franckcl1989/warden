"""Operation planning: pure plan generation from the persisted device snapshot.

docs/DEVICE_ADAPTERS.md §2.4 (``OperationPlan`` field list), API_CONTRACT.md
§6.1 (two-phase flow: the API builds previews ONLY from the persisted
DeviceSnapshot — no network contact), contracts/operations.json (per-operation
semantics are read exclusively from the generated profile registry).

``plan_operation`` mirrors the matched profile: it validates capability
support state and parameters, then returns the plan (impact/steps/timeout/
verification/cancel semantics). Nothing here touches the device, a database or
FastAPI (ARCHITECTURE.md §4); the caller assembles the ``DeviceSnapshot`` from
persisted rows. Step/impact wording comes from static Chinese maps keyed by
the profile's ``verification.strategy`` and requirement title — platform
wording only, never invented per-device behavior.

Error mapping contract (M2T4): capability unknown/unsupported ->
``unsupported_operation``; support state ``not_configured`` ->
``not_configured``; bad parameters -> ``validation_failed`` field=parameters.
Preview staleness (409) is NOT raised here — that is confirm-time drift logic
(application layer). Launch-channel profiles are allowed to be planned so the
preview is uniform; the task flow rejects ``channel != task`` at confirm
(API_CONTRACT.md §6.1, documented in the M2T4 report).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from app.domain.adapter import canonical_json
from app.domain.contracts import OperationProfile, Requirement
from app.domain.errors import AppError
from app.domain.roles import (
    OPERATION_EXECUTE_HIGH,
    OPERATION_EXECUTE_LOW,
    OPERATION_EXECUTE_MEDIUM,
)
from app.domain.schema_validation import validate_parameters
from app.generated.capabilities import REQUIREMENTS
from app.generated.operations import OPERATION_PROFILES

# Strategy -> Chinese impact description. Every key is one of the
# verification.strategy values present in contracts/operations.json; the
# fallback entry guards future strategies until their wording is added.
IMPACT_TEXTS: dict[str, str] = {
    "admin_state_readback": "修改目标端口的管理状态，该端口业务将按设置接通或中断",
    "artifact_manifest": "采集设备日志/诊断信息并加密保存，不改变设备运行状态",
    "artifact_parse_and_hash": "采集并加密保存设备当前配置，不改变设备运行状态",
    "certified_restore_reconnect_fingerprint": "将认证备份配置恢复到设备，设备将重启使配置生效，业务可能中断",
    "configuration_readback_and_test_trap": "写入平台指定的 SNMP 配置并发送测试告警，将改变设备 SNMP 设置",
    "device_job_status": "在目标磁盘上启动 S.M.A.R.T 检测任务，检测期间该磁盘负载会升高",
    "disconnect_reconnect_identity": "重启目标设备/管理卡，管理连接短暂中断，重启后需回连确认",
    "disconnect_reconnect_identity_uptime": "重启目标设备，管理连接将短暂中断，重启完成后需回连核对身份",
    "expected_disconnect": "优雅关闭目标设备电源，设备将下线且需人工重新开机",
    "inventory_persisted": "读取并保存只读清单/状态信息，不改变设备运行状态",
    "job_and_version_readback": "执行固件升级任务，设备可能重启并中断业务",
    "job_reconnect_version": "执行固件升级任务，NAS 将重启并中断存储服务一段时间",
    "launch_target_validation": "生成一次性的受控访问入口，不改变设备状态",
    "mounted_media_readback": "挂载/弹出虚拟介质，服务器将看到新的可引导介质",
    "observation_persisted": "读取并保存目标接口的光模块诊断信息，不影响业务",
    "poe_state_readback": "对目标 PoE 端口执行通电、断电或重启，受电设备供电将变化",
    "power_state_readback": "执行电源控制动作并改变系统电源状态",
    "power_transition_and_readback": "执行电源重启动作，系统将短暂中断后恢复开机",
    "reconnect_version_boot_image": "升级设备固件，设备将重启且业务中断较长时间",
    "ticket_and_handshake": "创建一次性终端连接，不改变设备状态",
}
DEFAULT_IMPACT = "执行目标设备操作，可能影响该设备上的业务"
DISCONNECT_SUFFIX = "。操作期间设备可能短暂失联"

# Strategy -> Chinese expected steps (one entry per strategy in the 39
# profiles). Static wording only; unknown strategies fall back to a generic
# three-step description.
STEP_TEXTS: dict[str, tuple[str, ...]] = {
    "admin_state_readback": ("读取目标端口当前管理状态", "设置端口管理状态", "回读端口管理状态确认结果"),
    "artifact_manifest": ("校验采集路径与存储空间", "采集设备日志/诊断信息并加密保存", "核对产物清单与完成标记"),
    "artifact_parse_and_hash": (
        "校验配置采集路径与存储空间",
        "采集并加密保存设备配置",
        "解析配置内容并计算哈希确认完整",
    ),
    "certified_restore_reconnect_fingerprint": (
        "核对设备身份、型号与固件大版本",
        "按认证策略恢复配置并等待设备重新上线",
        "回连核对设备身份与配置指纹",
    ),
    "configuration_readback_and_test_trap": (
        "读取设备当前 SNMP 配置",
        "写入目标 SNMP 配置",
        "回读配置并核验测试告警",
    ),
    "device_job_status": ("校验目标磁盘支持检测且无冲突作业", "启动 S.M.A.R.T 检测任务", "跟踪任务直至产出结果"),
    "disconnect_reconnect_identity": (
        "检查设备当前在线状态",
        "执行重启/复位并等待设备重新上线",
        "回连核对设备身份",
    ),
    "disconnect_reconnect_identity_uptime": (
        "检查设备当前运行状态",
        "执行重启并等待设备重新上线",
        "回连核对设备身份与重置后的运行时长",
    ),
    "expected_disconnect": ("检查设备当前运行与存储状态", "执行优雅关机并等待关机完成", "确认管理服务按预期停止"),
    "inventory_persisted": (
        "调用已认证的只读清单接口",
        "读取当前清单快照",
        "持久化清单并明确标注不可用项",
    ),
    "job_and_version_readback": (
        "校验固件包与目标设备元数据",
        "提交升级任务并跟踪进度",
        "核对任务结果与目标版本",
    ),
    "job_reconnect_version": ("校验固件包与设备版本元数据", "提交升级任务并等待设备重新上线", "核对任务结果与版本回读"),
    "launch_target_validation": ("校验管理入口来源", "生成不包含凭据的一次性启动描述符", "打开受控入口"),
    "mounted_media_readback": (
        "校验输入文件就绪与设备可达性",
        "插入或弹出目标虚拟介质",
        "回读介质身份确认达到预期",
    ),
    "observation_persisted": ("读取目标接口诊断数据", "按单位与时间戳保存诊断结果", "明确标注缺失字段并记录"),
    "poe_state_readback": (
        "读取目标端口当前 PoE 供电状态",
        "执行 PoE 通电、断电或重启",
        "回读 PoE 供电状态确认结果",
    ),
    "power_state_readback": ("读取系统当前电源状态", "执行电源控制动作", "回读电源状态确认达到预期"),
    "power_transition_and_readback": (
        "确认系统当前处于开机状态",
        "执行重启/强制重启动作",
        "回读系统电源状态确认恢复开机",
    ),
    "reconnect_version_boot_image": (
        "校验固件包元数据与设备兼容性",
        "传输并执行固件升级",
        "等待设备重新上线并核对版本与启动镜像",
    ),
    "ticket_and_handshake": ("校验连接前置条件", "签发一次性连接票据", "完成握手并进入受控会话"),
}
DEFAULT_STEPS: tuple[str, ...] = ("校验操作前置条件", "执行操作并等待完成", "回读验证并记录结果")

RISK_PERMISSIONS: dict[str, str] = {
    "low": OPERATION_EXECUTE_LOW,
    "medium": OPERATION_EXECUTE_MEDIUM,
    "high": OPERATION_EXECUTE_HIGH,
}


def execute_permission_for(risk_level: str) -> str:
    """The SECURITY.md §3.1 permission key required to run a risk level."""
    return RISK_PERMISSIONS.get(risk_level, OPERATION_EXECUTE_HIGH)


@dataclass(frozen=True)
class CapabilityView:
    """Persisted capability support state for one key (DATA_MODEL.md §4.3)."""

    capability_key: str
    support_state: str
    requirement_id: str
    discovery_method: str
    adapter_version: str
    reason_code: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class DeviceSnapshot:
    """Pure persisted-snapshot view used by planning (DEVICE_ADAPTERS.md §2.4).

    Assembled by the application layer from DB rows only; carrying ORM objects
    here would leak persistence into the pure plan. ``device_version`` is the
    devices.version optimistic-lock counter the confirm token binds.
    """

    device_id: uuid.UUID
    device_name: str
    device_type: str
    device_version: int
    adapter_key: str
    enabled: bool
    readiness: str
    capabilities: tuple[CapabilityView, ...] = ()


@dataclass(frozen=True)
class OperationRequest:
    """What the operator asks to plan: capability + validated parameter set."""

    capability_key: str
    parameters: dict[str, object]


@dataclass(frozen=True)
class OperationPlan:
    """The full plan per DEVICE_ADAPTERS.md §2.4 (mirrors one profile).

    ``runtime_context`` (M3T3) is platform-assembled execution material that
    is NEVER part of the plan hash: the worker fills it right before
    preflight/execute/verify with file rows, platform-issued device-pull
    ticket URLs, expected package metadata and the task deadline. It never
    contains credentials, file storage paths or ticket-URL bearer material
    beyond what the device itself must see.
    """

    requirement_id: str
    capability_key: str
    risk_level: str
    channel: str
    conflict_scope: str
    normalized_parameters: dict[str, object]
    impact: str
    steps: tuple[str, ...]
    timeout_seconds: int
    expected_disconnect: bool
    side_effect: bool
    cancel_policy: str
    verification_strategy: str
    verification_success: str
    verification_ambiguous: str
    parameter_hash: str
    plan_hash: str
    adapter_version: str
    runtime_context: dict[str, object] = field(default_factory=dict)


def _requirement_for(capability_key: str, device_type: str) -> Requirement | None:
    """The ACT requirement declaring ``capability_key`` for this device type.

    ``capability_key`` alone is ambiguous (interface.admin.set exists under
    CORE-ACT-02 and ACCESS-ACT-02), so resolution needs the snapshot's
    device_type; iteration is over sorted ids for determinism.
    """
    for requirement_id in sorted(REQUIREMENTS):
        requirement = REQUIREMENTS[requirement_id]
        if requirement.kind != "operation" or requirement.device_type != device_type:
            continue
        if any(key == capability_key for key, _risk in requirement.operations):
            return requirement
    return None


def _capability_row(snapshot: DeviceSnapshot, capability_key: str) -> CapabilityView | None:
    for row in snapshot.capabilities:
        if row.capability_key == capability_key:
            return row
    return None


def _unsupported_operation(requirement_id: str | None, capability_key: str) -> AppError:
    return AppError(
        "unsupported_operation",
        "该能力不承载可执行的人工操作或不被目标设备支持",
        details={"requirement_id": requirement_id, "capability_key": capability_key},
    )


def _plan_hash(profile: OperationProfile, parameter_hash: str) -> str:
    payload = {
        "requirement_id": profile.requirement_id,
        "capability_key": profile.key,
        "risk_level": profile.risk,
        "channel": profile.channel,
        "conflict_scope": profile.conflict_scope,
        "timeout_seconds": profile.timeout_seconds,
        "expected_disconnect": profile.expected_disconnect,
        "side_effect": profile.side_effect,
        "cancel_policy": profile.cancel_policy,
        "verification_strategy": profile.verification.strategy,
        "parameter_hash": parameter_hash,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def parameters_hash(parameters: dict[str, object]) -> str:
    """SHA-256 of the canonical normalized parameters (audit/evidence value)."""
    return hashlib.sha256(canonical_json(parameters).encode("utf-8")).hexdigest()


def _impact_for(profile: OperationProfile) -> str:
    base = IMPACT_TEXTS.get(profile.verification.strategy, DEFAULT_IMPACT)
    if profile.expected_disconnect:
        base += DISCONNECT_SUFFIX
    return base


def plan_operation(snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
    """Mirror the profile into an OperationPlan after support/parameter checks.

    Reads ONLY the persisted snapshot; never contacts the device
    (DEVICE_ADAPTERS.md §2.4: API 可在 2 秒目标内生成预览). Raises stable
    AppError codes: unsupported_operation (unknown/monitoring capability,
    device-type mismatch, unsupported support state, missing profile),
    not_configured (support state without required configuration) and
    validation_failed field=parameters (schema violations).
    """
    capability_key = request.capability_key
    requirement = _requirement_for(capability_key, snapshot.device_type)
    if requirement is None:
        raise _unsupported_operation(None, capability_key)
    profile = OPERATION_PROFILES.get(f"{requirement.id}:{capability_key}")
    if profile is None:
        raise _unsupported_operation(requirement.id, capability_key)
    row = _capability_row(snapshot, capability_key)
    if row is None:
        raise _unsupported_operation(requirement.id, capability_key)
    if row.requirement_id != requirement.id:
        raise _unsupported_operation(requirement.id, capability_key)
    if row.support_state == "unsupported":
        raise _unsupported_operation(requirement.id, capability_key)
    if row.support_state == "not_configured":
        missing = row.reason_code or row.detail or "required configuration"
        raise AppError(
            "not_configured",
            "该能力当前缺少必要配置，无法执行",
            details={"capability_key": capability_key, "missing": missing[:200]},
        )
    if row.support_state != "supported":
        raise _unsupported_operation(requirement.id, capability_key)
    errors = validate_parameters(request.parameters, profile.parameter_schema.raw)
    if errors:
        raise AppError("validation_failed", errors[0], details={"field": "parameters", "reason": errors[0]})
    parameter_hash = parameters_hash(request.parameters)
    return OperationPlan(
        requirement_id=requirement.id,
        capability_key=capability_key,
        risk_level=profile.risk,
        channel=profile.channel,
        conflict_scope=profile.conflict_scope,
        normalized_parameters=dict(request.parameters),
        impact=_impact_for(profile),
        steps=STEP_TEXTS.get(profile.verification.strategy, DEFAULT_STEPS),
        timeout_seconds=profile.timeout_seconds,
        expected_disconnect=profile.expected_disconnect,
        side_effect=profile.side_effect,
        cancel_policy=profile.cancel_policy,
        verification_strategy=profile.verification.strategy,
        verification_success=profile.verification.success,
        verification_ambiguous=profile.verification.ambiguous,
        parameter_hash=parameter_hash,
        plan_hash=_plan_hash(profile, parameter_hash),
        adapter_version=row.adapter_version,
    )
