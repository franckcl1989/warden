"""Huawei VRP CLI/SSH operations (M5T3) — CORE-ACT-01/02/04/05/07 +
ACCESS-ACT-01/02/03/05/06 over the VRP executor + SFTP.

Every operation follows the M3T3/M4T3 pattern: plan (shared domain planner)
-> preflight (read-only, before the dispatch fence) -> execute (after the
fence) -> verify (read-back per profile). Success is ONLY ever proven by
the profile's read-back strategy — never by a command reply alone
(DEVICE_ADAPTERS.md §9, HARDWARE_CERTIFICATION.md).

Honest [sim] framing: every command template is [sim] DSL (the registry
basis tag ``vrp-cli-sim-1``); template version + basis travel into every
evidence record. Operations run ONLY against devices whose SSH endpoint is
configured AND whose host-key fingerprint is pinned — automation never
first-connects (SECURITY.md §8 + M5T3 decision).

Binding rules enforced here (AGENTS.md):

- no free-text commands: only ``executor.run_template(key, params)``;
- restart NEVER auto-saves: the executor aborts when the device asks the
  save prompt (execution evidence/profiles: platform 不擅自保存);
- config.restore runs ONE certified strategy (full replace: SFTP upload of
  the Warden backup -> ``startup saved-configuration`` -> reboot) and NEVER
  guesses merge-vs-replace or save/restart behavior at runtime
  (contracts/operations.json prohibition);
- poe.port.set cycle proves the off transition (read-back inside the
  off window) and the final on;
- diagnostics/config/log artifacts carry completion evidence but never raw
  content in task evidence (SECURITY.md §9/§10: 明文日志/配置不进证据);
- identity/uptime/fingerprint read-backs drive disconnect/restore/firmware
  verification; task-side budgets cap every reconnect wait (the worker
  deadline from ``runtime_context[task_timeout_at]`` wins when smaller).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from collections.abc import Callable, Coroutine, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from app.domain.adapter import (
    AdapterError,
    AdapterTimeoutError,
    ArtifactDescriptor,
    ConnectionProfile,
    DeviceSession,
    OperationProgress,
    OperationResult,
    PreflightResult,
    ProbeStage,
    VerificationResult,
)
from app.domain.operation_plan import OperationPlan
from app.infrastructure.protocols.vrp import (
    PromptAction,
    VrpCliExecutor,
    VrpError,
    VrpSshConfig,
    canonical_fingerprint,
    config_fingerprint,
    config_parse_ok,
    normalize_config_text,
    parse_compare_configuration,
    parse_dir_free_kb,
    parse_interface_state,
    parse_poe_state,
    parse_startup,
    parse_version,
    template_evidence_for,
    vrp_major_version,
)
from app.infrastructure.protocols.vrp.errors import VrpTimeoutError
from app.infrastructure.protocols.vrp.executor import REBOOTED_MARKER, open_cli_executor

#: per-family verification budgets (documented defensive caps; the task
#: deadline from the runtime context always wins — DSM-mirror semantics).
VRP_RECONNECT_CAP_SECONDS = 120.0
VRP_RESTORE_CAP_SECONDS = 120.0
VRP_FIRMWARE_CAP_SECONDS = 120.0
VRP_POE_READBACK_CAP_SECONDS = 10.0
VRP_STATE_READBACK_CAP_SECONDS = 10.0
VRP_RETRY_INTERVAL_SECONDS = 1.0
#: an uptime below this bound proves the device restarted (DSL: uptime is
#: reset at boot; a switch that never went down keeps a large uptime).
VRP_UPTIME_RESET_MAX_SECONDS = 300

#: config-restore payload bound (decrypted backup bytes in the runtime
#: context; running configs are small — beyond this the task is refused).
RESTORE_CONTENT_MAX_BYTES = 8 * 1024 * 1024
#: firmware transfer bound per chunk stream (worker provides a chunk
#: iterator; transfers are bounded by the task deadline).
RESTORE_FILE_PREFIX = "warden-restore-"
IMAGE_FILE_PREFIX = "firmware-"
#: ctx keys the worker fills (worker/operation_executor.py + this module
#: must agree; runtime contexts never enter evidence/logs).
CTX_FILE = "file"
CTX_RESTORE = "restore"

SAVE_PROMPT_RE = re.compile(r"Save it now\? \[Y/N\]:\s*$")
CONTINUE_REBOOT_RE = re.compile(r"Continue\? \[Y/N\]:\s*$")

_SAVE_PROMPT_ABORT = PromptAction(
    pattern=SAVE_PROMPT_RE,
    abort=True,
    abort_code="validation_failed",
    abort_detail="检测到未保存配置提示（save prompt）；平台不自动保存，中止重启（不回答 Y）",
)
_CONTINUE_REBOOT = PromptAction(pattern=CONTINUE_REBOOT_RE, reply="y")
REBOOT_INTERACTIONS: tuple[PromptAction, ...] = (_SAVE_PROMPT_ABORT, _CONTINUE_REBOOT)


# ---------------------------------------------------------------------------
# evidence / context helpers


def _ctx_dict(plan: OperationPlan, key: str) -> dict[str, object]:
    value = plan.runtime_context.get(key)
    return value if isinstance(value, dict) else {}


def _evidence_get(evidence: Mapping[str, object] | None, key: str) -> object | None:
    """Evidence value tolerating flat and ``execution`` nesting (recovery)."""
    if not evidence:
        return None
    if key in evidence:
        return evidence[key]
    nested_value = evidence.get("execution")
    if isinstance(nested_value, Mapping):
        nested = cast(Mapping[str, object], nested_value)
        if key in nested:
            return nested[key]
    return None


def _ctx_value(ctx: dict[str, object], key: str) -> object | None:
    value = ctx.get(key)
    return value if value is not None else None


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


def _ssh_config(session: DeviceSession) -> VrpSshConfig:
    """The automation SSH target from a session (no first-connect allowed).

    Raises AdapterError ``not_configured`` when the SSH endpoint/credentials
    are missing and ``validation_failed`` for a malformed fingerprint.
    """
    return _ssh_config_from(session)


def _ssh_config_from(source: DeviceSession | ConnectionProfile) -> VrpSshConfig:
    """The SSH target of a session or probe profile (shared rules)."""
    config = dict(source.connection_config)
    credentials = dict(source.credentials)
    ssh = credentials.get("ssh")
    raw_port = config.get("ssh_port")
    if not isinstance(ssh, dict) or not ssh.get("username") or not ssh.get("password"):
        raise AdapterError(
            "not_configured",
            "设备未配置 SSH 账号（credentials.ssh）；CLI 操作需要 SSH 凭据",
            stage="connect",
        )
    if not isinstance(raw_port, int):
        raise AdapterError(
            "not_configured",
            "设备未配置 SSH 端口（connection_config.ssh_port）；CLI 操作需要 SSH 端口",
            stage="connect",
        )
    host = (
        source.resolved_ip
        if source.resolved_ip is not None
        else source.management_endpoint
    )
    raw_fingerprint = config.get("ssh_host_fingerprint")
    fingerprint: str | None = None
    if isinstance(raw_fingerprint, str) and raw_fingerprint:
        try:
            fingerprint = canonical_fingerprint(raw_fingerprint)
        except ValueError as exc:
            raise AdapterError(
                "validation_failed", f"SSH 主机指纹格式非法：{exc}", stage="connect"
            ) from exc
    return VrpSshConfig(
        host=str(host),
        port=raw_port,
        username=str(ssh["username"]),
        password=str(ssh["password"]),
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# async/sync boundary


def _run_sync(flow: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
    return asyncio.run(flow())


def _map_error(exc: BaseException) -> AdapterError:
    """Translate protocol-layer failures to adapter errors."""
    if isinstance(exc, AdapterError):
        return exc
    if isinstance(exc, VrpTimeoutError):
        return AdapterTimeoutError(str(exc.message))
    if isinstance(exc, VrpError):
        return AdapterError(exc.code, exc.message, stage=exc.stage)
    if isinstance(exc, asyncio.TimeoutError):
        return AdapterTimeoutError("操作等待超时")
    return AdapterError(
        "protocol_error", f"CLI 通道异常：{type(exc).__name__}", stage="execute"
    )


class _Boundary:
    """Run one coroutine and translate protocol errors at the boundary."""

    def __init__(self, stage: str) -> None:
        self.stage = stage

    def __call__(self, flow: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
        try:
            return _run_sync(flow)
        except BaseException as exc:  # noqa: BLE001 - boundary translation
            raise _map_error(exc) from exc


# ---------------------------------------------------------------------------
# shared async flows


@dataclass(frozen=True)
class DeviceIdentity:
    """The read-back identity of one device (display version, [sim] DSL)."""

    model: str
    vrp_version: str
    serial: str
    uptime_seconds: int | None


def _identity_from_parsed(
    parsed: Mapping[str, object], certified_models: tuple[str, ...]
) -> DeviceIdentity | None:
    model = parsed.get("model")
    vrp_version = parsed.get("vrp_version")
    serial = parsed.get("serial")
    if not (
        isinstance(model, str)
        and isinstance(vrp_version, str)
        and isinstance(serial, str)
        and model in certified_models
        and vrp_major_version(vrp_version) is not None
    ):
        return None
    uptime = parsed.get("uptime_seconds")
    return DeviceIdentity(
        model=model,
        vrp_version=vrp_version,
        serial=serial,
        uptime_seconds=uptime if isinstance(uptime, int) else None,
    )


async def _read_identity(
    executor: VrpCliExecutor, certified_models: tuple[str, ...]
) -> DeviceIdentity | None:
    """display version read-back (identity gate of every SSH op)."""
    result = await executor.run_template("display.version", {})
    if not result.completed:
        return None
    return _identity_from_parsed(parse_version(result.text), certified_models)


def _identity_evidence(identity: DeviceIdentity, template: str) -> dict[str, object]:
    return {
        "model": identity.model,
        "vrp_version": identity.vrp_version,
        "serial": identity.serial,
        "uptime_seconds": identity.uptime_seconds,
        "template": template,
    }


def _progress(progress: OperationProgress, percent: int, step: str | None) -> None:
    if progress is not None:
        progress(percent, step)


def _noop_progress(percent: int, step: str | None) -> None:
    del percent, step


async def _preflight_identity_gate(
    executor: VrpCliExecutor, certified_models: tuple[str, ...]
) -> PreflightResult | DeviceIdentity:
    """Identity + template-availability gate shared by every SSH operation.

    Returns the DeviceIdentity on success or a not-ok PreflightResult.
    """
    identity = await _read_identity(executor, certified_models)
    if identity is None:
        return PreflightResult(
            ok=False,
            error_code="validation_failed",
            detail=(
                "display version 回读未通过身份校验（型号不在认证集或 VRP 版本不可解析）；"
                "命令模板按型号选择（[sim] vrp-cli-sim-1）"
            ),
        )
    return identity


async def _open_executor(session: DeviceSession) -> VrpCliExecutor:
    config = _ssh_config(session)
    if config.fingerprint is None:
        raise AdapterError(
            "not_configured",
            "未固定 SSH 主机指纹（connection_config.ssh_host_fingerprint）；"
            "自动化连接拒绝首次信任（host_key_missing）",
            stage="connect",
        )
    try:
        return await open_cli_executor(config)
    except VrpError as exc:
        raise AdapterError(exc.code, exc.message, stage=exc.stage) from exc


async def _ssh_probe_stage_async(profile: ConnectionProfile) -> ProbeStage:
    """The probe's ``ssh`` stage: authenticate + enforce/capture the key.

    Pinned fingerprint: a mismatch fails the stage (host_key_mismatch,
    validation_failed). No fingerprint yet (first connect): the connect
    succeeds in CAPTURE mode and the stage reports the ACTUAL device key
    for the operator to pin — automation itself never trusts it.
    """
    config = _ssh_config_from(profile)
    accept_unpinned = config.fingerprint is None
    executor = await open_cli_executor(
        config, accept_unpinned=accept_unpinned, connect_wait_seconds=15.0
    )
    try:
        detail = "SSH 认证通过"
        if config.fingerprint is None:
            detail = (
                "SSH 首次连接（未固定主机指纹）：请将实际指纹 "
                f"{executor.actual_fingerprint or '未知'} 保存到 ssh_host_fingerprint — "
                "自动化操作在固定前会被拒绝（不首次信任）"
            )
        else:
            detail = f"SSH 主机指纹校验通过（{config.fingerprint}）"
        return ProbeStage(stage="ssh", ok=True, detail_safe=detail)
    finally:
        await executor.close()


def ssh_probe_stage(profile: ConnectionProfile) -> ProbeStage:
    """Sync probe-stage wrapper (boundary; never raises — stage result)."""
    try:
        return cast(ProbeStage, _Boundary("probe")(lambda: _ssh_probe_stage_async(profile)))
    except AdapterError as exc:
        return ProbeStage(
            stage="ssh",
            ok=False,
            error_code=exc.code,
            detail_safe=exc.message,
        )
    except Exception as exc:  # noqa: BLE001 - probe stages never raise
        return ProbeStage(
            stage="ssh",
            ok=False,
            error_code="network_unreachable",
            detail_safe=f"SSH 探测失败：{type(exc).__name__}",
        )


# ---------------------------------------------------------------------------
# preflight


async def _preflight_async(
    session: DeviceSession,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> PreflightResult:
    _progress(progress, 5, "建立 SSH 会话")
    executor = await _open_executor(session)
    try:
        key = plan.capability_key
        gate = await _preflight_identity_gate(executor, certified_models)
        if isinstance(gate, PreflightResult):
            return gate
        identity = gate
        _progress(progress, 30, "读取设备状态")

        def refused(detail: str) -> PreflightResult:
            return PreflightResult(ok=False, error_code="validation_failed", detail=detail)

        if key == "device.restart":
            dirty = await _compare_configuration(executor)
            if dirty is None:
                return PreflightResult(
                    ok=False,
                    error_code="protocol_error",
                    detail="compare configuration 无法解析（未保存配置状态不明，阻断重启）",
                )
            if dirty:
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail="设备存在未保存配置（compare configuration 检出）；平台不自动保存，请先保存或恢复配置",
                )
            return PreflightResult(ok=True)
        if key == "interface.admin.set":
            interface_id = plan.normalized_parameters.get("interface_id")
            if not isinstance(interface_id, str):
                return refused("缺少 interface_id 参数")
            try:
                result = await executor.run_template(
                    "display.interface", {"interface_id": interface_id}
                )
            except VrpError as exc:
                return refused(
                    f"设备拒绝读取接口（{exc.message[:120]}）：接口不存在或不受支持"
                )
            state = parse_interface_state(result.text)
            if not state["found"]:
                return refused("display interface 未返回可解析状态（接口不存在）")
            return PreflightResult(ok=True)
        if key == "poe.port.set":
            interface_id = plan.normalized_parameters.get("interface_id")
            if not isinstance(interface_id, str):
                return refused("缺少 interface_id 参数")
            try:
                result = await executor.run_template(
                    "display.poe", {"interface_id": interface_id}
                )
            except VrpError as exc:
                return refused(
                    f"设备拒绝读取 PoE 状态（{exc.message[:120]}）：非 PoE 端口或接口不存在"
                )
            if parse_poe_state(result.text) is None:
                return refused("display poe-power 未返回可解析状态")
            return PreflightResult(ok=True)
        if key in ("logs.diagnostic.collect", "logs.collect"):
            # File-storage readiness is checked by the worker pre-fence
            # (runtime context); the device side only needs the certified
            # template to answer — proven by the identity gate above.
            return PreflightResult(ok=True)
        if key == "config.backup":
            return PreflightResult(ok=True)
        if key == "config.restore":
            restore = _ctx_dict(plan, CTX_RESTORE)
            expected_model = _ctx_value(restore, "model")
            expected_vrp_major = _ctx_value(restore, "vrp_major")
            content_b64 = _ctx_value(restore, "content_b64")
            if not (
                isinstance(expected_model, str)
                and isinstance(expected_vrp_major, str)
                and isinstance(content_b64, str)
            ):
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未提供备份文件元数据（模型/VRP 大版本/内容）；无法执行恢复",
                )
            try:
                content = base64.b64decode(content_b64, validate=True)
            except ValueError:
                return refused("备份内容无法解码（base64 损坏）")
            if len(content) > RESTORE_CONTENT_MAX_BYTES:
                return refused(f"备份内容超过 {RESTORE_CONTENT_MAX_BYTES // 1024 // 1024} MiB 上限")
            parse_ok, reason = config_parse_ok(content.decode("utf-8", errors="replace"))
            if not parse_ok:
                return refused(f"备份配置未通过解析检查：{reason}")
            if identity.model != expected_model:
                return refused(
                    f"备份型号（{expected_model}）与设备型号（{identity.model}）不匹配"
                )
            major = vrp_major_version(identity.vrp_version)
            if major is None or major != expected_vrp_major:
                return refused(
                    f"备份 VRP 大版本（{expected_vrp_major}）与设备 VRP（{identity.vrp_version}）不匹配"
                )
            return PreflightResult(ok=True)
        if key == "firmware.update":
            file_ctx = _ctx_dict(plan, CTX_FILE)
            expected_version = _ctx_value(file_ctx, "expected_version")
            expected_size = _ctx_value(file_ctx, "size_bytes")
            if not isinstance(expected_version, str) or not expected_version:
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未提供固件包目标版本（元数据不可用），无法执行升级",
                )
            dirty = await _compare_configuration(executor)
            if dirty is None:
                return PreflightResult(
                    ok=False,
                    error_code="protocol_error",
                    detail="compare configuration 无法解析（未保存配置状态不明，阻断升级）",
                )
            if dirty:
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail="设备存在未保存配置（profile 前置条件）；平台不自动保存，请先保存或恢复配置",
                )
            free_kb = parse_dir_free_kb((await executor.run_template("dir.flash", {})).text)
            if free_kb is None:
                return PreflightResult(
                    ok=False,
                    error_code="protocol_error",
                    detail="dir flash: 无法解析（空间检查未完成）",
                )
            if isinstance(expected_size, int) and expected_size > free_kb * 1024:
                return refused(
                    f"flash 空间不足（需要 {expected_size} 字节，可用 {free_kb} KB）"
                )
            startup = parse_startup((await executor.run_template("display.startup", {})).text)
            if startup["boot_image"] is None:
                return PreflightResult(
                    ok=False,
                    error_code="protocol_error",
                    detail="display startup 无法解析启动镜像（boot-variable 检查未完成）",
                )
            return PreflightResult(ok=True)
        return PreflightResult(
            ok=False,
            error_code="unsupported_capability",
            detail=f"Huawei VRP 适配器未实现操作 {key}",
        )
    finally:
        await executor.close()


async def _compare_configuration(executor: VrpCliExecutor) -> bool | None:
    result = await executor.run_template("compare.configuration", {})
    if not result.completed:
        return None
    return parse_compare_configuration(result.text)


def preflight_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
) -> PreflightResult:
    return cast(
        PreflightResult,
        _Boundary("preflight")(
            lambda: _preflight_async(session, plan, certified_models, _noop_progress)
        ),
    )


# ---------------------------------------------------------------------------
# execute


async def _execute_async(
    session: DeviceSession,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    key = plan.capability_key
    executor = await _open_executor(session)
    try:
        if key == "device.restart":
            return await _restart_execute(executor, plan, certified_models, progress)
        if key == "interface.admin.set":
            return await _interface_execute(executor, plan, progress)
        if key == "poe.port.set":
            return await _poe_execute(executor, plan, progress)
        if key in ("logs.diagnostic.collect", "logs.collect"):
            return await _log_execute(executor, plan, certified_models, progress, key)
        if key == "config.backup":
            return await _config_backup_execute(executor, plan, certified_models, progress)
        if key == "config.restore":
            return await _config_restore_execute(executor, plan, certified_models, progress)
        if key == "firmware.update":
            return await _firmware_execute(executor, plan, certified_models, progress)
        raise AdapterError(
            "unsupported_capability", f"Huawei VRP 适配器未实现操作 {key}", stage="execute"
        )
    finally:
        await executor.close()


async def _restart_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    _progress(progress, 30, "记录重启前身份")
    before = await _read_identity(executor, certified_models)
    _progress(progress, 50, "执行 reboot（不自动保存）")
    result = await executor.run_template("reboot", {}, interactions=REBOOT_INTERACTIONS)
    evidence: dict[str, object] = {
        "action": "reboot",
        "template": template_evidence_for("reboot"),
        "save_prompt_answered": False,
    }
    if before is not None:
        evidence["identity_before"] = _identity_evidence(before, template_evidence_for("display.version"))
    if result.closed and result.completed:
        evidence["session_closed"] = True
        evidence["reboot_marker"] = REBOOTED_MARKER
        _progress(progress, 90, "重启已接受，等待回连验证")
        return OperationResult(
            ok=True, evidence=evidence, disconnected=True, device_job_id=None
        )
    raise AdapterError(
        "operation_failed",
        "设备未执行重启（会话未断开且无重启标记）",
        stage="execute",
    )


async def _interface_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    interface_id = plan.normalized_parameters.get("interface_id")
    enabled = plan.normalized_parameters.get("enabled")
    if not isinstance(interface_id, str) or not isinstance(enabled, bool):
        raise AdapterError("validation_failed", "缺少 interface_id/enabled 参数", stage="execute")
    template_key = "interface.undo_shutdown" if enabled else "interface.shutdown"
    _progress(progress, 40, f"设置接口管理状态（enabled={enabled}）")
    await executor.run_template(template_key, {"interface_id": interface_id})
    _progress(progress, 80, "接口命令已下发")
    return OperationResult(
        ok=True,
        evidence={
            "interface_id": interface_id,
            "enabled": enabled,
            "template": template_evidence_for(template_key),
        },
    )


async def _poe_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    interface_id = plan.normalized_parameters.get("interface_id")
    mode = plan.normalized_parameters.get("mode")
    if not isinstance(interface_id, str) or mode not in ("on", "off", "cycle"):
        raise AdapterError("validation_failed", "缺少 interface_id/mode 参数", stage="execute")
    off_seconds = plan.normalized_parameters.get("off_seconds")
    if mode == "cycle" and (not isinstance(off_seconds, int) or not 5 <= off_seconds <= 60):
        raise AdapterError(
            "validation_failed", "cycle 模式需要 off_seconds（5-60 秒）", stage="execute"
        )
    transitions: list[dict[str, object]] = []

    async def apply_and_read(state: str) -> None:
        template_key = "interface.poe_on" if state == "on" else "interface.poe_off"
        await executor.run_template(template_key, {"interface_id": interface_id})
        # The command is accepted but the STATE may take a moment to flip
        # (the poe_delayed knob models a slow power controller): read back
        # within a bounded window until the state matches; unproven stays
        # ambiguous — never a guessed success.
        deadline = datetime.now(UTC).timestamp() + VRP_POE_READBACK_CAP_SECONDS
        seen: str | None = None
        while True:
            readback = await executor.run_template("display.poe", {"interface_id": interface_id})
            seen = parse_poe_state(readback.text)
            if seen == state:
                break
            if datetime.now(UTC).timestamp() >= deadline:
                raise AdapterError(
                    "ambiguous_result",
                    f"PoE 状态在时限内未到达 {state}（回读 {seen}）；结果不明",
                    stage="execute",
                )
            await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
        transitions.append(
            {
                "state": state,
                "readback": seen,
                "template": template_evidence_for(template_key),
            }
        )

    _progress(progress, 25, "读取端口当前 PoE 状态")
    if mode == "on":
        await apply_and_read("on")
    elif mode == "off":
        await apply_and_read("off")
    else:
        assert isinstance(off_seconds, int)  # validated above (cycle)
        _progress(progress, 30, "cycle：先断电")
        await apply_and_read("off")
        _progress(progress, 45, f"保持断电 {off_seconds} 秒（off_seconds）")
        await asyncio.sleep(off_seconds)
        _progress(progress, 70, "cycle：恢复供电")
        await apply_and_read("on")
    _progress(progress, 90, "PoE 状态回读一致")
    return OperationResult(
        ok=True,
        evidence={
            "interface_id": interface_id,
            "mode": mode,
            "off_seconds": off_seconds,
            "poe_transitions": transitions,
        },
    )


def _artifact_evidence(
    content: bytes,
    *,
    kind: str,
    model: str,
    vrp_version: str,
    template: str,
) -> dict[str, object]:
    return {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        "artifact_kind": kind,
        "model": model,
        "vrp_version": vrp_version,
        "template": template,
    }


async def _log_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
    key: str,
) -> OperationResult:
    if key == "logs.diagnostic.collect":
        template_key = "display.diagnostic_information"
        filename = "vrp-diagnostic-information.log"
        mime = "text/plain"
    else:
        template_key = "display.logbuffer"
        filename = "vrp-logbuffer.log"
        mime = "text/plain"
    _progress(progress, 20, "执行诊断/日志采集命令")
    result = await executor.run_template(template_key, {})
    if not result.completed:
        raise AdapterError(
            "ambiguous_result",
            "采集命令未到达完成标记（会话中断）；产物不完整",
            stage="execute",
        )
    content = result.text.encode("utf-8")
    identity = await _read_identity(executor, certified_models)
    model = identity.model if identity is not None else ""
    vrp = identity.vrp_version if identity is not None else ""
    evidence = _artifact_evidence(
        content,
        kind=key,
        model=model,
        vrp_version=vrp,
        template=template_evidence_for(template_key),
    )
    evidence["completion_marker"] = "prompt_returned"
    manifest: dict[str, object] = {
        "format": "vrp-cli-output",
        "model": model,
        "vrp_version": vrp,
        "source": template_key,
        "sha256": evidence["artifact_sha256"],
        "lines": len(result.text.splitlines()),
        "completion": "prompt_returned",
    }
    artifact = ArtifactDescriptor(
        file_type="operation_log",
        filename=filename,
        content_bytes=content,
        mime_type=mime,
        manifest=manifest,
    )
    _progress(progress, 90, "采集产物已就绪")
    return OperationResult(ok=True, evidence=evidence, artifacts=(artifact,))


async def _config_backup_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    del plan
    _progress(progress, 20, "导出运行配置")
    result = await executor.run_template("display.current_configuration", {})
    if not result.completed:
        raise AdapterError(
            "ambiguous_result",
            "配置导出未到达完成标记（会话中断）；不生成备份",
            stage="execute",
        )
    parse_ok, reason = config_parse_ok(result.text)
    if not parse_ok:
        raise AdapterError(
            "protocol_error",
            f"运行配置未通过解析检查（{reason}）；不生成备份",
            stage="execute",
        )
    content = normalize_config_text(result.text).encode("utf-8")
    identity = await _read_identity(executor, certified_models)
    evidence: dict[str, object] = {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        "artifact_kind": "config_backup",
        "parse_ok": True,
        "template": template_evidence_for("display.current_configuration"),
    }
    manifest: dict[str, object] = {
        "format": "vrp-running-config",
        "parse_ok": True,
        "sha256": evidence["artifact_sha256"],
    }
    if identity is not None:
        evidence["model"] = identity.model
        evidence["vrp_version"] = identity.vrp_version
        manifest["model"] = identity.model
        manifest["vrp_version"] = identity.vrp_version
    else:
        raise AdapterError(
            "protocol_error", "配置导出的身份回读不可用；不生成无法归属的备份", stage="execute"
        )
    artifact = ArtifactDescriptor(
        file_type="config_backup",
        filename="vrp-running-config.cfg",
        content_bytes=content,
        mime_type="text/plain",
        manifest=manifest,
    )
    _progress(progress, 90, "配置备份已就绪")
    return OperationResult(ok=True, evidence=evidence, artifacts=(artifact,))


def _restore_file_name(plan: OperationPlan) -> str:
    raw = _ctx_value(_ctx_dict(plan, CTX_RESTORE), "file_id")
    if isinstance(raw, str):
        hexid = re.sub(r"[^0-9a-f]", "", raw)[:8]
        if len(hexid) == 8:
            return f"{RESTORE_FILE_PREFIX}{hexid}.cfg"
    return f"{RESTORE_FILE_PREFIX}00000000.cfg"


async def _config_restore_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    del certified_models
    restore = _ctx_dict(plan, CTX_RESTORE)
    content_b64 = _ctx_value(restore, "content_b64")
    expected_fingerprint = _ctx_value(restore, "sha256")
    if not isinstance(content_b64, str) or not isinstance(expected_fingerprint, str):
        raise AdapterError(
            "not_configured",
            "平台未提供备份内容/指纹（runtime restore ctx）；无法执行恢复",
            stage="execute",
        )
    try:
        content = base64.b64decode(content_b64, validate=True)
    except ValueError as exc:
        raise AdapterError(
            "validation_failed", "备份内容无法解码（base64 损坏）", stage="execute"
        ) from exc
    if len(content) > RESTORE_CONTENT_MAX_BYTES:
        raise AdapterError(
            "validation_failed",
            f"备份内容超过 {RESTORE_CONTENT_MAX_BYTES // 1024 // 1024} MiB 上限",
            stage="execute",
        )
    parse_ok, reason = config_parse_ok(content.decode("utf-8", errors="replace"))
    if not parse_ok:
        raise AdapterError(
            "validation_failed", f"备份配置未通过解析检查：{reason}", stage="execute"
        )
    file_name = _restore_file_name(plan)
    _progress(progress, 30, "上传备份配置到 flash（SFTP，全量替换策略）")
    chunks = [
        content[index : index + 64 * 1024] for index in range(0, len(content), 64 * 1024)
    ]
    await executor.sftp_put_bytes(file_name, chunks)
    _progress(progress, 55, "设置启动配置文件")
    await executor.run_template(
        "startup.saved_configuration", {"file_name": file_name}
    )
    _progress(progress, 75, "重启使配置生效")
    result = await executor.run_template("reboot", {}, interactions=REBOOT_INTERACTIONS)
    if not (result.closed and result.completed):
        raise AdapterError(
            "operation_failed",
            "配置恢复重启未被设备接受（会话未断开）",
            stage="execute",
        )
    _progress(progress, 90, "恢复已接受，等待回连指纹校验")
    return OperationResult(
        ok=True,
        disconnected=True,
        evidence={
            "restore_file": file_name,
            "certified_strategy": "full_replace_via_startup_config_and_reboot",
            "expected_fingerprint": expected_fingerprint,
            "restore_bytes": len(content),
            "template": template_evidence_for("startup.saved_configuration"),
        },
    )


def _image_slug(version: str) -> str:
    """Flash-safe file name slug of the expected version.

    The version comes from the platform image metadata (JSON header); every
    character must already be file-name-safe — anything else is refused
    (allowlist defense: the slug feeds a CLI command line).
    """
    if re.fullmatch(r"[A-Za-z0-9._-]+", version) is None:
        raise AdapterError(
            "validation_failed",
            f"固件目标版本 {version!r} 含不允许的字符，无法构成 flash 文件名",
            stage="execute",
        )
    return version


async def _firmware_execute(
    executor: VrpCliExecutor,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    del certified_models
    file_ctx = _ctx_dict(plan, CTX_FILE)
    expected_version = _ctx_value(file_ctx, "expected_version")
    expected_sha256 = _ctx_value(file_ctx, "sha256")
    raw_stream = file_ctx.get("stream")
    if not isinstance(expected_version, str) or not isinstance(expected_sha256, str):
        raise AdapterError(
            "not_configured",
            "平台未提供固件包元数据（目标版本/散列）；无法执行升级",
            stage="execute",
        )
    if not callable(raw_stream):
        raise AdapterError(
            "not_configured",
            "平台未提供固件内容流（runtime file ctx.stream）；无法执行升级",
            stage="execute",
        )
    stream: Callable[[], Iterable[bytes]] = cast(
        Callable[[], Iterable[bytes]], raw_stream
    )
    image_name = f"{IMAGE_FILE_PREFIX}{_image_slug(expected_version)}.bin"
    _progress(progress, 20, "检查 flash 空间")
    free_kb = parse_dir_free_kb((await executor.run_template("dir.flash", {})).text)
    if free_kb is None:
        raise AdapterError("protocol_error", "dir flash: 无法解析（空间检查失败）", stage="execute")
    _progress(progress, 35, "上传固件镜像（SFTP）")
    await executor.sftp_put_bytes(image_name, stream())
    _progress(progress, 65, "设置启动系统软件")
    await executor.run_template("startup.system_software", {"file_name": image_name})
    startup = parse_startup((await executor.run_template("display.startup", {})).text)
    if startup["boot_image"] != image_name:
        raise AdapterError(
            "protocol_error",
            f"display startup 启动镜像回读不一致（期望 {image_name}）",
            stage="execute",
        )
    _progress(progress, 80, "重启应用新镜像")
    result = await executor.run_template("reboot", {}, interactions=REBOOT_INTERACTIONS)
    if not (result.closed and result.completed):
        raise AdapterError(
            "operation_failed",
            "固件升级重启未被设备接受（会话未断开）",
            stage="execute",
        )
    _progress(progress, 90, "升级已接受，等待版本回读")
    return OperationResult(
        ok=True,
        disconnected=True,
        evidence={
            "image_file": image_name,
            "expected_version": expected_version,
            "expected_sha256": expected_sha256,
            "template": template_evidence_for("startup.system_software"),
        },
    )


def execute_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    certified_models: tuple[str, ...],
    progress: OperationProgress,
) -> OperationResult:
    return cast(
        OperationResult,
        _Boundary("execute")(
            lambda: _execute_async(session, plan, certified_models, progress)
        ),
    )


# ---------------------------------------------------------------------------
# verify


async def _verify_async(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult | None,
    certified_models: tuple[str, ...],
) -> VerificationResult:
    key = plan.capability_key
    evidence = dict(result.evidence) if result is not None else {}
    if key == "device.restart":
        return await _restart_verify(session, plan, evidence, certified_models)
    if key == "interface.admin.set":
        return await _interface_verify(session, plan, evidence)
    if key == "poe.port.set":
        return await _poe_verify(session, plan, evidence)
    if key in ("logs.diagnostic.collect", "logs.collect", "config.backup"):
        return _artifact_verify(plan, evidence, key)
    if key == "config.restore":
        return await _restore_verify(session, plan, evidence, certified_models)
    if key == "firmware.update":
        return await _firmware_verify(session, plan, evidence, certified_models)
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": f"unsupported verify for {key}"},
    )


async def _restart_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    certified_models: tuple[str, ...],
) -> VerificationResult:
    """disconnect_reconnect_identity_uptime.

    Success = an offline window was observed, the device reconnects with the
    SAME model+serial and its uptime reset (< VRP_UPTIME_RESET_MAX_SECONDS).
    """
    identity_before = _evidence_get(evidence, "identity_before")
    before = identity_before if isinstance(identity_before, Mapping) else {}
    before_serial = before.get("serial")
    before_model = before.get("model")
    saw_offline = False
    budget = _budget_remaining(plan, VRP_RECONNECT_CAP_SECONDS)
    deadline = datetime.now(UTC).timestamp() + budget
    while True:
        try:
            executor = await _open_executor(session)
        except AdapterError as exc:
            if exc.code == "network_unreachable":
                saw_offline = True
                if datetime.now(UTC).timestamp() >= deadline:
                    break
                await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"reconnect failed ({exc.code})"},
            )
        try:
            identity = await _read_identity(executor, certified_models)
            if identity is not None:
                if (
                    isinstance(before_model, str)
                    and isinstance(before_serial, str)
                    and (identity.model != before_model or identity.serial != before_serial)
                ):
                    return VerificationResult(
                        succeeded=False,
                        error_code="operation_failed",
                        evidence={
                            "reason": "identity_changed_after_restart",
                            "identity_before": before,
                            "identity_after": _identity_evidence(
                                identity, template_evidence_for("display.version")
                            ),
                        },
                    )
                if (
                    identity.uptime_seconds is not None
                    and identity.uptime_seconds < VRP_UPTIME_RESET_MAX_SECONDS
                ):
                    if not saw_offline:
                        await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                        continue
                    return VerificationResult(
                        succeeded=True,
                        evidence={
                            "strategy": plan.verification_strategy,
                            "identity_verified": _identity_evidence(
                                identity, template_evidence_for("display.version")
                            ),
                            "uptime_reset_seconds": identity.uptime_seconds,
                            "disconnect_observed": True,
                        },
                    )
                # Device is up but the uptime did not reset: keep waiting.
                if datetime.now(UTC).timestamp() >= deadline:
                    break
                await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                continue
        finally:
            await executor.close()
        if datetime.now(UTC).timestamp() >= deadline:
            break
        await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
    if not saw_offline:
        reason = "no offline window observed — the restart cannot be proven"
    else:
        reason = "reconnect deadline reached without the switch returning"
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": reason},
    )


async def _state_readback(
    session: DeviceSession, plan: OperationPlan, template_key: str, params: dict[str, str]
) -> str | None:
    """One read-back attempt (fresh session); None when unreachable."""
    try:
        executor = await _open_executor(session)
    except AdapterError as exc:
        if exc.code == "network_unreachable":
            return None
        raise
    try:
        result = await executor.run_template(template_key, params)
        return result.text if result.completed else None
    finally:
        await executor.close()


async def _interface_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """admin_state_readback: readback equals the requested admin state."""
    interface_id = plan.normalized_parameters.get("interface_id")
    enabled = plan.normalized_parameters.get("enabled")
    if not isinstance(interface_id, str) or not isinstance(enabled, bool):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "missing_parameters_in_plan"},
        )
    budget = _budget_remaining(plan, VRP_STATE_READBACK_CAP_SECONDS)
    deadline = datetime.now(UTC).timestamp() + budget
    while True:
        text = await _state_readback(
            session, plan, "display.interface", {"interface_id": interface_id}
        )
        if text is not None:
            state = parse_interface_state(text)
            if not state["found"]:
                return VerificationResult(
                    succeeded=False,
                    ambiguous=True,
                    error_code="ambiguous_result",
                    evidence={"reason": "interface_state_unreadable"},
                )
            wanted = "up" if enabled else "down"
            if state["admin"] == wanted:
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "strategy": plan.verification_strategy,
                        "interface_id": interface_id,
                        "admin_state_readback": state["admin"],
                    },
                )
            # Definitively NOT the requested state: failed (readable).
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "interface_id": interface_id,
                    "requested": wanted,
                    "admin_state_readback": state["admin"],
                },
            )
        if datetime.now(UTC).timestamp() >= deadline:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "admin_state_unreadable_within_budget"},
            )
        await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)


async def _poe_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """poe_state_readback: final state matches; cycle additionally requires
    the off transition recorded in the execution evidence."""
    interface_id = plan.normalized_parameters.get("interface_id")
    mode = plan.normalized_parameters.get("mode")
    if not isinstance(interface_id, str) or mode not in ("on", "off", "cycle"):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "missing_parameters_in_plan"},
        )
    wanted = "on"
    if mode == "cycle":
        transitions = _evidence_get(evidence, "poe_transitions")
        if not isinstance(transitions, list) or not transitions:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "no_poe_transition_evidence"},
            )
        states = [item.get("readback") for item in transitions if isinstance(item, Mapping)]
        if states != ["off", "on"]:
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "reason": "cycle_off_transition_not_proven",
                    "readbacks": states,
                },
            )
    elif mode == "off":
        wanted = "off"
    budget = _budget_remaining(plan, VRP_POE_READBACK_CAP_SECONDS)
    deadline = datetime.now(UTC).timestamp() + budget
    while True:
        text = await _state_readback(session, plan, "display.poe", {"interface_id": interface_id})
        if text is not None:
            seen = parse_poe_state(text)
            if seen is None:
                return VerificationResult(
                    succeeded=False,
                    ambiguous=True,
                    error_code="ambiguous_result",
                    evidence={"reason": "poe_state_unreadable"},
                )
            if seen == wanted:
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "strategy": plan.verification_strategy,
                        "interface_id": interface_id,
                        "mode": mode,
                        "poe_state_readback": seen,
                        "poe_transitions": transitions if mode == "cycle" else None,
                    },
                )
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "interface_id": interface_id,
                    "requested": wanted,
                    "poe_state_readback": seen,
                },
            )
        if datetime.now(UTC).timestamp() >= deadline:
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "poe_state_unreadable_within_budget"},
            )
        await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)


def _artifact_verify(
    plan: OperationPlan, evidence: Mapping[str, object], key: str
) -> VerificationResult:
    """artifact_manifest / artifact_parse_and_hash: completion marker (log/
    diagnostic streams) or parse gate (config backup) + platform-stored
    artifact hash matches the execution hash."""
    if key == "config.backup":
        if _evidence_get(evidence, "parse_ok") is not True:
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={"reason": "config_parse_check_failed"},
            )
    elif _evidence_get(evidence, "completion_marker") != "prompt_returned":
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_completion_marker"},
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
    if not isinstance(expected_sha, str) or stored.get("sha256") != expected_sha:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={"reason": "artifact_hash_mismatch"},
        )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "artifact_stored": stored,
            "completion_marker": "prompt_returned",
        },
    )


async def _restore_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    certified_models: tuple[str, ...],
) -> VerificationResult:
    """certified_restore_reconnect_fingerprint: reconnect, same identity,
    and the normalized running-config fingerprint equals the backup's."""
    restore = _ctx_dict(plan, CTX_RESTORE)
    expected_fingerprint = _ctx_value(restore, "sha256")
    if not isinstance(expected_fingerprint, str):
        raw = _evidence_get(evidence, "expected_fingerprint")
        expected_fingerprint = raw if isinstance(raw, str) else None
    if not isinstance(expected_fingerprint, str) or len(expected_fingerprint) != 64:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_expected_fingerprint"},
        )
    budget = _budget_remaining(plan, VRP_RESTORE_CAP_SECONDS)
    deadline = datetime.now(UTC).timestamp() + budget
    while True:
        try:
            executor = await _open_executor(session)
        except AdapterError as exc:
            if exc.code == "network_unreachable":
                if datetime.now(UTC).timestamp() >= deadline:
                    break
                await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"reconnect failed ({exc.code})"},
            )
        try:
            result = await executor.run_template("display.current_configuration", {})
            if not result.completed:
                continue
            identity = await _read_identity(executor, certified_models)
            parse_ok, _reason = config_parse_ok(result.text)
            fingerprint = config_fingerprint(result.text)
            if identity is not None:
                actual = {"model": identity.model, "serial": identity.serial}
                if parse_ok and fingerprint == expected_fingerprint:
                    return VerificationResult(
                        succeeded=True,
                        evidence={
                            "strategy": plan.verification_strategy,
                            "config_fingerprint": fingerprint,
                            "identity_verified": actual,
                            "template": template_evidence_for(
                                "display.current_configuration"
                            ),
                        },
                    )
                return VerificationResult(
                    succeeded=False,
                    error_code="operation_failed",
                    evidence={
                        "reason": (
                            "config_fingerprint_mismatch"
                            if parse_ok
                            else "restored_config_unparseable"
                        ),
                        "expected_fingerprint": expected_fingerprint,
                        "actual_fingerprint": fingerprint,
                    },
                )
        finally:
            await executor.close()
        if datetime.now(UTC).timestamp() >= deadline:
            break
        await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": "restore_reconnect_deadline_reached"},
    )


async def _firmware_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    certified_models: tuple[str, ...],
) -> VerificationResult:
    """reconnect_version_boot_image: reconnect, same identity, reported
    version == package target and boot image == uploaded file."""
    expected_version = _evidence_get(evidence, "expected_version")
    expected_image = _evidence_get(evidence, "image_file")
    if not isinstance(expected_version, str) or not isinstance(expected_image, str):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_expected_version_in_evidence"},
        )
    budget = _budget_remaining(plan, VRP_FIRMWARE_CAP_SECONDS)
    deadline = datetime.now(UTC).timestamp() + budget
    while True:
        try:
            executor = await _open_executor(session)
        except AdapterError as exc:
            if exc.code == "network_unreachable":
                if datetime.now(UTC).timestamp() >= deadline:
                    break
                await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"reconnect failed ({exc.code})"},
            )
        try:
            version_result = await executor.run_template("display.version", {})
            startup_result = await executor.run_template("display.startup", {})
            if not (version_result.completed and startup_result.completed):
                continue
            parsed = parse_version(version_result.text)
            identity = _identity_from_parsed(parsed, certified_models)
            boot = parse_startup(startup_result.text)
            if identity is None:
                if datetime.now(UTC).timestamp() >= deadline:
                    break
                await asyncio.sleep(VRP_RETRY_INTERVAL_SECONDS)
                continue
            if identity.vrp_version == expected_version and boot["boot_image"] == expected_image:
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "strategy": plan.verification_strategy,
                        "version_readback": identity.vrp_version,
                        "boot_image_readback": boot["boot_image"],
                        "identity_verified": {"model": identity.model, "serial": identity.serial},
                    },
                )
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "reason": "version_or_boot_image_mismatch",
                    "expected_version": expected_version,
                    "version_readback": identity.vrp_version,
                    "expected_boot_image": expected_image,
                    "boot_image_readback": boot["boot_image"],
                },
            )
        finally:
            await executor.close()
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": "firmware_reconnect_deadline_reached"},
    )


def verify_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult | None,
    certified_models: tuple[str, ...],
) -> VerificationResult:
    return cast(
        VerificationResult,
        _Boundary("verify")(
            lambda: _verify_async(session, plan, result, certified_models)
        ),
    )
