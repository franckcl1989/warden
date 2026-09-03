"""Synology DSM operation methods (M4T3): power, DSM console launch, support
bundles, SMART tests, backup status, firmware update, SNMP trap config.

Serves contracts/operations.json profiles NAS-ACT-01..06 for
``synology_nas`` devices (docs/DEVICE_ADAPTERS.md §5.2, §7, §9). The
operation protocol methods (plan/preflight/execute/verify + create_launch)
are mixed into ``app.adapters.dsm.SynologyDsmAdapter``; everything here only
talks to the certified DSM WebAPI rows of the adapter module (ADR-018 — the
client ledger refuses uncertified API names/versions).

Device-side semantics per profile (the ONLY authority — contracts/
operations.json):

- power.restart/power.shutdown (NAS-ACT-01): SYNO.Core.System
  restart/shutdown [sim fixture basis]. expected_disconnect=true — execute
  only reports the DSM accepted; verification is bounded:
  restart -> disconnect_reconnect_identity (poll the offline window, then a
  fresh login proves reconnect and the identity values serial/model/firmware
  are unchanged — both proofs required, never a trivial success);
  shutdown -> expected_disconnect (management surface observed unreachable
  inside the window = success; still reachable at the deadline = ambiguous).
  Never 204/200-as-success: the acceptance envelope alone never ends a task.
- console.dsm.open (NAS-ACT-02, LAUNCH channel): ``create_launch`` proves
  the management surface with a live authenticated read and returns a plain
  http(s) origin URL descriptor WITHOUT credentials (SECURITY.md §6, ADR-006).
- logs.support_bundle.collect (NAS-ACT-03): SYNO.Core.Support export [sim]
  returns a device-ORIGIN download path; the adapter streams the bundle over
  the same origin (a foreign/absolute URL is refused — no SSRF from device
  answers) and yields BYTES + a parsed manifest (artifact boundary, M3T3
  pattern: the worker stores the encrypted file and merges the stored proof
  before verification runs artifact_manifest).
- disk.smart_test.quick/full (NAS-ACT-04): disk_id validated against the
  discovered disks; SYNO.Storage.CGI.Storage smart_test [sim] returns a DSM
  task id -> device_job semantics (the worker persists the job id and polls
  verify: running -> pending, success -> succeeded, failure -> failed,
  vanished/unknown -> ambiguous).
- backup.status.refresh (NAS-ACT-05): read-only SYNO.Core.Backup list [sim]
  -> normalized job inventory (no new schema: the refresh result is
  persisted as the task evidence — DATA_MODEL decision documented in the
  M4T3 report; the NAS 任务与日志 page reads the latest succeeded task
  evidence).
- firmware.update (NAS-ACT-06): SYNO.Core.Upgrade upgrade [sim] with the
  platform device-pull ticket URL (runtime context — never user-supplied);
  the accepted DSM task id is tracked with device_job semantics;
  expected_disconnect=true. job_reconnect_version: terminal job success +
  fresh-login identity (serial/model unchanged) + firmware version readback
  == the platform-declared package version; a completed job with a provably
  wrong final version is a device-side failure (operation_failed), never
  success without proof. PAT header metadata parsing is the WORKER's
  (platform side, warden-sim PAT header; real Synology PAT parsing is
  vendor_private, [sim] basis until certified).
- snmp.configure (NAS-ACT-06): SYNO.Core.Network.SNMP set/get [sim]. The
  trap receiver address comes ONLY from the platform deployment config via
  the plan runtime context (profile prohibition: 用户不能提供接收地址 —
  the parameter schema accepts ``enabled`` only). Verification is
  configuration_readback_and_test_trap: readback match decides success; the
  test-trap ATTRIBUTION (ingest side) is documented as a real-hardware/M5
  item — no received trap is ever fabricated.

Budgets (documented caps; real-DSM certification re-pins timings): a single
verify call may poll a reconnect for DSM_RECONNECT_CAP_SECONDS (120 s) /
shutdown unavailability for DSM_SHUTDOWN_CAP_SECONDS (60 s) / a post-job
firmware version read-back for DSM_VERSION_READBACK_CAP_SECONDS (60 s);
reconnect polls use DSM_RETRY_INTERVAL_SECONDS (0.25 s). When the worker put
the task ``timeout_at`` into the runtime context the budget shrinks to the
remaining task time. Job flows poll per worker poll interval: each verify
call performs ONE job read (plus the bounded post-terminal version
read-back).

Error mapping (DEVICE_ADAPTERS.md §7): escaped DSMErrors translate to
AdapterErrors with the same stable code at every boundary. Side-effect
ACTION calls whose response dies in transit (transport/5xx/parse failures —
the DSM may have accepted before the connection broke) surface as
``ambiguous_result`` so the executor parks the task in verification_required
instead of failing it (DEVICE_ADAPTERS.md §9: 连接中断且无法确认是否执行);
envelope-level device refusals (101 validation, 105 permission, unknown
method/API, login failures) stay explicit and terminal. Evidence never
carries the device-pull ticket URL: the recorded command has it redacted and
a ``ticket_id`` reference instead (SECURITY.md §7 file-layer invariant).

Verification reports explicit outcomes: device-declared job failures ->
failed (never retried); unprovable results (vanished job, deadline without
the state, identity unreadable) -> VerificationResult(ambiguous=True) so the
executor parks the task (AGENTS.md: 不得把不确定的结果伪装成成功).
"""

from __future__ import annotations

import hashlib
import io
import time
import zipfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from typing import Any, TypeVar

import httpx

from app.domain.adapter import (
    AdapterError,
    ArtifactDescriptor,
    DeviceSession,
    LaunchDescriptor,
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
from app.infrastructure.protocols.dsm.errors import (
    DSMError,
    classify_transport_error,
    raise_http_error,
)

T = TypeVar("T")

# --- documented single-call verification budgets (see module docstring) ------
DSM_RECONNECT_CAP_SECONDS = 120.0
DSM_SHUTDOWN_CAP_SECONDS = 60.0
DSM_VERSION_READBACK_CAP_SECONDS = 60.0
DSM_RETRY_INTERVAL_SECONDS = 0.25

# DSM method parameters that carry the platform device-pull TICKET URL to
# the device; their recorded values are redacted from evidence (SECURITY.md
# §7 file-layer invariant).
_TICKET_URL_PARAMS = frozenset({"url"})
_TICKET_REDACTION_PLACEHOLDER = "<platform-device-pull-ticket-url-redacted>"

# Identity values compared across an expected disconnect (serial/model/
# firmware); the restart/update verifies require at least one comparable
# non-None value read before the action.
_IDENTITY_FIELDS = ("serial", "model", "firmware")

# Stable identity fields for the firmware update (the firmware value itself
# intentionally changes with the upgrade).
_IDENTITY_STABLE_FIELDS = ("serial", "model")

# DSM errors that mean "the device/session is not back yet" during an
# expected_disconnect verify window (the bounded reconnect/shutdown loops
# treat them as offline; authentication_failed covers the boot window where
# DSM refuses logins before all services are up).
_DSM_OFFLINE_CODES = frozenset(
    {
        "network_unreachable",
        "operation_failed",
        "protocol_error",
        "rate_limited",
        "device_busy",
        "authentication_failed",
    }
)

# Side-effect ACTION calls whose failure is transport/server-side: the DSM
# may have accepted the action before the connection broke, so the adapter
# reports ambiguous_result (verification_required) instead of a clean
# failure (DEVICE_ADAPTERS.md §7/§9). Explicit envelope refusals (101
# validation, 105 permission, unknown API/method, auth) are never mapped
# through this set.
_ACTION_AMBIGUOUS_CODES = frozenset(
    {"network_unreachable", "tls_validation_failed", "protocol_error", "operation_failed"}
)

SUPPORT_BUNDLE_FORMAT = "warden-dsm-support-bundle/1"
SUPPORT_BUNDLE_MANIFEST_MEMBER = "manifest.json"

# Platform runtime-context key the worker fills for snmp.configure: the trap
# receiver address from the DEPLOYMENT CONFIG only (never a user parameter).
SNMP_RECEIVER_CTX_KEY = "snmp_receiver"

# Evidence note documenting the snmp.configure trap-attribution boundary:
# the platform ingest receiver arrives in M5; nothing here fakes a trap.
SNMP_TRAP_ATTRIBUTION_NOTE = (
    "trap attribution is an ingest(M5)/real-hardware item; the test device "
    "emits its test-trap record on the simulator state, no received trap "
    "is fabricated as platform evidence"
)


def _is_offline(exc: DSMError) -> bool:
    return exc.code in _DSM_OFFLINE_CODES


def _dsm_to_adapter(exc: DSMError, stage: str) -> AdapterError:
    return AdapterError(exc.code, exc.message, stage=exc.stage if exc.stage is not None else stage)


def _adapter_boundary(stage: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Translate ANY escaped ``DSMError`` into the matching ``AdapterError``.

    One boundary per protocol method (preflight/execute/verify/launch): the
    worker executor only maps AdapterError/AdapterTimeoutError, so a raw
    protocol error escaping here would become lease churn instead of a clean
    terminal outcome with the stable §7 code.
    """

    def decorate(fn: Callable[..., T]) -> Callable[..., T]:
        @wraps(fn)
        def wrapped(*args: object, **kwargs: object) -> T:
            try:
                return fn(*args, **kwargs)
            except DSMError as exc:
                raise _dsm_to_adapter(exc, stage) from exc

        return wrapped

    return decorate


# -- runtime-context contract (worker fills; adapter consumes) ----------------
# Keys (all optional, JSON-safe):
#   "ticket":  {"url": ..., "id": ...}                 (firmware.update)
#   "file":    {"file_id", "file_type", "sha256", "expected_model",
#               "expected_version"}                    (firmware.update)
#   "task_timeout_at": ISO-8601 task deadline          (budget shrinking)
#   "snmp_receiver": {"address": "host:port"}          (snmp.configure — the
#               ONLY source of the trap receiver address)
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
    """Read an evidence value tolerating both flat and ``execution`` nesting
    (the crash-recovery path nests execution evidence)."""
    if not evidence:
        return None
    if key in evidence:
        return evidence[key]
    nested = evidence.get("execution")
    if isinstance(nested, Mapping) and key in nested:
        return nested[key]  # type: ignore[no-any-return]
    return None


def _text_of(payload: object, key: str) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get(key)
    return value if isinstance(value, str) and value else None


def _int_of(payload: object, key: str) -> int | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _rows_of(payload: object, key: str) -> list[Mapping[str, object]] | None:
    if not isinstance(payload, Mapping):
        return None
    raw = payload.get(key)
    if not isinstance(raw, list):
        return None
    rows: list[Mapping[str, object]] = []
    for item in raw:
        if isinstance(item, Mapping):
            rows.append(item)
    return rows


def _api_evidence(
    client: Any,
    api_name: str,
    method: str,
    extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """ADR-018 per-call evidence block: exact API name, negotiated version
    and the [guide]/[sim] basis text of the certified row."""
    from app.adapters.dsm import API_BASIS

    spec = client.call_spec(api_name)
    block: dict[str, object] = {
        "api": api_name,
        "method": method,
        "version": spec.version if spec is not None else "?",
        "basis": API_BASIS.get(api_name, f"[sim] api {api_name}"),
    }
    if extra:
        block.update(dict(extra))
    return block


def _action_call(
    client: Any,
    api_name: str,
    method: str,
    params: Mapping[str, object],
    progress: OperationProgress,
    step: str,
) -> object:
    """One DSM side-effect action call with §7 ambiguous mapping.

    Envelope-level refusals keep their explicit codes; transport/server-side
    failures (the DSM may have accepted the action) surface as
    ``ambiguous_result`` so the executor parks the task in
    verification_required — never a clean failure of a possibly-executed
    action and never a replay.
    """
    progress(60, step)
    try:
        return client.call(api_name, method, safe=False, params=params)
    except DSMError as exc:
        if exc.code in _ACTION_AMBIGUOUS_CODES:
            raise AdapterError(
                "ambiguous_result",
                f"{method} 动作调用中断且无法确认是否执行（{exc.code}）",
                stage="execute",
            ) from exc
        raise


def _redact_ticket_params(params: Mapping[str, object], plan: OperationPlan) -> tuple[dict[str, object], str | None]:
    """(evidence-safe params, ticket_id) for a device call carrying the
    platform ticket URL: evidence references the ticket by id ONLY."""
    ticket = _ctx_dict(plan, "ticket")
    ticket_url = ticket.get("url")
    ticket_id = ticket.get("id")
    command: dict[str, object] = {}
    for key, value in params.items():
        if key in _TICKET_URL_PARAMS and isinstance(value, str) and value == ticket_url:
            command[key] = _TICKET_REDACTION_PLACEHOLDER
        else:
            command[key] = value
    return command, ticket_id if isinstance(ticket_id, str) else None


# -- transport ----------------------------------------------------------------


@contextmanager
def _open_device(session: DeviceSession) -> Iterator[tuple[Any, httpx.Client]]:
    """One DSM device boundary for an operation call: policy-resolved IP or
    an IP-literal endpoint, protocol/port from ``connection_config`` (same
    rules as the collect path). Yields (DSMClient, raw httpx.Client) so
    binary device-origin downloads reuse the same transport."""
    from app.adapters.dsm import _build_http_client, _dsm_client, _endpoint_for

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
        with _dsm_client(http, endpoint=endpoint, credentials=session.credentials) as client:
            yield client, http
    finally:
        http.close()


def _origin_url_of(session: DeviceSession) -> str:
    """The validated management origin for launch descriptors (never
    credentials; SECURITY.md §6/ADR-006 — the vendor page may ask the
    operator to authenticate again)."""
    from app.adapters.dsm import _endpoint_for

    endpoint = _endpoint_for(
        resolved_ip=session.resolved_ip,
        management_endpoint=session.management_endpoint,
        connection_config=dict(session.connection_config),
    )
    return f"{endpoint.scheme}://{endpoint.host}:{endpoint.port}"


# -- shared device reads ------------------------------------------------------


def _identity_payload(payload: object) -> dict[str, object]:
    """serial/model/firmware identity evidence from a System info payload."""
    identity: dict[str, object] = {}
    for key in _IDENTITY_FIELDS:
        value = _text_of(payload, key)
        if value is not None:
            identity[key] = value
    return identity


def _system_info(client: Any) -> object:
    return client.call("SYNO.Core.System", "info", safe=True)


def _maintenance_of(payload: object) -> str | None:
    """Active storage-maintenance kind from System info (DSL member present
    only while a scrub/rebuild runs; None = no conflicting maintenance)."""
    if not isinstance(payload, Mapping):
        return None
    raw = payload.get("maintenance")
    if not isinstance(raw, Mapping) or raw.get("active") is not True:
        return None
    kind = raw.get("kind")
    return kind if isinstance(kind, str) and kind else "active"


def _storage_data(client: Any) -> object:
    """One SYNO.Storage.CGI.Storage load_info read (preflight/execute source)."""
    return client.call("SYNO.Storage.CGI.Storage", "load_info", safe=True)


def _disk_ids_of(payload: object) -> set[str]:
    disks = _rows_of(payload, "disk") or []
    ids: set[str] = set()
    for disk in disks:
        native = disk.get("id")
        if isinstance(native, (str, int)) and not isinstance(native, bool):
            ids.add(str(native))
    return ids


def _running_jobs_of(payload: object) -> list[Mapping[str, object]]:
    return _rows_of(payload, "active_jobs") or []


def _storage_conflict(payload: object, *, disk_id: str | None = None) -> str | None:
    """A device-reported conflict for power/update (any running job or active
    maintenance) or SMART preflight (a job touching the same disk). Returns
    the conflict description or None."""
    for job in _running_jobs_of(payload):
        kind = job.get("kind")
        job_disk = job.get("disk")
        if disk_id is None:
            return f"设备存在进行中的作业（{kind}）"
        if kind == "smart" and job_disk == disk_id:
            return f"磁盘 {disk_id} 已有进行中的检测作业"
        if kind == "update":
            return "设备正在执行固件更新作业"
    return None


def _pool_blocked(payload: object) -> str | None:
    """A pool state that blocks storage-consuming operations (Failed)."""
    pools = _rows_of(payload, "pool") or []
    for pool in pools:
        status = pool.get("status")
        if status == "Failed":
            name = pool.get("name") or pool.get("id") or "?"
            return f"存储池 {name} 处于 Failed 状态"
    return None


def _volume_without_space(payload: object) -> str | None:
    """A volume whose free space cannot serve an update (used >= total)."""
    volumes = _rows_of(payload, "volume") or []
    for volume in volumes:
        used = volume.get("used_bytes")
        total = volume.get("total_bytes")
        if isinstance(used, int) and isinstance(total, int) and used >= total:
            name = volume.get("name") or volume.get("id") or "?"
            return f"卷 {name} 已无可用空间"
    return None


def _log_centre_readable(client: Any) -> None:
    """One lightweight SYNO.Core.System.Log read (support-bundle liveness)."""
    client.call("SYNO.Core.System.Log", "list", safe=True, params={"offset": 0, "limit": 1})


def _backup_status(client: Any) -> object:
    return client.call("SYNO.Core.Backup", "list", safe=True)


def _normalize_backup_rows(client: Any) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """(packages, jobs) normalized from SYNO.Core.Backup list.

    Only string members survive (name/type/status/last_run_at); unparseable
    rows are a protocol error — never guessed values (the DSL fixture shape
    is certified; real Hyper Backup / Snapshot Replication surfaces need
    target-model certification per ADR-018)."""
    payload = _backup_status(client)
    packages: list[dict[str, object]] = []
    for package in _rows_of(payload, "packages") or []:
        name = _text_of(package, "name")
        package_id = _text_of(package, "package")
        available = package.get("available")
        if not name or not package_id or not isinstance(available, bool):
            raise DSMError(
                "protocol_error", "Backup API 返回了无法解析的 package 行", stage="parse"
            )
        row: dict[str, object] = {"name": name, "package": package_id, "available": available}
        if not available:
            reason = _text_of(package, "reason")
            row["reason"] = reason or "unknown"
        packages.append(row)
    jobs: list[dict[str, object]] = []
    for job in _rows_of(payload, "jobs") or []:
        name = _text_of(job, "name")
        job_type = _text_of(job, "type")
        status = _text_of(job, "status")
        last_run_at = _text_of(job, "last_run_at")
        if not (name and job_type and status and last_run_at):
            raise DSMError("protocol_error", "Backup API 返回了无法解析的 job 行", stage="parse")
        jobs.append(
            {"name": name, "type": job_type, "status": status, "last_run_at": last_run_at}
        )
    return packages, jobs


def _snmp_config(client: Any) -> dict[str, object]:
    payload = client.call("SYNO.Core.Network.SNMP", "get", safe=True)
    enabled = payload.get("enabled") if isinstance(payload, Mapping) else None
    receiver = payload.get("receiver_address") if isinstance(payload, Mapping) else None
    # An EMPTY receiver address is a valid state (traps disabled): only the
    # member TYPE is certified, never a non-empty value requirement.
    if not isinstance(enabled, bool) or not isinstance(receiver, str):
        raise DSMError("protocol_error", "SNMP API 返回了无法解析的配置", stage="parse")
    return {"enabled": enabled, "receiver_address": receiver}


def _smart_status(client: Any, task_id: str) -> tuple[str, int | None]:
    """One smart task read: (status, progress); raises DSMError when the
    device cannot answer (a 101 answer = the job vanished, mapped by the
    caller)."""
    payload = client.call(
        "SYNO.Storage.CGI.Storage", "smart_task_status", safe=True, params={"taskid": task_id}
    )
    status = _text_of(payload, "status")
    progress = _int_of(payload, "progress")
    if status not in ("running", "success", "failure"):
        raise DSMError("protocol_error", f"SMART 任务状态 {status!r} 无法解析", stage="verify")
    return status, progress


def _update_job_status(client: Any, task_id: str) -> tuple[str, int | None]:
    payload = client.call(
        "SYNO.Core.Upgrade", "update_task_status", safe=True, params={"taskid": task_id}
    )
    status = _text_of(payload, "status")
    progress = _int_of(payload, "progress")
    if status not in ("running", "success", "failure"):
        raise DSMError("protocol_error", f"更新任务状态 {status!r} 无法解析", stage="verify")
    return status, progress


# -- launch (API_CONTRACT.md §7, LAUNCH channel) ------------------------------


@_adapter_boundary("launch")
def create_launch_method(session: DeviceSession, capability: str) -> LaunchDescriptor:
    """console.dsm.open: the validated DSM origin, never credentials.

    A live authenticated System read proves the DSM management surface still
    answers; the descriptor URL is the plain http(s) origin of that same
    endpoint (launch_target_validation: an unvalidated/redirected origin is
    rejected — the adapter never follows redirects and never injects
    credentials or platform tokens into the URL)."""
    if capability != "console.dsm.open":
        raise AdapterError(
            "unsupported_capability",
            f"DSM 适配器未实现该能力的启动描述符 {capability}",
            stage="launch",
        )
    with _open_device(session) as (client, _http):
        payload = _system_info(client)
        if not isinstance(payload, Mapping):
            raise AdapterError(
                "not_configured", "no_dsm_origin：DSM System 读取未返回可用身份数据", stage="launch"
            )
        if not _text_of(payload, "model"):
            raise AdapterError("not_configured", "no_dsm_origin：DSM 未返回型号身份", stage="launch")
    return LaunchDescriptor(
        kind="url",
        url=_origin_url_of(session),
        display_hint="DSM 管理界面入口（无凭据注入）",
    )


# -- plan ---------------------------------------------------------------------


def plan_operation_method(snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
    """Planning mirrors the shared domain planner (profiles only from
    contracts/operations.json via the generated registry)."""
    return plan_operation(snapshot, request)


# -- preflight ----------------------------------------------------------------


@_adapter_boundary("preflight")
def preflight_operation_method(session: DeviceSession, plan: OperationPlan) -> PreflightResult:
    """Real-time read-only preflight per profile preconditions (no side
    effects). All reads are the certified safe rows of the mapping table."""
    key = plan.capability_key
    with _open_device(session) as (client, _http):
        if key in ("power.restart", "power.shutdown"):
            # Preconditions: DSM System callable + no conflicting storage
            # maintenance reported by the device.
            maintenance = _maintenance_of(_system_info(client))
            if maintenance is not None:
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail=f"设备报告进行中的存储维护（{maintenance}），与重启/关机冲突",
                )
            return PreflightResult(ok=True)
        if key in ("disk.smart_test.quick", "disk.smart_test.full"):
            disk_id = plan.normalized_parameters.get("disk_id")
            payload = _storage_data(client)
            if not isinstance(disk_id, str) or disk_id not in _disk_ids_of(payload):
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail=f"磁盘 {disk_id or '(缺失)'} 不在当前发现结果中（状态漂移）",
                )
            conflict = _storage_conflict(payload, disk_id=disk_id)
            if conflict is not None:
                return PreflightResult(ok=False, error_code="device_busy", detail=conflict)
            return PreflightResult(ok=True)
        if key == "logs.support_bundle.collect":
            # Certified log/support path available AND the log centre answers
            # (the export path liveness is proven at execute: export +
            # device-origin download).
            _log_centre_readable(client)
            return PreflightResult(ok=True)
        if key == "backup.status.refresh":
            _backup_status(client)
            return PreflightResult(ok=True)
        if key == "firmware.update":
            file_ctx = _ctx_dict(plan, "file")
            if not isinstance(file_ctx.get("expected_version"), str):
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未提供 PAT 包目标版本，无法执行升级",
                )
            if _ctx_text(plan, "ticket") is None:
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未提供设备拉取票据，无法执行升级",
                )
            maintenance = _maintenance_of(_system_info(client))
            if maintenance is not None:
                return PreflightResult(
                    ok=False,
                    error_code="validation_failed",
                    detail=f"设备报告进行中的存储维护（{maintenance}），与固件升级冲突",
                )
            payload = _storage_data(client)
            pool_blocked = _pool_blocked(payload)
            if pool_blocked is not None:
                return PreflightResult(ok=False, error_code="validation_failed", detail=pool_blocked)
            space_blocked = _volume_without_space(payload)
            if space_blocked is not None:
                return PreflightResult(
                    ok=False, error_code="validation_failed", detail=space_blocked
                )
            return PreflightResult(ok=True)
        if key == "snmp.configure":
            receiver = _ctx_dict(plan, SNMP_RECEIVER_CTX_KEY).get("address")
            if not isinstance(receiver, str) or not receiver:
                return PreflightResult(
                    ok=False,
                    error_code="not_configured",
                    detail="平台未配置 SNMP Trap 接收地址（部署配置），无法执行 snmp.configure",
                )
            _snmp_config(client)
            return PreflightResult(ok=True)
    return PreflightResult(
        ok=False,
        error_code="unsupported_capability",
        detail=f"DSM 适配器未实现操作 {key}",
    )


# -- execute ------------------------------------------------------------------


def _power_execute(
    client: Any,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    key = plan.capability_key
    method = "restart" if key == "power.restart" else "shutdown"
    identity: dict[str, object] = {}
    if key == "power.restart":
        identity = _identity_payload(_system_info(client))
    _action_call(client, "SYNO.Core.System", method, {}, progress, f"{method} 动作已被设备接受")
    evidence: dict[str, object] = {
        "action": method,
        "accepted": True,
        **_api_evidence(client, "SYNO.Core.System", method),
    }
    if identity:
        evidence["identity_before"] = identity
    return OperationResult(ok=True, evidence=evidence)


def _smart_execute(
    client: Any,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    disk_id = plan.normalized_parameters.get("disk_id")
    if not isinstance(disk_id, str):
        raise AdapterError("validation_failed", "缺少 disk_id 参数", stage="execute")
    smart_type = "quick" if plan.capability_key == "disk.smart_test.quick" else "full"
    payload = _storage_data(client)
    if disk_id not in _disk_ids_of(payload):
        raise AdapterError(
            "validation_failed", f"磁盘 {disk_id} 不在当前发现结果中", stage="execute"
        )
    conflict = _storage_conflict(payload, disk_id=disk_id)
    if conflict is not None:
        raise AdapterError("device_busy", conflict, stage="execute")
    progress(30, f"在磁盘 {disk_id} 启动 {smart_type} SMART 检测")
    data = _action_call(
        client,
        "SYNO.Storage.CGI.Storage",
        "smart_test",
        {"disk": disk_id, "type": smart_type},
        progress,
        "检测任务已被设备接受",
    )
    task_id = _int_of(data, "taskid")
    if task_id is None:
        raise DSMError("protocol_error", "SMART 检测未返回任务编号", stage="parse")
    evidence: dict[str, object] = {
        "disk_id": disk_id,
        "test_type": smart_type,
        "device_job_id": str(task_id),
        "accepted": True,
        **_api_evidence(client, "SYNO.Storage.CGI.Storage", "smart_test"),
    }
    return OperationResult(ok=True, evidence=evidence, device_job_id=str(task_id))


def _support_bundle_execute(
    client: Any,
    http: httpx.Client,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    del plan
    progress(20, "请求 DSM 支持包导出")
    data = client.call("SYNO.Core.Support", "export", safe=False)
    download_path = _text_of(data, "file")
    if download_path is None:
        raise DSMError("protocol_error", "支持包导出未返回下载路径", stage="parse")
    # DEVICE-ORIGIN ONLY: a relative path on the same host/port. Absolute or
    # foreign URLs from the device are refused (no SSRF from device answers).
    if not download_path.startswith("/") or "://" in download_path:
        raise DSMError(
            "protocol_error",
            "支持包导出返回了非设备来源的下载地址",
            stage="parse",
        )
    progress(50, "下载支持包产物")
    try:
        response = http.get(download_path)
    except httpx.TransportError as exc:
        raise classify_transport_error(exc) from exc
    if response.status_code >= 400:
        raise_http_error(
            response.status_code,
            context="read",
            api_name="SYNO.Core.Support",
            method="export",
        )
    content = response.content
    if not content:
        raise DSMError("protocol_error", "支持包下载为空", stage="parse")
    progress(75, "核对支持包清单")
    manifest = _parse_bundle_manifest(content)
    progress(90, "支持包就绪")
    artifact = ArtifactDescriptor(
        file_type="support_bundle",
        filename="dsm-support-bundle.zip",
        content_bytes=content,
        mime_type="application/zip",
        manifest=manifest,
    )
    evidence: dict[str, object] = {
        "artifact_manifest": manifest,
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        **_api_evidence(client, "SYNO.Core.Support", "export"),
    }
    return OperationResult(ok=True, evidence=evidence, artifacts=(artifact,))


def _parse_bundle_manifest(content: bytes) -> dict[str, object]:
    """The warden-dsm-support-bundle manifest (top-level manifest.json).

    Shape is simulator-DSL certified (tests/simulators/dsm/README.md); a zip
    without the manifest member or with an unparseable one is a protocol
    error — never a guessed manifest."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            raw = archive.read(SUPPORT_BUNDLE_MANIFEST_MEMBER)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise DSMError(
            "protocol_error", "支持包缺少可解析的 manifest.json", stage="parse"
        ) from exc
    try:
        import json

        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DSMError(
            "protocol_error", "支持包 manifest.json 无法解析", stage="parse"
        ) from exc
    if not isinstance(manifest, dict):
        raise DSMError("protocol_error", "支持包 manifest.json 不是对象", stage="parse")
    return manifest


def _backup_refresh_execute(
    client: Any,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    del plan
    progress(30, "读取备份/快照任务状态")
    packages, jobs = _normalize_backup_rows(client)
    progress(100, "备份状态读取完成")
    evidence: dict[str, object] = {
        "packages": packages,
        "jobs": jobs,
        "observed_at": datetime.now(UTC).isoformat(),
        **_api_evidence(client, "SYNO.Core.Backup", "list"),
    }
    return OperationResult(ok=True, evidence=evidence)


def _firmware_update_execute(
    client: Any,
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
            "validation_failed", "平台未提供 PAT 包目标版本，无法执行升级", stage="execute"
        )
    progress(20, "提交 DSM 固件升级任务")
    # Identity BEFORE the update (serial/model — the stable device fields):
    # the post-upgrade verify compares them over a fresh session.
    identity_before = _identity_payload(_system_info(client))
    data = _action_call(
        client,
        "SYNO.Core.Upgrade",
        "upgrade",
        {"url": ticket_url},
        progress,
        "升级任务已被设备接受",
    )
    task_id = _int_of(data, "taskid")
    if task_id is None:
        raise DSMError("protocol_error", "固件升级未返回任务编号", stage="parse")
    command, ticket_id = _redact_ticket_params({"url": ticket_url}, plan)
    evidence: dict[str, object] = {
        "command": command,
        "device_job_id": str(task_id),
        "expected_version": expected_version,
        "file_sha256": file_ctx.get("sha256"),
        "accepted": True,
        **_api_evidence(client, "SYNO.Core.Upgrade", "upgrade"),
    }
    if identity_before:
        evidence["identity_before"] = identity_before
    if ticket_id is not None:
        evidence["ticket_id"] = ticket_id
    return OperationResult(ok=True, evidence=evidence, device_job_id=str(task_id))


def _snmp_execute(
    client: Any,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    enabled = plan.normalized_parameters.get("enabled")
    if not isinstance(enabled, bool):
        raise AdapterError("validation_failed", "缺少 enabled 参数", stage="execute")
    receiver_ctx = _ctx_dict(plan, SNMP_RECEIVER_CTX_KEY)
    receiver = receiver_ctx.get("address")
    if not isinstance(receiver, str) or not receiver:
        raise AdapterError(
            "not_configured",
            "平台未配置 SNMP Trap 接收地址（部署配置；用户不可提供接收地址）",
            stage="execute",
        )
    wire_receiver = receiver if enabled else ""
    progress(20, f"写入 DSM SNMP 配置（enabled={enabled}）")
    _action_call(
        client,
        "SYNO.Core.Network.SNMP",
        "set",
        {"enabled": "true" if enabled else "false", "receiver_address": wire_receiver},
        progress,
        "SNMP 配置写入已被设备接受",
    )
    evidence: dict[str, object] = {
        "enabled": enabled,
        "receiver_address": receiver if enabled else "",
        "accepted": True,
        **_api_evidence(client, "SYNO.Core.Network.SNMP", "set"),
    }
    return OperationResult(ok=True, evidence=evidence)


@_adapter_boundary("execute")
def execute_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    progress: OperationProgress,
) -> OperationResult:
    """Execute a device-side operation (called only AFTER the dispatch fence)."""
    key = plan.capability_key
    with _open_device(session) as (client, http):
        if key in ("power.restart", "power.shutdown"):
            return _power_execute(client, plan, progress)
        if key in ("disk.smart_test.quick", "disk.smart_test.full"):
            return _smart_execute(client, plan, progress)
        if key == "logs.support_bundle.collect":
            return _support_bundle_execute(client, http, plan, progress)
        if key == "backup.status.refresh":
            return _backup_refresh_execute(client, plan, progress)
        if key == "firmware.update":
            return _firmware_update_execute(client, plan, progress)
        if key == "snmp.configure":
            return _snmp_execute(client, plan, progress)
    raise AdapterError(
        "unsupported_capability", f"DSM 适配器未实现操作 {key}", stage="execute"
    )


# -- verification -------------------------------------------------------------


def _power_restart_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """disconnect_reconnect_identity: offline window + fresh-session identity.

    Success requires BOTH proofs (never a trivial pass): at least one
    non-None pre-restart identity value (serial/model/firmware) equals the
    same value over a FRESH post-restart session, AND the offline window was
    observed during this verification (a device that never went down cannot
    be proven to have restarted)."""
    identity_before = _evidence_get(evidence, "identity_before")
    before = identity_before if isinstance(identity_before, Mapping) else {}
    before_values = {key: before.get(key) for key in _IDENTITY_FIELDS if before.get(key) is not None}
    deadline = time.monotonic() + _budget_remaining(plan, DSM_RECONNECT_CAP_SECONDS)
    saw_offline = False
    while time.monotonic() < deadline:
        try:
            with _open_device(session) as (client, _http):
                current = _identity_payload(_system_info(client))
        except DSMError as exc:
            if _is_offline(exc):
                saw_offline = True
                time.sleep(DSM_RETRY_INTERVAL_SECONDS)
                continue
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"reconnect failed ({exc.code})"},
            )
        if not current:
            time.sleep(DSM_RETRY_INTERVAL_SECONDS)
            continue
        if not before_values:
            # The device is back but identity cannot be PROVEN unchanged
            # (no pre-restart values to compare).
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": "no_pre_reset_identity_evidence", "identity_after": current},
            )
        comparable = {key: value for key, value in before_values.items() if current.get(key) is not None}
        if not comparable:
            time.sleep(DSM_RETRY_INTERVAL_SECONDS)
            continue
        if any(current.get(key) != value for key, value in comparable.items()):
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "reason": "identity_changed_after_restart",
                    "identity_before": before,
                    "identity_after": current,
                },
            )
        if not saw_offline:
            time.sleep(DSM_RETRY_INTERVAL_SECONDS)
            continue
        return VerificationResult(
            succeeded=True,
            evidence={
                "strategy": plan.verification_strategy,
                "identity_verified": current,
                "disconnect_observed": True,
            },
        )
    if not saw_offline and before_values:
        reason = "no offline window observed — the restart cannot be proven"
    elif saw_offline and not before_values:
        reason = "no pre-restart identity values — identity cannot be proven unchanged"
    else:
        reason = "reconnect deadline reached without the DSM returning"
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": reason},
    )


def _power_shutdown_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """expected_disconnect: the shutdown was accepted and the management
    surface becomes unreachable within the certified window."""
    del evidence
    deadline = time.monotonic() + _budget_remaining(plan, DSM_SHUTDOWN_CAP_SECONDS)
    while time.monotonic() < deadline:
        try:
            with _open_device(session) as (client, _http):
                _system_info(client)
        except DSMError as exc:
            if _is_offline(exc):
                return VerificationResult(
                    succeeded=True,
                    evidence={
                        "strategy": plan.verification_strategy,
                        "disconnect_observed": True,
                        "observed_error": exc.code,
                    },
                )
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"unexpected verify failure ({exc.code})"},
            )
        time.sleep(DSM_RETRY_INTERVAL_SECONDS)
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={"reason": "management surface still reachable at the deadline"},
    )


def _smart_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """device_job_status: ONE job read per worker poll (the worker renews
    the lease and re-polls while pending; the task deadline decides the
    final ambiguity, never this call)."""
    job = result.device_job_id if result is not None else None
    if job is None:
        raw = _evidence_get(evidence, "device_job_id")
        job = raw if isinstance(raw, str) else None
    if job is None:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_device_job_id_for_verification"},
        )
    disk_id = _evidence_get(evidence, "disk_id")
    test_type = _evidence_get(evidence, "test_type")
    try:
        with _open_device(session) as (client, _http):
            status, progress_value = _smart_status(client, job)
    except DSMError as exc:
        if exc.code == "validation_failed" and exc.dsm_code == 101:
            # The DSM no longer knows the task: the test may have been
            # interrupted (reboot/manual action) — unprovable.
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"job_id": job, "reason": "job_vanished"},
            )
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"job_id": job, "reason": f"job unreadable ({exc.code})"},
        )
    if status == "running":
        return VerificationResult(
            succeeded=False, pending=True, evidence={"job_id": job, "job_state": "running"}
        )
    if status == "failure":
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={"job_id": job, "job_state": "failure", "progress": progress_value},
        )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "job_id": job,
            "job_state": "success",
            "progress": progress_value,
            "disk_id": disk_id,
            "test_type": test_type,
        },
    )


def _support_bundle_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """artifact_manifest: manifest self-consistency + stored artifact proof
    (the worker merged the encrypted file row proof into the evidence before
    verification) + the log centre is still readable."""
    manifest = _evidence_get(evidence, "artifact_manifest")
    if not isinstance(manifest, Mapping):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_artifact_manifest_in_evidence"},
        )
    if manifest.get("format") != SUPPORT_BUNDLE_FORMAT:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={"reason": "artifact_manifest_unknown_format"},
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
    try:
        with _open_device(session) as (client, _http):
            _log_centre_readable(client)
    except DSMError as exc:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": f"log_centre_unreadable_during_verify ({exc.code})"},
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


def _backup_refresh_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """inventory_persisted: the refresh result IS the persisted task
    evidence (no backup table — M4T3 report decision); verification proves
    the evidence holds the jobs/packages inventory and the read-only API
    still answers (job values are time-sensitive device data, so a later
    readback is NOT compared member-by-member)."""
    jobs = _evidence_get(evidence, "jobs")
    packages = _evidence_get(evidence, "packages")
    if not isinstance(jobs, list) or not isinstance(packages, list):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "backup_inventory_not_persisted"},
        )
    try:
        with _open_device(session) as (client, _http):
            _normalize_backup_rows(client)
    except DSMError as exc:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": f"backup_api_unreadable_during_verify ({exc.code})"},
        )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "jobs_persisted": len(jobs),
            "packages_persisted": len(packages),
            "readback_consistent": True,
        },
    )


def _firmware_update_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
    result: OperationResult | None,
) -> VerificationResult:
    """job_reconnect_version: terminal job + same-device reconnect + version
    readback == the platform-declared package version.

    With a persisted job each call is ONE cheap poll while the job runs or
    the DSM is offline mid-update (expected_disconnect -> ``pending``; the
    worker re-polls with lease renewals). After the job is terminal the
    version/identity read-back happens inside a budget-bounded loop (the DSM
    may still be applying): readback == expected AND identity unchanged ->
    succeeded; a terminal job with a provably wrong final version at the
    deadline -> failed (operation_failed); unprovable -> ambiguous."""
    file_ctx = _ctx_dict(plan, "file")
    expected_version = file_ctx.get("expected_version")
    if not isinstance(expected_version, str):
        raw = _evidence_get(evidence, "expected_version")
        expected_version = raw if isinstance(raw, str) else None
    if not expected_version:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_expected_version_in_context"},
        )
    job = result.device_job_id if result is not None else None
    if job is None:
        raw = _evidence_get(evidence, "device_job_id")
        job = raw if isinstance(raw, str) else None
    deadline = time.monotonic() + _budget_remaining(plan, DSM_VERSION_READBACK_CAP_SECONDS)
    terminal_success_seen = job is None
    job_state_seen: str | None = None
    last_concrete_version: str | None = None
    while time.monotonic() < deadline:
        try:
            with _open_device(session) as (client, _http):
                if job is not None:
                    try:
                        status, _progress = _update_job_status(client, job)
                    except DSMError as exc:
                        if _is_offline(exc):
                            # DSM mid-reboot: the worker keeps polling the
                            # SAME persisted job (never re-executed).
                            return VerificationResult(
                                succeeded=False,
                                pending=True,
                                evidence={"job_state": "device_offline"},
                            )
                        if exc.code == "validation_failed" and exc.dsm_code == 101:
                            return VerificationResult(
                                succeeded=False,
                                ambiguous=True,
                                error_code="ambiguous_result",
                                evidence={"job_id": job, "reason": "job_vanished"},
                            )
                        return VerificationResult(
                            succeeded=False,
                            ambiguous=True,
                            error_code="ambiguous_result",
                            evidence={"job_id": job, "reason": f"job unreadable ({exc.code})"},
                        )
                    job_state_seen = status
                    if status == "running":
                        return VerificationResult(
                            succeeded=False, pending=True, evidence={"job_state": "running"}
                        )
                    if status == "failure":
                        return VerificationResult(
                            succeeded=False,
                            error_code="operation_failed",
                            evidence={"job_state": "failure"},
                        )
                    terminal_success_seen = True
                # Post-terminal read-back: a fresh session proves reconnect;
                # identity must be unchanged and the version must match.
                try:
                    current = _identity_payload(_system_info(client))
                except DSMError as exc:
                    if _is_offline(exc):
                        return VerificationResult(
                            succeeded=False,
                            pending=True,
                            evidence={"job_state": "device_offline"},
                        )
                    return VerificationResult(
                        succeeded=False,
                        ambiguous=True,
                        error_code="ambiguous_result",
                        evidence={"reason": f"version read-back failed ({exc.code})"},
                    )
        except DSMError as exc:
            if _is_offline(exc):
                return VerificationResult(
                    succeeded=False,
                    pending=True,
                    evidence={"job_state": "device_offline"},
                )
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                error_code="ambiguous_result",
                evidence={"reason": f"version read-back failed ({exc.code})"},
            )
        readback_version = current.get("firmware")
        if isinstance(readback_version, str) and readback_version == expected_version:
            # Same device proof: serial/model (stable identity fields — the
            # firmware itself intentionally changed) must not have drifted.
            identity_before = _evidence_get(evidence, "identity_before")
            before = identity_before if isinstance(identity_before, Mapping) else {}
            if before:
                mismatch = {
                    key: value
                    for key, value in before.items()
                    if key in _IDENTITY_STABLE_FIELDS
                    and current.get(key) is not None
                    and current.get(key) != value
                }
                if mismatch:
                    time.sleep(DSM_RETRY_INTERVAL_SECONDS)
                    continue
            return VerificationResult(
                succeeded=True,
                evidence={
                    "strategy": plan.verification_strategy,
                    "job_state": job_state_seen,
                    "expected_version": expected_version,
                    "readback_version": readback_version,
                    "identity_after": current,
                },
            )
        if isinstance(readback_version, str):
            last_concrete_version = readback_version
        time.sleep(DSM_RETRY_INTERVAL_SECONDS)
    if terminal_success_seen and last_concrete_version is not None:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={
                "reason": "version_mismatch_after_completed_job",
                "expected_version": expected_version,
                "readback_version": last_concrete_version,
                "job_state": job_state_seen,
            },
        )
    return VerificationResult(
        succeeded=False,
        ambiguous=True,
        error_code="ambiguous_result",
        evidence={
            "reason": "version read-back deadline reached",
            "expected_version": expected_version,
        },
    )


def _snmp_verify(
    session: DeviceSession,
    plan: OperationPlan,
    evidence: Mapping[str, object],
) -> VerificationResult:
    """configuration_readback_and_test_trap: the DSM config readback matches
    the requested state; trap attribution stays an ingest/M5 + real-hardware
    item (documented note — no received trap is ever fabricated)."""
    expected_enabled = plan.normalized_parameters.get("enabled")
    expected_receiver = _ctx_dict(plan, SNMP_RECEIVER_CTX_KEY).get("address")
    if not isinstance(expected_enabled, bool) or not isinstance(expected_receiver, str):
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": "no_expected_config_in_context"},
        )
    try:
        with _open_device(session) as (client, _http):
            current = _snmp_config(client)
    except DSMError as exc:
        return VerificationResult(
            succeeded=False,
            ambiguous=True,
            error_code="ambiguous_result",
            evidence={"reason": f"config read-back failed ({exc.code})"},
        )
    if current.get("enabled") != expected_enabled:
        return VerificationResult(
            succeeded=False,
            error_code="operation_failed",
            evidence={
                "reason": "config_readback_mismatch",
                "expected_enabled": expected_enabled,
                "readback": current,
            },
        )
    readback_matches = True
    if expected_enabled:
        readback_matches = current.get("receiver_address") == expected_receiver
        if not readback_matches:
            return VerificationResult(
                succeeded=False,
                error_code="operation_failed",
                evidence={
                    "reason": "receiver_readback_mismatch",
                    "expected_receiver": expected_receiver,
                    "readback": current,
                },
            )
    return VerificationResult(
        succeeded=True,
        evidence={
            "strategy": plan.verification_strategy,
            "enabled": expected_enabled,
            "receiver_address": expected_receiver if expected_enabled else None,
            "config_readback": current,
            "readback_matches": readback_matches,
            "trap_attribution_note": SNMP_TRAP_ATTRIBUTION_NOTE,
        },
    )


@_adapter_boundary("verify")
def verify_operation_method(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult | None,
) -> VerificationResult:
    """Read-back verification per the profile's verification strategy."""
    evidence: Mapping[str, object] = result.evidence if result is not None else {}
    key = plan.capability_key
    if key == "power.restart":
        return _power_restart_verify(session, plan, evidence)
    if key == "power.shutdown":
        return _power_shutdown_verify(session, plan, evidence)
    if key in ("disk.smart_test.quick", "disk.smart_test.full"):
        return _smart_verify(session, plan, evidence, result)
    if key == "logs.support_bundle.collect":
        return _support_bundle_verify(session, plan, evidence)
    if key == "backup.status.refresh":
        return _backup_refresh_verify(session, plan, evidence)
    if key == "firmware.update":
        return _firmware_update_verify(session, plan, evidence, result)
    if key == "snmp.configure":
        return _snmp_verify(session, plan, evidence)
    raise AdapterError(
        "unsupported_capability", f"DSM 适配器未实现操作验证 {key}", stage="verify"
    )


# -- mixin --------------------------------------------------------------------


class SynologyDsmOperationsMixin:
    """Operation protocol methods for the Synology DSM adapter (M4T3)."""

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

    def create_launch(self, session: DeviceSession, capability: str) -> LaunchDescriptor:
        return create_launch_method(session, capability)
