"""Worker operation executor: preflight -> dispatch fence -> execute -> verify.

docs/ARCHITECTURE.md §5.2 (人工操作数据流步骤 3-8), §7 (失败与恢复),
DEVICE_ADAPTERS.md §9 (dispatch fence / replay protection), SECURITY.md §4
保护链 step 9 (Worker 二次校验并持久化 dispatch fence) and §12 (审计).
DATA_MODEL.md §11 (任务终态、验证结果与结束审计同一事务).

The executor runs inside the operation pool worker thread, in its own DB
session, and only ever touches a task it holds the lease for. Flow:

1. Re-verify the claimed task under MY lease (any state/lease drift -> no-op).
2. If the dispatch fence is already committed (a recovery verify-only claim)
   -> verify/read-back ONLY, never execute (DEVICE_ADAPTERS.md §9).
3. Otherwise re-check the current persisted state (device enabled, plan
   hashes unchanged, capability still supported), run the live READ-ONLY
   preflight, then commit the dispatch fence (``dispatch_started_at`` +
   adapter version + plan/parameter hashes) BEFORE any device-changing call.
4. Execute through the adapter with throttled progress persistence and lease
   renewals; a returned vendor ``device_job_id`` is persisted and the task
   moves to ``waiting_device`` before polling the job.
5. Verify per the profile through ``verify_operation`` (job polling keeps
   renewing the lease); the outcome decides the terminal transition:
   verified success -> succeeded; explicit failure -> failed (never retried);
   unprovable -> verification_required (never failed + auto-replay).
6. Terminal/holding state + append-only event + audit + ui_event commit in
   ONE transaction (DATA_MODEL.md §11).

Outcome rules that MUST never be violated (AGENTS.md, M2T1 gate):

- fenced side-effect tasks are never executed twice; the crash-after-fence
  recovery only consumes ``verify_operation`` (E2E enforces execute_count=1);
- ambiguous NEVER becomes failed + auto-replay; verification_required is only
  left via the admin verify/resolve flows; this holds for EVERY stage that
  surfaces the ``ambiguous_result`` code — including the execute stage, where
  an adapter may report 连接中断且无法确认是否执行 (ok=False/ambiguous_result
  or an AdapterError with that code) and the executor must route it through
  ``_verification_required``, never ``_fail_task``;
- adapter errors are never swallowed into success; a timeout error maps per
  ``timeout_transition`` (fenced side-effect -> verification_required).

Transient adapter failures of READ profiles do not auto-retry here: the task
fails terminally with the adapter error code (API_CONTRACT.md §6.2: 终态无
retry API); crash-driven retry as NEW attempts is the maintenance recovery's
job (bounded by ``attempt_count`` + ``operation_read_max_attempts``).
"""

from __future__ import annotations

import base64
import datetime
import json
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import replace as dataclass_replace

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.adapters import UnknownAdapterError, get_adapter
from app.application.collection import emit_ui_event
from app.application.files import (
    FileAuditContext,
    active_device_file_ticket,
    issue_device_file_ticket,
    link_input_file,
    revoke_device_file_ticket,
    storage_key,
    store_operation_artifact,
    ticket_url_for,
)
from app.application.operations import apply_operation_inventory, build_snapshot
from app.config import WardenSettings, get_settings
from app.domain.adapter import (
    AdapterError,
    AdapterTimeoutError,
    DeviceAdapter,
    DeviceSession,
    OperationResult,
    VerificationResult,
)
from app.domain.contracts import OperationProfile
from app.domain.errors import AppError
from app.domain.operation import (
    TaskFence,
    TaskState,
    timeout_transition,
)
from app.domain.operation_plan import OperationPlan, OperationRequest, plan_operation
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import (
    CredentialKeyring,
    DecryptionError,
    EncryptedSecret,
    FileKeyCipher,
    credential_aad,
)
from app.infrastructure.files import FileStorage, FileStorageError, StoredFile
from app.infrastructure.tasks import (
    dispatch_fence,
    enter_waiting_device,
    record_execution_evidence,
    renew_lease,
    transition_task,
    update_progress,
)
from app.infrastructure.time import utcnow
from app.models.devices import Device, DeviceCredential
from app.models.files import File, FileLink
from app.models.operation import OperationTask

# An adapter is allowed this many seconds past the plan deadline to return a
# verdict; the executor stops ITS OWN wait loops at ``timeout_at`` regardless.
DEADLINE_MARGIN_SECONDS = 0.25

UI_EVENT_TYPE_OPERATION_UPDATED = "operation.updated"

# Platform runtime-context key for snmp.configure (NAS-ACT-06): the trap
# receiver address from the deployment config — same key as the adapter's
# dsm_operations module reads.
SNMP_RECEIVER_CTX_KEY = "snmp_receiver"

# Virtual-media device-pull tickets live up to 24 h (ARCHITECTURE.md §3.6).
VIRTUAL_MEDIA_TICKET_HOURS = 24

# Firmware image metadata header: the warden-sim image format (simulator
# certification shape only — real vendor images are overlay territory, M3T5).
IMAGE_HEADER_MARKER = b"WARDEN-SIM-FW "
IMAGE_HEADER_MAX_BYTES = 4096

# NAS PAT package metadata header: the warden-sim PAT format (simulator
# certification shape only — real Synology PAT metadata parsing is
# vendor_private, [sim] basis until target-model certification, ADR-018).
PAT_HEADER_MARKER = b"WARDEN-SIM-PAT "
PAT_HEADER_MAX_BYTES = 4096


def _replace_plan_runtime(plan: OperationPlan, runtime: dict[str, object]) -> OperationPlan:
    return dataclass_replace(plan, runtime_context=runtime)


def _replace_result_evidence(
    result: OperationResult, evidence: dict[str, object]
) -> OperationResult:
    return dataclass_replace(result, evidence=evidence)


def _profile_for(task: OperationTask) -> OperationProfile | None:
    return OPERATION_PROFILES.get(f"{task.requirement_id}:{task.capability_key}")


class OperationExecutor:
    """Processes one claimed operation task (injected pool handler, M2T6)."""

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        lease_owner: str,
        lease_seconds: int,
        settings: WardenSettings | None = None,
        keyring: CredentialKeyring | None = None,
        audit_logger: AuditLogger | None = None,
        job_poll_interval_seconds: float | None = None,
        progress_min_interval_seconds: float | None = None,
        file_storage: FileStorage | None = None,
        file_key_cipher: FileKeyCipher | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._lease_owner = lease_owner
        self._lease_seconds = lease_seconds
        self._settings = settings if settings is not None else get_settings()
        self._keyring = keyring
        self._audit_logger = audit_logger
        self._job_poll_interval = (
            job_poll_interval_seconds
            if job_poll_interval_seconds is not None
            else self._settings.operation_job_poll_interval_seconds
        )
        self._progress_min_interval = (
            progress_min_interval_seconds
            if progress_min_interval_seconds is not None
            else self._settings.operation_progress_min_interval_seconds
        )
        self._file_storage = file_storage
        self._file_key_cipher = file_key_cipher
        self._log = structlog.get_logger()

    # -- pool handler entry -------------------------------------------------

    def __call__(self, task: OperationTask) -> None:
        with self._session_factory() as session:
            row = session.get(OperationTask, task.id)
            if row is None:
                return
            if row.lease_owner != self._lease_owner:
                self._log.info("executor_lease_lost", task_id=str(task.id))
                return
            if row.state not in (TaskState.RUNNING.value, TaskState.WAITING_DEVICE.value):
                self._log.info("executor_state_superseded", task_id=str(task.id), state=row.state)
                return
            profile = _profile_for(row)
            if profile is None:
                msg = (
                    f"operation profile {row.requirement_id}:{row.capability_key} "
                    "missing from the generated registry"
                )
                raise RuntimeError(msg)
            if row.dispatch_started_at is not None or row.state == TaskState.WAITING_DEVICE.value:
                self._log.info(
                    "executor_verify_only_start", task_id=str(row.id), device_id=str(row.device_id)
                )
                self._verify_only(session, row, profile)
            else:
                self._log.info(
                    "executor_execute_start", task_id=str(row.id), device_id=str(row.device_id)
                )
                self._run_execute(session, row, profile)

    # -- execution path -----------------------------------------------------

    def _run_execute(self, session: Session, task: OperationTask, profile: OperationProfile) -> None:
        """Preflight -> dispatch fence -> adapter execute -> verify."""
        if self._deadline_passed(task):
            self._handle_timeout_like(session, task, profile, reason="任务总超时已到（尚未派发）")
            return
        device = session.get(Device, task.device_id)
        if device is None or not device.enabled:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail="设备不存在或已停用，操作未执行；请重新预览",
            )
            return
        try:
            adapter = get_adapter(device.adapter_key)
        except UnknownAdapterError:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail="设备适配器键已不可用，操作未执行；请重新预览",
            )
            return
        plan = self._replan_or_fail(session, task, device)
        if plan is None:
            return
        if self._deadline_passed(task):
            self._handle_timeout_like(session, task, profile, reason="任务总超时已到（尚未派发）")
            return
        session_ctx = self._device_session(session, task, device)
        if session_ctx is None:
            return
        # M3T3 platform execution material (file rows, tickets, image
        # metadata) is assembled BEFORE the device-side preflight so that a
        # bad/missing input fails safely before the dispatch fence.
        plan = self._operation_context(session, task, device, plan)
        if plan is None:
            return
        # Step 3 of ARCHITECTURE.md §5.2: live READ-ONLY preflight BEFORE the
        # dispatch fence; any failure fails the task safely, never executes.
        try:
            preflight = adapter.preflight_operation(session_ctx, plan)
        except AdapterTimeoutError as exc:
            self._handle_timeout_like(
                session, task, profile, reason=f"设备前置检查超时：{exc.message}"
            )
            return
        except AdapterError as exc:
            self._fail_task(
                session,
                task,
                error_code=exc.code,
                error_detail=self._safe(exc.message, exc.stage),
            )
            return
        if not preflight.ok:
            stale = preflight.stale or (preflight.error_code == "preview_stale")
            self._fail_task(
                session,
                task,
                error_code=preflight.error_code or "validation_failed",
                error_detail=(
                    "实时前置检查发现设备状态与计划不一致（preflight_stale）；请重新预览"
                    if stale
                    else preflight.detail or "实时前置检查未通过"
                ),
            )
            return
        # Step 4 of ARCHITECTURE.md §5.2 / DEVICE_ADAPTERS.md §9: the fence is
        # committed (and committed ONLY) before execute may run.
        now = utcnow()
        if self._deadline_passed(task):
            self._handle_timeout_like(session, task, profile, reason="任务总超时已到（尚未派发）")
            return
        fenced = dispatch_fence(
            session,
            task_id=task.id,
            owner=self._lease_owner,
            now=now,
            adapter_version=plan.adapter_version,
            plan_hash=plan.plan_hash,
            parameter_hash=plan.parameter_hash,
        )
        if fenced is None:
            return
        self._audit_start(session, fenced)
        self._emit_ui_event(session, fenced)
        session.commit()
        self._log.info(
            "executor_fence_committed",
            task_id=str(task.id),
            dispatch_started_at=(
                fenced.dispatch_started_at.isoformat() if fenced.dispatch_started_at else None
            ),
        )
        # Step 5-6: execute with progress, then verify per profile.
        progress = self._progress_callback(task.id)
        try:
            result = adapter.execute_operation(session_ctx, plan, progress)
        except AdapterTimeoutError as exc:
            self._handle_timeout_like(session, task, profile, reason=f"设备调用超时：{exc.message}")
            return
        except AdapterError as exc:
            if exc.code == "ambiguous_result":
                # DEVICE_ADAPTERS.md §7: 连接中断且无法确认是否执行 ->
                # 禁止重放，进入待核验. The fence is committed, so this task
                # may never be failed + auto-replayed.
                self._verification_required(
                    session,
                    task,
                    f"设备调用结果不明（ambiguous_result）：{self._safe(exc.message, exc.stage)}；"
                    "等待核验（不自动重放）",
                )
                return
            self._fail_task(
                session,
                task,
                error_code=exc.code,
                error_detail=self._safe(exc.message, exc.stage),
            )
            return
        if not result.ok:
            if result.error_code == "ambiguous_result":
                # Explicit device ambiguity is NOT a clean failure: the device
                # may have executed the action (DEVICE_ADAPTERS.md §7/§9).
                self._verification_required(
                    session,
                    task,
                    "设备调用结果不明（ambiguous_result）："
                    + (result.error_detail or "连接中断且无法确认是否执行")
                    + "；等待核验（不自动重放）",
                    evidence={"execution": dict(result.evidence)} if result.evidence else None,
                )
                return
            # Explicit device failure: terminal failed, NEVER retried
            # (DEVICE_ADAPTERS.md §7: operation_failed 不自动重试).
            self._fail_task(
                session,
                task,
                error_code=result.error_code or "operation_failed",
                error_detail=result.error_detail or "设备明确返回执行失败",
                execution_evidence=result.evidence,
            )
            return
        # Platform side of the M3T3 boundary: artifacts/inventory are
        # persisted and their proofs merged into the evidence BEFORE
        # verification (the adapter only ever yields bytes/descriptors).
        consumed = self._consume_execution_outputs(session, task, device, plan, result)
        if consumed is None:
            return
        result = consumed
        if result.device_job_id is not None:
            self._poll_device_job(session, task, profile, plan, adapter, session_ctx, result)
        else:
            self._verify_once(session, task, profile, plan, adapter, session_ctx, result)

    def _replan_or_fail(
        self,
        session: Session,
        task: OperationTask,
        device: Device,
    ) -> OperationPlan | None:
        """Rebuild the plan from the CURRENT persisted snapshot (worker 二次校验).

        SECURITY.md §4 step 9: the worker re-checks permissions/capabilities
        before dispatch; capability/support drift or plan-hash drift fails the
        task with ``validation_failed`` and the user must re-preview
        (DEVICE_ADAPTERS.md §2.4: 计划关键字段或设备版本变化则任务以
        validation_failed/preview_stale 结束并要求重新预览).
        """
        try:
            plan = plan_operation(
                build_snapshot(session, device),
                OperationRequest(
                    capability_key=task.capability_key, parameters=dict(task.parameters)
                ),
            )
        except AppError as exc:
            code = exc.code if exc.code in ("validation_failed", "not_configured") else "validation_failed"
            self._fail_task(
                session,
                task,
                error_code=code,
                error_detail=exc.message[:400],
            )
            return None
        mismatch: list[str] = []
        if task.plan_hash is not None and task.plan_hash != plan.plan_hash:
            mismatch.append("计划散列")
        if task.parameter_hash is not None and task.parameter_hash != plan.parameter_hash:
            mismatch.append("参数散列")
        if task.adapter_version is not None and task.adapter_version != plan.adapter_version:
            mismatch.append("适配器版本")
        if mismatch:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail=f"执行计划已漂移（{'、'.join(mismatch)}），操作未执行；请重新预览",
            )
            return None
        return plan

    def _device_session(
        self,
        session: Session,
        task: OperationTask,
        device: Device,
    ) -> DeviceSession | None:
        """Decrypted per-run device session (SECURITY.md §5: plaintext only
        inside the adapter call boundary)."""
        try:
            credential = session.get(DeviceCredential, device.id)
            if credential is None:
                msg = "credential row missing"
                raise DecryptionError(msg)
            raw = self._decrypt(credential, device)
        except DecryptionError:
            self._fail_task(
                session,
                task,
                error_code="internal_error",
                error_detail="设备凭据不可用，操作未执行",
            )
            return None
        return DeviceSession(
            device_id=device.id,
            management_endpoint=device.management_endpoint,
            connection_config=dict(device.connection_config),
            credentials=raw,
        )

    def _decrypt(self, credential: DeviceCredential, device: Device) -> dict[str, object]:
        if self._keyring is None:
            msg = "executor keyring is not configured"
            raise DecryptionError(msg)
        encrypted = EncryptedSecret(
            ciphertext=credential.ciphertext,
            nonce=credential.nonce,
            key_version=credential.key_version,
        )
        plaintext = self._keyring.decrypt(
            encrypted,
            aad=credential_aad(str(device.id), device.adapter_key, credential.secret_schema_version),
        )
        value = json.loads(plaintext)
        if not isinstance(value, dict):
            msg = "decrypted credentials are not an object"
            raise DecryptionError(msg)
        return value

    def _progress_callback(self, task_id: uuid.UUID) -> Callable[[int, str | None], None]:
        """Throttled progress persistence + lease renewal (adapter callback)."""
        last_write = time.monotonic() - 10_000.0

        def _on_progress(percent: int, step: str | None) -> None:
            nonlocal last_write
            now = time.monotonic()
            try:
                with self._session_factory() as write_session:
                    if percent >= 100 or now - last_write >= self._progress_min_interval:
                        updated = update_progress(
                            write_session,
                            task_id=task_id,
                            owner=self._lease_owner,
                            progress_percent=percent,
                            current_step=step,
                            message=f"执行中：{step}" if step else "执行中",
                        )
                        if updated is not None:
                            last_write = now
                    else:
                        renew_lease(
                            write_session,
                            task_id=task_id,
                            owner=self._lease_owner,
                            lease_seconds=self._lease_seconds,
                        )
                    write_session.commit()
            except Exception:
                self._log.exception(
                    "progress_persist_failed",
                    task_id=str(task_id),
                    message="progress write failed; device call continues, lease recovery will decide",
                )

        return _on_progress

    def _verify_once(
        self,
        session: Session,
        task: OperationTask,
        profile: OperationProfile,
        plan: OperationPlan,
        adapter: DeviceAdapter,
        session_ctx: DeviceSession,
        result: OperationResult,
    ) -> None:
        """One read-back verification after execute (no async job)."""
        verdict = self._call_verify(session, task, profile, plan, adapter, session_ctx, result)
        if verdict is None:
            return
        if verdict.pending:
            # A single-shot verify should never report pending without a job;
            # treat it as unprovable rather than inventing a result.
            self._verification_required(
                session,
                task,
                "回读验证无结果（作业仍在进行且无已持久化作业 ID）",
            )
            return
        self._finish_verdict(session, task, result, verdict)

    def _poll_device_job(
        self,
        session: Session,
        task: OperationTask,
        profile: OperationProfile,
        plan: OperationPlan,
        adapter: DeviceAdapter,
        session_ctx: DeviceSession,
        result: OperationResult,
    ) -> None:
        """Persist the vendor job id, then poll it with lease renewals.

        DATA_MODEL.md §7.1: 存在时只查询，不重复创建 — the job id is stored
        (with the waiting_device event) BEFORE the first poll, so every later
        poll only ever queries the SAME job.
        """
        assert result.device_job_id is not None
        if task.state == TaskState.RUNNING.value:
            waiting = enter_waiting_device(
                session,
                task_id=task.id,
                owner=self._lease_owner,
                device_job_id=result.device_job_id,
            )
            if waiting is None:
                return
            self._emit_ui_event(session, waiting)
            session.commit()
        timeout_at = task.timeout_at
        while True:
            if self._deadline_passed_at(timeout_at):
                self._handle_timeout_like(
                    session, task, profile, reason="任务总超时已到（设备作业未在时限内完成）"
                )
                return
            verdict = self._call_verify(session, task, profile, plan, adapter, session_ctx, result)
            if verdict is None:
                return
            if not verdict.pending:
                self._finish_verdict(session, task, result, verdict)
                return
            # Job still running: renew the lease, then wait one poll interval.
            if not renew_lease(
                session,
                task_id=task.id,
                owner=self._lease_owner,
                lease_seconds=self._lease_seconds,
            ):
                return
            session.commit()
            remaining = self._remaining_seconds(timeout_at)
            sleep_for = min(
                self._job_poll_interval,
                max(0.0, remaining - DEADLINE_MARGIN_SECONDS)
                if remaining is not None
                else self._job_poll_interval,
            )
            if sleep_for > 0:
                time.sleep(sleep_for)

    def _call_verify(
        self,
        session: Session,
        task: OperationTask,
        profile: OperationProfile,
        plan: OperationPlan,
        adapter: DeviceAdapter,
        session_ctx: DeviceSession,
        result: OperationResult,
    ) -> VerificationResult | None:
        """Run one adapter verify call; maps failures per the §9 rules."""
        try:
            return adapter.verify_operation(session_ctx, plan, result)
        except AdapterTimeoutError as exc:
            self._handle_timeout_like(session, task, profile, reason=f"回读验证超时：{exc.message}")
            return None
        except AdapterError as exc:
            # Cannot prove success or failure -> verification_required
            # (DEVICE_ADAPTERS.md §9: 无法证明成功或失败：进入 verification_required).
            self._verification_required(
                session,
                task,
                f"回读验证失败（{exc.code}）：无法证明操作结果，等待核验（不自动重放）",
            )
            return None

    def _finish_verdict(
        self,
        session: Session,
        task: OperationTask,
        execution: OperationResult,
        verdict: VerificationResult,
    ) -> None:
        """Map a verification verdict to the terminal/holding transition."""
        evidence = self._evidence(execution, verdict)
        if verdict.ambiguous:
            self._verification_required(
                session,
                task,
                "回读验证无法确认操作结果（ambiguous），等待人工核验",
                evidence=evidence,
            )
            return
        if verdict.succeeded:
            updated = transition_task(
                session,
                task_id=task.id,
                owner=self._lease_owner,
                to_state=TaskState.SUCCEEDED,
                message="操作执行成功并通过回读验证",
                now=utcnow(),
                result_summary="操作执行成功并通过回读验证",
                verification_state="passed",
                evidence=evidence,
            )
            outcome = "succeeded"
        else:
            updated = transition_task(
                session,
                task_id=task.id,
                owner=self._lease_owner,
                to_state=TaskState.FAILED,
                message="回读验证确认操作未达到预期结果",
                now=utcnow(),
                result_summary="回读验证确认操作未达到预期结果",
                error_code=verdict.error_code or "operation_failed",
                error_detail=verdict.error_code or "operation_failed",
                verification_state="failed",
                evidence=evidence,
            )
            outcome = "failed"
        if updated is None:
            return
        self._finish_bookkeeping(session, updated, outcome)

    def _evidence(
        self, execution: OperationResult, verdict: VerificationResult
    ) -> dict[str, object]:
        evidence: dict[str, object] = {}
        if execution.evidence:
            evidence["execution"] = dict(execution.evidence)
        verification: dict[str, object] = {
            "succeeded": verdict.succeeded,
            "ambiguous": verdict.ambiguous,
            "pending": verdict.pending,
        }
        verification.update(dict(verdict.evidence))
        evidence["verification"] = verification
        return evidence

    # -- verify-only recovery path -----------------------------------------

    def _verify_only(self, session: Session, task: OperationTask, profile: OperationProfile) -> None:
        """Consume a parked fenced task: read-back/verify ONLY (M2T6).

        DEVICE_ADAPTERS.md §9: after the dispatch fence of a side-effect task
        (or a read task with a persisted job) the recovery handler may only
        call ``verify_operation`` — never ``execute_operation``. Terminal
        state + audit + ui_events still land in one transaction.
        """
        if self._deadline_passed(task):
            self._handle_timeout_like(session, task, profile, reason="任务总超时已到（恢复核验）")
            return
        device = session.get(Device, task.device_id)
        if device is None:
            self._verification_required(session, task, "设备已不存在，无法回读核验操作结果")
            return
        try:
            adapter = get_adapter(device.adapter_key)
            plan = plan_operation(
                build_snapshot(session, device),
                OperationRequest(
                    capability_key=task.capability_key, parameters=dict(task.parameters)
                ),
            )
        except (AppError, UnknownAdapterError) as exc:
            detail = exc.message if isinstance(exc, AppError) else str(exc)
            self._verification_required(
                session,
                task,
                f"无法回读核验（{detail[:200]}）：操作结果无法证明，等待人工核验",
            )
            return
        session_ctx = self._device_session(session, task, device)
        if session_ctx is None:
            self._verification_required(session, task, "设备凭据不可用，无法回读核验操作结果")
            return
        # Verify-only recovery of a file-consuming task rebuilds the platform
        # context best-effort (tickets/files may still be live).
        plan = self._operation_context(session, task, device, plan, recovery=True) or plan
        persisted = OperationResult(
            ok=task.error_code is None,
            evidence=dict(task.evidence) if task.evidence else {},
            error_code=task.error_code,
            error_detail=task.error_detail,
            device_job_id=task.device_job_id,
        )
        if task.state == TaskState.WAITING_DEVICE.value or task.device_job_id is not None:
            if task.state == TaskState.RUNNING.value:
                waiting = enter_waiting_device(
                    session,
                    task_id=task.id,
                    owner=self._lease_owner,
                    device_job_id=task.device_job_id or "",
                )
                if waiting is None:
                    return
                self._emit_ui_event(session, waiting)
                session.commit()
            self._poll_device_job(session, task, profile, plan, adapter, session_ctx, persisted)
        else:
            self._verify_once(session, task, profile, plan, adapter, session_ctx, persisted)

    # -- M3T3 platform execution material (files/tickets/artifacts) ----------

    def _file_audit(self, task: OperationTask) -> FileAuditContext:
        return FileAuditContext(
            actor_user_id=task.requested_by,
            session_id=None,
            source_ip=None,
            user_agent_summary=None,
            request_id=f"operation:{task.id}",
        )

    def _file_services(self) -> tuple[FileStorage, FileKeyCipher | None]:
        """Lazily-built file-volume services (same root/cipher as the API)."""
        if self._file_storage is None:
            self._file_storage = FileStorage(self._settings.resolved_file_store_root)
        if self._file_key_cipher is None:
            material = self._settings.file_master_key.get_secret_value().encode("utf-8")
            if material:
                self._file_key_cipher = FileKeyCipher(material)
        return self._file_storage, self._file_key_cipher

    def _input_file_row(
        self, session: Session, task: OperationTask, file_id: object, *, file_type: str
    ) -> File | None:
        """Load and validate an operation input file row (pre-fence, M3T3)."""
        parsed = uuid.UUID(str(file_id)) if isinstance(file_id, str) else None
        row = session.get(File, parsed) if parsed is not None else None
        if row is None:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail="任务引用的文件不存在，操作未执行；请重新预览",
            )
            return None
        if row.status != "ready" or row.sha256 is None:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail="任务引用的文件未就绪，操作未执行",
            )
            return None
        if row.file_type != file_type:
            self._fail_task(
                session,
                task,
                error_code="validation_failed",
                error_detail=f"文件类型与操作不匹配（期望 {file_type}）",
            )
            return None
        return row

    def _firmware_image_metadata(
        self, storage: FileStorage, file_row: File
    ) -> dict[str, str] | None:
        """Parse the warden-sim firmware image header (bounded head read).

        The platform reads ONLY the certified image header (simulator shape;
        real vendor images are M3T5 overlay territory). An unreadable/absent
        header returns None — the platform never guesses package metadata.
        """
        stored = StoredFile(
            storage_key=storage_key(file_row),
            encrypted=False,
            size_bytes=file_row.size_bytes,
            key_version=None,
        )
        try:
            limit = min(IMAGE_HEADER_MAX_BYTES, file_row.size_bytes)
            chunks = storage.open_chunks(
                stored, key_cipher=None, start=0, limit=limit
            )
            head = b"".join(chunks)
        except (FileStorageError, ValueError):
            return None
        line, _, _ = head.partition(b"\n")
        if not line.startswith(IMAGE_HEADER_MARKER):
            return None
        raw = line[len(IMAGE_HEADER_MARKER) :].strip()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        model = payload.get("model")
        target = payload.get("target")
        version = payload.get("version")
        if not (
            isinstance(model, str)
            and model
            and isinstance(target, str)
            and target
            and isinstance(version, str)
            and version
        ):
            return None
        return {"model": model, "target": target, "version": version}

    def _nas_pat_metadata(
        self, storage: FileStorage, file_row: File
    ) -> dict[str, str] | None:
        """Parse the warden-sim PAT header (bounded head read).

        The platform reads ONLY the certified PAT header shape (simulator
        DSL; real Synology PAT metadata parsing is vendor_private — [sim]
        basis until target-model certification records the exact format,
        ADR-018). An unreadable/absent header returns None — the platform
        never guesses package metadata.
        """
        stored = StoredFile(
            storage_key=storage_key(file_row),
            encrypted=False,
            size_bytes=file_row.size_bytes,
            key_version=None,
        )
        try:
            limit = min(PAT_HEADER_MAX_BYTES, file_row.size_bytes)
            chunks = storage.open_chunks(stored, key_cipher=None, start=0, limit=limit)
            head = b"".join(chunks)
        except (FileStorageError, ValueError):
            return None
        line, _, _ = head.partition(b"\n")
        if not line.startswith(PAT_HEADER_MARKER):
            return None
        raw = line[len(PAT_HEADER_MARKER) :].strip()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        model = payload.get("model")
        version = payload.get("version")
        if not (
            isinstance(model, str)
            and model
            and isinstance(version, str)
            and version
        ):
            return None
        return {"model": model, "version": version}

    def _operation_context(
        self,
        session: Session,
        task: OperationTask,
        device: Device,
        plan: OperationPlan,
        *,
        recovery: bool = False,
    ) -> OperationPlan | None:
        """Assemble the platform runtime context for one operation.

        File-consuming operations (virtual_media.mount, firmware.update)
        resolve the input file row, link it to the task, and issue (or reuse)
        the platform device-pull ticket bound to device+file+purpose+expiry;
        the ticket URL is what the adapter passes to the device — never a
        user-supplied URL. unmount validates that the slot belongs to a
        platform-managed mount before anything touches the device. All this
        happens BEFORE the dispatch fence; in the verify-only recovery path it
        is best-effort (a missing context degrades verification to ambiguous,
        never to success).
        """
        try:
            return self._operation_context_or_error(session, task, device, plan)
        except Exception as exc:  # noqa: BLE001
            if recovery:
                self._log.info(
                    "operation_context_recovery_degraded",
                    task_id=str(task.id),
                    error=type(exc).__name__,
                )
                runtime = dict(plan.runtime_context)
                if task.timeout_at is not None:
                    runtime["task_timeout_at"] = task.timeout_at.isoformat()
                return _replace_plan_runtime(plan, runtime)
            raise

    def _operation_context_or_error(
        self,
        session: Session,
        task: OperationTask,
        device: Device,
        plan: OperationPlan,
    ) -> OperationPlan | None:
        runtime: dict[str, object] = {}
        if task.timeout_at is not None:
            runtime["task_timeout_at"] = task.timeout_at.isoformat()
        key = plan.capability_key
        audit = self._file_audit(task)
        if key == "virtual_media.mount":
            file_row = self._input_file_row(
                session, task, plan.normalized_parameters.get("file_id"), file_type="virtual_media"
            )
            if file_row is None:
                return None
            link_input_file(
                db=session,
                file_row=file_row,
                device_id=device.id,
                task_id=task.id,
                created_by=task.requested_by,
            )
            ticket = active_device_file_ticket(
                db=session, device_id=device.id, file_id=file_row.id, purpose="virtual_media"
            )
            if ticket is None:
                ticket = issue_device_file_ticket(
                    db=session,
                    file_row=file_row,
                    device=device,
                    purpose="virtual_media",
                    expires_at=utcnow() + datetime.timedelta(hours=VIRTUAL_MEDIA_TICKET_HOURS),
                    task_id=task.id,
                    logger=self._audit_logger,
                    audit=audit,
                )
                session.flush()
            runtime["file"] = {
                "file_id": str(file_row.id),
                "file_type": file_row.file_type,
                "sha256": file_row.sha256,
            }
            runtime["ticket"] = {
                "url": ticket_url_for(self._settings, ticket),
                "id": str(ticket.id),
            }
        elif key == "firmware.update":
            file_row = self._input_file_row(
                session, task, plan.normalized_parameters.get("file_id"), file_type="firmware"
            )
            if file_row is None:
                return None
            storage, _cipher = self._file_services()
            if plan.requirement_id in ("CORE-ACT-07", "ACCESS-ACT-06"):
                # Switch firmware (M5T3): the image travels via SFTP from the
                # Warden host (the switch only SERVES SFTP), so there is no
                # device-pull ticket — the runtime carries a chunk stream
                # over the plain firmware file plus the warden-sim header
                # metadata (model + target version). Anything else fails
                # BEFORE the dispatch fence.
                metadata = self._vrp_image_metadata(storage, file_row)
                if metadata is None:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail="固件包元数据无法解析（缺少 warden-sim 图像头），操作未执行",
                    )
                    return None
                if device.model is not None and device.model != metadata["model"]:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail=f"固件包型号（{metadata['model']}）与设备型号（{device.model}）不匹配，操作未执行",
                    )
                    return None
                link_input_file(
                    db=session,
                    file_row=file_row,
                    device_id=device.id,
                    task_id=task.id,
                    created_by=task.requested_by,
                )
                stored = StoredFile(
                    storage_key=storage_key(file_row),
                    encrypted=False,
                    size_bytes=file_row.size_bytes,
                    key_version=None,
                )
                expected_model = metadata["model"]
                expected_version = metadata["version"]
                stream = self._plain_stream_provider(storage, stored)
                runtime["file"] = {
                    "file_id": str(file_row.id),
                    "file_type": file_row.file_type,
                    "sha256": file_row.sha256,
                    "size_bytes": file_row.size_bytes,
                    "expected_model": expected_model,
                    "expected_version": expected_version,
                    "stream": stream,
                }
                return _replace_plan_runtime(plan, runtime)
            if plan.requirement_id == "NAS-ACT-06":
                # NAS PAT update (M4T3): the warden-sim PAT header carries
                # model + version only (no target inventory id). The model
                # must match the device — anything else fails BEFORE the
                # dispatch fence (validation_failed), never reaching the DSM.
                metadata = self._nas_pat_metadata(storage, file_row)
                if metadata is None:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail="PAT 包元数据无法解析（缺少 warden-sim PAT 头），操作未执行",
                    )
                    return None
                if device.model is not None and device.model != metadata["model"]:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail=f"PAT 包型号（{metadata['model']}）与设备型号（{device.model}）不匹配，操作未执行",
                    )
                    return None
            else:
                metadata = self._firmware_image_metadata(storage, file_row)
                target_id = plan.normalized_parameters.get("target_id")
                if metadata is None:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail="固件包元数据无法解析（缺少 warden-sim 图像头），操作未执行",
                    )
                    return None
                if metadata["target"] != target_id:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail=f"固件包目标（{metadata['target']}）与操作参数（{target_id}）不一致，操作未执行",
                    )
                    return None
                if device.model is not None and device.model != metadata["model"]:
                    self._fail_task(
                        session,
                        task,
                        error_code="validation_failed",
                        error_detail=f"固件包型号（{metadata['model']}）与设备型号（{device.model}）不匹配，操作未执行",
                    )
                    return None
            link_input_file(
                db=session,
                file_row=file_row,
                device_id=device.id,
                task_id=task.id,
                created_by=task.requested_by,
            )
            ticket = active_device_file_ticket(
                db=session, device_id=device.id, file_id=file_row.id, purpose="firmware"
            )
            if ticket is None:
                ticket = issue_device_file_ticket(
                    db=session,
                    file_row=file_row,
                    device=device,
                    purpose="firmware",
                    expires_at=utcnow() + datetime.timedelta(seconds=plan.timeout_seconds),
                    task_id=task.id,
                    logger=self._audit_logger,
                    audit=audit,
                )
                session.flush()
            file_ctx: dict[str, object] = {
                "file_id": str(file_row.id),
                "file_type": file_row.file_type,
                "sha256": file_row.sha256,
                "expected_model": metadata["model"],
                "expected_version": metadata["version"],
            }
            if "expected_target" in metadata:
                file_ctx["expected_target"] = metadata["target"]
            runtime["file"] = file_ctx
            runtime["ticket"] = {
                "url": ticket_url_for(self._settings, ticket),
                "id": str(ticket.id),
            }
        elif key == "config.restore":
            # CORE-ACT-05/ACCESS-ACT-05 restore (M5T3): the ONLY input is a
            # Warden-produced config_backup artifact (origin check via the
            # output_config_backup link bound to THIS device), whose decrypted
            # content + model/VRP metadata travel in the runtime context for
            # the adapter's certified full-replace strategy. The content is
            # bounded (RESTORE_CONTENT_MAX_BYTES); anything unexpected fails
            # BEFORE the dispatch fence (validation_failed).
            file_row = self._input_file_row(
                session,
                task,
                plan.normalized_parameters.get("file_id"),
                file_type="config_backup",
            )
            if file_row is None:
                return None
            origin = session.execute(
                select(FileLink).where(
                    FileLink.file_id == file_row.id,
                    FileLink.device_id == device.id,
                    FileLink.purpose == "output_config_backup",
                )
            ).scalar_one_or_none()
            if origin is None:
                self._fail_task(
                    session,
                    task,
                    error_code="validation_failed",
                    error_detail="配置文件不是本设备上由平台产出（缺少 output_config_backup 归属），操作未执行",
                )
                return None
            backup_metadata = file_row.metadata_json or {}
            model = backup_metadata.get("model")
            vrp_version = backup_metadata.get("vrp_version")
            if not (
                isinstance(model, str)
                and isinstance(vrp_version, str)
                and file_row.sha256 is not None
            ):
                self._fail_task(
                    session,
                    task,
                    error_code="validation_failed",
                    error_detail="配置备份缺少模型/VRP 元数据或散列，无法执行恢复",
                )
                return None
            storage, cipher = self._file_services()
            stored = StoredFile(
                storage_key=storage_key(file_row),
                encrypted=file_row.encrypted,
                size_bytes=file_row.size_bytes,
                key_version=file_row.key_version,
            )
            content = self._decrypt_bounded(storage, cipher, stored)
            if content is None:
                self._fail_task(
                    session,
                    task,
                    error_code="validation_failed",
                    error_detail="配置备份内容不可解密或超过恢复上限，操作未执行",
                )
                return None
            runtime["restore"] = {
                "file_id": str(file_row.id),
                "content_b64": base64.b64encode(content).decode("ascii"),
                "model": model,
                "vrp_version": vrp_version,
                "vrp_major": self._vrp_major_of(vrp_version),
                "sha256": file_row.sha256,
            }
        elif key == "snmp.configure":
            # The trap receiver address comes ONLY from the deployment
            # configuration (NAS-ACT-06 profile prohibition: 用户不能提供接
            # 收地址 — the parameter schema accepts enabled only). An empty
            # value stays in the context so the ADAPTER preflight fails
            # not_configured before the dispatch fence.
            receiver = self._settings.snmp_trap_receiver_address.strip()
            runtime[SNMP_RECEIVER_CTX_KEY] = {"address": receiver}
        elif key == "virtual_media.unmount":
            slot_id = plan.normalized_parameters.get("slot_id")
            if isinstance(slot_id, str) and self._mount_task_for_slot(session, task, slot_id) is None:
                self._fail_task(
                    session,
                    task,
                    error_code="validation_failed",
                    error_detail="未找到该槽位对应的平台虚拟介质挂载记录，操作未执行",
                )
                return None
        elif key in (
            "logs.support_bundle.collect",
            "logs.diagnostic.collect",
            "logs.collect",
            "config.backup",
        ):
            storage, _cipher = self._file_services()
            try:
                storage.check_available()
            except FileStorageError:
                self._fail_task(
                    session,
                    task,
                    error_code="storage_unavailable",
                    error_detail="文件存储不可用，无法保存操作产物",
                )
                return None
        return _replace_plan_runtime(plan, runtime)

    def _vrp_image_metadata(
        self, storage: FileStorage, file_row: File
    ) -> dict[str, str] | None:
        """Parse the warden-sim switch image header (model + version).

        The VRP switch firmware shape carries NO ``target`` inventory id
        (CORE-ACT-07/ACCESS-ACT-06 profiles take file_id only) — everything
        else mirrors the server image parser. An unreadable/absent header
        returns None — the platform never guesses package metadata.
        """
        stored = StoredFile(
            storage_key=storage_key(file_row),
            encrypted=False,
            size_bytes=file_row.size_bytes,
            key_version=None,
        )
        try:
            limit = min(IMAGE_HEADER_MAX_BYTES, file_row.size_bytes)
            head = b"".join(
                storage.open_chunks(stored, key_cipher=None, start=0, limit=limit)
            )
        except (FileStorageError, ValueError):
            return None
        line, _, _ = head.partition(b"\n")
        if not line.startswith(IMAGE_HEADER_MARKER):
            return None
        raw = line[len(IMAGE_HEADER_MARKER) :].strip()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        model = payload.get("model")
        version = payload.get("version")
        if not (
            isinstance(model, str)
            and model
            and isinstance(version, str)
            and version
        ):
            return None
        return {"model": model, "version": version}

    def _plain_stream_provider(
        self, storage: FileStorage, stored: StoredFile
    ) -> Callable[[], Iterator[bytes]]:
        """A re-openable chunk stream over a PLAIN stored file.

        The adapter boundary rule (M3T3) keeps adapters away from storage
        paths; this provider hands the firmware transfer an opaque chunk
        stream that re-opens the volume on every call — bounded memory, no
        paths, and the plain firmware file never touches the adapter config.
        """

        def _stream() -> Iterator[bytes]:
            yield from storage.open_chunks(stored, key_cipher=None)

        return _stream

    def _decrypt_bounded(
        self,
        storage: FileStorage,
        cipher: FileKeyCipher | None,
        stored: StoredFile,
    ) -> bytes | None:
        """Decrypt a sensitive config_backup artifact (bounded read).

        Restore payloads are small running configs; anything beyond the
        restore cap is refused (never an unbounded memory copy)."""
        if stored.encrypted and cipher is None:
            return None
        cap = 8 * 1024 * 1024
        if stored.size_bytes > cap:
            return None
        try:
            return b"".join(storage.open_chunks(stored, key_cipher=cipher, start=0, limit=None))
        except (FileStorageError, ValueError):
            return None

    @staticmethod
    def _vrp_major_of(vrp_version: str) -> str | None:
        """The VRP major prefix gate (restore identity precondition)."""
        import re

        match = re.match(r"^(V[0-9]+R[0-9]+C[0-9]+)", vrp_version.strip())
        return match.group(1) if match is not None else None

    def _mount_task_for_slot(
        self, session: Session, task: OperationTask, slot_id: str
    ) -> OperationTask | None:
        """The latest SUCCEEDED mount task whose evidence names ``slot_id``.

        Platform-side knowledge of which slot holds OUR medium comes from the
        mount task evidence (never from the device alone) — unmount only acts
        on platform-managed mounts.
        """
        candidates = session.scalars(
            select(OperationTask)
            .where(
                OperationTask.device_id == task.device_id,
                OperationTask.requirement_id == "SRV-ACT-05",
                OperationTask.capability_key == "virtual_media.mount",
                OperationTask.state == TaskState.SUCCEEDED.value,
            )
            .order_by(OperationTask.created_at.desc())
            .limit(10)
        ).all()
        for candidate in candidates:
            evidence = dict(candidate.evidence) if candidate.evidence else {}
            execution = evidence.get("execution")
            nested = execution if isinstance(execution, dict) else evidence
            if nested.get("slot_id") == slot_id:
                return candidate
        return None

    def _revoke_tickets_of_task(
        self, session: Session, task: OperationTask, purpose: str
    ) -> list[str]:
        """Revoke every (unrevoked) ticket this task created (idempotent)."""
        from app.models.files import DeviceFileTicket as TicketRow

        rows = session.scalars(
            select(TicketRow).where(
                TicketRow.created_by_task_id == task.id,
                TicketRow.device_id == task.device_id,
                TicketRow.purpose == purpose,
                TicketRow.revoked_at.is_(None),
            )
        ).all()
        revoked: list[str] = []
        audit = self._file_audit(task)
        for ticket in rows:
            revoke_device_file_ticket(
                db=session,
                ticket_id=str(ticket.id),
                logger=self._audit_logger,
                audit=audit,
                device_id=task.device_id,
            )
            revoked.append(str(ticket.id))
        return revoked

    def _consume_execution_outputs(
        self,
        session: Session,
        task: OperationTask,
        device: Device,
        plan: OperationPlan,
        result: OperationResult,
    ) -> OperationResult | None:
        """Persist the execution side outputs and merge their proofs.

        Artifacts -> encrypted file rows + file_links (adapter boundary: the
        adapter yielded bytes; the platform stores). Inventory -> device row +
        operation-applied components. unmount -> the platform revokes the
        mount's ticket right after a successful eject. The merged execution
        evidence is checkpointed onto the task row so the verify-only recovery
        can still read back (crash between execute and the terminal
        transition). Any persistence failure fails the task safely BEFORE
        verification — never a fabricated success.
        """
        storage, cipher = self._file_services()
        audit = self._file_audit(task)
        merged_evidence = dict(result.evidence)
        try:
            stored_rows: list[dict[str, object]] = []
            for artifact in result.artifacts:
                row = store_operation_artifact(
                    db=session,
                    artifact=artifact,
                    device_id=device.id,
                    task_id=task.id,
                    created_by=task.requested_by,
                    storage=storage,
                    key_cipher=cipher,
                    logger=self._audit_logger,
                    audit=audit,
                )
                stored_rows.append(
                    {
                        "file_id": str(row.id),
                        "file_type": row.file_type,
                        "sha256": row.sha256,
                        "encrypted": row.encrypted,
                        "size_bytes": row.size_bytes,
                        "filename": artifact.filename,
                        "status": row.status,
                    }
                )
            if stored_rows:
                merged_evidence["artifact_stored"] = stored_rows[0]
                merged_evidence["artifacts_stored"] = stored_rows
            if result.inventory is not None:
                proof = apply_operation_inventory(
                    session, device=device, inventory=result.inventory
                )
                merged_evidence["inventory_persisted"] = proof
            if plan.capability_key == "virtual_media.unmount":
                slot_id = plan.normalized_parameters.get("slot_id")
                mount = (
                    self._mount_task_for_slot(session, task, slot_id)
                    if isinstance(slot_id, str)
                    else None
                )
                if mount is not None:
                    revoked = self._revoke_tickets_of_task(session, mount, "virtual_media")
                    if revoked:
                        merged_evidence["ticket_revoked"] = utcnow().isoformat()
        except AppError as exc:
            code = (
                exc.code
                if exc.code in ("storage_unavailable", "dependency_unavailable", "validation_failed")
                else "internal_error"
            )
            self._fail_task(
                session,
                task,
                error_code=code,
                error_detail=f"执行产物持久化失败：{exc.message[:200]}",
            )
            return None
        except (FileStorageError, ValueError) as exc:
            self._fail_task(
                session,
                task,
                error_code="storage_unavailable",
                error_detail=f"执行产物写入失败：{type(exc).__name__}",
            )
            return None
        consumed = _replace_result_evidence(result, merged_evidence)
        checkpointed = record_execution_evidence(
            session,
            task_id=task.id,
            owner=self._lease_owner,
            evidence=merged_evidence,
        )
        if checkpointed is None:
            return None
        session.commit()
        return consumed

    def _release_task_resources(
        self, session: Session, task: OperationTask, outcome: str
    ) -> None:
        """Terminal bookkeeping: revoke task-bound tickets that are dead.

        Rules (M3T3): a firmware-update ticket dies on every terminal outcome
        except verification_required (the job may still be transferring); a
        mount ticket dies on failed/timed_out (nothing usable was mounted) but
        SURVIVES success (the medium stays mounted until unmount or expiry)
        and verification_required (it may be mounted); unmount tickets are
        revoked right after a successful eject (execute path), never here.
        Revocation only ever touches tickets this task created (pre-fence
        context issuance included).
        """
        key = task.capability_key
        try:
            if key == "firmware.update" and outcome != "verification_required":
                self._revoke_tickets_of_task(session, task, "firmware")
            elif key == "virtual_media.mount" and outcome in ("failed", "timed_out"):
                self._revoke_tickets_of_task(session, task, "virtual_media")
        except Exception:  # noqa: BLE001
            self._log.exception(
                "task_resource_release_failed",
                task_id=str(task.id),
                message="ticket revocation failed; expiry/retention sweep is the fallback",
            )

    # -- terminal/holding bookkeeping --------------------------------------

    def _fail_task(
        self,
        session: Session,
        task: OperationTask,
        *,
        error_code: str,
        error_detail: str,
        execution_evidence: dict[str, object] | None = None,
    ) -> None:
        evidence: dict[str, object] | None = (
            {"execution": dict(execution_evidence)} if execution_evidence else None
        )
        detail = error_detail[:400]
        updated = transition_task(
            session,
            task_id=task.id,
            owner=self._lease_owner,
            to_state=TaskState.FAILED,
            message="操作失败：" + (error_code + "：" + error_detail)[:300],
            now=utcnow(),
            result_summary="操作失败：" + detail[:300],
            error_code=error_code,
            error_detail=detail,
            evidence=evidence,
        )
        if updated is None:
            return
        self._finish_bookkeeping(session, updated, "failed", error_code=error_code)

    def _verification_required(
        self,
        session: Session,
        task: OperationTask,
        message: str,
        *,
        evidence: dict[str, object] | None = None,
    ) -> None:
        updated = transition_task(
            session,
            task_id=task.id,
            owner=self._lease_owner,
            to_state=TaskState.VERIFICATION_REQUIRED,
            message=message[:400],
            now=utcnow(),
            result_summary="结果待核验：" + message[:300],
            error_code="ambiguous_result",
            error_detail=message[:400],
            evidence=evidence,
        )
        if updated is None:
            return
        self._finish_bookkeeping(session, updated, "verification_required")

    def _handle_timeout_like(
        self,
        session: Session,
        task: OperationTask,
        profile: OperationProfile,
        reason: str,
    ) -> None:
        """Deadline/adapter-timeout outcome per ``timeout_transition`` rules.

        Fenced side-effect tasks become verification_required (the device may
        have accepted the action; never failed + auto-replay); unfenced or
        read profiles become timed_out (positive no-execution evidence or no
        irreversible effect — M2T1 timeout semantics).
        """
        fence = TaskFence(task.dispatch_started_at, task.device_job_id)
        to_state = timeout_transition(fence, profile)
        if to_state is TaskState.VERIFICATION_REQUIRED:
            self._verification_required(
                session,
                task,
                f"{reason}；设备可能已接受动作，等待核验（不自动重放）",
            )
            return
        updated = transition_task(
            session,
            task_id=task.id,
            owner=self._lease_owner,
            to_state=TaskState.TIMED_OUT,
            message=f"{reason}；无继续执行证据（从未派发或只读 profile）",
            now=utcnow(),
            result_summary="任务超时：" + reason[:300],
            error_code=None,
            error_detail=None,
        )
        if updated is None:
            return
        self._finish_bookkeeping(session, updated, "timed_out")

    def _finish_bookkeeping(
        self,
        session: Session,
        updated: OperationTask,
        outcome: str,
        *,
        error_code: str | None = None,
    ) -> None:
        """Audit + ui_event in the SAME transaction as the terminal/holding
        transition (DATA_MODEL.md §11)."""
        self._release_task_resources(session, updated, outcome)
        self._emit_ui_event(session, updated)
        self._audit_finish(session, updated, outcome, error_code=error_code)
        session.commit()

    def _audit_start(self, session: Session, task: OperationTask) -> None:
        if self._audit_logger is None:
            return
        self._audit_logger.record_in(
            session,
            action="operation.start",
            actor_user_id=task.requested_by,
            resource_type="operation_task",
            resource_id=str(task.id),
            device_id=task.device_id,
            requirement_id=task.requirement_id,
            task_id=task.id,
            result="dispatched",
            detail={
                "capability_key": task.capability_key,
                "risk_level": task.risk_level,
                "plan_hash": task.plan_hash,
                "parameter_hash": task.parameter_hash,
                "adapter_version": task.adapter_version,
                "timeout_at": task.timeout_at.isoformat() if task.timeout_at else None,
            },
        )

    def _audit_finish(
        self,
        session: Session,
        task: OperationTask,
        outcome: str,
        *,
        error_code: str | None = None,
    ) -> None:
        if self._audit_logger is None:
            return
        self._audit_logger.record_in(
            session,
            action="operation.finish",
            actor_user_id=task.requested_by,
            resource_type="operation_task",
            resource_id=str(task.id),
            device_id=task.device_id,
            requirement_id=task.requirement_id,
            task_id=task.id,
            result=outcome,
            detail={
                "capability_key": task.capability_key,
                "state": task.state,
                "error_code": error_code or task.error_code,
                "verification_state": task.verification_state,
                "device_job_id": task.device_job_id,
            },
        )

    def _emit_ui_event(self, session: Session, task: OperationTask) -> None:
        emit_ui_event(
            session,
            entity_type="operation_task",
            entity_id=task.id,
            version=task.version,
            event_type=UI_EVENT_TYPE_OPERATION_UPDATED,
            payload={"state": task.state},
        )

    # -- timing helpers -----------------------------------------------------

    @staticmethod
    def _remaining_seconds(timeout_at: datetime.datetime | None) -> float | None:
        if timeout_at is None:
            return None
        return (timeout_at - utcnow()).total_seconds()

    def _deadline_passed_at(self, timeout_at: datetime.datetime | None) -> bool:
        remaining = self._remaining_seconds(timeout_at)
        return remaining is not None and remaining <= DEADLINE_MARGIN_SECONDS

    def _deadline_passed(self, task: OperationTask) -> bool:
        return self._deadline_passed_at(task.timeout_at)

    @staticmethod
    def _safe(message: str, stage: str | None) -> str:
        """Sanitized adapter summary: stable code + short safe message."""
        prefix = f"{stage}：" if stage else ""
        return (prefix + message)[:400]
