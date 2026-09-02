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
  left via the admin verify/resolve flows;
- adapter errors are never swallowed into success; a timeout error maps per
  ``timeout_transition`` (fenced side-effect -> verification_required).

Transient adapter failures of READ profiles do not auto-retry here: the task
fails terminally with the adapter error code (API_CONTRACT.md §6.2: 终态无
retry API); crash-driven retry as NEW attempts is the maintenance recovery's
job (bounded by ``attempt_count`` + ``operation_read_max_attempts``).
"""

from __future__ import annotations

import datetime
import json
import time
import uuid
from collections.abc import Callable

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.adapters import UnknownAdapterError, get_adapter
from app.application.collection import emit_ui_event
from app.application.operations import build_snapshot
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
    credential_aad,
)
from app.infrastructure.tasks import (
    dispatch_fence,
    enter_waiting_device,
    renew_lease,
    transition_task,
    update_progress,
)
from app.infrastructure.time import utcnow
from app.models.devices import Device, DeviceCredential
from app.models.operation import OperationTask

# An adapter is allowed this many seconds past the plan deadline to return a
# verdict; the executor stops ITS OWN wait loops at ``timeout_at`` regardless.
DEADLINE_MARGIN_SECONDS = 0.25

UI_EVENT_TYPE_OPERATION_UPDATED = "operation.updated"


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
            self._fail_task(
                session,
                task,
                error_code=exc.code,
                error_detail=self._safe(exc.message, exc.stage),
            )
            return
        if not result.ok:
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
