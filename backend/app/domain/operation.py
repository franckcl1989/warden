"""Operation task state machine, dispatch fence and recovery rules.

docs/DATA_MODEL.md §7.2 (state machine diagram), docs/DEVICE_ADAPTERS.md §9
(dispatch fence / replay protection), contracts/operations.json (per-operation
semantics). This module is pure domain: it imports no FastAPI, SQLAlchemy or
vendor SDK (ARCHITECTURE.md §4). Every per-operation value (side_effect,
expected_disconnect, cancel_policy, verification.ambiguous) is read from the
generated operation profile registry by the caller; only platform invariants
(mutex scope set, cancel-policy vocabulary, state vocabulary) live here.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from enum import StrEnum

from app.domain.contracts import OperationProfile

# 0.1.0 conservative mutex mapping (decision documented in migration 0005):
# profiles declaring conflict_scope=device or component:disk both map to a
# device-level mutual exclusion (two component-scoped tasks on one device
# never run concurrently). Read scopes (device_read / device_read_heavy) and
# launch scopes never conflict and never enter this set.
MUTEX_SCOPES: frozenset[str] = frozenset({"device", "component:disk"})

# contracts/operations.json cancel_policy vocabulary (loader-validated).
CANCEL_POLICY_BEFORE_DISPATCH_ONLY = "before_dispatch_only"
CANCEL_POLICY_ADAPTER_DECLARED = "adapter_declared_before_device_job"
CANCEL_POLICY_NOT_APPLICABLE = "not_applicable"
# Running tasks may only be cancelled while unfenced and under one of these
# policies; adapter_declared_before_device_job keeps its M2T6 caveat (the
# adapter may declare a later cancellation boundary once device jobs land).
CANCELLABLE_RUNNING_POLICIES: frozenset[str] = frozenset(
    {CANCEL_POLICY_BEFORE_DISPATCH_ONLY, CANCEL_POLICY_ADAPTER_DECLARED}
)


class TaskState(StrEnum):
    """Operation task states (docs/DATA_MODEL.md §7.2, GLOSSARY.md)."""

    QUEUED = "queued"
    RUNNING = "running"
    WAITING_DEVICE = "waiting_device"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    VERIFICATION_REQUIRED = "verification_required"


# Terminal states accept no outgoing transitions (DATA_MODEL.md §7.2:
# 终态不可原地重跑，新执行创建新任务). verification_required is NOT terminal:
# the diagram shows verification_required -> succeeded/failed.
TERMINAL_STATES: frozenset[TaskState] = frozenset(
    {
        TaskState.SUCCEEDED,
        TaskState.FAILED,
        TaskState.TIMED_OUT,
        TaskState.CANCELLED,
    }
)

ALL_TASK_STATES: tuple[str, ...] = tuple(state.value for state in TaskState)


class VerificationState(StrEnum):
    """Read-back verification outcome (docs/DATA_MODEL.md §7.1).

    ``verification_state`` on the task row; set by the M2T6 verify flow.
    Recovery treats a failed verification as report_ambiguous: the action may
    have executed and cannot be proven, so the task must be verification_required
    (DEVICE_ADAPTERS.md §9: 无法证明成功或失败：进入 verification_required).
    """

    PASSED = "passed"
    FAILED = "failed"


class InvalidTransition(ValueError):
    """Raised when a state transition violates the DATA_MODEL §7.2 diagram."""


class TaskCancellationPolicy:
    """Cancellation decision from a profile cancel_policy string.

    Rules (DATA_MODEL.md §7.2, API_CONTRACT.md §6.2): a queued task is always
    cancellable; a running task only when no dispatch fence exists AND the
    profile policy is in CANCELLABLE_RUNNING_POLICIES; never for
    not_applicable (launch profiles never enter the task queue anyway).
    """

    @staticmethod
    def can_cancel(state: TaskState, *, dispatch_started: bool, cancel_policy: str) -> bool:
        if state is TaskState.QUEUED:
            return True
        if state is TaskState.RUNNING:
            return (not dispatch_started) and cancel_policy in CANCELLABLE_RUNNING_POLICIES
        return False


@dataclass(frozen=True)
class TaskFence:
    """Dispatch-fence view of a task (docs/DEVICE_ADAPTERS.md §9).

    Pure domain data so the state machine stays free of ORM dependencies;
    callers build it from the operation_tasks row.
    """

    dispatch_started_at: datetime.datetime | None = None
    device_job_id: str | None = None

    @property
    def fenced(self) -> bool:
        """True once the irreversible dispatch fence was committed."""
        return self.dispatch_started_at is not None


class OperationTaskStateMachine:
    """Legal transitions EXACTLY per docs/DATA_MODEL.md §7.2 diagram.

    ``running -> cancelled`` is the only conditional arrow: it requires no
    dispatch fence AND a profile cancel_policy that allows cancellation.
    Recovery requeue (running -> queued) is NOT part of the visible state
    machine; it is applied by the recovery logic through
    ``recover_task``/``requeue_task`` with its own fence checks.
    """

    _LEGAL: dict[TaskState, frozenset[TaskState]] = {
        TaskState.QUEUED: frozenset({TaskState.RUNNING, TaskState.CANCELLED}),
        TaskState.RUNNING: frozenset(
            {
                TaskState.WAITING_DEVICE,
                TaskState.SUCCEEDED,
                TaskState.FAILED,
                TaskState.TIMED_OUT,
                TaskState.VERIFICATION_REQUIRED,
            }
        ),
        TaskState.WAITING_DEVICE: frozenset(
            {
                TaskState.SUCCEEDED,
                TaskState.FAILED,
                TaskState.TIMED_OUT,
                TaskState.VERIFICATION_REQUIRED,
            }
        ),
        TaskState.VERIFICATION_REQUIRED: frozenset({TaskState.SUCCEEDED, TaskState.FAILED}),
    }

    @classmethod
    def transition(
        cls,
        from_state: TaskState,
        to_state: TaskState,
        *,
        dispatch_started: bool = False,
        cancel_policy: str | None = None,
    ) -> bool:
        """Validate a transition; raises ``InvalidTransition`` on illegal moves."""
        if from_state is TaskState.QUEUED and to_state is TaskState.CANCELLED:
            return True
        if from_state is TaskState.RUNNING and to_state is TaskState.CANCELLED:
            if dispatch_started:
                raise InvalidTransition(f"{from_state.value} -> {to_state.value} is forbidden after the dispatch fence")
            if cancel_policy not in CANCELLABLE_RUNNING_POLICIES:
                raise InvalidTransition(f"{from_state.value} -> {to_state.value} requires a cancellable profile policy")
            return True
        if to_state in cls._LEGAL.get(from_state, frozenset()):
            return True
        raise InvalidTransition(f"Illegal transition: {from_state.value} -> {to_state.value} (DATA_MODEL §7.2)")

    @staticmethod
    def can_cancel(state: TaskState, *, dispatch_started: bool, cancel_policy: str) -> bool:
        return TaskCancellationPolicy.can_cancel(state, dispatch_started=dispatch_started, cancel_policy=cancel_policy)

    @staticmethod
    def can_execute(fence: TaskFence, *, side_effect: bool) -> bool:
        """True when the worker may call the adapter execution path.

        After the dispatch fence is committed for a side_effect=true profile,
        the ONLY allowed worker action is verify (read-back) — never a second
        execute (DEVICE_ADAPTERS.md §9, AGENTS.md 实施规则).
        """
        return not (fence.fenced and side_effect)

    @staticmethod
    def can_requeue(fence: TaskFence) -> bool:
        """True when the task may be reclaimed for a fresh attempt.

        No dispatch fence means nothing was ever sent to the device: the task
        can be re-claimed, but every precondition must be rechecked
        (DEVICE_ADAPTERS.md §9: 没有 dispatch_started_at：任务可以重新领取但
        仍需重新检查全部前置条件).
        """
        return not fence.fenced

    @staticmethod
    def can_retry_read(fence: TaskFence, *, side_effect: bool) -> bool:
        """True when a read-only profile may start a new attempt.

        side_effect=false profiles may retry the read call as a new attempt;
        once a device_job_id is persisted only the original job may be queried
        (DEVICE_ADAPTERS.md §9, DATA_MODEL.md §7.2).
        """
        return (not side_effect) and fence.device_job_id is None


class RecoveryAction(StrEnum):
    """Fence-aware recovery decision (DEVICE_ADAPTERS.md §9)."""

    REQUEUE = "requeue"
    VERIFY_ONLY = "verify_only"
    REPORT_AMBIGUOUS = "report_ambiguous"


def recover_task(
    fence: TaskFence,
    *,
    side_effect: bool,
    verification_state: str | None = None,
) -> RecoveryAction:
    """Decide what recovery may do with an expired-lease running task.

    - No dispatch fence: requeue (reclaim with full precondition recheck).
    - Read-only profile without a device job: requeue as a new attempt.
    - Verification already attempted and failed to prove: report ambiguous —
      the task must enter verification_required, never be replayed.
    - Fenced side-effect task (or read with a persisted job): verify_only —
      only read-back/job query, never a second execute.
    """
    if not fence.fenced:
        return RecoveryAction.REQUEUE
    if verification_state == VerificationState.FAILED.value:
        return RecoveryAction.REPORT_AMBIGUOUS
    if not side_effect and fence.device_job_id is None:
        return RecoveryAction.REQUEUE
    return RecoveryAction.VERIFY_ONLY


def timeout_transition(fence: TaskFence, profile: OperationProfile) -> TaskState:
    """Decide the timeout outcome from profile semantics (GLOSSARY.md).

    ``timed_out`` means a confirmed timeout with no evidence of continued
    execution; ``verification_required`` means the device may have accepted
    the action but the result cannot be proven (DATA_MODEL.md §7.2, contracts
    operations.json global invariant ``ambiguity``: 设备可能已接受动作但无法
    完成验证时必须 verification_required；不得 failed 后自动重放).

    Rules (corrected per the M2T1 review controller ruling; documented in
    tests/domain/test_timeout_transition.py):

    - No dispatch fence: the action was never dispatched to the device, so
      there is positive evidence it did not execute -> timed_out.
    - Read-only profile (side_effect=false): a read has no irreversible
      device-side effect; the timeout is clean and a new attempt is allowed
      (DEVICE_ADAPTERS.md §9 fence rules) -> timed_out.
    - Otherwise (fenced side-effect task): verification is impossible or
      incomplete — the device may have accepted the action (e.g. an
      expected_disconnect action whose timeout shows no reconnect/identity
      evidence) -> verification_required. A terminal timed_out would permit
      a clean-looking retry of a possibly-executed action, which the
      ambiguity invariant forbids.
    """
    if not fence.fenced:
        return TaskState.TIMED_OUT
    if not profile.side_effect:
        return TaskState.TIMED_OUT
    return TaskState.VERIFICATION_REQUIRED
