"""Operation task state machine: full DATA_MODEL §7.2 transition table.

Every arrow of the diagram is a legal transition; every missing arrow is
rejected with ``InvalidTransition``; the fence rules and the cancellation
policy matrix follow DEVICE_ADAPTERS.md §9 and DATA_MODEL.md §7.2. Pure unit
tests — no database.
"""

from __future__ import annotations

import datetime

import pytest
from app.domain.operation import (
    CANCEL_POLICY_BEFORE_DISPATCH_ONLY,
    CANCEL_POLICY_NOT_APPLICABLE,
    CANCELLABLE_RUNNING_POLICIES,
    TERMINAL_STATES,
    InvalidTransition,
    RecoveryAction,
    TaskCancellationPolicy,
    TaskFence,
    TaskState,
    VerificationState,
    recover_task,
)
from app.domain.operation import (
    OperationTaskStateMachine as Machine,
)

QUEUED = TaskState.QUEUED
RUNNING = TaskState.RUNNING
WAITING_DEVICE = TaskState.WAITING_DEVICE
SUCCEEDED = TaskState.SUCCEEDED
FAILED = TaskState.FAILED
TIMED_OUT = TaskState.TIMED_OUT
CANCELLED = TaskState.CANCELLED
VERIFICATION_REQUIRED = TaskState.VERIFICATION_REQUIRED

ALL_STATES = {QUEUED, RUNNING, WAITING_DEVICE, SUCCEEDED, FAILED, TIMED_OUT, CANCELLED, VERIFICATION_REQUIRED}


def _legal_arrows() -> list[tuple[TaskState, TaskState]]:
    arrows = [
        (QUEUED, RUNNING),
        (QUEUED, CANCELLED),
        (RUNNING, WAITING_DEVICE),
        (RUNNING, SUCCEEDED),
        (RUNNING, FAILED),
        (RUNNING, TIMED_OUT),
        (RUNNING, VERIFICATION_REQUIRED),
        (WAITING_DEVICE, SUCCEEDED),
        (WAITING_DEVICE, FAILED),
        (WAITING_DEVICE, TIMED_OUT),
        (WAITING_DEVICE, VERIFICATION_REQUIRED),
        (VERIFICATION_REQUIRED, SUCCEEDED),
        (VERIFICATION_REQUIRED, FAILED),
    ]
    # running -> cancelled is conditional (fence + cancel_policy); it is
    # asserted separately in the cancel matrix.
    return arrows


def _all_state_pairs() -> list[tuple[TaskState, TaskState]]:
    return [(source, target) for source in ALL_STATES for target in ALL_STATES]


class TestLegalTransitions:
    @pytest.mark.parametrize("source,target", _legal_arrows())
    def test_every_diagram_arrow_is_legal(self, source: TaskState, target: TaskState) -> None:
        assert Machine.transition(source, target) is True

    def test_queued_to_running(self) -> None:
        assert Machine.transition(QUEUED, RUNNING) is True

    def test_verification_required_is_not_terminal(self) -> None:
        assert VERIFICATION_REQUIRED not in TERMINAL_STATES
        assert Machine.transition(VERIFICATION_REQUIRED, SUCCEEDED) is True
        assert Machine.transition(VERIFICATION_REQUIRED, FAILED) is True


class TestIllegalTransitions:
    @pytest.mark.parametrize(
        "source,target",
        [
            (state, target)
            for state in ALL_STATES
            for target in ALL_STATES
            if (state, target) not in _legal_arrows() and not (state is RUNNING and target is CANCELLED)
        ],
    )
    def test_non_arrow_transitions_raise(self, source: TaskState, target: TaskState) -> None:
        with pytest.raises(InvalidTransition):
            Machine.transition(source, target)

    @pytest.mark.parametrize("terminal", sorted(TERMINAL_STATES, key=lambda s: s.value))
    def test_terminal_states_have_no_outgoing_arrows(self, terminal: TaskState) -> None:
        for target in ALL_STATES:
            with pytest.raises(InvalidTransition):
                Machine.transition(terminal, target)

    def test_running_to_queued_is_not_a_machine_transition(self) -> None:
        # Recovery requeue lives outside the visible diagram (§7.2); it is
        # applied via recover_task/requeue_task with fence checks instead.
        with pytest.raises(InvalidTransition):
            Machine.transition(RUNNING, QUEUED)


class TestRunningCancellationMatrix:
    @pytest.mark.parametrize("policy", sorted(CANCELLABLE_RUNNING_POLICIES))
    def test_running_cancel_allowed_when_unfenced_and_policy_allows(self, policy: str) -> None:
        assert Machine.transition(RUNNING, CANCELLED, dispatch_started=False, cancel_policy=policy) is True
        assert TaskCancellationPolicy.can_cancel(RUNNING, dispatch_started=False, cancel_policy=policy) is True

    def test_running_cancel_forbidden_after_dispatch_fence(self) -> None:
        for policy in CANCELLABLE_RUNNING_POLICIES:
            with pytest.raises(InvalidTransition):
                Machine.transition(RUNNING, CANCELLED, dispatch_started=True, cancel_policy=policy)
            assert TaskCancellationPolicy.can_cancel(RUNNING, dispatch_started=True, cancel_policy=policy) is False

    def test_running_cancel_forbidden_for_not_applicable(self) -> None:
        with pytest.raises(InvalidTransition):
            Machine.transition(RUNNING, CANCELLED, dispatch_started=False, cancel_policy=CANCEL_POLICY_NOT_APPLICABLE)
        assert (
            TaskCancellationPolicy.can_cancel(
                RUNNING, dispatch_started=False, cancel_policy=CANCEL_POLICY_NOT_APPLICABLE
            )
            is False
        )

    def test_running_cancel_forbidden_without_policy(self) -> None:
        with pytest.raises(InvalidTransition):
            Machine.transition(RUNNING, CANCELLED, dispatch_started=False)

    def test_queued_cancel_always_allowed(self) -> None:
        assert Machine.transition(QUEUED, CANCELLED) is True
        assert (
            TaskCancellationPolicy.can_cancel(QUEUED, dispatch_started=True, cancel_policy=CANCEL_POLICY_NOT_APPLICABLE)
            is True
        )

    def test_non_running_non_queued_cancel_forbidden(self) -> None:
        for state in (WAITING_DEVICE, SUCCEEDED, FAILED, TIMED_OUT, VERIFICATION_REQUIRED):
            with pytest.raises(InvalidTransition):
                Machine.transition(
                    state, CANCELLED, dispatch_started=False, cancel_policy=CANCEL_POLICY_BEFORE_DISPATCH_ONLY
                )


class TestFenceRules:
    def test_can_execute_before_fence(self) -> None:
        fence = TaskFence(dispatch_started_at=None)
        assert Machine.can_execute(fence, side_effect=True) is True
        assert Machine.can_execute(fence, side_effect=False) is True

    def test_can_execute_after_fence_blocks_side_effect(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC))
        assert Machine.can_execute(fence, side_effect=True) is False
        assert Machine.can_execute(fence, side_effect=False) is True

    def test_can_requeue_only_without_fence(self) -> None:
        assert Machine.can_requeue(TaskFence(dispatch_started_at=None)) is True
        assert Machine.can_requeue(TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC))) is False

    def test_can_retry_read(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        no_fence = TaskFence(dispatch_started_at=None, device_job_id=None)
        assert Machine.can_retry_read(no_fence, side_effect=False) is True
        # read-only with a persisted job: only query the original job
        with_job = TaskFence(dispatch_started_at=now, device_job_id="job-1")
        without_job = TaskFence(dispatch_started_at=now, device_job_id=None)
        assert Machine.can_retry_read(with_job, side_effect=False) is False
        assert Machine.can_retry_read(without_job, side_effect=False) is True
        # side-effect profiles never get a fresh attempt after dispatch
        assert Machine.can_retry_read(without_job, side_effect=True) is False


class TestRecoveryDecision:
    """recover_task fence-aware decision table (DEVICE_ADAPTERS.md §9)."""

    def test_no_fence_always_requeues(self) -> None:
        assert recover_task(TaskFence(dispatch_started_at=None), side_effect=True) is RecoveryAction.REQUEUE
        assert recover_task(TaskFence(dispatch_started_at=None), side_effect=False) is RecoveryAction.REQUEUE

    def test_read_only_without_job_requeues_as_new_attempt(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC), device_job_id=None)
        assert recover_task(fence, side_effect=False) is RecoveryAction.REQUEUE

    def test_read_only_with_job_is_verify_only(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC), device_job_id="job-7")
        assert recover_task(fence, side_effect=False) is RecoveryAction.VERIFY_ONLY

    def test_fenced_side_effect_is_verify_only(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC))
        assert recover_task(fence, side_effect=True) is RecoveryAction.VERIFY_ONLY
        assert (
            recover_task(
                TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC), device_job_id="job-9"),
                side_effect=True,
            )
            is RecoveryAction.VERIFY_ONLY
        )

    def test_failed_verification_reports_ambiguous(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC))
        assert (
            recover_task(fence, side_effect=True, verification_state=VerificationState.FAILED.value)
            is RecoveryAction.REPORT_AMBIGUOUS
        )
        assert (
            recover_task(
                TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC), device_job_id="job-1"),
                side_effect=False,
                verification_state=VerificationState.FAILED.value,
            )
            is RecoveryAction.REPORT_AMBIGUOUS
        )

    def test_passed_verification_is_not_ambiguous(self) -> None:
        fence = TaskFence(dispatch_started_at=datetime.datetime.now(datetime.UTC))
        assert (
            recover_task(fence, side_effect=True, verification_state=VerificationState.PASSED.value)
            is RecoveryAction.VERIFY_ONLY
        )
