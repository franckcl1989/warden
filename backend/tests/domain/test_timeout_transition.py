"""Timeout outcome decision: pure rules over the generated profile registry.

The engine must never hardcode per-operation semantics: every decision reads
the profile fields (side_effect, expected_disconnect, verification.ambiguous)
from contracts/operations.json via the generated registry. These tests pin
the rules documented in ``app.domain.operation.timeout_transition``
(corrected per the M2T1 review controller ruling — contracts/operations.json
global invariant ``ambiguity``: 设备可能已接受动作但无法完成验证时必须
verification_required；不得 failed 后自动重放; GLOSSARY.md ``timed_out``:
已确认没有继续执行证据且超过计划时限；不确定时使用结果待核验):

- no dispatch fence -> timed_out (the action was never dispatched, so there
  is positive evidence it did not execute);
- read-only profiles (side_effect=false) -> timed_out (no irreversible
  device-side effect; a new attempt is allowed);
- fenced side-effect tasks -> verification_required (verification is
  impossible or incomplete — the device may have accepted the action, e.g.
  an expected_disconnect action whose timeout shows no reconnect/identity
  evidence; a terminal timed_out would permit a clean-looking retry of a
  possibly-executed action).
"""

from __future__ import annotations

import datetime

import pytest
from app.domain.operation import TaskFence, TaskState, timeout_transition
from app.generated.operations import OPERATION_PROFILES

NOW = datetime.datetime.now(datetime.UTC)


def _profile(profile_id: str):
    profile = OPERATION_PROFILES.get(profile_id)
    assert profile is not None, f"profile {profile_id} missing from registry"
    return profile


class TestTimeoutDecision:
    def test_unfenced_timeout_is_timed_out_even_for_side_effect_profiles(self) -> None:
        # power.cycle is high-risk side-effect with real ambiguity; without a
        # dispatch fence the device was never called, so the timeout is clean.
        assert (
            timeout_transition(TaskFence(), _profile("SRV-ACT-02:power.cycle"))
            is TaskState.TIMED_OUT
        )

    @pytest.mark.parametrize(
        "profile_id",
        [
            "SRV-ACT-06:firmware.query",  # ambiguity "not applicable"
            "SRV-ACT-07:asset.refresh",  # ambiguity "not applicable"
            "CORE-ACT-06:transceiver.diagnose",  # ambiguity "not applicable"
            "NAS-ACT-05:backup.status.refresh",  # ambiguity "not applicable"
        ],
    )
    def test_fenced_read_profile_without_ambiguity_is_timed_out(self, profile_id: str) -> None:
        profile = _profile(profile_id)
        assert profile.side_effect is False
        assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is TaskState.TIMED_OUT

    def test_fenced_read_profile_with_real_ambiguity_and_job_is_timed_out(self) -> None:
        # logs.support_bundle.collect is read-only but its ambiguity is real
        # ("DSM job may continue but final artifact cannot be retrieved"). A
        # read has no irreversible device-side effect: the timeout is clean
        # and a new attempt is allowed (side_effect=false fence rules).
        profile = _profile("NAS-ACT-03:logs.support_bundle.collect")
        assert profile.side_effect is False
        assert not profile.verification.ambiguous.lower().startswith("not applicable")
        assert (
            timeout_transition(TaskFence(dispatch_started_at=NOW, device_job_id="job-1"), profile)
            is TaskState.TIMED_OUT
        )

    @pytest.mark.parametrize(
        "profile_id",
        [
            "SRV-ACT-01:manager.reset",
            "NAS-ACT-01:power.restart",
            "NAS-ACT-01:power.shutdown",
            "CORE-ACT-01:device.restart",
            "ACCESS-ACT-01:device.restart",
        ],
    )
    def test_expected_disconnect_fenced_without_job_is_verification_required(
        self, profile_id: str
    ) -> None:
        # expected_disconnect with a committed fence and NO reconnect/identity
        # evidence is genuinely ambiguous: the device may have accepted the
        # action. Never a terminal timed_out (which would permit a clean-
        # looking retry of a possibly-executed action).
        profile = _profile(profile_id)
        assert profile.expected_disconnect is True
        assert profile.side_effect is True
        assert (
            timeout_transition(TaskFence(dispatch_started_at=NOW), profile)
            is TaskState.VERIFICATION_REQUIRED
        )

    def test_expected_disconnect_with_device_job_is_verification_required(self) -> None:
        # firmware.update declares expected_disconnect AND real ambiguity
        # ("job accepted or disconnect occurred but final job/version cannot
        # be proven"): a persisted job is evidence the device accepted.
        profile = _profile("SRV-ACT-06:firmware.update")
        assert profile.expected_disconnect is True
        assert profile.side_effect is True
        assert (
            timeout_transition(TaskFence(dispatch_started_at=NOW, device_job_id="job-fw-1"), profile)
            is TaskState.VERIFICATION_REQUIRED
        )

    @pytest.mark.parametrize(
        "profile_id",
        [
            "SRV-ACT-02:power.on",
            "SRV-ACT-02:power.cycle",
            "SRV-ACT-05:virtual_media.mount",
            "ACCESS-ACT-03:poe.port.set",
            "NAS-ACT-04:disk.smart_test.quick",
        ],
    )
    def test_fenced_ambiguous_profiles_become_verification_required(self, profile_id: str) -> None:
        profile = _profile(profile_id)
        assert profile.side_effect is True
        assert not profile.verification.ambiguous.lower().startswith("not applicable")
        assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is TaskState.VERIFICATION_REQUIRED

    def test_dispatch_fence_is_required_for_ambiguity(self) -> None:
        # Same profile, no fence: the outcome flips to timed_out.
        profile = _profile("SRV-ACT-02:power.on")
        assert timeout_transition(TaskFence(), profile) is TaskState.TIMED_OUT

    def test_full_registry_matrix_follows_fence_and_side_effect(self) -> None:
        # Every task-channel profile obeys the corrected rule: unfenced ->
        # timed_out; fenced -> verification_required iff side_effect=true.
        for profile in OPERATION_PROFILES.values():
            if profile.channel != "task":
                continue
            assert timeout_transition(TaskFence(), profile) is TaskState.TIMED_OUT
            expected = (
                TaskState.VERIFICATION_REQUIRED if profile.side_effect else TaskState.TIMED_OUT
            )
            assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is expected
