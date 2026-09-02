"""Timeout outcome decision: pure rules over the generated profile registry.

The engine must never hardcode per-operation semantics: every decision reads
the profile fields (expected_disconnect, verification.ambiguous) from
contracts/operations.json via the generated registry. These tests pin the
rules documented in ``app.domain.operation.timeout_transition``:

- no dispatch fence -> timed_out (nothing was ever sent to the device);
- profile declares no ambiguity ("not applicable") -> timed_out;
- expected_disconnect without a persisted device job -> timed_out
  (the certified disconnect/reconnect window elapsed with no evidence);
- otherwise (fenced and ambiguity is possible) -> verification_required
  (the device may have accepted the action — never auto-replay).
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
            timeout_transition(TaskFence(dispatch_started_at=None), _profile("SRV-ACT-02:power.cycle"))
            is TaskState.TIMED_OUT
        )

    def test_not_applicable_ambiguity_is_timed_out(self) -> None:
        # firmware.query: "not applicable; unreadable inventory is failed or unsupported"
        profile = _profile("SRV-ACT-06:firmware.query")
        assert profile.verification.ambiguous.lower().startswith("not applicable")
        assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is TaskState.TIMED_OUT

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
    def test_expected_disconnect_without_job_evidence_is_timed_out(self, profile_id: str) -> None:
        profile = _profile(profile_id)
        assert profile.expected_disconnect is True
        assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is TaskState.TIMED_OUT

    def test_expected_disconnect_with_device_job_is_verification_required(self) -> None:
        # firmware.update declares expected_disconnect AND real ambiguity
        # ("job accepted or disconnect occurred but final job/version cannot
        # be proven"): a persisted job is evidence the device accepted.
        profile = _profile("SRV-ACT-06:firmware.update")
        assert profile.expected_disconnect is True
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
            "NAS-ACT-03:logs.support_bundle.collect",
        ],
    )
    def test_fenced_ambiguous_profiles_become_verification_required(self, profile_id: str) -> None:
        profile = _profile(profile_id)
        assert profile.expected_disconnect is False
        assert not profile.verification.ambiguous.lower().startswith("not applicable")
        assert timeout_transition(TaskFence(dispatch_started_at=NOW), profile) is TaskState.VERIFICATION_REQUIRED

    def test_dispatch_fence_is_required_for_ambiguity(self) -> None:
        # Same profile, no fence: the outcome flips to timed_out.
        profile = _profile("SRV-ACT-02:power.on")
        assert timeout_transition(TaskFence(dispatch_started_at=None), profile) is TaskState.TIMED_OUT
