"""Common Redfish operation contract suite (M3T3, SRV-ACT-01/02/04/05/06/07).

Drives the registered ``server.redfish`` adapter against the TEST-DEVICE
simulator (session fixture in conftest.py) through the FULL device-side
contract: plan -> preflight -> execute -> verify for the seven operation
profiles, per contracts/operations.json (timeouts/risks/verification
strategies come ONLY from the registry), with the failure and ambiguity
semantics of DEVICE_ADAPTERS.md §7/§9:

- verification is read-back only (never "HTTP 204 = success");
- power.off never falls back to ForceOff (profile prohibition);
- power.cycle mapping (ForceRestart else PowerCycle) is recorded in evidence;
- unprovable outcomes (stale read-back, vanished job, reconnect deadline) are
  reported ambiguous -> the worker parks them in verification_required;
- explicit device failures carry stable error codes and are never retried.

The platform half of the M3T3 boundary (ticket issuance, encrypted artifact
storage, inventory persistence) is exercised by the worker slice suite
(test_redfish_operations_platform.py); here the adapter contract is verified
with evidence merges that mirror what the worker injects before verification.
"""

from __future__ import annotations

import dataclasses
import datetime
import io
import json
import time
import uuid
import zipfile
from ipaddress import ip_address

import pytest
from app.adapters.redfish.common import RedfishCommonAdapter
from app.domain.adapter import (
    AdapterError,
    DeviceSession,
    OperationResult,
    PreflightResult,
    VerificationResult,
)
from app.domain.operation_plan import (
    CapabilityView,
    DeviceSnapshot,
    OperationPlan,
    OperationRequest,
)
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.time import utcnow

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME, SimAccess

ADAPTER = RedfishCommonAdapter()

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

REQUIREMENT_BY_KEY = {
    "manager.reset": "SRV-ACT-01",
    "power.on": "SRV-ACT-02",
    "power.off": "SRV-ACT-02",
    "power.cycle": "SRV-ACT-02",
    "logs.support_bundle.collect": "SRV-ACT-04",
    "virtual_media.mount": "SRV-ACT-05",
    "virtual_media.unmount": "SRV-ACT-05",
    "firmware.query": "SRV-ACT-06",
    "firmware.update": "SRV-ACT-06",
    "asset.refresh": "SRV-ACT-07",
}


def _session(sim: SimAccess, **config: object) -> DeviceSession:
    merged: dict[str, object] = {"protocol": "http", "port": sim.port}
    merged.update(config)
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
        resolved_ip=ip_address(SIM_HOST),
    )


def _snapshot(key: str) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_id=uuid.uuid4(),
        device_name="sim-srv",
        device_type="server",
        device_version=1,
        adapter_key=ADAPTER.adapter_key,
        enabled=True,
        readiness="ready",
        capabilities=(
            CapabilityView(
                capability_key=key,
                support_state="supported",
                requirement_id=REQUIREMENT_BY_KEY[key],
                discovery_method=ADAPTER.adapter_key,
                adapter_version=ADAPTER.adapter_version,
            ),
        ),
    )


def _plan(
    key: str,
    parameters: dict[str, object] | None = None,
    *,
    runtime_context: dict[str, object] | None = None,
) -> OperationPlan:
    plan = ADAPTER.plan_operation(_snapshot(key), OperationRequest(capability_key=key, parameters=parameters or {}))
    if runtime_context:
        plan = dataclasses.replace(plan, runtime_context=runtime_context)
    return plan


def _short_deadline(plan: OperationPlan, seconds: float = 4.0) -> OperationPlan:
    """Give the plan a near task deadline so internal read-back loops exit fast."""
    return dataclasses.replace(
        plan,
        runtime_context={
            **plan.runtime_context,
            "task_timeout_at": (utcnow() + datetime.timedelta(seconds=seconds)).isoformat(),
        },
    )


def _job_result(result: OperationResult) -> OperationResult:
    assert result.device_job_id is not None
    return result


def _poll_verify(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult,
    *,
    timeout: float = 20.0,
) -> VerificationResult:
    """Poll verify until a terminal verdict (the executor's job loop shape)."""
    deadline = time.monotonic() + timeout
    verdict = None
    while time.monotonic() < deadline:
        verdict = ADAPTER.verify_operation(session, plan, result)
        if not verdict.pending:
            return verdict
        time.sleep(0.1)
    assert verdict is not None
    raise AssertionError("verify stayed pending past the test timeout")


def _merge_evidence(result: OperationResult, **extra: object) -> OperationResult:
    return dataclasses.replace(result, evidence={**result.evidence, **extra})


def _ticket_context(url: str, *, expected_version: str | None = None) -> dict[str, object]:
    context: dict[str, object] = {"ticket": {"url": url, "id": str(uuid.uuid4())}}
    if expected_version is not None:
        context["file"] = {
            "file_id": str(uuid.uuid4()),
            "file_type": "firmware",
            "sha256": "a" * 64,
            "expected_model": "Warden SimServer 1U (simulated)",
            "expected_target": "BMC",
            "expected_version": expected_version,
        }
    return context


# -- plan/profile contract ----------------------------------------------------


class TestPlanContract:
    def test_plans_mirror_the_registry_profiles(self) -> None:
        file_id = str(uuid.uuid4())
        params: dict[str, dict[str, object]] = {
            "virtual_media.mount": {"file_id": file_id, "media_kind": "iso"},
            "virtual_media.unmount": {"slot_id": "1"},
            "firmware.update": {"file_id": file_id, "target_id": "BMC"},
        }
        expected = {
            "manager.reset": ("SRV-ACT-01", 600, "disconnect_reconnect_identity", True),
            "power.on": ("SRV-ACT-02", 600, "power_state_readback", False),
            "power.off": ("SRV-ACT-02", 900, "power_state_readback", False),
            "power.cycle": ("SRV-ACT-02", 900, "power_transition_and_readback", False),
            "logs.support_bundle.collect": (
                "SRV-ACT-04",
                1800,
                "artifact_manifest",
                False,
            ),
            "virtual_media.mount": ("SRV-ACT-05", 900, "mounted_media_readback", False),
            "virtual_media.unmount": ("SRV-ACT-05", 300, "mounted_media_readback", False),
            "firmware.query": ("SRV-ACT-06", 300, "inventory_persisted", False),
            "firmware.update": ("SRV-ACT-06", 7200, "job_and_version_readback", True),
            "asset.refresh": ("SRV-ACT-07", 300, "inventory_persisted", False),
        }
        for key, (requirement, timeout, strategy, disconnect) in expected.items():
            plan = _plan(key, params.get(key))
            profile = OPERATION_PROFILES[f"{requirement}:{key}"]
            assert plan.requirement_id == requirement
            assert plan.risk_level == profile.risk
            assert plan.timeout_seconds == timeout
            assert plan.verification_strategy == strategy
            assert plan.expected_disconnect is disconnect
            assert plan.side_effect == profile.side_effect
            assert plan.cancel_policy == profile.cancel_policy

    def test_parameters_validated_against_the_profile_schema(self) -> None:
        with pytest.raises(Exception) as exc_info:
            _plan("virtual_media.mount", {})
        assert exc_info.type.__name__ == "AppError"
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("virtual_media.mount", {"file_id": "not-a-uuid", "media_kind": "iso"})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("firmware.update", {"file_id": str(uuid.uuid4())})
        assert getattr(exc_info.value, "code", "") == "validation_failed"


# -- error boundary (DEVICE_ADAPTERS.md §7) -----------------------------------


class TestErrorBoundary:
    """Every RedfishError escaping a preflight/execute read must surface as an
    AdapterError with the SAME stable code — raw protocol errors leaking out
    would turn into executor pool lease churn (and eventually a mislabeled
    timeout) instead of a clean terminal failure."""

    def test_preflight_login_401_raises_adapter_error_authentication_failed(self, sim: SimAccess) -> None:
        sim.set(failures={"login_401": True})
        session = _session(sim)
        plan = _plan("power.off")
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.preflight_operation(session, plan)
        assert exc_info.value.code == "authentication_failed"

    def test_preflight_read_403_raises_adapter_error_permission_denied(self, sim: SimAccess) -> None:
        sim.set(failures={"reads_403": True})
        session = _session(sim)
        plan = _plan("power.cycle")
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.preflight_operation(session, plan)
        assert exc_info.value.code == "permission_denied_by_device"

    def test_execute_read_500_raises_adapter_error_operation_failed(self, sim: SimAccess) -> None:
        # A non-POST read that fails mid-execute (500) maps through the same
        # boundary: the executor sees AdapterError(operation_failed), never a
        # raw protocol error.
        sim.set(failures={"reads_500": True})
        session = _session(sim)
        plan = _plan("power.cycle")
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "operation_failed"

    def test_action_post_403_raises_adapter_error_permission_denied(self, sim: SimAccess) -> None:
        sim.set(failures={"reset_forbidden_403": True})
        session = _session(sim)
        plan = _plan("power.cycle")
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "permission_denied_by_device"


# -- power (SRV-ACT-02) -------------------------------------------------------


class TestPower:
    def test_power_off_and_on_round_trip_with_readback(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05)
        session = _session(sim)
        off_plan = _plan("power.off")
        preflight = ADAPTER.preflight_operation(session, off_plan)
        assert preflight.ok is True
        progress: list[tuple[int, str | None]] = []

        def _progress(percent: int, step: str | None) -> None:
            progress.append((percent, step))

        result = ADAPTER.execute_operation(session, _short_deadline(off_plan), _progress)
        assert result.ok is True
        assert result.evidence["reset_type"] == "GracefulShutdown"
        assert result.evidence["command"] == {"ResetType": "GracefulShutdown"}  # never ForceOff
        verdict = _poll_verify(session, off_plan, _job_result(result))
        assert verdict.succeeded is True
        assert verdict.ambiguous is False
        assert verdict.evidence["target_state"] == "Off"
        assert [percent for percent, _step in progress] == [20, 60]

        on_plan = _plan("power.on")
        preflight = ADAPTER.preflight_operation(session, on_plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(on_plan), _progress)
        assert result.ok is True
        assert result.evidence["reset_type"] == "On"
        verdict = _poll_verify(session, on_plan, _job_result(result))
        assert verdict.succeeded is True
        assert verdict.evidence["target_state"] == "On"

    def test_power_off_precondition_drift_when_already_on(self, sim: SimAccess) -> None:
        # The simulator starts powered On: power.on preflight must reject.
        session = _session(sim)
        on_preflight = ADAPTER.preflight_operation(session, _plan("power.on"))
        assert isinstance(on_preflight, PreflightResult)
        assert on_preflight.ok is False
        assert on_preflight.error_code == "validation_failed"
        off_preflight = ADAPTER.preflight_operation(session, _plan("power.off"))
        assert off_preflight.ok is True

    def test_power_cycle_maps_force_restart_and_proves_transition(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05, power_blip_seconds=0.5)
        session = _session(sim)
        plan = _plan("power.cycle")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        assert result.evidence["reset_type"] == "ForceRestart"
        assert "ForceRestart" in str(result.evidence["mapping"])
        verdict = _poll_verify(session, plan, _job_result(result))
        assert verdict.succeeded is True
        assert verdict.evidence["transition_observed"] is True
        observed = verdict.evidence["observed_states"]
        assert "Off" in observed and observed[-1] == "On"

    def test_power_off_never_falls_back_to_force_off(self, sim: SimAccess) -> None:
        # Device rejects GracefulShutdown entirely: the operation must fail as
        # unsupported — the adapter NEVER substitutes ForceOff (prohibition).
        sim.set(no_graceful_shutdown=True)
        session = _session(sim)
        plan = _plan("power.off")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is False
        assert preflight.error_code == "unsupported_capability"
        # Even if a caller skipped preflight, execute must not send ForceOff.
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "unsupported_capability"

    def test_power_readback_stale_is_ambiguous_never_success(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05, power_readback_stale=True)
        session = _session(sim)
        plan = _plan("power.off")
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=3.0), lambda *_: None)
        assert result.ok is True
        verdict = _poll_verify(session, plan, _job_result(result), timeout=15.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True
        assert verdict.error_code == "ambiguous_result"

    def test_reset_rejected_400_maps_to_unsupported_capability(self, sim: SimAccess) -> None:
        sim.set(failures={"reset_rejected_400": True})
        session = _session(sim)
        plan = _plan("power.cycle")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True  # advertised; rejection only at call time
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "unsupported_capability"

    def test_reset_task_failure_is_explicit_operation_failed(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05, failures={"reset_task_fails": True})
        session = _session(sim)
        plan = _plan("power.cycle")
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = _poll_verify(session, plan, _job_result(result))
        assert verdict.succeeded is False
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"


# -- manager.reset (SRV-ACT-01) -----------------------------------------------


class TestManagerReset:
    def test_reset_reconnects_with_same_identity(self, sim: SimAccess) -> None:
        sim.set(manager_blip_seconds=0.6)
        session = _session(sim)
        plan = _plan("manager.reset")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=10.0), lambda *_: None)
        assert result.ok is True
        assert result.evidence["reset_type"] == "GracefulRestart"
        identity_before = result.evidence["identity_before"]
        assert identity_before["manager_uuid"] == "66666666-7777-8888-9999-aaaaaaaaaaaa"
        assert identity_before["system_serial"] == "WARDEN-SIM-0001"
        verdict = _poll_verify(session, plan, _job_result(result), timeout=30.0)
        assert verdict.succeeded is True
        assert verdict.ambiguous is False
        assert verdict.evidence["identity_verified"]["manager_uuid"] == identity_before["manager_uuid"]

    def test_reset_without_pre_reset_identity_is_ambiguous(self, sim: SimAccess) -> None:
        sim.set(manager_blip_seconds=0.4)
        session = _session(sim)
        plan = _plan("manager.reset")
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=10.0), lambda *_: None)
        assert result.ok is True
        stripped = dataclasses.replace(
            result, evidence={"http_status": 202, "command": {"ResetType": "GracefulRestart"}}
        )
        # Crash-recovery shape: no identity_before in the evidence.
        verdict = _poll_verify(session, plan, _job_result(stripped), timeout=30.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True
        assert verdict.error_code == "ambiguous_result"

    def test_reset_with_both_identity_values_none_is_ambiguous_never_success(
        self, sim: SimAccess
    ) -> None:
        # The pre-reset evidence holds NO usable identity value (both
        # manager_uuid and system_serial are None — e.g. a device that never
        # reported them): identity equality must never pass trivially.
        sim.set(manager_blip_seconds=0.4)
        session = _session(sim)
        plan = _plan("manager.reset")
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=10.0), lambda *_: None)
        assert result.ok is True
        stripped = dataclasses.replace(
            result,
            evidence={
                "http_status": 202,
                "command": {"ResetType": "GracefulRestart"},
                "identity_before": {
                    "manager_uuid": None,
                    "system_serial": None,
                    "model": "Warden SimServer 1U (simulated)",
                },
            },
        )
        verdict = _poll_verify(session, plan, _job_result(stripped), timeout=30.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True
        assert verdict.error_code == "ambiguous_result"
        assert verdict.evidence["reason"] == "no_pre_reset_identity_evidence"

    def test_reset_without_observed_offline_window_is_ambiguous(self, sim: SimAccess) -> None:
        # The manager never actually goes down (blip 0: the reset is accepted,
        # the task vanishes, identity is unchanged) — without an observed
        # offline window the restart cannot be PROVEN and success would be
        # fabricated.
        sim.set(manager_blip_seconds=0.0)
        session = _session(sim)
        plan = _plan("manager.reset")
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=4.0), lambda *_: None)
        assert result.ok is True
        assert (result.evidence["identity_before"]["manager_uuid"]) is not None
        verdict = _poll_verify(session, plan, _job_result(result), timeout=15.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True
        assert verdict.error_code == "ambiguous_result"
        assert "no offline window observed" in str(verdict.evidence.get("reason"))


# -- logs.support_bundle.collect (SRV-ACT-04) ---------------------------------


class TestSupportBundle:
    def test_bundle_export_artifact_and_manifest_verify(self, sim: SimAccess) -> None:
        sim.set(profile="slow_paginated", pagination="skip")
        session = _session(sim)
        plan = _plan("logs.support_bundle.collect")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.file_type == "support_bundle"
        assert artifact.content_bytes.startswith(b"PK")
        with zipfile.ZipFile(io.BytesIO(artifact.content_bytes)) as archive:
            names = set(archive.namelist())
            assert "manifest.json" in names
            assert "system.json" in names
            manifest = json.loads(archive.read("manifest.json"))
            sources = {source["name"] for source in manifest["sources"]}
            assert "SEL" in sources
        # Worker-side merge: stored artifact proof (encrypted support bundle).
        stored = {
            "status": "ready",
            "file_id": str(uuid.uuid4()),
            "file_type": "support_bundle",
            "encrypted": True,
            "sha256": result.evidence["artifact_sha256"],
        }
        merged = _merge_evidence(result, artifact_stored=stored)
        verdict = ADAPTER.verify_operation(session, plan, merged)
        assert verdict.succeeded is True
        assert verdict.ambiguous is False
        assert verdict.evidence["sources"] >= 2
        # Recovery shape (evidence nested under "execution") also verifies.
        nested = dataclasses.replace(merged, evidence={"execution": dict(merged.evidence)})
        verdict = ADAPTER.verify_operation(session, plan, nested)
        assert verdict.succeeded is True

    def test_bundle_without_stored_artifact_proof_is_ambiguous(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("logs.support_bundle.collect")
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True

    def test_bundle_export_with_no_sel_is_unsupported(self, sim: SimAccess) -> None:
        sim.set(empty_sel=True)
        session = _session(sim)
        plan = _plan("logs.support_bundle.collect")
        # An EMPTY SEL yields no parseable entries anywhere: the export must
        # not fabricate an empty-but-"successful" bundle — it fails honestly.
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "operation_failed"


# -- virtual media (SRV-ACT-05) ------------------------------------------------


class TestVirtualMedia:
    def test_mount_readback_and_unmount(self, sim: SimAccess) -> None:
        session = _session(sim)
        ticket_url = "http://127.0.0.1:9/isos/debian.iso"
        mount_ctx = _ticket_context(ticket_url)
        mount = _plan(
            "virtual_media.mount",
            {"file_id": str(uuid.uuid4()), "media_kind": "iso"},
            runtime_context=mount_ctx,
        )
        preflight = ADAPTER.preflight_operation(session, mount)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(mount), lambda *_: None)
        assert result.ok is True
        slot_id = result.evidence["slot_id"]
        # The ticket URL never enters evidence: the command is redacted and a
        # ticket_id reference stays (file-layer invariant, SECURITY.md §7).
        assert result.evidence["ticket_id"] == mount_ctx["ticket"]["id"]
        assert ticket_url not in json.dumps(result.evidence, ensure_ascii=False)
        assert result.evidence["command"]["Image"] != ticket_url
        verdict = ADAPTER.verify_operation(session, mount, result)
        assert verdict.succeeded is True
        assert verdict.evidence["inserted"] is True
        assert verdict.evidence["image_matches_ticket"] is True

        unmount = _plan(
            "virtual_media.unmount",
            {"slot_id": slot_id},
            runtime_context={"ticket": {"url": ticket_url, "id": str(uuid.uuid4())}},
        )
        preflight = ADAPTER.preflight_operation(session, unmount)
        assert preflight.ok is True
        ejected = ADAPTER.execute_operation(session, _short_deadline(unmount), lambda *_: None)
        assert ejected.ok is True
        verdict = ADAPTER.verify_operation(
            session,
            unmount,
            _merge_evidence(ejected, ticket_revoked=utcnow().isoformat()),
        )
        assert verdict.succeeded is True
        assert verdict.evidence["inserted"] is False
        assert verdict.evidence["ticket_revoked"] is True

    def test_mount_verify_repolls_until_a_delayed_insert_applies(self, sim: SimAccess) -> None:
        # A real manager may stage the insert after the 204 acceptance: the
        # single-shot read-back would wrongly declare ambiguity. The bounded
        # re-poll must observe the applied insert and succeed.
        sim.set(media_insert_delayed=True)
        session = _session(sim)
        ticket_url = "http://127.0.0.1:9/isos/debian.iso"
        plan = _plan(
            "virtual_media.mount",
            {"file_id": str(uuid.uuid4()), "media_kind": "iso"},
            runtime_context=_ticket_context(ticket_url),
        )
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded is True, verdict
        assert verdict.ambiguous is False
        assert verdict.evidence["inserted"] is True
        assert verdict.evidence["polls"] >= 2

    def test_unmount_precondition_drift_when_slot_empty(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("virtual_media.unmount", {"slot_id": "1"})
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is False
        assert preflight.error_code == "validation_failed"

    def test_mount_without_ticket_is_not_configured(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("virtual_media.mount", {"file_id": str(uuid.uuid4()), "media_kind": "iso"})
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is False
        assert preflight.error_code == "not_configured"

    def test_foreign_image_url_is_rejected_by_the_device(self, sim: SimAccess) -> None:
        sim.set(media_insert_rejects_foreign_url=True, media_hosts=["127.0.0.1"])
        session = _session(sim)
        plan = _plan(
            "virtual_media.mount",
            {"file_id": str(uuid.uuid4()), "media_kind": "iso"},
            runtime_context=_ticket_context("http://evil.example.com/iso"),
        )
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "validation_failed"
        # An image on an allowed host passes (device-side host check only).
        ok_plan = _plan(
            "virtual_media.mount",
            {"file_id": str(uuid.uuid4()), "media_kind": "iso"},
            runtime_context=_ticket_context("http://127.0.0.1:9/debian.iso"),
        )
        result = ADAPTER.execute_operation(session, _short_deadline(ok_plan), lambda *_: None)
        assert result.ok is True

    def test_media_fetch_emulation_requires_a_reachable_ticket(self, sim: SimAccess) -> None:
        sim.set(media_fetch_required=True)
        session = _session(sim)
        plan = _plan(
            "virtual_media.mount",
            {"file_id": str(uuid.uuid4()), "media_kind": "usb_image"},
            runtime_context=_ticket_context("http://127.0.0.1:1/unreachable.img"),
        )
        with pytest.raises(AdapterError) as exc_info:
            ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert exc_info.value.code == "validation_failed"


# -- firmware (SRV-ACT-06) ----------------------------------------------------


class TestFirmware:
    def test_firmware_query_returns_normalized_inventory(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("firmware.query")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        inventory = result.inventory
        assert inventory is not None
        assert inventory.firmware_version == "SIM-BMC-1.0.0"
        items = {item.target: item for item in inventory.firmware_items}
        assert items["BMC"].version == "SIM-BMC-1.0.0"
        assert items["BIOS"].version == "SIM-BIOS-2.0"
        persisted = {
            "observed_at": utcnow().isoformat(),
            "firmware_items": len(items),
            "firmware_version": "SIM-BMC-1.0.0",
        }
        merged = _merge_evidence(result, inventory_persisted=persisted)
        verdict = ADAPTER.verify_operation(session, plan, merged)
        assert verdict.succeeded is True

    def test_firmware_update_job_version_readback(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05, firmware_update_version="SIM-BMC-1.1.0")
        session = _session(sim)
        update_ctx = _ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-1.1.0")
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "BMC"},
            runtime_context=update_ctx,
        )
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=10.0), lambda *_: None)
        assert result.ok is True
        assert result.evidence["target_id"] == "BMC"
        # The ticket URL never enters evidence: the ImageURI command field is
        # redacted and the ticket is referenced by id only.
        assert result.evidence["ticket_id"] == update_ctx["ticket"]["id"]
        assert "http://127.0.0.1:9/fw.iso" not in json.dumps(result.evidence, ensure_ascii=False)
        assert result.evidence["command"]["ImageURI"] != "http://127.0.0.1:9/fw.iso"
        verdict = _poll_verify(session, plan, _job_result(result), timeout=30.0)
        assert verdict.succeeded is True
        assert verdict.evidence["readback_version"] == "SIM-BMC-1.1.0"
        assert verdict.evidence["expected_version"] == "SIM-BMC-1.1.0"

    def test_firmware_update_completed_job_with_wrong_version_is_failed(self, sim: SimAccess) -> None:
        # The device reports job success but bumps the target to a version
        # DIFFERENT from the package target: a provably-wrong final version is
        # an explicit device-side failure (operation_failed), never success
        # without proof and never an ambiguity.
        sim.set(task_duration_seconds=0.05, firmware_update_version="SIM-BMC-1.1.0")
        session = _session(sim)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "BMC"},
            runtime_context=_ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-9.9.9"),
        )
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=3.0), lambda *_: None)
        assert result.ok is True
        verdict = _poll_verify(session, plan, _job_result(result), timeout=15.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["reason"] == "version_mismatch_after_completed_job"
        assert verdict.evidence["readback_version"] == "SIM-BMC-1.1.0"
        assert verdict.evidence["expected_version"] == "SIM-BMC-9.9.9"

    def test_firmware_update_task_failure_is_operation_failed(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=0.05, failures={"update_task_fails": True})
        session = _session(sim)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "BMC"},
            runtime_context=_ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-1.1.0"),
        )
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = _poll_verify(session, plan, _job_result(result))
        assert verdict.succeeded is False
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"

    def test_firmware_update_running_job_is_pending(self, sim: SimAccess) -> None:
        sim.set(task_duration_seconds=5.0, update_never_completes=True)
        session = _session(sim)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "BMC"},
            runtime_context=_ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-1.1.0"),
        )
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = ADAPTER.verify_operation(session, plan, _job_result(result))
        assert verdict.pending is True

    def test_firmware_update_reboot_loop_completed_job_never_bumps_is_failed(
        self, sim: SimAccess
    ) -> None:
        # The update job completes but the version never reaches the package
        # target (reboot loop, version stays readable): terminal job success
        # + a provably-wrong final read-back version = operation_failed —
        # polling to the budget may never masquerade as ambiguity.
        sim.set(task_duration_seconds=0.05, update_reboot_loop=True)
        session = _session(sim)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "BMC"},
            runtime_context=_ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-1.1.0"),
        )
        result = ADAPTER.execute_operation(session, _short_deadline(plan, seconds=3.0), lambda *_: None)
        assert result.ok is True
        verdict = _poll_verify(session, plan, _job_result(result), timeout=15.0)
        assert verdict.succeeded is False
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["reason"] == "version_mismatch_after_completed_job"
        assert verdict.evidence["readback_version"] == "SIM-BMC-1.0.0"

    def test_firmware_update_unknown_target_fails_preflight(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4()), "target_id": "CXL"},
            runtime_context=_ticket_context("http://127.0.0.1:9/fw.iso", expected_version="SIM-BMC-1.1.0"),
        )
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is False
        assert preflight.error_code == "validation_failed"


# -- asset.refresh (SRV-ACT-07) -----------------------------------------------


class TestAssetRefresh:
    def test_asset_inventory_with_fru_components_verifies(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("asset.refresh")
        preflight = ADAPTER.preflight_operation(session, plan)
        assert preflight.ok is True
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        inventory = result.inventory
        assert inventory is not None
        assert inventory.serial_number == "WARDEN-SIM-0001"
        assert inventory.model == "Warden SimServer 1U (simulated)"
        assert inventory.firmware_version == "SIM-BMC-1.0.0"
        fru = {component.native_id: component for component in inventory.components}
        assert "chassis-1" in fru and "manager-1" in fru
        assert fru["chassis-1"].properties["part_number"] == "SIM-CH-1U-A"
        persisted = {
            "observed_at": utcnow().isoformat(),
            "serial_number": "WARDEN-SIM-0001",
            "components": len(inventory.components),
        }
        merged = _merge_evidence(result, inventory_persisted=persisted)
        verdict = ADAPTER.verify_operation(session, plan, merged)
        assert verdict.succeeded is True
        assert verdict.ambiguous is False

    def test_asset_verify_without_persistence_proof_is_ambiguous(self, sim: SimAccess) -> None:
        session = _session(sim)
        plan = _plan("asset.refresh")
        result = ADAPTER.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded is False
        assert verdict.ambiguous is True
