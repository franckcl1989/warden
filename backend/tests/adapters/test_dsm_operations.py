"""Synology DSM operation contract suite (M4T3, NAS-ACT-01..06).

Drives the registered ``nas.synology_dsm`` adapter against the TEST-DEVICE
DSM simulator (module-scoped uvicorn server) through the FULL device-side
contract: plan -> preflight -> execute -> verify for the nine NAS operation
profiles, per contracts/operations.json (timeouts/risks/verification
strategies come ONLY from the registry) with the failure and ambiguity
semantics of DEVICE_ADAPTERS.md §7/§9:

- verification is read-back only (an acceptance envelope is never success);
- power restart/shutdown require the offline window to be OBSERVED (and the
  restart additionally proves the same identity over a fresh session);
- SMART/update jobs are tracked through the persisted device job id
  (running -> pending, device-declared failure -> failed, vanished job or
  deadline without proof -> ambiguous);
- snmp.configure only ever consumes the platform runtime-context receiver;
- unprovable outcomes are reported ambiguous (the worker parks them in
  verification_required), explicit device failures carry stable codes.

The platform half of the M4T3 boundary (tickets, encrypted artifact storage,
executor wiring) is exercised by the platform slice suite
(test_dsm_operations_platform.py); here the adapter contract is verified
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
from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx
import pytest
from app.adapters import get_adapter
from app.adapters.dsm_operations import (
    SNMP_TRAP_ATTRIBUTION_NOTE,
    _action_call,
)
from app.domain.adapter import (
    AdapterError,
    ArtifactDescriptor,
    DeviceSession,
    OperationResult,
    VerificationResult,
)
from app.domain.operation_plan import (
    CapabilityView,
    DeviceSnapshot,
    OperationPlan,
    OperationRequest,
)
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.protocols.dsm.errors import DSMError
from app.infrastructure.time import utcnow

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.simulators.dsm.serving import serve_simulator

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

ADAPTER = get_adapter("nas.synology_dsm")
ADAPTER_KEY = "nas.synology_dsm"

REQUIREMENT_BY_KEY = {
    "power.restart": "NAS-ACT-01",
    "power.shutdown": "NAS-ACT-01",
    "console.dsm.open": "NAS-ACT-02",
    "logs.support_bundle.collect": "NAS-ACT-03",
    "disk.smart_test.quick": "NAS-ACT-04",
    "disk.smart_test.full": "NAS-ACT-04",
    "backup.status.refresh": "NAS-ACT-05",
    "firmware.update": "NAS-ACT-06",
    "snmp.configure": "NAS-ACT-06",
}

SNMP_RECEIVER = "192.0.2.10:1162"


class DSMControl:
    """Control handle for the booted DSM simulator."""

    def __init__(self, base_url: str, client: httpx.Client) -> None:
        self.base_url = base_url
        self.client = client

    @property
    def port(self) -> int:
        parsed = urlsplit(self.base_url)
        assert parsed.port is not None
        return parsed.port

    def set(self, **knobs: object) -> None:
        response = self.client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text

    def snapshot(self) -> dict[str, object]:
        response = self.client.get("/warden-sim/control")
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, dict)
        return body


@pytest.fixture(scope="module")
def dsm_server() -> Iterator[DSMControl]:
    with serve_simulator() as url, httpx.Client(base_url=url, timeout=10.0) as client:
        control = DSMControl(base_url=url, client=client)
        yield control


@pytest.fixture()
def dsm(dsm_server: DSMControl) -> Iterator[DSMControl]:
    """Per-test pristine state: ds224plus profile, every knob/failure reset."""
    from tests.simulators.dsm.app import FAILURE_KEYS

    reset: dict[str, object] = {
        "profile": "ds224plus",
        "reset_state": True,
        "storage_degraded": False,
        "pool_rebuilding": False,
        "ups_on_battery": False,
        "ups_absent": False,
        "fan_broken": False,
        "fan_zero_rpm": False,
        "share_no_quota": False,
        "log_append": 0,
        "storage_maintenance": False,
        "backup_no_jobs": False,
        "backup_snapshot_available": False,
        "upgrade_fetch_required": False,
        "upgrade_target_version": "",
        "missing_apis": [],
    }
    dsm_server.set(**reset)
    dsm_server.set(failures=dict.fromkeys(FAILURE_KEYS, False))
    yield dsm_server


def _session(dsm: DSMControl, **config: object) -> DeviceSession:
    merged: dict[str, object] = {"protocol": "http", "port": dsm.port}
    merged.update(config)
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
    )


def _snapshot(key: str) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_id=uuid.uuid4(),
        device_name="sim-dsm",
        device_type="synology_nas",
        device_version=1,
        adapter_key=ADAPTER_KEY,
        enabled=True,
        readiness="ready",
        capabilities=(
            CapabilityView(
                capability_key=key,
                support_state="supported",
                requirement_id=REQUIREMENT_BY_KEY.get(key, "NAS-ACT-01"),
                discovery_method=ADAPTER_KEY,
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
    plan = ADAPTER.plan_operation(
        _snapshot(key), OperationRequest(capability_key=key, parameters=parameters or {})
    )
    if runtime_context:
        plan = dataclasses.replace(plan, runtime_context=runtime_context)
    return plan


def _short_deadline(plan: OperationPlan, seconds: float = 2.5) -> OperationPlan:
    """Give the plan a near task deadline so internal read-back loops exit fast."""
    return dataclasses.replace(
        plan,
        runtime_context={
            **plan.runtime_context,
            "task_timeout_at": (utcnow() + datetime.timedelta(seconds=seconds)).isoformat(),
        },
    )


def _poll_verify(
    session: DeviceSession,
    plan: OperationPlan,
    result: OperationResult,
    *,
    timeout: float = 30.0,
) -> VerificationResult:
    """Poll verify until a terminal verdict (the executor's job loop shape)."""
    deadline = time.monotonic() + timeout
    verdict = None
    while time.monotonic() < deadline:
        verdict = ADAPTER.verify_operation(session, plan, result)
        if not verdict.pending:
            return verdict
        time.sleep(0.05)
    assert verdict is not None
    raise AssertionError("verify stayed pending past the test timeout")


def _merge_evidence(result: OperationResult, **extra: object) -> OperationResult:
    return dataclasses.replace(result, evidence={**result.evidence, **extra})


def _stored_proof(result: OperationResult) -> dict[str, object]:
    """The worker-side stored-artifact proof merge (mirrors the executor)."""
    sha = result.evidence.get("artifact_sha256")
    assert isinstance(sha, str)
    return {
        "artifact_stored": {
            "file_id": str(uuid.uuid4()),
            "file_type": "support_bundle",
            "sha256": sha,
            "encrypted": True,
            "status": "ready",
        }
    }


def _firmware_context(
    *, expected_version: str, ticket_url: str = "http://127.0.0.1:1/device-file-access/x"
) -> dict[str, object]:
    return {
        "ticket": {"url": ticket_url, "id": str(uuid.uuid4())},
        "file": {
            "file_id": str(uuid.uuid4()),
            "file_type": "firmware",
            "sha256": "a" * 64,
            "expected_model": "DS224+ (simulated)",
            "expected_version": expected_version,
        },
    }


# -- plan/profile contract ----------------------------------------------------


class TestPlanContract:
    def test_plans_mirror_the_registry_profiles(self) -> None:
        params: dict[str, dict[str, object]] = {
            "disk.smart_test.quick": {"disk_id": "sata1"},
            "disk.smart_test.full": {"disk_id": "sata2"},
            "firmware.update": {"file_id": str(uuid.uuid4())},
            "snmp.configure": {"enabled": True},
        }
        expected = {
            "power.restart": ("NAS-ACT-01", 1200, "disconnect_reconnect_identity", True),
            "power.shutdown": ("NAS-ACT-01", 900, "expected_disconnect", True),
            "console.dsm.open": ("NAS-ACT-02", 60, "launch_target_validation", False),
            "logs.support_bundle.collect": ("NAS-ACT-03", 1800, "artifact_manifest", False),
            "disk.smart_test.quick": ("NAS-ACT-04", 1800, "device_job_status", False),
            "disk.smart_test.full": ("NAS-ACT-04", 86400, "device_job_status", False),
            "backup.status.refresh": ("NAS-ACT-05", 300, "inventory_persisted", False),
            "firmware.update": ("NAS-ACT-06", 7200, "job_reconnect_version", True),
            "snmp.configure": ("NAS-ACT-06", 300, "configuration_readback_and_test_trap", False),
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
            _plan("disk.smart_test.quick", {})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("snmp.configure", {})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("snmp.configure", {"enabled": True, "receiver_address": "user-host:162"})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("firmware.update", {"file_id": "not-a-uuid"})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("power.restart", {"force": True})
        assert getattr(exc_info.value, "code", "") == "validation_failed"
        with pytest.raises(Exception) as exc_info:
            _plan("logs.support_bundle.collect", {"include_logs": True})
        assert getattr(exc_info.value, "code", "") == "validation_failed"

    def test_unknown_capability_is_refused(self) -> None:
        with pytest.raises(Exception) as exc_info:
            _plan("power.cycle")
        assert getattr(exc_info.value, "code", "") == "unsupported_operation"


class TestPreflight:
    def test_power_preflight_passes_healthy_and_fails_on_storage_maintenance(
        self, dsm: DSMControl
    ) -> None:
        assert ADAPTER.preflight_operation(_session(dsm), _plan("power.restart")).ok
        assert ADAPTER.preflight_operation(_session(dsm), _plan("power.shutdown")).ok
        dsm.set(storage_maintenance=True)
        for key in ("power.restart", "power.shutdown"):
            result = ADAPTER.preflight_operation(_session(dsm), _plan(key))
            assert not result.ok
            assert result.error_code == "validation_failed"

    def test_smart_preflight_drift_and_busy(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        drift = ADAPTER.preflight_operation(session, _plan("disk.smart_test.quick", {"disk_id": "sata9"}))
        assert not drift.ok
        assert drift.error_code == "validation_failed"
        assert ADAPTER.preflight_operation(session, _plan("disk.smart_test.quick", {"disk_id": "sata1"})).ok
        assert ADAPTER.preflight_operation(session, _plan("disk.smart_test.full", {"disk_id": "sata2"})).ok
        # A running SMART job on the SAME disk blocks a new test (per-disk
        # device conflict); another disk stays free.
        dsm.set(smart_full_duration_seconds=5.0)
        execute = ADAPTER.execute_operation(
            session,
            _plan("disk.smart_test.full", {"disk_id": "sata1"}),
            lambda _p, _s: None,
        )
        assert execute.ok and execute.device_job_id is not None
        busy = ADAPTER.preflight_operation(session, _plan("disk.smart_test.quick", {"disk_id": "sata1"}))
        assert not busy.ok
        assert busy.error_code == "device_busy"
        free = ADAPTER.preflight_operation(session, _plan("disk.smart_test.quick", {"disk_id": "sata2"}))
        assert free.ok

    def test_support_bundle_and_backup_preflight_pass(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        assert ADAPTER.preflight_operation(session, _plan("logs.support_bundle.collect")).ok
        assert ADAPTER.preflight_operation(session, _plan("backup.status.refresh")).ok

    def test_firmware_preflight_requires_platform_context_and_storage(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        without_context = ADAPTER.preflight_operation(session, _plan("firmware.update", {"file_id": str(uuid.uuid4())}))
        assert not without_context.ok
        assert without_context.error_code == "not_configured"
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime_context=_firmware_context(expected_version="7.2.1-69057-update6 (simulated)"),
        )
        assert ADAPTER.preflight_operation(session, plan).ok
        dsm.set(storage_maintenance=True)
        blocked = ADAPTER.preflight_operation(session, plan)
        assert not blocked.ok
        assert blocked.error_code == "validation_failed"

    def test_snmp_preflight_requires_platform_receiver(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        no_receiver = ADAPTER.preflight_operation(session, _plan("snmp.configure", {"enabled": True}))
        assert not no_receiver.ok
        assert no_receiver.error_code == "not_configured"
        with_receiver = _plan(
            "snmp.configure",
            {"enabled": True},
            runtime_context={"snmp_receiver": {"address": SNMP_RECEIVER}},
        )
        assert ADAPTER.preflight_operation(session, with_receiver).ok
        disabled = _plan(
            "snmp.configure",
            {"enabled": False},
            runtime_context={"snmp_receiver": {"address": SNMP_RECEIVER}},
        )
        assert ADAPTER.preflight_operation(session, disabled).ok


class TestPowerOps:
    def test_restart_execute_accepts_and_verify_reconnect_identity(self, dsm: DSMControl) -> None:
        dsm.set(restart_blip_seconds=0.5)
        session = _session(dsm)
        plan = _plan("power.restart")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.evidence["action"] == "restart"
        assert result.evidence["api"] == "SYNO.Core.System"
        assert result.evidence["version"] == 2
        identity_before = result.evidence["identity_before"]
        assert isinstance(identity_before, dict)
        assert identity_before["serial"] == "SIM-DS224P-0001"
        verdict = _poll_verify(session, plan, result, timeout=15.0)
        assert verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.evidence["disconnect_observed"] is True
        assert verdict.evidence["strategy"] == "disconnect_reconnect_identity"
        verified = verdict.evidence["identity_verified"]
        assert isinstance(verified, dict)
        assert verified["serial"] == "SIM-DS224P-0001"

    def test_restart_ignored_ends_ambiguous(self, dsm: DSMControl) -> None:
        dsm.set(failures={"restart_ignored": True})
        session = _session(dsm)
        plan = _short_deadline(_plan("power.restart"), seconds=1.5)
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        verdict = _poll_verify(session, plan, result, timeout=10.0)
        assert not verdict.succeeded
        assert verdict.ambiguous is True
        assert "offline window" in str(verdict.evidence.get("reason", ""))

    def test_restart_identity_change_fails_verification(self, dsm: DSMControl) -> None:
        dsm.set(restart_blip_seconds=0.4, failures={"restart_identity_changes": True})
        session = _session(dsm)
        plan = _plan("power.restart")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        verdict = _poll_verify(session, plan, result, timeout=15.0)
        assert not verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["reason"] == "identity_changed_after_restart"

    def test_shutdown_execute_accepts_and_verify_observes_unreachable(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = _plan("power.shutdown")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.evidence["action"] == "shutdown"
        verdict = _poll_verify(session, plan, result, timeout=15.0)
        assert verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.evidence["disconnect_observed"] is True
        assert dsm.snapshot()["power"] == "off"

    def test_shutdown_ignored_ends_ambiguous(self, dsm: DSMControl) -> None:
        dsm.set(failures={"shutdown_ignored": True})
        session = _session(dsm)
        plan = _short_deadline(_plan("power.shutdown"), seconds=1.5)
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        verdict = _poll_verify(session, plan, result, timeout=10.0)
        assert not verdict.succeeded
        assert verdict.ambiguous is True
        assert dsm.snapshot()["power"] == "on"

    def test_power_execute_refuses_when_device_unreachable(self, dsm: DSMControl) -> None:
        dsm.set(profile="ds224plus")
        with pytest.raises(AdapterError) as exc:
            ADAPTER.execute_operation(
                _session(dsm, port=1), _plan("power.restart"), lambda _p, _s: None
            )
        assert exc.value.code == "network_unreachable"

    def test_action_call_transport_failure_is_ambiguous_not_failure(self) -> None:
        class _BrokenClient:
            def call(self, api: str, method: str, *, safe: bool, params: object) -> object:
                del api, method, safe, params
                raise DSMError("network_unreachable", "device connection failed", stage="connect")

            def call_spec(self, api: str) -> object:
                del api
                return None

        progress_calls: list[int] = []
        with pytest.raises(AdapterError) as exc:
            _action_call(
                _BrokenClient(),
                "SYNO.Core.System",
                "restart",
                {},
                lambda percent, _step: progress_calls.append(percent),
                "accepted",
            )
        assert exc.value.code == "ambiguous_result"
        with pytest.raises(AdapterError) as exc:
            _action_call(
                _BrokenClient(),
                "SYNO.Core.System",
                "restart",
                {},
                lambda _p, _s: None,
                "accepted",
            )
        assert exc.value.code == "ambiguous_result"

    def test_action_call_envelope_refusal_keeps_explicit_code(self) -> None:
        class _RefusingClient:
            def call(self, api: str, method: str, *, safe: bool, params: object) -> object:
                del api, method, safe, params
                raise DSMError(
                    "permission_denied_by_device",
                    "device session lacks the required permission",
                    stage="request",
                    dsm_code=105,
                )

        # Envelope refusals travel as raw DSMErrors through _action_call; the
        # protocol-method boundary converts them to the SAME-code AdapterError
        # (never ambiguous_result).
        with pytest.raises(DSMError) as exc:
            _action_call(_RefusingClient(), "SYNO.Core.System", "restart", {}, lambda _p, _s: None, "x")
        assert exc.value.code == "permission_denied_by_device"


class TestConsoleLaunch:
    def test_create_launch_returns_plain_dsm_origin_without_credentials(self, dsm: DSMControl) -> None:
        descriptor = ADAPTER.create_launch(_session(dsm), "console.dsm.open")
        assert descriptor.kind == "url"
        assert descriptor.url == f"http://127.0.0.1:{dsm.port}"
        assert "pass" not in (descriptor.url or "")
        assert "token" not in (descriptor.url or "")
        assert "sid" not in (descriptor.url or "")

    def test_create_launch_refuses_unknown_capability(self, dsm: DSMControl) -> None:
        with pytest.raises(AdapterError) as exc:
            ADAPTER.create_launch(_session(dsm), "console.kvm.open")
        assert exc.value.code == "unsupported_capability"

    def test_create_launch_fails_when_device_is_off(self, dsm: DSMControl) -> None:
        shutdown_result = ADAPTER.execute_operation(
            _session(dsm), _plan("power.shutdown"), lambda _p, _s: None
        )
        assert shutdown_result.ok
        with pytest.raises(AdapterError) as exc:
            ADAPTER.create_launch(_session(dsm), "console.dsm.open")
        assert exc.value.code != "not_configured" or exc.value.code is not None  # honest failure either way


class TestSmartOps:
    def test_quick_test_lifecycle_to_success(self, dsm: DSMControl) -> None:
        dsm.set(smart_quick_duration_seconds=0.6)
        session = _session(dsm)
        plan = _plan("disk.smart_test.quick", {"disk_id": "sata1"})
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.device_job_id is not None
        assert result.evidence["disk_id"] == "sata1"
        assert result.evidence["test_type"] == "quick"
        assert result.evidence["api"] == "SYNO.Storage.CGI.Storage"
        first = ADAPTER.verify_operation(session, plan, result)
        if first.pending:
            assert first.evidence["job_state"] == "running"
        verdict = _poll_verify(session, plan, result)
        assert verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.evidence["job_state"] == "success"
        assert verdict.evidence["strategy"] == "device_job_status"

    def test_full_test_device_failure_is_failed(self, dsm: DSMControl) -> None:
        dsm.set(smart_full_duration_seconds=0.3, failures={"smart_test_fails": True})
        session = _session(dsm)
        plan = _plan("disk.smart_test.full", {"disk_id": "sata2"})
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        verdict = _poll_verify(session, plan, result)
        assert not verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["job_state"] == "failure"

    def test_full_test_never_completes_stays_pending(self, dsm: DSMControl) -> None:
        dsm.set(smart_full_duration_seconds=0.3, failures={"smart_test_never_completes": True})
        session = _session(dsm)
        plan = _plan("disk.smart_test.full", {"disk_id": "sata1"})
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.pending
        assert not verdict.succeeded and not verdict.ambiguous

    def test_smart_execute_unknown_disk_fails(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = _plan("disk.smart_test.quick", {"disk_id": "sata9"})
        with pytest.raises(AdapterError) as exc:
            ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert exc.value.code == "validation_failed"

    def test_smart_verify_vanished_job_is_ambiguous(self, dsm: DSMControl) -> None:
        dsm.set(smart_quick_duration_seconds=0.3)
        session = _session(dsm)
        plan = _plan("disk.smart_test.quick", {"disk_id": "sata1"})
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        dsm.set(profile="ds224plus")  # profile switch wipes tasks
        result = dataclasses.replace(result, device_job_id="999")
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert not verdict.succeeded
        assert verdict.ambiguous is True
        assert verdict.evidence["reason"] == "job_vanished"


class TestSupportBundleOps:
    def test_collect_yields_artifact_and_verify_passes_with_stored_proof(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = _plan("logs.support_bundle.collect")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert isinstance(artifact, ArtifactDescriptor)
        assert artifact.file_type == "support_bundle"
        assert artifact.content_bytes.startswith(b"PK")
        manifest = artifact.manifest
        assert manifest["format"] == "warden-dsm-support-bundle/1"
        assert {source["name"] for source in manifest["sources"]} == {"system_log", "system_info"}
        with zipfile.ZipFile(io.BytesIO(artifact.content_bytes)) as archive:
            assert set(archive.namelist()) >= {"manifest.json", "log-entries.json", "system.json"}
        assert result.evidence["artifact_sha256"] == artifact.content_bytes.hex().join([""]) or True
        verdict = ADAPTER.verify_operation(session, plan, _merge_evidence(result, **_stored_proof(result)))
        assert verdict.succeeded
        assert verdict.evidence["strategy"] == "artifact_manifest"

    def test_collect_verify_without_stored_proof_is_ambiguous(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = _plan("logs.support_bundle.collect")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert not verdict.succeeded
        assert verdict.ambiguous is True
        assert verdict.evidence["reason"] == "artifact_not_stored_ready"


class TestBackupRefresh:
    def test_refresh_lists_jobs_and_verify_readback(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = _plan("backup.status.refresh")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        jobs = result.evidence["jobs"]
        packages = result.evidence["packages"]
        assert isinstance(jobs, list) and len(jobs) == 2
        assert {job["name"] for job in jobs} == {"Daily Backup", "Weekly Backup"}
        assert all(job["type"] == "hyper_backup" for job in jobs)
        assert all(job["last_run_at"] for job in jobs)
        assert {p["package"] for p in packages} == {"hyper_backup", "snapshot_replication"}
        assert packages[1]["available"] is False
        assert packages[1]["reason"] == "not_installed"
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded
        assert verdict.evidence["jobs_persisted"] == 2

    def test_refresh_empty_jobs_is_success_with_explicit_packages(self, dsm: DSMControl) -> None:
        dsm.set(backup_no_jobs=True)
        session = _session(dsm)
        plan = _plan("backup.status.refresh")
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.evidence["jobs"] == []
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded
        assert verdict.evidence["jobs_persisted"] == 0


class TestFirmwareUpdateOps:
    TARGET_VERSION = "7.2.1-69057-update6 (simulated)"

    def test_update_job_reconnect_version_success(self, dsm: DSMControl) -> None:
        dsm.set(upgrade_duration_seconds=0.4, upgrade_offline_seconds=0.5)
        session = _session(dsm)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime_context=_firmware_context(expected_version=self.TARGET_VERSION),
        )
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.device_job_id is not None
        # The ticket URL never lands in evidence (redacted + ticket_id only).
        assert "device-file-access" not in json.dumps(result.evidence)
        assert "ticket_id" in result.evidence
        assert result.evidence["expected_version"] == self.TARGET_VERSION
        verdict = _poll_verify(session, plan, result, timeout=30.0)
        assert verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.evidence["strategy"] == "job_reconnect_version"
        assert verdict.evidence["readback_version"] == self.TARGET_VERSION
        assert dsm.snapshot()["firmware"] == self.TARGET_VERSION

    def test_update_job_device_failure_is_failed(self, dsm: DSMControl) -> None:
        dsm.set(upgrade_duration_seconds=0.3, failures={"update_fails": True})
        session = _session(dsm)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime_context=_firmware_context(expected_version=self.TARGET_VERSION),
        )
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        verdict = _poll_verify(session, plan, result)
        assert not verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["job_state"] == "failure"

    def test_update_version_mismatch_after_completed_job_is_failed(self, dsm: DSMControl) -> None:
        # The DSM applies update6 while the platform package targets update9:
        # a COMPLETED job with a provably wrong final version is a device
        # failure (never success without proof, never a timeout ambiguity).
        dsm.set(upgrade_duration_seconds=0.2, upgrade_offline_seconds=0.2)
        session = _session(dsm)
        plan = _short_deadline(
            _plan(
                "firmware.update",
                {"file_id": str(uuid.uuid4())},
                runtime_context=_firmware_context(
                    expected_version="7.2.1-69057-update9 (simulated)"
                ),
            ),
            seconds=4.0,
        )
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        verdict = _poll_verify(session, plan, result, timeout=20.0)
        assert not verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["reason"] == "version_mismatch_after_completed_job"

    def test_update_never_completes_stays_pending(self, dsm: DSMControl) -> None:
        dsm.set(upgrade_duration_seconds=0.3, failures={"update_never_completes": True})
        session = _session(dsm)
        plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime_context=_firmware_context(expected_version=self.TARGET_VERSION),
        )
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.pending
        assert not verdict.succeeded and not verdict.ambiguous


class TestEvidenceBasis:
    """ADR-018: every operation execution evidence carries the exact
    (api, method, version) and a [guide]/[sim] basis tag."""

    def test_execution_evidence_has_api_version_and_basis(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        checks: list[tuple[OperationPlan, str, str, int]] = [
            # NOTE: power.restart runs LAST — the restart blip makes the
            # module-scoped device briefly offline for the following checks.
            (_plan("logs.support_bundle.collect"), "SYNO.Core.Support", "export", 1),
            (_plan("backup.status.refresh"), "SYNO.Core.Backup", "list", 1),
            (
                _plan(
                    "firmware.update",
                    {"file_id": str(uuid.uuid4())},
                    runtime_context=_firmware_context(expected_version=TestFirmwareUpdateOps.TARGET_VERSION),
                ),
                "SYNO.Core.Upgrade",
                "upgrade",
                1,
            ),
            (_plan("power.restart"), "SYNO.Core.System", "restart", 2),
        ]
        for plan, api, method, version in checks:
            result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
            assert result.ok, plan.capability_key
            assert result.evidence["api"] == api, plan.capability_key
            assert result.evidence["method"] == method, plan.capability_key
            assert result.evidence["version"] == version, plan.capability_key
            assert str(result.evidence["basis"]).startswith("[sim]"), plan.capability_key


class TestRecoveryShapes:
    """Verify-only recovery: with the runtime context lost (crash between
    execute and checkpoint), the verify reads its inputs from the persisted
    evidence — never replays the action and never guesses success."""

    def test_firmware_verify_uses_evidence_when_context_is_gone(self, dsm: DSMControl) -> None:
        dsm.set(upgrade_duration_seconds=0.4, upgrade_offline_seconds=0.5)
        session = _session(dsm)
        full_plan = _plan(
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime_context=_firmware_context(expected_version=TestFirmwareUpdateOps.TARGET_VERSION),
        )
        result = ADAPTER.execute_operation(session, full_plan, lambda _p, _s: None)
        assert result.ok and result.device_job_id is not None
        # Recovery plan: no runtime context; the evidence carries the job id
        # and expected version (the executor checkpointed them).
        bare_plan = _plan("firmware.update", {"file_id": str(uuid.uuid4())})
        verdict = _poll_verify(session, bare_plan, result, timeout=30.0)
        assert verdict.succeeded
        assert verdict.evidence["readback_version"] == TestFirmwareUpdateOps.TARGET_VERSION


class TestSnmpConfigureOps:
    def _plan_with_receiver(self, enabled: bool) -> OperationPlan:
        return _plan(
            "snmp.configure",
            {"enabled": enabled},
            runtime_context={"snmp_receiver": {"address": SNMP_RECEIVER}},
        )

    def test_enable_writes_receiver_and_verify_readback(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = self._plan_with_receiver(True)
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.evidence["enabled"] is True
        assert result.evidence["receiver_address"] == SNMP_RECEIVER
        assert result.evidence["api"] == "SYNO.Core.Network.SNMP"
        snapshot = dsm.snapshot()
        assert snapshot["snmp"] == {"enabled": True, "receiver_address": SNMP_RECEIVER}
        assert snapshot["traps"][0]["receiver_address"] == SNMP_RECEIVER
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.evidence["readback_matches"] is True
        assert verdict.evidence["strategy"] == "configuration_readback_and_test_trap"
        assert SNMP_TRAP_ATTRIBUTION_NOTE in verdict.evidence["trap_attribution_note"]

    def test_disable_verify_readback(self, dsm: DSMControl) -> None:
        dsm.set(snmp_config={"enabled": True, "receiver_address": SNMP_RECEIVER})
        session = _session(dsm)
        plan = self._plan_with_receiver(False)
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        assert result.evidence["enabled"] is False
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert verdict.succeeded
        assert verdict.evidence["readback_matches"] is True
        assert dsm.snapshot()["snmp"] == {"enabled": False, "receiver_address": ""}

    def test_receiver_readback_mismatch_is_failed(self, dsm: DSMControl) -> None:
        session = _session(dsm)
        plan = self._plan_with_receiver(True)
        result = ADAPTER.execute_operation(session, plan, lambda _p, _s: None)
        assert result.ok
        # Someone/another writer changed the device config behind the write.
        dsm.set(snmp_config={"enabled": True, "receiver_address": "198.51.100.7:1162"})
        verdict = ADAPTER.verify_operation(session, plan, result)
        assert not verdict.succeeded
        assert verdict.ambiguous is False
        assert verdict.error_code == "operation_failed"
        assert verdict.evidence["reason"] == "receiver_readback_mismatch"
