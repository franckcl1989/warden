"""Fake adapter operation methods (M2T4, docs/DEVICE_ADAPTERS.md §2.4/§4.2/§9).

Unit tests over plan/preflight/execute/verify with their mode flags; the
worker wiring that CALLS them lands in M2T6, so these cover the adapter
contract itself. Plans mirror the shared domain planner over a hand-built
server snapshot (no DB, no device).
"""

from __future__ import annotations

import time
import uuid

import pytest
from app.adapters.fake import (
    AMBIGUOUS_MODE_KEY,
    DEVICE_JOB_MODE_KEY,
    EXECUTE_FAIL_MODE_KEY,
    EXECUTE_TIMEOUT_MODE_KEY,
    FAIL_PREFLIGHT_MODE_KEY,
    FAKE_DEVICE_JOB_ID,
    STALE_PREFLIGHT_MODE_KEY,
    VERIFY_AMBIGUOUS_MODE_KEY,
    VERIFY_FAIL_MODE_KEY,
    FakeSimpleAdapter,
)
from app.domain.adapter import (
    AdapterTimeoutError,
    DeviceSession,
    OperationResult,
    PreflightResult,
    VerificationResult,
)
from app.domain.errors import AppError
from app.domain.operation_plan import (
    CapabilityView,
    DeviceSnapshot,
    OperationPlan,
    OperationRequest,
)
from app.generated.operations import OPERATION_PROFILES

FAKE = FakeSimpleAdapter()
DEVICE_ID = uuid.uuid4()

_SNAPSHOT_CAPABILITIES = (
    CapabilityView(
        capability_key="power.on",
        support_state="supported",
        requirement_id="SRV-ACT-02",
        discovery_method="fake.simple",
        adapter_version="0.1.0",
    ),
    CapabilityView(
        capability_key="logs.support_bundle.collect",
        support_state="supported",
        requirement_id="SRV-ACT-04",
        discovery_method="fake.simple",
        adapter_version="0.1.0",
    ),
)

SNAPSHOT = DeviceSnapshot(
    device_id=DEVICE_ID,
    device_name="fake-srv-01",
    device_type="server",
    device_version=1,
    adapter_key="fake.simple",
    enabled=True,
    readiness="ready",
    capabilities=_SNAPSHOT_CAPABILITIES,
)


def _session(**config_overrides: object) -> DeviceSession:
    config: dict[str, object] = dict(config_overrides)
    return DeviceSession(
        device_id=DEVICE_ID,
        management_endpoint="192.0.2.10",
        connection_config=config,
        credentials={"username": "admin", "password": "secret"},
    )


def _power_on_plan() -> OperationPlan:
    return FAKE.plan_operation(SNAPSHOT, OperationRequest(capability_key="power.on", parameters={}))


def _noop_progress(_percent: int, _message: str | None) -> None:
    del _percent, _message


@pytest.mark.unit
def test_plan_operation_mirrors_profile_semantics() -> None:
    plan = _power_on_plan()
    profile = OPERATION_PROFILES["SRV-ACT-02:power.on"]
    assert plan.requirement_id == "SRV-ACT-02"
    assert plan.capability_key == "power.on"
    assert plan.risk_level == "high"
    assert plan.timeout_seconds == profile.timeout_seconds
    assert plan.conflict_scope == profile.conflict_scope
    assert plan.expected_disconnect is False
    assert plan.side_effect is True
    assert plan.verification_strategy == profile.verification.strategy
    assert plan.steps
    assert plan.impact
    assert plan.parameter_hash == plan.parameter_hash
    assert isinstance(plan.plan_hash, str) and len(plan.plan_hash) == 64


@pytest.mark.unit
def test_plan_operation_rejects_unsupported_capability() -> None:
    with pytest.raises(AppError) as excinfo:
        FAKE.plan_operation(SNAPSHOT, OperationRequest(capability_key="interface.admin.set", parameters={}))
    assert excinfo.value.code == "unsupported_operation"


@pytest.mark.unit
def test_preflight_success_by_default() -> None:
    result = FAKE.preflight_operation(_session(), _power_on_plan())
    assert isinstance(result, PreflightResult)
    assert result.ok is True
    assert result.stale is False


@pytest.mark.unit
def test_preflight_fail_mode_rejects_with_validation_failed() -> None:
    result = FAKE.preflight_operation(_session(**{FAIL_PREFLIGHT_MODE_KEY: True}), _power_on_plan())
    assert result.ok is False
    assert result.error_code == "validation_failed"
    assert result.stale is False


@pytest.mark.unit
def test_preflight_stale_mode_signals_device_version_drift() -> None:
    result = FAKE.preflight_operation(_session(**{STALE_PREFLIGHT_MODE_KEY: True}), _power_on_plan())
    assert result.ok is False
    assert result.error_code == "preview_stale"
    assert result.stale is True


@pytest.mark.unit
def test_execute_success_by_default() -> None:
    result = FAKE.execute_operation(_session(), _power_on_plan(), _noop_progress)
    assert isinstance(result, OperationResult)
    assert result.ok is True
    assert result.evidence.get("command") == "fake-ok"
    assert result.device_job_id is None
    assert result.disconnected is False


@pytest.mark.unit
def test_execute_fail_mode_returns_explicit_device_failure() -> None:
    result = FAKE.execute_operation(
        _session(**{EXECUTE_FAIL_MODE_KEY: True}), _power_on_plan(), _noop_progress
    )
    assert result.ok is False
    assert result.error_code == "operation_failed"


@pytest.mark.unit
def test_execute_ambiguous_mode_disconnects_without_verifiable_result() -> None:
    result = FAKE.execute_operation(
        _session(**{AMBIGUOUS_MODE_KEY: True}), _power_on_plan(), _noop_progress
    )
    assert result.ok is True
    assert result.disconnected is True
    assert result.device_job_id is None


@pytest.mark.unit
def test_execute_device_job_mode_returns_persistable_job_id() -> None:
    result = FAKE.execute_operation(
        _session(**{DEVICE_JOB_MODE_KEY: True}), _power_on_plan(), _noop_progress
    )
    assert result.ok is True
    assert result.device_job_id == FAKE_DEVICE_JOB_ID


@pytest.mark.unit
def test_execute_timeout_mode_raises_adapter_timeout() -> None:
    started = time.monotonic()
    with pytest.raises(AdapterTimeoutError):
        FAKE.execute_operation(
            _session(**{EXECUTE_TIMEOUT_MODE_KEY: True}), _power_on_plan(), _noop_progress
        )
    elapsed = time.monotonic() - started
    assert elapsed >= 0.9, "execute_timeout_mode must simulate a slow device call"
    assert elapsed < 5, "execute_timeout_mode must not hang"


@pytest.mark.unit
def test_verify_success_by_default() -> None:
    result = FAKE.verify_operation(_session(), _power_on_plan(), None)
    assert isinstance(result, VerificationResult)
    assert result.succeeded is True
    assert result.ambiguous is False
    assert result.evidence["strategy"] == "power_state_readback"


@pytest.mark.unit
def test_verify_carries_job_id_from_the_execute_result() -> None:
    executed = FAKE.execute_operation(
        _session(**{DEVICE_JOB_MODE_KEY: True}), _power_on_plan(), _noop_progress
    )
    result = FAKE.verify_operation(_session(**{DEVICE_JOB_MODE_KEY: True}), _power_on_plan(), executed)
    assert result.succeeded is True
    assert result.evidence.get("device_job_id") == FAKE_DEVICE_JOB_ID


@pytest.mark.unit
def test_verify_fail_mode_reports_explicit_failure() -> None:
    result = FAKE.verify_operation(
        _session(**{VERIFY_FAIL_MODE_KEY: True}), _power_on_plan(), None
    )
    assert result.succeeded is False
    assert result.ambiguous is False
    assert result.error_code == "operation_failed"


@pytest.mark.unit
def test_verify_ambiguous_mode_reports_unprovable_outcome() -> None:
    result = FAKE.verify_operation(
        _session(**{VERIFY_AMBIGUOUS_MODE_KEY: True}), _power_on_plan(), None
    )
    assert result.succeeded is False
    assert result.ambiguous is True
    assert result.error_code == "ambiguous_result"
