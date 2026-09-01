"""Codegen drift tests: regenerated artifacts must match the committed ones.

Regenerating into the real paths is intentional: codegen is the single source
of truth for ``backend/app/generated`` and ``frontend/src/api/generated``, and
CI fails on drift. These tests are pure unit tests (no DB, no network).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from app.contracts.loader import load_contracts
from app.domain.contracts import ContractSet, OperationProfile
from app.tools.codegen import run

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_GENERATED = REPO_ROOT / "backend" / "app" / "generated"
FRONTEND_GENERATED = REPO_ROOT / "frontend" / "src" / "api" / "generated"

GIT = shutil.which("git")
assert GIT is not None, "git executable not found on PATH"


def normalize_schema(value: object) -> object:
    """Recursively treat JSON lists and codegen tuples as the same structure.

    The loader keeps ``parameter_schema.raw`` exactly as parsed from JSON
    (lists), while codegen emits tuple literals. Both are the same schema;
    compare them structurally instead of by Python container type.
    """

    if isinstance(value, dict):
        return {key: normalize_schema(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return tuple(normalize_schema(item) for item in value)
    return value


def assert_profiles_equal(
    loaded: dict[str, OperationProfile], generated: dict[str, OperationProfile]
) -> None:
    assert set(generated) == set(loaded)
    for profile_id, profile in loaded.items():
        other = generated[profile_id]
        assert other.id == profile.id
        assert other.requirement_id == profile.requirement_id
        assert other.device_type == profile.device_type
        assert other.key == profile.key
        assert other.channel == profile.channel
        assert other.risk == profile.risk
        assert other.side_effect == profile.side_effect
        assert normalize_schema(other.parameter_schema.raw) == normalize_schema(profile.parameter_schema.raw)
        assert other.conflict_scope == profile.conflict_scope
        assert other.timeout_seconds == profile.timeout_seconds
        assert other.expected_disconnect == profile.expected_disconnect
        assert other.cancel_policy == profile.cancel_policy
        assert other.preconditions == profile.preconditions
        assert other.verification == profile.verification


def git_diff_generated() -> subprocess.CompletedProcess[str]:
    # S603: fixed static argument list (no user input); shell=False by default.
    return subprocess.run(  # noqa: S603
        [GIT, "diff", "--exit-code", "--", "backend/app/generated", "frontend/src/api/generated"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.unit
def test_codegen_output_matches_committed() -> None:
    run()
    result = git_diff_generated()
    assert result.returncode == 0, f"codegen drift:\n{result.stdout}\n{result.stderr}"


@pytest.mark.unit
def test_codegen_is_idempotent() -> None:
    run()
    assert git_diff_generated().returncode == 0
    run()
    assert git_diff_generated().returncode == 0


@pytest.mark.unit
def test_generated_python_matches_loaded_contracts(contracts: ContractSet) -> None:
    from app.generated import alerts, capabilities, errors, events, hardware_targets, http_api, metrics, operations

    assert contracts.metric_definitions == metrics.METRIC_DEFINITIONS
    assert contracts.enum_sets == metrics.ENUM_SETS
    assert contracts.event_definitions == events.EVENT_DEFINITIONS
    assert_profiles_equal(contracts.operation_profiles, operations.OPERATION_PROFILES)
    assert contracts.stable_errors == errors.STABLE_ERRORS
    assert contracts.requirements == capabilities.REQUIREMENTS
    assert {
        key: requirement.id for key, requirement in contracts.requirements_by_capability.items()
    } == capabilities.REQUIREMENT_BY_CAPABILITY
    assert {rule.rule_key for rule in alerts.ALERT_RULES} == {rule.rule_key for rule in contracts.alert_rules}
    assert contracts.http_endpoints == http_api.HTTP_ENDPOINTS
    assert contracts.hardware_targets == hardware_targets.HARDWARE_TARGETS


@pytest.mark.unit
def test_generated_frontend_contains_metric_keys_and_device_types() -> None:
    contracts = load_contracts()
    text = (FRONTEND_GENERATED / "contracts.ts").read_text(encoding="utf-8")
    for key in contracts.metric_definitions:
        assert f'"{key}"' in text, f"contracts.ts missing metric key: {key}"
    for device_type in sorted({r.device_type for r in contracts.requirements.values()}):
        assert device_type in text, f"contracts.ts missing device type: {device_type}"
