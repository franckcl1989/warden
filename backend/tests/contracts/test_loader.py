"""Loader tests: contract JSON files parse into the frozen domain types.

These tests pin the committed 0.1.0 baseline (counts, id sets, cross-reference
closure). They are pure unit tests: they only read ``contracts/`` through the
loader and never touch a database or network.
"""

from __future__ import annotations

import json

import pytest
from app.contracts.loader import CONTRACTS_DIR
from app.domain.contracts import ContractSet

EXPECTED_CONTRACT_FILES = (
    "capabilities.json",
    "metrics.json",
    "events.json",
    "operations.json",
    "alert-rules.json",
    "http-api.json",
    "error-codes.json",
    "hardware-targets.json",
    "hardware-certification.schema.json",
)

EXPECTED_REQUIREMENT_ID_PREFIXES: tuple[tuple[str, int], ...] = (
    ("SRV-MON", 8),
    ("SRV-ACT", 7),
    ("NAS-MON", 6),
    ("NAS-ACT", 6),
    ("CORE-MON", 6),
    ("CORE-ACT", 7),
    ("ACCESS-MON", 5),
    ("ACCESS-ACT", 6),
)


def expected_requirement_ids() -> set[str]:
    return {f"{prefix}-{i:02d}" for prefix, count in EXPECTED_REQUIREMENT_ID_PREFIXES for i in range(1, count + 1)}


@pytest.mark.unit
def test_all_contract_files_present() -> None:
    for name in EXPECTED_CONTRACT_FILES:
        assert (CONTRACTS_DIR / name).is_file(), f"missing contract file: {name}"


@pytest.mark.unit
def test_baseline_counts(contracts: ContractSet) -> None:
    assert len(contracts.requirements) == 51
    assert len(contracts.metric_definitions) == 52
    assert len(contracts.enum_sets) == 13
    assert len(contracts.event_definitions) == 5
    assert len(contracts.operation_profiles) == 39
    assert len(contracts.stable_errors) == 27
    assert len(contracts.alert_rules) == 4
    assert len(contracts.enum_value_maps) == 11
    assert len(contracts.boolean_value_maps) == 2
    assert len(contracts.http_endpoints) == 50
    assert len(contracts.hardware_targets) == 10


@pytest.mark.unit
def test_requirement_id_set_matches_baseline(contracts: ContractSet) -> None:
    assert set(contracts.requirements) == expected_requirement_ids()


@pytest.mark.unit
def test_requirements_by_capability_is_complete_and_unique(contracts: ContractSet) -> None:
    referenced: set[str] = set()
    for requirement in contracts.requirements.values():
        referenced.update(requirement.metrics)
        referenced.update(requirement.events)
        referenced.update(key for key, _ in requirement.operations)

    assert set(contracts.requirements_by_capability) == referenced
    mapped_ids = {contracts.requirements_by_capability[key].id for key in referenced}
    assert mapped_ids <= set(contracts.requirements)


@pytest.mark.unit
def test_operation_profile_ids_match_requirement_keys(contracts: ContractSet) -> None:
    for profile in contracts.operation_profiles.values():
        expected_id = f"{profile.requirement_id}:{profile.key}"
        assert profile.id == expected_id
        requirement = contracts.requirements[profile.requirement_id]
        operations = dict(requirement.operations)
        assert profile.key in operations
        assert profile.risk == operations[profile.key]
        assert profile.device_type == requirement.device_type


@pytest.mark.unit
def test_enum_metrics_reference_existing_enum_sets(contracts: ContractSet) -> None:
    for definition in contracts.metric_definitions.values():
        if definition.value_type == "enum":
            assert definition.enum_set is not None
            assert definition.enum_set in contracts.enum_sets, f"missing enum set {definition.enum_set}"


@pytest.mark.unit
def test_enum_value_maps_cover_full_enum_sets(contracts: ContractSet) -> None:
    for value_map in contracts.enum_value_maps:
        enum_set = contracts.enum_sets.get(value_map.enum_set)
        assert enum_set is not None, f"enum map references unknown enum set {value_map.enum_set}"
        assert {value for value, _ in value_map.values} == set(enum_set)


@pytest.mark.unit
def test_http_endpoint_paths_are_absolute_as_committed(contracts: ContractSet) -> None:
    raw = json.loads((CONTRACTS_DIR / "http-api.json").read_text(encoding="utf-8"))
    assert raw["base_path"] == "/api/v1"
    for endpoint in contracts.http_endpoints.values():
        assert endpoint.path.startswith("/"), f"{endpoint.operation_id}: non-absolute path {endpoint.path}"
