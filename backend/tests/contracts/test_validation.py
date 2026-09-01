"""Cross-contract closure validation tests (Python mirror of check-design.ps1)."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from app.contracts.loader import load_contracts
from app.contracts.validation import ContractValidationError, validate_contracts
from app.domain.contracts import ContractSet


def mutated() -> ContractSet:
    return copy.deepcopy(load_contracts())


@pytest.mark.unit
def test_validate_passes_on_loaded_contracts() -> None:
    validate_contracts(load_contracts())


@pytest.mark.unit
def test_missing_metric_definition_rejected() -> None:
    contracts = mutated()
    contracts.metric_definitions.pop("temperature.cpu")
    with pytest.raises(ContractValidationError, match="temperature.cpu"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_extra_requirement_rejected() -> None:
    contracts = mutated()
    original = contracts.requirements["SRV-MON-01"]
    contracts.requirements["SRV-MON-99"] = replace(original, id="SRV-MON-99")
    with pytest.raises(ContractValidationError, match="SRV-MON-99"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_removed_requirement_rejected() -> None:
    contracts = mutated()
    contracts.requirements.pop("ACCESS-ACT-06")
    with pytest.raises(ContractValidationError, match="ACCESS-ACT-06"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_deleted_operation_profile_rejected() -> None:
    contracts = mutated()
    contracts.operation_profiles.pop("ACCESS-ACT-06:firmware.update")
    with pytest.raises(ContractValidationError, match="ACCESS-ACT-06:firmware.update"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_deleted_endpoint_rejected() -> None:
    contracts = mutated()
    contracts.http_endpoints.pop("auth_login")
    with pytest.raises(ContractValidationError, match="endpoint whitelist"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_deleted_hardware_target_rejected() -> None:
    contracts = mutated()
    contracts.hardware_targets.pop(list(contracts.hardware_targets)[0])
    with pytest.raises(ContractValidationError, match="hardware targets"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_removed_alert_rule_rejected() -> None:
    contracts = mutated()
    rules = tuple(rule for rule in contracts.alert_rules if rule.rule_key != "device.offline")
    with pytest.raises(ContractValidationError, match="device.offline"):
        validate_contracts(replace(contracts, alert_rules=rules))


@pytest.mark.unit
def test_forbidden_metric_alert_policy_rejected() -> None:
    contracts = mutated()
    contracts.metric_definitions["temperature.cpu"] = replace(
        contracts.metric_definitions["temperature.cpu"], alert_policy="device_threshold"
    )
    with pytest.raises(ContractValidationError, match="temperature.cpu"):
        validate_contracts(contracts)


@pytest.mark.unit
def test_incomplete_enum_value_map_rejected() -> None:
    contracts = mutated()
    new_maps = []
    for value_map in contracts.enum_value_maps:
        if value_map.alert_policy == "health":
            new_maps.append(replace(value_map, values=value_map.values[:-1]))
        else:
            new_maps.append(value_map)
    with pytest.raises(ContractValidationError, match="health"):
        validate_contracts(replace(contracts, enum_value_maps=tuple(new_maps)))
