"""Schema-validator tests over ALL 39 contracts/operations.json profiles.

M2T4 brief §5: the minimal strict validator must accept profile-appropriate
positive samples and reject malformed ones for every profile in the registry
(jsonschema is deliberately NOT a dependency). Positive samples are built from
each profile's parameter_schema (required properties filled with valid
values); negatives cover unknown keys, missing required, wrong types, and the
declared constraints (enum set, uuid format, integer bounds, string length)
plus the poe.port.set allOf if/then/else semantics.
"""

from __future__ import annotations

import uuid

import pytest
from app.domain.schema_validation import SchemaNotSupportedError, validate_parameters
from app.generated.operations import OPERATION_PROFILES

ALL_PROFILE_IDS = sorted(OPERATION_PROFILES)

POE_PROFILE_ID = "ACCESS-ACT-03:poe.port.set"


def _string_sample(schema: dict[str, object]) -> str:
    if schema.get("format") == "uuid":
        return str(uuid.uuid4())
    return "sample-value"


def _integer_sample(schema: dict[str, object]) -> int:
    minimum = schema.get("minimum")
    return minimum if isinstance(minimum, int) else 1


def _property_sample(schema: dict[str, object]) -> object:
    declared = schema.get("type")
    if declared == "boolean":
        return True
    if declared == "integer":
        return _integer_sample(schema)
    enum_values = schema.get("enum")
    if isinstance(enum_values, (list, tuple)) and enum_values:
        return enum_values[0]
    if declared == "string":
        return _string_sample(schema)
    return None


def _fill_required(profile_id: str) -> dict[str, object]:
    """A positive sample: every REQUIRED property filled with a valid value.

    All 39 profiles keep their optional properties conditional (only
    poe.port.set declares one, behind allOf), so a required-only fill is a
    valid sample for every profile.
    """
    raw = OPERATION_PROFILES[profile_id].parameter_schema.raw
    required = raw.get("required") or ()
    properties = raw.get("properties") or {}
    return {
        key: _property_sample(properties[key])
        for key in required
        if isinstance(properties.get(key), dict)
    }


@pytest.mark.parametrize("profile_id", ALL_PROFILE_IDS)
def test_positive_sample_is_accepted(profile_id: str) -> None:
    schema = OPERATION_PROFILES[profile_id].parameter_schema.raw
    sample = _fill_required(profile_id)
    errors = validate_parameters(sample, schema)
    assert errors == [], f"{profile_id} positive sample rejected: {errors}"


@pytest.mark.parametrize("profile_id", ALL_PROFILE_IDS)
def test_unknown_extra_key_is_rejected(profile_id: str) -> None:
    schema = OPERATION_PROFILES[profile_id].parameter_schema.raw
    sample = dict(_fill_required(profile_id))
    sample["unexpected_extra_key"] = 1
    errors = validate_parameters(sample, schema)
    assert errors, f"{profile_id} accepted an unknown key"
    assert any("unexpected_extra_key" in error for error in errors)


@pytest.mark.parametrize("profile_id", ALL_PROFILE_IDS)
def test_missing_required_property_is_rejected(profile_id: str) -> None:
    schema = OPERATION_PROFILES[profile_id].parameter_schema.raw
    raw = OPERATION_PROFILES[profile_id].parameter_schema.raw
    required = raw.get("required") or ()
    if not required:
        pytest.skip(f"{profile_id} declares no required properties")
    sample = dict(_fill_required(profile_id))
    del sample[required[0]]
    errors = validate_parameters(sample, schema)
    assert errors, f"{profile_id} accepted a sample missing required {required[0]}"
    assert any(required[0] in error for error in errors)


@pytest.mark.parametrize("profile_id", ALL_PROFILE_IDS)
def test_wrong_property_type_is_rejected(profile_id: str) -> None:
    schema = OPERATION_PROFILES[profile_id].parameter_schema.raw
    properties = schema.get("properties") or {}
    if not properties:
        pytest.skip(f"{profile_id} declares no properties")
    key = next(iter(properties))
    prop_schema = properties[key]
    assert isinstance(prop_schema, dict)
    declared = prop_schema.get("type")
    bad: object
    if declared == "integer":
        bad = "not-an-integer"
    elif declared == "boolean":
        bad = "not-a-boolean"
    else:
        bad = 12345
    sample = dict(_fill_required(profile_id))
    sample[key] = bad
    errors = validate_parameters(sample, schema)
    assert errors, f"{profile_id} accepted wrong type for {key}"
    assert any(key in error for error in errors)


def _negative_property_values(schema: dict[str, object]) -> list[object]:
    """Out-of-constraint values for one property (empty when unconstrained)."""
    negatives: list[object] = []
    declared = schema.get("type")
    enum_values = schema.get("enum")
    if isinstance(enum_values, (list, tuple)) and enum_values:
        negatives.append("out-of-enum-value")
    if declared == "string":
        if schema.get("format") == "uuid":
            negatives.append("not-a-uuid")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int):
            negatives.append("x" * (max_length + 1))
    if declared == "integer":
        minimum = schema.get("minimum")
        if isinstance(minimum, int):
            negatives.append(minimum - 1)
    return negatives


@pytest.mark.parametrize("profile_id", ALL_PROFILE_IDS)
def test_declared_property_constraints_are_enforced(profile_id: str) -> None:
    schema = OPERATION_PROFILES[profile_id].parameter_schema.raw
    properties = schema.get("properties") or {}
    checked = 0
    for key, prop_schema in properties.items():
        assert isinstance(prop_schema, dict)
        for bad in _negative_property_values(prop_schema):
            sample = dict(_fill_required(profile_id))
            sample[key] = bad
            errors = validate_parameters(sample, schema)
            assert errors, f"{profile_id} accepted {bad!r} for {key}"
            checked += 1
    if checked == 0:
        pytest.skip(f"{profile_id} declares no constrained optional property values to test")


def test_poe_allof_cycle_requires_off_seconds() -> None:
    schema = OPERATION_PROFILES[POE_PROFILE_ID].parameter_schema.raw
    errors = validate_parameters({"interface_id": "if-1", "mode": "cycle"}, schema)
    assert errors, "mode=cycle without off_seconds must be rejected"
    errors = validate_parameters(
        {"interface_id": "if-1", "mode": "cycle", "off_seconds": 30}, schema
    )
    assert errors == [], "mode=cycle with off_seconds must be accepted"


def test_poe_allof_else_forbids_off_seconds() -> None:
    schema = OPERATION_PROFILES[POE_PROFILE_ID].parameter_schema.raw
    errors = validate_parameters(
        {"interface_id": "if-1", "mode": "on", "off_seconds": 30}, schema
    )
    assert errors, "mode=on with off_seconds must be rejected"
    errors = validate_parameters({"interface_id": "if-1", "mode": "off"}, schema)
    assert errors == [], "mode=off without off_seconds must be accepted"


def test_poe_off_seconds_bounds() -> None:
    schema = OPERATION_PROFILES[POE_PROFILE_ID].parameter_schema.raw
    errors = validate_parameters(
        {"interface_id": "if-1", "mode": "cycle", "off_seconds": 4}, schema
    )
    assert errors, "off_seconds below minimum must be rejected"
    errors = validate_parameters(
        {"interface_id": "if-1", "mode": "cycle", "off_seconds": 61}, schema
    )
    assert errors, "off_seconds above maximum must be rejected"
    errors = validate_parameters(
        {"interface_id": "if-1", "mode": "cycle", "off_seconds": 30}, schema
    )
    assert errors == []


def test_non_object_value_is_rejected() -> None:
    schema = OPERATION_PROFILES["SRV-ACT-02:power.on"].parameter_schema.raw
    errors = validate_parameters("power-on", schema)
    assert errors


def test_unsupported_keyword_fails_loudly() -> None:
    schema = {"type": "object", "additionalProperties": False, "properties": {}, "patternProperties": {}}
    with pytest.raises(SchemaNotSupportedError):
        validate_parameters({}, schema)
