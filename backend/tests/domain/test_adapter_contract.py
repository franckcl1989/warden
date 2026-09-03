"""Device adapter contract tests (M1T3, docs/DEVICE_ADAPTERS.md §2).

Protocol shape (probe/discover), the registry, and the fake adapter: full
discovery for server with every capability key backed by the generated
requirement registry and valid support_state values. The fake is the CI
onboarding stand-in; it must never be conflated with hardware certification.
"""

from __future__ import annotations

import pytest
from app.adapters import UnknownAdapterError, adapter_for_device_type, get_adapter
from app.adapters.fake import FakeSimpleAdapter
from app.domain.adapter import (
    SUPPORT_STATES,
    ConnectionProfile,
    DeviceAdapter,
    ProbeResult,
    validate_json_schema,
)
from app.generated.capabilities import REQUIREMENTS

FAKE = FakeSimpleAdapter()


def profile(**overrides: object) -> ConnectionProfile:
    values: dict[str, object] = {
        "adapter_key": FAKE.adapter_key,
        "management_endpoint": "192.0.2.10",
        "port": 443,
        "connection_config": {},
        "credentials": {"username": "admin", "password": "secret-pass"},
        "verify_tls": True,
        "tls_fingerprint_sha256": None,
        "device_id": None,
    }
    values.update(overrides)
    return ConnectionProfile(**values)  # type: ignore[arg-type]


@pytest.mark.unit
def test_protocol_shape_declares_probe_and_discover() -> None:
    protocol_methods = set(DeviceAdapter.__dict__) | set(DeviceAdapter.__protocol_attrs__)
    assert {"probe", "discover"} <= protocol_methods
    assert FAKE.adapter_key == "fake.simple"
    assert "server" in FAKE.supported_device_types
    assert isinstance(FAKE.secret_schema, dict)
    assert isinstance(FAKE.connection_schema, dict)
    assert FAKE.secret_schema_version >= 1
    assert isinstance(FAKE.adapter_version, str)


@pytest.mark.unit
def test_fake_probe_reports_all_stages_ok() -> None:
    result = FAKE.probe(profile())
    assert isinstance(result, ProbeResult)
    assert result.ok
    assert [stage.stage for stage in result.stages] == [
        "network",
        "tls",
        "auth",
        "identity",
        "capabilities",
    ]
    assert all(stage.ok for stage in result.stages)
    assert result.identity_hint == {"vendor": "Fake", "model": "FakeServer-1"}


@pytest.mark.unit
def test_fake_probe_credentials_fail_mode() -> None:
    result = FAKE.probe(profile(connection_config={"fail_credentials": True}))
    assert not result.ok
    auth_stage = next(stage for stage in result.stages if stage.stage == "auth")
    assert auth_stage.error_code == "authentication_failed"
    identity_stage = next(stage for stage in result.stages if stage.stage == "identity")
    assert identity_stage.ok is False
    assert identity_stage.error_code is None


@pytest.mark.unit
def test_fake_probe_tls_fail_mode() -> None:
    result = FAKE.probe(profile(connection_config={"fail_tls": True}))
    assert not result.ok
    tls_stage = next(stage for stage in result.stages if stage.stage == "tls")
    assert tls_stage.error_code == "tls_validation_failed"
    # Network was reachable; everything after tls was not executed — never
    # fabricated as ok.
    assert next(stage for stage in result.stages if stage.stage == "network").ok is True
    assert all(not stage.ok for stage in result.stages if stage.stage not in {"network", "tls"})


@pytest.mark.unit
def test_fake_discovery_returns_server_identity_and_inventory() -> None:
    discovery = FAKE.discover(profile())
    assert discovery.vendor == "Fake"
    assert discovery.model == "FakeServer-1"
    assert discovery.serial_number == "FAKE-SN-0001"
    assert discovery.firmware_version == "1.0.0"
    assert discovery.secrets_schema == FAKE.secret_schema
    assert discovery.secrets_schema_version == FAKE.secret_schema_version
    kinds = {component.kind for component in discovery.components}
    assert {"processor", "memory", "drive", "fan", "psu"} <= kinds
    assert all(component.status == "ok" for component in discovery.components)


@pytest.mark.unit
def test_fake_discovery_capabilities_all_in_generated_registry() -> None:
    discovery = FAKE.discover(profile())
    assert discovery.capabilities
    for capability in discovery.capabilities:
        assert capability.support_state in SUPPORT_STATES
        requirement = REQUIREMENTS.get(capability.requirement_id)
        assert requirement is not None
        # Shared keys (e.g. logs.support_bundle.collect served by both NAS and
        # server requirements) map to the requirement of the device type the
        # fake serves; the key must be declared by that requirement.
        assert requirement.device_type == "server"
        declared = set(requirement.metrics) | set(requirement.events)
        declared.update(op[0] for op in requirement.operations)
        assert capability.capability_key in declared
        assert capability.discovery_method == FAKE.adapter_key


@pytest.mark.unit
def test_fake_capabilities_cover_all_server_requirement_keys() -> None:
    discovery = FAKE.discover(profile())
    discovered = {capability.capability_key for capability in discovery.capabilities}
    expected: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type == "server":
            expected.update(requirement.metrics)
            expected.update(requirement.events)
            expected.update(op[0] for op in requirement.operations)
    assert discovered == expected


@pytest.mark.unit
def test_registry_lookup_and_type_lookup() -> None:
    assert get_adapter("fake.simple").adapter_key == "fake.simple"
    # M3T2: server.redfish (common Redfish base) joined fake.simple as a
    # registered server adapter — a unique per-type lookup now has two
    # matches, so onboarding always selects by adapter_key.
    assert get_adapter("server.redfish").adapter_key == "server.redfish"
    assert "server" in get_adapter("server.redfish").supported_device_types
    with pytest.raises(UnknownAdapterError):
        adapter_for_device_type("server")
    with pytest.raises(UnknownAdapterError):
        get_adapter("server.dell_idrac")
    with pytest.raises(UnknownAdapterError):
        adapter_for_device_type("synology_nas")


@pytest.mark.unit
def test_registry_rejects_duplicate_adapter_key() -> None:
    import app.adapters.registry as registry

    duplicate = FakeSimpleAdapter()
    with pytest.raises(ValueError, match="already registered"):
        registry.register(duplicate)


@pytest.mark.unit
def test_schema_validation_rejects_bad_credentials() -> None:
    errors = validate_json_schema({"username": "admin"}, FAKE.secret_schema)
    assert any("password" in error for error in errors)
    errors = validate_json_schema({"username": "admin", "password": "x", "extra": 1}, FAKE.secret_schema)
    assert any("extra" in error for error in errors)
    assert validate_json_schema({"username": "admin", "password": "x"}, FAKE.secret_schema) == []


@pytest.mark.unit
def test_schema_validation_rejects_bad_connection_config() -> None:
    errors = validate_json_schema({"protocol": "http"}, FAKE.connection_schema)
    assert any("protocol" in error for error in errors)
    errors = validate_json_schema({"port": 0}, FAKE.connection_schema)
    assert any("port" in error for error in errors)
    errors = validate_json_schema({"tls_fingerprint_sha256": "short"}, FAKE.connection_schema)
    assert any("tls_fingerprint_sha256" in error for error in errors)
    assert validate_json_schema(
        {"protocol": "https", "verify_tls": True, "fail_tls": False}, FAKE.connection_schema
    ) == []
