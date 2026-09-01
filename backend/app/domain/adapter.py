"""Device adapter contract (docs/DEVICE_ADAPTERS.md §2) — M1T3 scope: probe + discover.

Pure domain types: frozen dataclasses and a structural Protocol; this module
imports nothing from FastAPI, SQLAlchemy or vendor SDKs (ARCHITECTURE.md §4).

The full protocol grows in M2/M3 (``collect``, ``plan_operation``,
``preflight_operation``, ``execute_operation``, ``verify_operation``,
``create_launch``) once the ``DeviceSession`` type lands with collection; a
Protocol can gain members later without breaking conforming implementations,
so only probe/discover are declared now.

Probe semantics (DEVICE_ADAPTERS.md §2.1): the probe reports each stage
separately — a single boolean never hides which phase failed. ``ProbeResult``
carries per-stage results; ``DiscoveryResult`` carries vendor/model/serial/
firmware plus the capability support states and observed components that
onboarding persists. ``support_state`` is only supported/unsupported/
not_configured (GLOSSARY.md); offline/busy states are dynamic
``runtime_availability`` and never overwrite the discovered support state.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

DEVICE_TYPES = ("server", "synology_nas", "core_switch", "access_switch")
SUPPORT_STATES = ("supported", "unsupported", "not_configured")
# contracts/metrics.json enum_sets.component_status
COMPONENT_STATUSES = ("unknown", "ok", "warning", "critical", "absent")

DEFAULT_MANAGEMENT_PORT = 443


@dataclass(frozen=True)
class ProbeStage:
    """One probe phase: network/tls/auth/identity/capabilities.

    ``error_code`` is a stable contracts/error-codes.json value (subset per
    DEVICE_ADAPTERS.md §7); ``detail_safe`` is display-safe free text. Stages
    that could not run because a previous stage failed report ``ok=False``
    with ``error_code=None`` — an honest "not executed", never a fabricated
    success.
    """

    stage: str
    ok: bool
    error_code: str | None = None
    detail_safe: str | None = None


@dataclass(frozen=True)
class ProbeResult:
    """Stage-by-stage probe outcome plus the verified identity hint."""

    stages: tuple[ProbeStage, ...]
    identity_hint: dict[str, str] | None = None

    @property
    def ok(self) -> bool:
        return all(stage.ok for stage in self.stages)


@dataclass(frozen=True)
class CapabilitySupport:
    """Discovered intrinsic support for one capability key."""

    capability_key: str
    support_state: str
    requirement_id: str
    discovery_method: str
    reason_code: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ComponentObserved:
    """A component seen by discovery (docs/DATA_MODEL.md §4.4)."""

    kind: str
    native_id: str
    name: str
    status: str
    properties: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DiscoveryResult:
    """Device identity + capability support + component inventory."""

    vendor: str
    model: str
    serial_number: str | None
    firmware_version: str | None
    capabilities: tuple[CapabilitySupport, ...]
    components: tuple[ComponentObserved, ...]
    secrets_schema: dict[str, object]
    secrets_schema_version: int


@dataclass(frozen=True)
class ConnectionProfile:
    """Everything an adapter needs for one probe/discover pass.

    ``credentials`` are plaintext ONLY inside the probe call boundary
    (SECURITY.md §5); ``resolved_ip`` is set by the SSRF policy so adapters
    connect to the validated address, never the raw hostname
    (SECURITY.md §7). ``device_id`` is None for pre-save probes and set for
    re-probes of saved devices.
    """

    adapter_key: str
    management_endpoint: str
    port: int
    connection_config: dict[str, object]
    credentials: dict[str, object]
    verify_tls: bool
    tls_fingerprint_sha256: str | None
    device_id: uuid.UUID | None = None
    resolved_ip: IPv4Address | IPv6Address | None = None


class DeviceAdapter(Protocol):
    """Unified adapter interface (docs/DEVICE_ADAPTERS.md §2).

    M1T3 declares probe/discover; M2/M3 extend the protocol with
    ``DeviceSession``-based collect/plan/preflight/execute/verify/create_launch.
    """

    adapter_key: str
    supported_device_types: frozenset[str]
    secret_schema: dict[str, object]
    connection_schema: dict[str, object]
    secret_schema_version: int
    adapter_version: str

    def probe(self, profile: ConnectionProfile) -> ProbeResult: ...
    def discover(self, profile: ConnectionProfile) -> DiscoveryResult: ...


@dataclass(frozen=True)
class ProbeOutcome:
    """Service-level probe result: stages, discovery (when all stages passed),
    the signed probe token and the credentials digest for audit."""

    stages: tuple[ProbeStage, ...]
    discovery: DiscoveryResult | None
    probe_token: str
    expires_at: datetime
    credentials_digest: str

    @property
    def ok(self) -> bool:
        return all(stage.ok for stage in self.stages)


def canonical_json(value: object) -> str:
    """Deterministic JSON: sorted keys, compact separators, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def profile_fingerprint(profile: ConnectionProfile) -> str:
    """SHA-256 of the normalized profile (credentials + endpoint + adapter).

    The probe token binds this fingerprint so a token issued for one profile
    can never save a different device/profile (API_CONTRACT.md §4).
    """
    payload = {
        "adapter_key": profile.adapter_key,
        "management_endpoint": profile.management_endpoint,
        "port": profile.port,
        "connection_config": profile.connection_config,
        "credentials": profile.credentials,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def credentials_digest(credentials: dict[str, object]) -> str:
    """SHA-256 digest of the canonical credentials JSON (audit-only value)."""
    return hashlib.sha256(canonical_json(credentials).encode("utf-8")).hexdigest()


_JSON_TYPES = frozenset({"object", "array", "string", "boolean", "integer", "number", "null"})


def _type_matches(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _check_schema(value: object, schema: dict[str, object], path: str, errors: list[str]) -> None:
    declared = schema.get("type")
    if declared is not None:
        allowed = [declared] if isinstance(declared, str) else list(declared) if isinstance(declared, list) else []
        if not any(_type_matches(value, item) for item in allowed):
            errors.append(f"{path} 类型不匹配，期望 {', '.join(allowed)}")
            return
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and value not in enum_values:
        errors.append(f"{path} 值不在允许范围内")
    if isinstance(value, dict):
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{path}.{key} 为必填项")
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for key, item in value.items():
                prop_schema = properties.get(key)
                if prop_schema is None:
                    if schema.get("additionalProperties") is False:
                        errors.append(f"{path}.{key} 是不允许的字段")
                elif isinstance(prop_schema, dict):
                    _check_schema(item, prop_schema, f"{path}.{key}", errors)
        elif schema.get("additionalProperties") is False:
            errors.append(f"{path} 不允许额外字段")
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                _check_schema(item, items, f"{path}[{index}]", errors)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{path} 小于最小值 {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{path} 大于最大值 {maximum}")
    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(value) < min_length:
            errors.append(f"{path} 长度小于最小值 {min_length}")
        if isinstance(max_length, int) and len(value) > max_length:
            errors.append(f"{path} 长度大于最大值 {max_length}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            errors.append(f"{path} 不符合格式要求")


def validate_json_schema(value: object, schema: dict[str, object]) -> list[str]:
    """Validate ``value`` against the adapter-declared JSON Schema subset.

    Supported keywords: type (string or list), enum, required, properties,
    additionalProperties (bool), minimum/maximum, minLength/maxLength, pattern,
    items. Returns human-readable Chinese error messages; an empty list means
    the value conforms. Unknown keywords are ignored — adapters declare only
    this subset (app-level strict schema per adapter, DATA_MODEL.md §4.1).
    """
    errors: list[str] = []
    if not isinstance(schema.get("type"), (str, list)) or "type" not in schema:
        errors.append("适配器声明的 schema 必须包含 type")
        return errors
    _check_schema(value, schema, "$", errors)
    return errors
