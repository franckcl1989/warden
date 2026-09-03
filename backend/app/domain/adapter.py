"""Device adapter contract (docs/DEVICE_ADAPTERS.md §2) — M1T3 probe/discover, M2T2 collect.

Pure domain types: frozen dataclasses and a structural Protocol; this module
imports nothing from FastAPI, SQLAlchemy or vendor SDKs (ARCHITECTURE.md §4).

The full protocol grows in M3 (``plan_operation``, ``preflight_operation``,
``execute_operation``, ``verify_operation``, ``create_launch``) once the
``DeviceSnapshot`` type lands with operations; a Protocol can gain members
later without breaking conforming implementations.

Probe semantics (DEVICE_ADAPTERS.md §2.1): the probe reports each stage
separately — a single boolean never hides which phase failed. ``ProbeResult``
carries per-stage results; ``DiscoveryResult`` carries vendor/model/serial/
firmware plus the capability support states and observed components that
onboarding persists. ``support_state`` is only supported/unsupported/
not_configured (GLOSSARY.md); offline/busy states are dynamic
``runtime_availability`` and never overwrite the discovered support state.

Collect semantics (DEVICE_ADAPTERS.md §2.3): ``ObservationBatch`` carries
successful observations (quality good/partial), time-point events and the
component inventory observed this pass; failures or missing values are
reported as separate ``ObservationError`` entries — NEVER as 0/normal
placeholder points. An observation with quality ``error`` is a failed
observation and is converted to an ``ObservationError`` by the pipeline
(never written as a point). Adapter-level failures (connection, TLS, auth,
protocol) raise ``AdapterError`` with a stable contracts/error-codes.json
code; the run is marked failed and reachability is fed a failure event.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from app.domain.operation_plan import DeviceSnapshot, OperationPlan, OperationRequest

DEVICE_TYPES = ("server", "synology_nas", "core_switch", "access_switch")
SUPPORT_STATES = ("supported", "unsupported", "not_configured")
# contracts/metrics.json enum_sets.component_status
COMPONENT_STATUSES = ("unknown", "ok", "warning", "critical", "absent")
# Component kinds that ONLY operation-side applies maintain (asset.refresh FRU
# members, firmware.query inventory items). The collect/discovery pipelines
# never observe them, so their soft-retire sweeps must not retire these rows
# as "missing" — the operation applier owns their lifecycle (M3T3 decision,
# documented in the M3T3 report; DATA_MODEL.md §4.4 kinds are open-ended).
OPERATION_APPLIED_COMPONENT_KINDS = frozenset({"fru", "firmware"})

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

    M1T3 declares probe/discover; M2T2 adds the collection pass
    (``DeviceSession`` + ``CollectionRequest`` -> ``ObservationBatch``); M2T4
    adds the operation contract (``plan_operation``/``preflight_operation``/
    ``execute_operation``/``verify_operation`` over
    ``DeviceSnapshot``/``OperationPlan``); M3 extends with launch descriptors.
    """

    adapter_key: str
    supported_device_types: frozenset[str]
    secret_schema: dict[str, object]
    connection_schema: dict[str, object]
    secret_schema_version: int
    adapter_version: str

    def probe(self, profile: ConnectionProfile) -> ProbeResult: ...
    def discover(self, profile: ConnectionProfile) -> DiscoveryResult: ...
    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch: ...
    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan: ...
    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult: ...
    def execute_operation(
        self, session: DeviceSession, plan: OperationPlan, progress: OperationProgress
    ) -> OperationResult: ...
    def verify_operation(
        self, session: DeviceSession, plan: OperationPlan, result: OperationResult | None
    ) -> VerificationResult: ...


class Quality(StrEnum):
    """Observation quality (docs/DEVICE_ADAPTERS.md §2.3).

    ``error``-quality observations are failed observations: the pipeline
    converts them to ``ObservationError`` rows and never writes a point.
    """

    GOOD = "good"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass(frozen=True)
class Observation:
    """One successful observation value (DEVICE_ADAPTERS.md §2.3).

    ``metric_key``/``unit``/``value_type`` semantics come from
    contracts/metrics.json; the adapter converts to the contract unit before
    returning. ``value`` is the raw normalized value (int/float for number/
    integer, bool for boolean, str for enum); the pipeline validates type and
    enum membership against the contract before persisting.
    """

    metric_key: str
    value: bool | int | float | str
    observed_at: datetime
    quality: Quality = Quality.GOOD
    unit: str | None = None
    source: str = "poll"
    component_kind: str | None = None
    component_native_id: str | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class EventObservation:
    """One time-point event (contracts/events.json, DATA_MODEL.md §5.5)."""

    event_type: str
    severity: str  # normalized: unknown/info/warning/critical (events.json rule)
    message: str
    occurred_at: datetime
    source: str = "poll"
    component_kind: str | None = None
    component_native_id: str | None = None
    native_event_id: str | None = None
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ObservationError:
    """A failed or missing observation (DEVICE_ADAPTERS.md §2.3, ADR-014).

    ``key`` is the metric or event key (None for adapter-level errors).
    ``error_code`` is a stable contracts/error-codes.json code; ``stage`` is
    the failing phase (collect/parse/validate/persist).
    """

    key: str | None
    error_code: str
    stage: str
    component_kind: str | None = None
    component_native_id: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ObservationBatch:
    """Everything one collect pass observed (DEVICE_ADAPTERS.md §2.3).

    Adapters MUST NOT return fabricated empty/zero data: every missing or
    failed item is an ``ObservationError`` entry.
    """

    observations: tuple[Observation, ...] = ()
    events: tuple[EventObservation, ...] = ()
    components: tuple[ComponentObserved, ...] = ()
    errors: tuple[ObservationError, ...] = ()


@dataclass(frozen=True)
class DeviceSession:
    """Per-run device connection context for a collect pass.

    ``credentials`` are plaintext ONLY inside the adapter call boundary
    (SECURITY.md §5); ``resolved_ip`` is set by the SSRF policy when the
    deployment enforces allowed management CIDRs (SECURITY.md §7).
    """

    device_id: uuid.UUID
    management_endpoint: str
    connection_config: dict[str, object]
    credentials: dict[str, object]
    resolved_ip: IPv4Address | IPv6Address | None = None


@dataclass(frozen=True)
class CollectionRequest:
    """What a collect pass is asked to read.

    ``collection_type`` is one of reachability/health/metrics/logs/discovery
    (ARCHITECTURE.md §8 periods); ``last_run_at`` lets adapters do delta
    reads (e.g. log pages since the previous pass).
    """

    device_id: uuid.UUID
    collection_type: str
    now: datetime
    last_run_at: datetime | None = None


class AdapterError(Exception):
    """Adapter-level failure with a stable error code (DEVICE_ADAPTERS.md §7).

    ``code`` must be a contracts/error-codes.json code (the adapter subset);
    ``message`` is a sanitized summary (never credentials/vendor bodies).
    """

    def __init__(self, code: str, message: str, *, stage: str = "collect") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage


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


class AdapterTimeoutError(AdapterError):
    """The device call did not complete within the adapter's read timeout.

    Explicitly NOT a confirmed failure: the device may still be working on the
    action (e.g. an accepted restart that lost its connection). Worker wiring
    (M2T6) maps this through ``timeout_transition`` so an unverifiable side
    effect never becomes a clean retryable failure (DEVICE_ADAPTERS.md §9,
    DATA_MODEL.md §7.2).
    """

    def __init__(self, message: str) -> None:
        super().__init__("protocol_error", message, stage="execute")


OperationProgress = Callable[[int, str | None], None]


@dataclass(frozen=True)
class ArtifactDescriptor:
    """One platform-bound artifact the adapter produced (M3T3 decision).

    Boundary rule (DEVICE_ADAPTERS.md §4.2 + M3T3 report): the adapter only
    ever yields BYTES + a machine-readable manifest inside ``OperationResult``;
    it never touches file paths or storage. The worker (application layer)
    persists the artifact through the controlled file service — encrypted for
    sensitive types (support_bundle) — creates the file row + ``file_link``
    and records the stored hashes in evidence before verification.
    """

    file_type: str  # contracts file type the artifact belongs to (support_bundle/...)
    filename: str  # display hint only; the platform owns the stored name
    content_bytes: bytes
    mime_type: str | None = None
    # Per-source content manifest: every included or explicitly-unavailable
    # source with its SHA-256 (artifact_manifest verification strategy).
    manifest: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class FirmwareItem:
    """One normalized firmware inventory entry (SRV-ACT-06 firmware.query)."""

    target: str  # the inventory resource Id (BMC/BIOS/...)
    name: str
    version: str | None  # None = the device did not report a parseable version


@dataclass(frozen=True)
class InventorySnapshot:
    """Read-only inventory an operation returned (firmware.query/asset.refresh).

    The worker persists the device identity fields onto the device row and
    keeps ``components`` (operation-applied kinds) + ``firmware_items`` in the
    component surface with the observation time (inventory_persisted strategy).
    """

    observed_at: datetime
    serial_number: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    components: tuple[ComponentObserved, ...] = ()
    firmware_items: tuple[FirmwareItem, ...] = ()


@dataclass(frozen=True)
class PreflightResult:
    """Real-time read-only preflight outcome (DEVICE_ADAPTERS.md §2.4).

    Preflight runs BEFORE the dispatch fence: it may reject the plan
    (``ok=False`` with a stable code such as validation_failed) or signal that
    the device identity drifted from the plan (``stale=True``), which the
    worker maps to a preview_stale terminal error requiring a fresh preview.
    It must never call a device-changing action.
    """

    ok: bool
    error_code: str | None = None
    detail: str | None = None
    stale: bool = False


@dataclass(frozen=True)
class OperationResult:
    """Outcome of one device-side execution (DEVICE_ADAPTERS.md §4.2/§9).

    ``ok=True`` means the device accepted the action, NOT that the end state is
    proven — proof comes from ``verify_operation``. ``disconnected`` flags an
    expected_disconnect action whose connection dropped before a verifiable
    result: the worker must verify (or enter verification_required), never
    treat it as terminal success. ``device_job_id`` persists the vendor job for
    later polling (DATA_MODEL.md §7.1: 存在时只查询，不重复创建).

    ``artifacts``/``inventory`` (M3T3) carry platform-bound side outputs; the
    worker persists them to the file service / device + component rows and
    merges the stored proof into the evidence it passes to verification.
    """

    ok: bool
    evidence: dict[str, object] = field(default_factory=dict)
    error_code: str | None = None
    error_detail: str | None = None
    device_job_id: str | None = None
    disconnected: bool = False
    artifacts: tuple[ArtifactDescriptor, ...] = ()
    inventory: InventorySnapshot | None = None


@dataclass(frozen=True)
class VerificationResult:
    """Read-back verification outcome (DEVICE_ADAPTERS.md §4.2/§9).

    ``ambiguous=True`` means success AND failure are both unproven: the task
    must enter/remain ``verification_required`` (error ambiguous_result) and
    may only be resolved by another read-back or by admin evidence — never by
    replaying the action (AGENTS.md: 不得把不确定的结果伪装成成功).

    ``pending=True`` reports an asynchronous device job that is STILL RUNNING
    (a device_job_status strategy whose persisted job has not finished yet):
    the worker keeps polling ``verify_operation`` for the same persisted job
    while the task stays ``waiting_device`` with renewed leases
    (DATA_MODEL.md §7.1: 存在时只查询，不重复创建). Pending is neither
    success nor failure and never maps to ambiguous — the job is known to
    still be in progress.
    """

    succeeded: bool
    ambiguous: bool = False
    pending: bool = False
    evidence: dict[str, object] = field(default_factory=dict)
    error_code: str | None = None
