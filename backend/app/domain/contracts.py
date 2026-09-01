"""Domain types for machine contracts (frozen data, generated from contracts/)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MetricDefinition:
    key: str
    value_type: str  # number | integer | boolean | enum
    enum_set: str | None
    unit: str | None
    scope: str  # device | component
    series: str
    alert_policy: str
    range: tuple[float, float] | None = None


@dataclass(frozen=True)
class EventDefinition:
    key: str
    scope: str
    sources: tuple[str, ...]
    required_fields: tuple[str, ...]


@dataclass(frozen=True)
class OperationParameterSchema:
    raw: dict[str, object]


@dataclass(frozen=True)
class OperationVerification:
    strategy: str
    success: str
    ambiguous: str
    prohibition: str | None = None


@dataclass(frozen=True)
class OperationProfile:
    id: str
    requirement_id: str
    device_type: str
    key: str
    channel: str  # task | launch
    risk: str  # low | medium | high
    side_effect: bool
    parameter_schema: OperationParameterSchema
    conflict_scope: str
    timeout_seconds: int
    expected_disconnect: bool
    cancel_policy: str
    preconditions: tuple[str, ...]
    verification: OperationVerification


@dataclass(frozen=True)
class StableError:
    code: str
    http_status: int
    retry_class: str
    safe_detail_fields: tuple[str, ...]


@dataclass(frozen=True)
class AlertRule:
    rule_key: str
    source: str
    selector: str
    severity: str | None
    severity_from_value: bool
    open_after: int
    resolve_after: int
    dedupe: str
    metric_key: str | None = None


@dataclass(frozen=True)
class Requirement:
    id: str
    device_type: str
    kind: str  # monitoring | operation
    title: str
    metrics: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    operations: tuple[tuple[str, str], ...] = ()  # (key, risk)


@dataclass(frozen=True)
class HttpEndpoint:
    method: str
    path: str
    operation_id: str
    support_id: str


@dataclass(frozen=True)
class HardwareTarget:
    target_id: str
    device_type: str
    vendor: str
    declared_target: str
    certification_scope: str
    adapter_key: str


@dataclass(frozen=True)
class EnumValueMap:
    alert_policy: str
    enum_set: str
    values: tuple[tuple[str, str], ...]  # (enum_value, outcome)


@dataclass(frozen=True)
class BooleanValueMap:
    alert_policy: str
    true_outcome: str
    false_outcome: str


@dataclass(frozen=True)
class ContractSet:
    product_version: str
    metric_definitions: dict[str, MetricDefinition]
    enum_sets: dict[str, tuple[str, ...]]
    event_definitions: dict[str, EventDefinition]
    operation_profiles: dict[str, OperationProfile]
    requirements: dict[str, Requirement]
    stable_errors: dict[str, StableError]
    alert_rules: tuple[AlertRule, ...]
    enum_value_maps: tuple[EnumValueMap, ...]
    boolean_value_maps: tuple[BooleanValueMap, ...]
    http_endpoints: dict[str, HttpEndpoint]
    hardware_targets: dict[str, HardwareTarget]
    requirements_by_capability: dict[str, Requirement] = field(default_factory=dict)

    def requirement_for(self, capability_key: str) -> Requirement | None:
        return self.requirements_by_capability.get(capability_key)

    def profile_for(self, requirement_id: str, capability_key: str) -> OperationProfile | None:
        return self.operation_profiles.get(f"{requirement_id}:{capability_key}")

    def metric(self, key: str) -> MetricDefinition | None:
        return self.metric_definitions.get(key)
