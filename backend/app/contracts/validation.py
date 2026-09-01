"""Cross-contract closure validation (Python mirror of scripts/check-design.ps1).

Codegen runs this before emitting artifacts; CI also runs it so contract
drift fails independently of the platform shell. Rules are intentionally kept
identical to the PowerShell baseline checker.
"""

from __future__ import annotations

from app.domain.contracts import ContractSet

EXPECTED_SOURCE_IDS = sorted(
    [
        *(f"SRV-MON-{i:02d}" for i in range(1, 9)),
        *(f"SRV-ACT-{i:02d}" for i in range(1, 8)),
        *(f"NAS-MON-{i:02d}" for i in range(1, 7)),
        *(f"NAS-ACT-{i:02d}" for i in range(1, 7)),
        *(f"CORE-MON-{i:02d}" for i in range(1, 7)),
        *(f"CORE-ACT-{i:02d}" for i in range(1, 8)),
        *(f"ACCESS-MON-{i:02d}" for i in range(1, 6)),
        *(f"ACCESS-ACT-{i:02d}" for i in range(1, 7)),
    ]
)

FORBIDDEN_METRIC_ALERT_POLICIES = {
    "device_threshold",
    "capacity",
    "utilization",
    "increase",
    "admin_oper_mismatch",
    "poe_budget",
}
FORBIDDEN_ALERT_RULES = {
    "sensor.threshold",
    "capacity.usage",
    "utilization.high",
    "counter.increase",
    "interface.admin_oper_mismatch",
    "poe.budget",
}
EXPECTED_ALERT_RULES = {"device.offline", "device.health", "data.expired", "status.problem"}


class ContractValidationError(ValueError):
    pass


def validate_contracts(contracts: ContractSet) -> None:
    errors: list[str] = []

    ids = sorted(contracts.requirements)
    if ids != EXPECTED_SOURCE_IDS:
        errors.append(f"source requirement id set drifted: expected {EXPECTED_SOURCE_IDS}, got {ids}")

    for req_id, requirement in contracts.requirements.items():
        expected_device_type = (
            "server"
            if req_id.startswith("SRV-")
            else "synology_nas"
            if req_id.startswith("NAS-")
            else "core_switch"
            if req_id.startswith("CORE-")
            else "access_switch"
        )
        if requirement.device_type != expected_device_type:
            errors.append(f"{req_id}: device_type {requirement.device_type} != {expected_device_type}")
        if "-MON-" in req_id and requirement.kind != "monitoring":
            errors.append(f"{req_id}: MON requirement with wrong kind")
        if "-ACT-" in req_id and requirement.kind != "operation":
            errors.append(f"{req_id}: ACT requirement with wrong kind")
        if requirement.kind == "monitoring" and not (requirement.metrics or requirement.events):
            errors.append(f"{req_id}: monitoring requirement lacks metrics/events")
        if requirement.kind == "operation" and not requirement.operations:
            errors.append(f"{req_id}: operation requirement lacks operations")
        for key in requirement.metrics:
            if key.startswith("event."):
                errors.append(f"{req_id}: event key stored as metric: {key}")
            if key not in contracts.metric_definitions:
                errors.append(f"{req_id}: metric {key} has no definition")
        for key in requirement.events:
            if not key.startswith("event."):
                errors.append(f"{req_id}: event key lacks prefix: {key}")
            if key not in contracts.event_definitions:
                errors.append(f"{req_id}: event {key} has no definition")
        for key, risk in requirement.operations:
            if risk not in {"low", "medium", "high"}:
                errors.append(f"{req_id}: invalid risk {risk}")
            profile_id = f"{req_id}:{key}"
            profile = contracts.operation_profiles.get(profile_id)
            if profile is None:
                errors.append(f"{profile_id}: operation profile missing")
                continue
            if profile.requirement_id != req_id or profile.key != key or profile.device_type != requirement.device_type:
                errors.append(f"{profile_id}: profile source mismatch")
            if profile.risk != risk:
                errors.append(f"{profile_id}: profile risk mismatch")
            if profile.channel not in {"task", "launch"}:
                errors.append(f"{profile_id}: invalid channel")
            if profile.timeout_seconds <= 0:
                errors.append(f"{profile_id}: invalid timeout")
            if (
                profile.parameter_schema.raw.get("type") != "object"
                or profile.parameter_schema.raw.get("additionalProperties") is not False
            ):
                errors.append(f"{profile_id}: parameter schema must be a closed object")
            if not profile.preconditions:
                errors.append(f"{profile_id}: lacks preconditions")
            if profile.cancel_policy not in {
                "before_dispatch_only",
                "adapter_declared_before_device_job",
                "not_applicable",
            }:
                errors.append(f"{profile_id}: invalid cancel_policy")
            if not (profile.verification.strategy and profile.verification.success and profile.verification.ambiguous):
                errors.append(f"{profile_id}: incomplete verification")
            if profile.risk == "high" and (profile.channel != "task" or not profile.side_effect):
                errors.append(f"{profile_id}: high-risk profile must be a side-effect task")
            if profile.channel == "launch" and (
                profile.side_effect
                or profile.risk != "medium"
                or not profile.key.startswith("console.")
                or profile.cancel_policy != "not_applicable"
            ):
                errors.append(f"{profile_id}: invalid launch profile")
            if profile.channel == "task" and profile.cancel_policy == "not_applicable":
                errors.append(f"{profile_id}: task profile must define a cancellation boundary")

    unused_profiles = set(contracts.operation_profiles) - {
        f"{req_id}:{key}" for req_id, requirement in contracts.requirements.items() for key, _ in requirement.operations
    }
    if unused_profiles:
        errors.append(f"operation profiles without source requirement: {sorted(unused_profiles)}")

    metric_refs = {key for requirement in contracts.requirements.values() for key in requirement.metrics}
    event_refs = {key for requirement in contracts.requirements.values() for key in requirement.events}
    if set(contracts.metric_definitions) != metric_refs:
        errors.append(
            f"metric definition/requirement set mismatch: "
            f"defs-only={sorted(set(contracts.metric_definitions) - metric_refs)} "
            f"refs-only={sorted(metric_refs - set(contracts.metric_definitions))}"
        )
    if set(contracts.event_definitions) != event_refs:
        errors.append(
            f"event definition/requirement set mismatch: "
            f"defs-only={sorted(set(contracts.event_definitions) - event_refs)} "
            f"refs-only={sorted(event_refs - set(contracts.event_definitions))}"
        )

    for definition in contracts.metric_definitions.values():
        if definition.value_type not in {"number", "integer", "boolean", "enum"}:
            errors.append(f"{definition.key}: invalid value_type")
        if definition.scope not in {"device", "component"}:
            errors.append(f"{definition.key}: invalid scope")
        if definition.value_type == "enum" and (
            not definition.enum_set or definition.enum_set not in contracts.enum_sets
        ):
            errors.append(f"{definition.key}: enum_set missing")

    rules = {rule.rule_key for rule in contracts.alert_rules}
    if rules != EXPECTED_ALERT_RULES:
        errors.append(f"alert rule set drifted: expected {sorted(EXPECTED_ALERT_RULES)}, got {sorted(rules)}")
    if FORBIDDEN_ALERT_RULES & rules:
        errors.append("out-of-scope alert rule present")
    if FORBIDDEN_METRIC_ALERT_POLICIES & {m.alert_policy for m in contracts.metric_definitions.values()}:
        errors.append("out-of-scope metric alert policy present")
    for definition in contracts.metric_definitions.values():
        if definition.value_type in {"number", "integer"} and definition.alert_policy != "none":
            errors.append(f"{definition.key}: numeric metric must be display-only (alert_policy=none)")
    for rule in contracts.alert_rules:
        if rule.source == "event":
            errors.append(f"{rule.rule_key}: log events must not be promoted into current-problem rules")

    selectors = {part for rule in contracts.alert_rules for part in rule.selector.split("|")}
    for definition in contracts.metric_definitions.values():
        if definition.alert_policy == "none":
            continue
        if definition.alert_policy not in selectors:
            errors.append(f"{definition.key}: alert policy {definition.alert_policy} lacks rule selector")
    for item in contracts.enum_value_maps:
        enum_set = contracts.enum_sets.get(item.enum_set)
        if enum_set is None:
            errors.append(f"enum map references unknown enum set: {item.enum_set}")
            continue
        if set(enum_set) != {value for value, _ in item.values}:
            errors.append(f"enum alert map incomplete for {item.alert_policy}/{item.enum_set}")
        for _, outcome in item.values:
            if outcome not in {"no_decision", "normal", "warning", "critical"}:
                errors.append(f"invalid enum alert outcome {outcome} in {item.enum_set}")
    for boolean_map in contracts.boolean_value_maps:
        if {boolean_map.true_outcome, boolean_map.false_outcome} > {"no_decision", "normal", "warning", "critical"}:
            errors.append(f"invalid boolean alert outcome in {boolean_map.alert_policy}")

    poe_expected_policies: dict[str, str] = {
        "poe.total_power_w": "none",
        "poe.total_power_percent": "none",
        "poe.total_power_alarm": "status",
    }
    missing_poe = [key for key in poe_expected_policies if key not in contracts.metric_definitions]
    if missing_poe:
        errors.append(f"PoE total metric(s) missing: {', '.join(sorted(missing_poe))}")
    elif any(
        contracts.metric_definitions[key].alert_policy != expected
        for key, expected in poe_expected_policies.items()
    ):
        errors.append("PoE total alarm must come from explicit alarm state; watt and percent are display-only")

    if len(contracts.http_endpoints) != 50:
        errors.append(f"endpoint whitelist must contain 50 endpoints, found {len(contracts.http_endpoints)}")
    for endpoint in contracts.http_endpoints.values():
        if endpoint.method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "SSE", "WS"}:
            errors.append(f"{endpoint.operation_id}: invalid method")
        if not (endpoint.support_id.startswith("PLT-0") and endpoint.support_id[4:].isdigit()):
            errors.append(f"{endpoint.operation_id}: invalid support id")

    if len(contracts.hardware_targets) != 10:
        errors.append(f"hardware targets must be 10, found {len(contracts.hardware_targets)}")

    if errors:
        raise ContractValidationError("\n- ".join(["contract validation failed:", *errors]))
