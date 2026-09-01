"""Contract loader: reads contracts/*.json into a validated ContractSet.

The loader only parses JSON into the frozen domain types. Runtime code should
import the generated registries (``app.generated``), which are produced from
these files by ``app.tools.codegen`` and verified drift-free by CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.domain.contracts import (
    AlertRule,
    BooleanValueMap,
    ContractSet,
    EnumValueMap,
    EventDefinition,
    HardwareTarget,
    HttpEndpoint,
    MetricDefinition,
    OperationParameterSchema,
    OperationProfile,
    OperationVerification,
    Requirement,
    StableError,
)

CONTRACTS_DIR = Path(__file__).resolve().parents[3] / "contracts"


def _load(name: str) -> dict[str, Any]:
    path = CONTRACTS_DIR / name
    with path.open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


def load_contracts() -> ContractSet:
    capabilities = _load("capabilities.json")
    metrics = _load("metrics.json")
    events = _load("events.json")
    operations = _load("operations.json")
    alerts = _load("alert-rules.json")
    errors = _load("error-codes.json")
    http_api = _load("http-api.json")
    targets = _load("hardware-targets.json")

    metric_definitions = {
        item["key"]: MetricDefinition(
            key=item["key"],
            value_type=item["value_type"],
            enum_set=item.get("enum_set"),
            unit=item.get("unit"),
            scope=item["scope"],
            series=item["series"],
            alert_policy=item["alert_policy"],
            range=tuple(item["range"]) if item.get("range") else None,
        )
        for item in metrics["definitions"]
    }
    enum_sets = {name: tuple(values) for name, values in metrics["enum_sets"].items()}

    event_definitions = {
        item["key"]: EventDefinition(
            key=item["key"],
            scope=item["scope"],
            sources=tuple(item["sources"]),
            required_fields=tuple(item["required_fields"]),
        )
        for item in events["definitions"]
    }

    operation_profiles = {
        item["id"]: OperationProfile(
            id=item["id"],
            requirement_id=item["requirement_id"],
            device_type=item["device_type"],
            key=item["key"],
            channel=item["channel"],
            risk=item["risk"],
            side_effect=item["side_effect"],
            parameter_schema=OperationParameterSchema(raw=item["parameter_schema"]),
            conflict_scope=item["conflict_scope"],
            timeout_seconds=item["timeout_seconds"],
            expected_disconnect=item["expected_disconnect"],
            cancel_policy=item["cancel_policy"],
            preconditions=tuple(item["preconditions"]),
            verification=OperationVerification(
                strategy=item["verification"]["strategy"],
                success=item["verification"]["success"],
                ambiguous=item["verification"]["ambiguous"],
                prohibition=item["verification"].get("prohibition"),
            ),
        )
        for item in operations["profiles"]
    }

    requirements = {
        item["id"]: Requirement(
            id=item["id"],
            device_type=item["device_type"],
            kind=item["kind"],
            title=item["title"],
            metrics=tuple(item.get("metrics") or ()),
            events=tuple(item.get("events") or ()),
            operations=tuple((op["key"], op["risk"]) for op in item.get("operations") or ()),
        )
        for item in capabilities["requirements"]
    }

    stable_errors = {
        item["code"]: StableError(
            code=item["code"],
            http_status=item["http_status"],
            retry_class=item["retry_class"],
            safe_detail_fields=tuple(item["safe_detail_fields"]),
        )
        for item in errors["errors"]
    }

    alert_rules = tuple(
        AlertRule(
            rule_key=item["rule_key"],
            source=item["source"],
            selector=item["selector"],
            severity=item.get("severity"),
            severity_from_value=item.get("severity_from_value", False),
            open_after=item["open_after"],
            resolve_after=item["resolve_after"],
            dedupe=item["dedupe"],
            metric_key=item.get("metric_key"),
        )
        for item in alerts["rules"]
    )
    enum_value_maps = tuple(
        EnumValueMap(
            alert_policy=item["alert_policy"],
            enum_set=item["enum_set"],
            values=tuple(sorted(item["values"].items())),
        )
        for item in alerts["enum_value_maps"]
    )
    boolean_value_maps = tuple(
        BooleanValueMap(
            alert_policy=item["alert_policy"],
            true_outcome=item["values"]["true"],
            false_outcome=item["values"]["false"],
        )
        for item in alerts["boolean_value_maps"]
    )

    http_endpoints = {
        item["operation_id"]: HttpEndpoint(
            method=item["method"],
            path=item["path"],
            operation_id=item["operation_id"],
            support_id=item["support_id"],
        )
        for item in http_api["endpoints"]
    }

    hardware_targets = {
        item["target_id"]: HardwareTarget(
            target_id=item["target_id"],
            device_type=item["device_type"],
            vendor=item["vendor"],
            declared_target=item["declared_target"],
            certification_scope=item["certification_scope"],
            adapter_key=item["adapter_key"],
        )
        for item in targets["targets"]
    }

    requirements_by_capability: dict[str, Requirement] = {}
    for requirement in requirements.values():
        for key in (*requirement.metrics, *requirement.events, *(op[0] for op in requirement.operations)):
            requirements_by_capability[key] = requirement

    return ContractSet(
        product_version=capabilities["product_version"],
        metric_definitions=metric_definitions,
        enum_sets=enum_sets,
        event_definitions=event_definitions,
        operation_profiles=operation_profiles,
        requirements=requirements,
        stable_errors=stable_errors,
        alert_rules=alert_rules,
        enum_value_maps=enum_value_maps,
        boolean_value_maps=boolean_value_maps,
        http_endpoints=http_endpoints,
        hardware_targets=hardware_targets,
        requirements_by_capability=requirements_by_capability,
    )
