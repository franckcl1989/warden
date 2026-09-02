"""Observation semantics: reachability, health, freshness and the alert engine.

Pure domain (ARCHITECTURE.md §4): no FastAPI, no SQLAlchemy, no vendor SDKs.

Every alert decision reads ONLY ``contracts/alert-rules.json`` via the
generated registries (ADR-025):

- no invented thresholds: metrics with ``alert_policy=none`` (all numeric
  display-only metrics) always map to ``no_decision``;
- ``unknown``/missing/error/unsupported is NEVER treated as normal and never
  resolves an alert (resolution requires subsequent trusted states);
- value maps are exhaustive per enum set (CI-validated, ADR-020).

State semantics (docs/PRODUCT_DESIGN.md §6, ADR-010/ADR-014):

- reachability hysteresis: 3 consecutive failures -> offline; after offline,
  2 consecutive successes -> online; a single success resets the failure
  counter;
- health priority critical > warning > healthy > unknown, with no-inference-
  without-evidence: an empty or partially-missing evidence set yields
  ``unknown``;
- freshness: <= 2x interval fresh, <= 3x stale, > 3x expired, no observation
  unknown.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.domain.contracts import AlertRule, BooleanValueMap, EnumValueMap, MetricDefinition
from app.generated.alerts import ALERT_RULES, BOOLEAN_VALUE_MAPS, ENUM_VALUE_MAPS
from app.generated.metrics import METRIC_DEFINITIONS

# PRODUCT_DESIGN.md §6.1: 连续 3 次基础连接失败 -> offline;
# 离线后连续 2 次成功才恢复在线.
OFFLINE_AFTER_FAILURES = 3
ONLINE_AFTER_SUCCESSES = 2

HEALTH_STATES = ("unknown", "healthy", "warning", "critical")
FRESHNESS_STATES = ("unknown", "fresh", "stale", "expired")

# data.expired group freshness worst-state ranking (worst wins):
# expired > stale > unknown > fresh (conservative: resolution only when the
# whole supported group is back to fresh).
_FRESHNESS_RANK: dict[str, int] = {"fresh": 1, "unknown": 2, "stale": 3, "expired": 4}

# API_CONTRACT.md §5 时间序列分辨率: within 7 days raw granularity, 7-30 days
# 5-minute rollups, 30-180 days 1-hour rollups. A client may request a COARSER
# resolution than the window default, never a finer one than retention
# supports. Rollups exist for numeric gauge series only (DATA_MODEL.md §5.4),
# so state/enum/boolean/counter history is always served raw (change points
# and checkpoints, never averages).
SERIES_RESOLUTIONS = ("raw", "5m", "1h")
RAW_RESOLUTION_MAX_DAYS = 7
FIVE_MINUTE_RESOLUTION_MAX_DAYS = 30
ONE_HOUR_RESOLUTION_MAX_DAYS = 180
_GRANULARITY: dict[str, int] = {"raw": 1, "5m": 2, "1h": 3}


def default_resolution_for_window(window_seconds: float) -> str:
    """The resolution the server picks for a [from, to) window (API_CONTRACT §5)."""
    days = window_seconds / 86400.0
    if days <= RAW_RESOLUTION_MAX_DAYS:
        return "raw"
    if days <= FIVE_MINUTE_RESOLUTION_MAX_DAYS:
        return "5m"
    return "1h"


def is_finer_resolution(requested: str, base: str) -> bool:
    """True when ``requested`` is strictly finer than ``base`` (raw < 5m < 1h)."""
    return _GRANULARITY[requested] < _GRANULARITY[base]


@dataclass(frozen=True)
class ReachabilityState:
    """Reachability evidence (docs/PRODUCT_DESIGN.md §6.1).

    ``reachability`` is unknown/online/offline; the counters are the durable
    hysteresis inputs stored on the devices row.
    """

    reachability: str
    consecutive_failures: int
    consecutive_successes: int

    @staticmethod
    def initial() -> ReachabilityState:
        return ReachabilityState(reachability="unknown", consecutive_failures=0, consecutive_successes=0)


class ReachabilityTracker:
    """Pure hysteresis: 3 failures -> offline, 2 successes -> online.

    Rules (PRODUCT_DESIGN.md §6.1, ADR-010):

    - ``success``: resets the failure counter; from ``offline`` the device
      returns online only on the second consecutive success; from
      ``unknown``/``online`` a single success is positive evidence -> online;
    - ``failure``: resets the success counter; the state only becomes
      ``offline`` on the third consecutive failure (一次失败只产生采集错误，
      不立即判离线); fewer failures from ``unknown`` leave it ``unknown``.
    """

    @staticmethod
    def update(current: ReachabilityState, event: str) -> ReachabilityState:
        if event == "failure":
            failures = current.consecutive_failures + 1
            reachability = "offline" if failures >= OFFLINE_AFTER_FAILURES else current.reachability
            return ReachabilityState(
                reachability=reachability,
                consecutive_failures=failures,
                consecutive_successes=0,
            )
        if event == "success":
            successes = current.consecutive_successes + 1
            if current.reachability == "offline":
                reachability = "online" if successes >= ONLINE_AFTER_SUCCESSES else "offline"
            else:
                reachability = "online"
            return ReachabilityState(
                reachability=reachability,
                consecutive_failures=0,
                consecutive_successes=successes,
            )
        msg = f"reachability event must be 'success' or 'failure', got {event!r}"
        raise ValueError(msg)


class HealthAggregator:
    """Explicit health evidence -> combined health (PRODUCT_DESIGN.md §6.2).

    Input is a sequence of explicit health states observed this batch
    (healthy/warning/critical only — no_decision evidence is excluded before
    calling). Priority: critical > warning > healthy > unknown; an empty
    evidence set (没有异常不等于健康, ADR-010) or any missing evidence yields
    ``unknown``: the caller decides what counts as "all relevant observed".
    """

    _PRIORITY: dict[str, int] = {"critical": 3, "warning": 2, "healthy": 1, "unknown": 0}

    @staticmethod
    def aggregate(states: Sequence[str]) -> str:
        if not states:
            return "unknown"
        if any(state == "critical" for state in states):
            return "critical"
        if any(state == "warning" for state in states):
            return "warning"
        if all(state == "healthy" for state in states):
            return "healthy"
        return "unknown"


class FreshnessCalculator:
    """Data freshness from the last trusted observation (PRODUCT_DESIGN.md §6.3).

    fresh <= 2x interval, stale <= 3x, expired > 3x, unknown when there has
    never been an observation. Unsupported metrics are a capability state, not
    a time state (ADR-014), and are excluded before calling.
    """

    @staticmethod
    def freshness(
        last_observed_at: datetime.datetime | None,
        interval_seconds: int,
        now: datetime.datetime,
    ) -> str:
        if last_observed_at is None:
            return "unknown"
        age = (now - last_observed_at).total_seconds()
        if age <= 2 * interval_seconds:
            return "fresh"
        if age <= 3 * interval_seconds:
            return "stale"
        return "expired"

    @staticmethod
    def group_freshness(states: Sequence[str]) -> str:
        """Worst freshness among a capability group's supported metrics.

        expired > stale > unknown > fresh: a group is only ``fresh`` (the
        resolution evidence) when every supported metric is fresh.
        """
        if not states:
            return "unknown"
        return max(states, key=lambda state: _FRESHNESS_RANK.get(state, 0))


def outcome_for_metric(
    metric: MetricDefinition,
    value: object,
    *,
    enum_maps: Sequence[EnumValueMap],
    boolean_maps: Sequence[BooleanValueMap],
) -> str:
    """Map a metric value to an alert outcome from the contract maps.

    Returns one of no_decision/normal/warning/critical (alert-rules.json
    ``value_outcomes``). Metrics with ``alert_policy=none`` (every numeric
    display-only metric) always return ``no_decision`` (ADR-025); values not
    covered by a map (unknown enum, wrong type) return ``no_decision``.
    """
    policy = metric.alert_policy
    if policy == "none":
        return "no_decision"
    if metric.value_type == "enum" and metric.enum_set is not None:
        for map_item in enum_maps:
            if map_item.alert_policy == policy and map_item.enum_set == metric.enum_set:
                return str(dict(map_item.values).get(str(value), "no_decision"))
        return "no_decision"
    if metric.value_type == "boolean":
        for bool_map in boolean_maps:
            if bool_map.alert_policy == policy:
                if value is True:
                    return str(bool_map.true_outcome)
                if value is False:
                    return str(bool_map.false_outcome)
                return "no_decision"
        return "no_decision"
    return "no_decision"


def health_state_from_outcome(outcome: str) -> str | None:
    """Map an alert outcome to explicit health evidence (or no evidence)."""
    if outcome == "normal":
        return "healthy"
    if outcome == "warning":
        return "warning"
    if outcome == "critical":
        return "critical"
    return None


@dataclass(frozen=True)
class MetricSignal:
    """A metric_latest row viewed by the alert evaluator."""

    metric_key: str
    value: object
    observed_at: datetime.datetime
    quality: str
    component_kind: str | None = None
    component_native_id: str | None = None
    component_id: uuid.UUID | None = None


@dataclass(frozen=True)
class CapabilityGroupFreshness:
    """One supported capability group's freshness state (data.expired input)."""

    requirement_id: str
    state: str  # unknown/fresh/stale/expired


@dataclass(frozen=True)
class DeviceAlertSnapshot:
    """Per-device current state the evaluator reasons over.

    ``supported_metric_keys`` is the set of contract metric keys whose
    capability is discovered ``supported`` on the device — a supported-but-
    missing health.overall is a no_decision signal, never a resolution.
    """

    device_id: uuid.UUID
    reachability: str
    consecutive_failures: int
    consecutive_successes: int
    supported_metric_keys: frozenset[str] = frozenset()
    metric_signals: tuple[MetricSignal, ...] = ()
    group_freshness: tuple[CapabilityGroupFreshness, ...] = ()


@dataclass(frozen=True)
class AlertSignal:
    """One rule evaluation result for one dedupe key.

    ``severity`` is set (warning/critical) for an open-worthy outcome;
    ``resolve=True`` for a trusted normal outcome; ``no_decision=True`` when
    the value was unknown/missing/error (breaks streaks, never resolves).
    ``condition_counted`` marks rules whose condition itself encodes
    open_after/resolve_after (device.offline: the reachability tracker
    already counts 3 failures / 2 successes), so the store skips its own
    signal counting for them. ``component_id`` is the resolved component row
    for component-scoped dedupes (status.problem).
    """

    rule_key: str
    dedupe_key: str
    title: str
    evidence: dict[str, object]
    severity: str | None = None
    resolve: bool = False
    no_decision: bool = False
    condition_counted: bool = False
    component_id: uuid.UUID | None = None


@dataclass(frozen=True)
class ActiveAlertView:
    """Durable open_after/resolve_after counter state (alerts.signal_count)."""

    dedupe_key: str
    signal_count: int


@dataclass(frozen=True)
class AlertDecision:
    """Store action for one alert dedupe key (open/resolve/refresh/count/none)."""

    action: str  # open | resolve | refresh | count | reset_count | none
    severity: str | None = None
    title: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    signal_count: int = 0


def decide_alert(
    rule: AlertRule,
    active: ActiveAlertView | None,
    signal: AlertSignal,
) -> AlertDecision:
    """Open/resolve/count transition per alert state (DATA_MODEL.md §6.1).

    Semantics (M2T2 decision, documented in migration 0006):

    - opening: an open-worthy signal creates the alert when the rule's
      open_after is satisfied. Only ``device.offline`` has open_after > 1,
      and its condition is count-encoded by the reachability tracker
      (``condition_counted``), so it opens on the first qualifying signal;
      rules with open_after > 1 that are NOT condition-counted wait (no
      durable counter exists before the alert row — the contracts guarantee
      no such rule exists for 0.1.0).
    - resolution: a trusted-normal signal resolves when resolve_after <= 1 or
      the condition is count-encoded (device.offline — online already means 2
      consecutive successes); otherwise it increments signal_count and
      resolves on the Nth consecutive good signal.
    - a no_decision signal resets the streak (consecutive GOOD signals only)
      but never resolves and never re-opens anything;
    - while active, a repeated open-worthy signal refreshes the alert
      (evidence/severity/last_occurred_at) and resets the streak.
    """
    if signal.no_decision:
        if active is not None and active.signal_count != 0:
            return AlertDecision(action="reset_count", signal_count=0)
        return AlertDecision(action="none")
    if active is not None:
        if signal.resolve:
            if rule.resolve_after <= 1 or signal.condition_counted:
                return AlertDecision(
                    action="resolve",
                    title=signal.title,
                    evidence=signal.evidence,
                    signal_count=active.signal_count,
                )
            new_count = active.signal_count + 1
            if new_count >= rule.resolve_after:
                return AlertDecision(
                    action="resolve",
                    title=signal.title,
                    evidence=signal.evidence,
                    signal_count=new_count,
                )
            return AlertDecision(action="count", signal_count=new_count)
        if signal.severity is not None:
            return AlertDecision(
                action="refresh",
                severity=signal.severity,
                title=signal.title,
                evidence=signal.evidence,
                signal_count=0,
            )
        return AlertDecision(action="none")
    if signal.severity is not None:
        if rule.open_after <= 1 or signal.condition_counted:
            return AlertDecision(
                action="open",
                severity=signal.severity,
                title=signal.title,
                evidence=signal.evidence,
                signal_count=0,
            )
        return AlertDecision(action="none")
    return AlertDecision(action="none")


class AlertEvaluator:
    """The current-problem engine: snapshot + contract rules -> AlertSignals.

    Rules come ONLY from ``app.generated.alerts`` (contracts/alert-rules.json):
    device.offline, device.health, data.expired, status.problem. Numeric
    metrics never alert; unknown/absent/error is never normal nor resolution
    evidence; device log events never become current problems.
    """

    def __init__(
        self,
        *,
        alert_rules: Sequence[AlertRule] = ALERT_RULES,
        enum_value_maps: Sequence[EnumValueMap] = ENUM_VALUE_MAPS,
        boolean_value_maps: Sequence[BooleanValueMap] = BOOLEAN_VALUE_MAPS,
        metric_definitions: dict[str, MetricDefinition] = METRIC_DEFINITIONS,
    ) -> None:
        self._rules = {rule.rule_key: rule for rule in alert_rules}
        self._enum_maps = tuple(enum_value_maps)
        self._boolean_maps = tuple(boolean_value_maps)
        self._metrics = dict(metric_definitions)

    def rule(self, rule_key: str) -> AlertRule | None:
        return self._rules.get(rule_key)

    def _map(self, metric_key: str, value: object) -> str:
        metric = self._metrics.get(metric_key)
        if metric is None:
            return "no_decision"
        return outcome_for_metric(
            metric, value, enum_maps=self._enum_maps, boolean_maps=self._boolean_maps
        )

    def evaluate(self, snapshot: DeviceAlertSnapshot) -> tuple[AlertSignal, ...]:
        signals: list[AlertSignal] = []
        device = str(snapshot.device_id)
        for rule in self._rules.values():
            if rule.rule_key == "device.offline":
                signals.append(self._device_offline(rule, device, snapshot))
            elif rule.rule_key == "device.health":
                signals.extend(self._device_health(rule, device, snapshot))
            elif rule.rule_key == "data.expired":
                signals.extend(self._data_expired(rule, device, snapshot))
            elif rule.rule_key == "status.problem":
                signals.extend(self._status_problem(rule, device, snapshot))
        return tuple(signals)

    def _device_offline(
        self, rule: AlertRule, device: str, snapshot: DeviceAlertSnapshot
    ) -> AlertSignal:
        base = {
            "reachability": snapshot.reachability,
            "consecutive_failures": snapshot.consecutive_failures,
            "consecutive_successes": snapshot.consecutive_successes,
        }
        if snapshot.reachability == "offline":
            return AlertSignal(
                rule_key=rule.rule_key,
                dedupe_key=f"{rule.rule_key}:{device}",
                title="设备离线",
                evidence=base,
                severity=rule.severity,
                condition_counted=True,
            )
        if snapshot.reachability == "online":
            return AlertSignal(
                rule_key=rule.rule_key,
                dedupe_key=f"{rule.rule_key}:{device}",
                title="设备离线",
                evidence=base,
                resolve=True,
                condition_counted=True,
            )
        return AlertSignal(
            rule_key=rule.rule_key,
            dedupe_key=f"{rule.rule_key}:{device}",
            title="设备离线",
            evidence=base,
            no_decision=True,
        )

    def _device_health(
        self, rule: AlertRule, device: str, snapshot: DeviceAlertSnapshot
    ) -> tuple[AlertSignal, ...]:
        assert rule.metric_key is not None
        supported = rule.metric_key in snapshot.supported_metric_keys
        row = next(
            (m for m in snapshot.metric_signals if m.metric_key == rule.metric_key), None
        )
        if not supported:
            return ()
        if row is None or row.quality != "good":
            evidence: dict[str, object] = {
                "metric_key": rule.metric_key,
                "quality": row.quality if row else None,
            }
            return (
                AlertSignal(
                    rule_key=rule.rule_key,
                    dedupe_key=f"{rule.rule_key}:{device}",
                    title="设备健康异常",
                    evidence=evidence,
                    no_decision=True,
                ),
            )
        outcome = self._map(rule.metric_key, row.value)
        evidence = {
            "metric_key": rule.metric_key,
            "value": row.value,
            "observed_at": row.observed_at.isoformat(),
        }
        if outcome == "no_decision":
            return (
                AlertSignal(
                    rule_key=rule.rule_key,
                    dedupe_key=f"{rule.rule_key}:{device}",
                    title="设备健康异常",
                    evidence=evidence,
                    no_decision=True,
                ),
            )
        if outcome == "normal":
            return (
                AlertSignal(
                    rule_key=rule.rule_key,
                    dedupe_key=f"{rule.rule_key}:{device}",
                    title="设备健康异常",
                    evidence=evidence,
                    resolve=True,
                ),
            )
        return (
            AlertSignal(
                rule_key=rule.rule_key,
                dedupe_key=f"{rule.rule_key}:{device}",
                title="设备健康异常",
                evidence=evidence,
                severity=outcome,
            ),
        )

    def _data_expired(
        self, rule: AlertRule, device: str, snapshot: DeviceAlertSnapshot
    ) -> tuple[AlertSignal, ...]:
        signals: list[AlertSignal] = []
        for group in snapshot.group_freshness:
            dedupe_key = f"{rule.rule_key}:{device}:{group.requirement_id}"
            evidence: dict[str, object] = {
                "requirement_id": group.requirement_id,
                "freshness": group.state,
            }
            if group.state == "expired":
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="监控数据过期",
                        evidence=evidence,
                        severity=rule.severity,
                    )
                )
            elif group.state == "fresh":
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="监控数据过期",
                        evidence=evidence,
                        resolve=True,
                    )
                )
            else:
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="监控数据过期",
                        evidence=evidence,
                        no_decision=True,
                    )
                )
        return tuple(signals)

    def _status_problem(
        self, rule: AlertRule, device: str, snapshot: DeviceAlertSnapshot
    ) -> tuple[AlertSignal, ...]:
        policies = frozenset(rule.selector.split("|"))
        signals: list[AlertSignal] = []
        for row in snapshot.metric_signals:
            # Unsupported metrics are a capability state, never a signal:
            # they must not open, refresh or resolve status.problem (ADR-014).
            if row.metric_key not in snapshot.supported_metric_keys:
                continue
            metric = self._metrics.get(row.metric_key)
            if metric is None or metric.alert_policy not in policies:
                continue
            component_key = str(row.component_id) if row.component_id is not None else "device"
            dedupe_key = f"{rule.rule_key}:{device}:{component_key}:{row.metric_key}"
            if row.quality != "good":
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="设备状态异常",
                        evidence={
                            "metric_key": row.metric_key,
                            "quality": row.quality,
                        },
                        no_decision=True,
                        component_id=row.component_id,
                    )
                )
                continue
            outcome = self._map(row.metric_key, row.value)
            evidence: dict[str, object] = {
                "metric_key": row.metric_key,
                "value": row.value,
                "observed_at": row.observed_at.isoformat(),
                "component": component_key,
            }
            if outcome == "no_decision":
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="设备状态异常",
                        evidence=evidence,
                        no_decision=True,
                        component_id=row.component_id,
                    )
                )
            elif outcome == "normal":
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="设备状态异常",
                        evidence=evidence,
                        resolve=True,
                        component_id=row.component_id,
                    )
                )
            else:
                signals.append(
                    AlertSignal(
                        rule_key=rule.rule_key,
                        dedupe_key=dedupe_key,
                        title="设备状态异常",
                        evidence=evidence,
                        severity=outcome,
                        component_id=row.component_id,
                    )
                )
        return tuple(signals)
