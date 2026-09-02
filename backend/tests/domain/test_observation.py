"""Unit tests for observation semantics (pure domain, no database).

Covers the M2T2 matrix (docs/PRODUCT_DESIGN.md §6, ADR-010/014/025):

- ReachabilityTracker hysteresis (3 failures offline / 2 successes online);
- HealthAggregator priority with no-inference-without-evidence;
- FreshnessCalculator 2x/3x boundaries;
- AlertEvaluator: every metric policy class with value-map outcomes,
  no_decision never resolves, numeric never alerts, data.expired per
  capability group, device.offline open/resolve, and the open_after /
  resolve_after counters via decide_alert.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.domain.observation import (
    ActiveAlertView,
    AlertEvaluator,
    AlertSignal,
    CapabilityGroupFreshness,
    DeviceAlertSnapshot,
    FreshnessCalculator,
    HealthAggregator,
    MetricSignal,
    ReachabilityState,
    ReachabilityTracker,
    decide_alert,
)
from app.generated.alerts import ALERT_RULES
from app.generated.metrics import METRIC_DEFINITIONS

NOW = datetime.datetime(2026, 9, 2, 12, 0, 0, tzinfo=datetime.UTC)
DEVICE_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
INTERVAL = 60


class TestReachabilityTracker:
    def test_failures_do_not_go_offline_before_three(self) -> None:
        state = ReachabilityState.initial()
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "unknown"
        assert state.consecutive_failures == 1
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "unknown"
        assert state.consecutive_failures == 2
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "offline"
        assert state.consecutive_failures == 3

    def test_failure_while_online_stays_online_until_third(self) -> None:
        state = ReachabilityState(reachability="online", consecutive_failures=0, consecutive_successes=1)
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "online"
        state = ReachabilityTracker.update(state, "failure")
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "offline"

    def test_single_success_resets_failure_counter(self) -> None:
        state = ReachabilityState(reachability="unknown", consecutive_failures=2, consecutive_successes=0)
        state = ReachabilityTracker.update(state, "success")
        assert state.reachability == "online"
        assert state.consecutive_failures == 0
        assert state.consecutive_successes == 1

    def test_offline_requires_two_consecutive_successes(self) -> None:
        state = ReachabilityState(reachability="offline", consecutive_failures=3, consecutive_successes=0)
        state = ReachabilityTracker.update(state, "success")
        assert state.reachability == "offline"
        assert state.consecutive_successes == 1
        state = ReachabilityTracker.update(state, "success")
        assert state.reachability == "online"
        assert state.consecutive_successes == 2

    def test_failure_after_one_success_resets_success_streak(self) -> None:
        state = ReachabilityState(reachability="offline", consecutive_failures=3, consecutive_successes=1)
        state = ReachabilityTracker.update(state, "failure")
        assert state.reachability == "offline"
        assert state.consecutive_successes == 0
        assert state.consecutive_failures == 4

    def test_rejects_unknown_event(self) -> None:
        with pytest.raises(ValueError):
            ReachabilityTracker.update(ReachabilityState.initial(), "maybe")


class TestHealthAggregator:
    def test_no_evidence_is_unknown(self) -> None:
        assert HealthAggregator.aggregate([]) == "unknown"

    def test_all_healthy_is_healthy(self) -> None:
        assert HealthAggregator.aggregate(["healthy", "healthy"]) == "healthy"

    def test_critical_wins_over_warning(self) -> None:
        assert HealthAggregator.aggregate(["warning", "critical", "healthy"]) == "critical"

    def test_warning_wins_over_healthy(self) -> None:
        assert HealthAggregator.aggregate(["healthy", "warning"]) == "warning"

    def test_partial_evidence_is_unknown(self) -> None:
        # 没有异常不等于健康：证据集不完整（含缺失）时保持 unknown。
        assert HealthAggregator.aggregate(["healthy", "unknown"]) == "unknown"


class TestFreshnessCalculator:
    def test_no_observation_is_unknown(self) -> None:
        assert FreshnessCalculator.freshness(None, INTERVAL, NOW) == "unknown"

    def test_exactly_2x_is_fresh(self) -> None:
        last = NOW - datetime.timedelta(seconds=2 * INTERVAL)
        assert FreshnessCalculator.freshness(last, INTERVAL, NOW) == "fresh"

    def test_just_over_2x_is_stale(self) -> None:
        last = NOW - datetime.timedelta(seconds=2 * INTERVAL + 1)
        assert FreshnessCalculator.freshness(last, INTERVAL, NOW) == "stale"

    def test_exactly_3x_is_stale(self) -> None:
        last = NOW - datetime.timedelta(seconds=3 * INTERVAL)
        assert FreshnessCalculator.freshness(last, INTERVAL, NOW) == "stale"

    def test_over_3x_is_expired(self) -> None:
        last = NOW - datetime.timedelta(seconds=3 * INTERVAL + 1)
        assert FreshnessCalculator.freshness(last, INTERVAL, NOW) == "expired"

    def test_group_worst_wins(self) -> None:
        assert FreshnessCalculator.group_freshness(["fresh", "expired"]) == "expired"
        assert FreshnessCalculator.group_freshness(["fresh", "stale"]) == "stale"
        assert FreshnessCalculator.group_freshness(["fresh", "fresh"]) == "fresh"
        assert FreshnessCalculator.group_freshness(["fresh", "unknown"]) == "unknown"
        assert FreshnessCalculator.group_freshness([]) == "unknown"


def _metric_signal(
    metric_key: str,
    value: object,
    *,
    component_id: uuid.UUID | None = None,
    quality: str = "good",
) -> MetricSignal:
    return MetricSignal(
        metric_key=metric_key,
        value=value,
        observed_at=NOW,
        quality=quality,
        component_id=component_id,
    )


def _snapshot(
    *,
    reachability: str = "online",
    failures: int = 0,
    successes: int = 1,
    metrics: tuple[MetricSignal, ...] = (),
    groups: tuple[CapabilityGroupFreshness, ...] = (),
    supported: frozenset[str] = frozenset(),
) -> DeviceAlertSnapshot:
    return DeviceAlertSnapshot(
        device_id=DEVICE_ID,
        reachability=reachability,
        consecutive_failures=failures,
        consecutive_successes=successes,
        supported_metric_keys=supported,
        metric_signals=metrics,
        group_freshness=groups,
    )


def _rules() -> dict[str, object]:
    return {rule.rule_key: rule for rule in ALERT_RULES}


class TestAlertEvaluatorDeviceOffline:
    def test_offline_opens_critical(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot(reachability="offline", failures=3, successes=0))
        offline = next(signal for signal in signals if signal.rule_key == "device.offline")
        assert offline.severity == "critical"
        assert offline.resolve is False
        assert offline.condition_counted is True

    def test_online_resolves(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot(reachability="online", successes=2))
        offline = next(signal for signal in signals if signal.rule_key == "device.offline")
        assert offline.resolve is True
        assert offline.severity is None

    def test_unknown_is_no_decision(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot(reachability="unknown"))
        offline = next(signal for signal in signals if signal.rule_key == "device.offline")
        assert offline.no_decision is True
        assert offline.resolve is False and offline.severity is None


class TestAlertEvaluatorDeviceHealth:
    def test_healthy_is_resolution_evidence(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("health.overall", "healthy"),), supported=frozenset({"health.overall"}))
        )
        signal = next(s for s in signals if s.rule_key == "device.health")
        assert signal.resolve is True

    def test_warning_opens_warning(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("health.overall", "warning"),), supported=frozenset({"health.overall"}))
        )
        signal = next(s for s in signals if s.rule_key == "device.health")
        assert signal.severity == "warning"

    def test_critical_opens_critical(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("health.overall", "critical"),), supported=frozenset({"health.overall"}))
        )
        signal = next(s for s in signals if s.rule_key == "device.health")
        assert signal.severity == "critical"

    def test_unknown_never_resolves(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("health.overall", "unknown"),), supported=frozenset({"health.overall"}))
        )
        signal = next(s for s in signals if s.rule_key == "device.health")
        assert signal.no_decision is True
        assert signal.resolve is False and signal.severity is None

    def test_supported_but_missing_is_no_decision(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot(supported=frozenset({"health.overall"})))
        signal = next(s for s in signals if s.rule_key == "device.health")
        assert signal.no_decision is True

    def test_unsupported_metric_produces_no_signal(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot(metrics=(_metric_signal("health.overall", "critical"),)))
        assert all(signal.rule_key != "device.health" for signal in signals)


class TestAlertEvaluatorStatusPolicies:
    """status.problem: every contract policy class with value-map outcomes."""

    @pytest.mark.parametrize(
        ("metric_key", "value", "expected"),
        [
            # status enum maps
            ("indicator.led", "normal", "resolve"),
            ("indicator.led", "critical", "critical"),
            ("indicator.led", "identify", "resolve"),
            ("indicator.led", "unknown", "no_decision"),
            ("memory.status", "ok", "resolve"),
            ("memory.status", "critical", "critical"),
            ("memory.status", "absent", "no_decision"),
            ("drive.smart", "passed", "resolve"),
            ("drive.smart", "failed", "critical"),
            ("drive.smart", "running", "resolve"),
            ("raid.status", "optimal", "resolve"),
            ("raid.status", "degraded", "warning"),
            ("raid.status", "failed", "critical"),
            ("psu.present", "present", "resolve"),
            ("psu.present", "absent", "critical"),
            ("ups.status", "normal", "resolve"),
            ("ups.status", "on_battery", "warning"),
            ("ups.status", "low_battery", "critical"),
            ("poe.port.status", "on", "resolve"),
            ("poe.port.status", "denied", "warning"),
            ("poe.port.status", "fault", "critical"),
            ("poe.total_power_alarm", "warning", "warning"),
            ("poe.total_power_alarm", "critical", "critical"),
            # detected_is_critical
            ("chassis.intrusion", "normal", "resolve"),
            ("chassis.intrusion", "detected", "critical"),
            # broken_is_critical
            ("stp.port_state", "forwarding", "resolve"),
            ("stp.port_state", "broken", "critical"),
            # true_is_critical
            ("drive.predictive_failure", True, "critical"),
            ("drive.predictive_failure", False, "resolve"),
        ],
    )
    def test_value_map_outcome(self, metric_key: str, value: object, expected: str) -> None:
        assert metric_key in METRIC_DEFINITIONS, "metric must exist in contracts/metrics.json"
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal(metric_key, value),), supported=frozenset({metric_key}))
        )
        signals = tuple(s for s in signals if s.rule_key == "status.problem")
        assert len(signals) == 1, f"{metric_key}: expected one status.problem signal"
        signal = signals[0]
        if expected == "resolve":
            assert signal.resolve is True and signal.severity is None
        elif expected == "no_decision":
            assert signal.no_decision is True and signal.resolve is False and signal.severity is None
        else:
            assert signal.severity == expected and signal.resolve is False

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, "normal"),
            (False, "critical"),
        ],
    )
    def test_connectivity_map_is_contract_defined_but_has_no_rule(
        self, value: bool, expected: str
    ) -> None:
        # contracts/alert-rules.json defines a boolean value map for the
        # connectivity policy, but no 0.1.0 rule selects it (the status.problem
        # selector is status|true_is_critical|detected_is_critical|
        # broken_is_critical), so the evaluator emits NO signal for it —
        # the map outcome itself is still contract-verified here.
        from app.domain.observation import outcome_for_metric
        from app.generated.alerts import BOOLEAN_VALUE_MAPS, ENUM_VALUE_MAPS

        metric = METRIC_DEFINITIONS["connectivity.management"]
        assert metric.alert_policy == "connectivity"
        assert (
            outcome_for_metric(
                metric, value, enum_maps=ENUM_VALUE_MAPS, boolean_maps=BOOLEAN_VALUE_MAPS
            )
            == expected
        )
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(
                metrics=(_metric_signal("connectivity.management", value),),
                supported=frozenset({"connectivity.management"}),
            )
        )
        assert all(signal.rule_key != "status.problem" for signal in signals)

    def test_numeric_metrics_never_alert(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(
                metrics=(
                    _metric_signal("temperature.cpu", 99.0),
                    _metric_signal("psu.load_w", 999.0),
                    _metric_signal("memory.ecc_errors", 0),
                    _metric_signal("system.cpu_percent", 100.0),
                ),
                supported=frozenset({"temperature.cpu", "psu.load_w", "memory.ecc_errors", "system.cpu_percent"}),
            )
        )
        assert all(signal.rule_key != "status.problem" for signal in signals)

    def test_unknown_enum_value_is_no_decision(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("memory.status", "bogus"),), supported=frozenset({"memory.status"}))
        )
        signal = next(s for s in signals if s.rule_key == "status.problem")
        assert signal.no_decision is True

    def test_dedupe_includes_component(self) -> None:
        component = uuid.UUID("22222222-2222-2222-2222-222222222222")
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(
                metrics=(_metric_signal("drive.status", "critical", component_id=component),),
                supported=frozenset({"drive.status"}),
            )
        )
        signal = next(s for s in signals if s.rule_key == "status.problem")
        assert str(component) in signal.dedupe_key

    def test_device_scope_uses_device_in_dedupe(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(metrics=(_metric_signal("indicator.led", "critical"),), supported=frozenset({"indicator.led"}))
        )
        signal = next(s for s in signals if s.rule_key == "status.problem")
        assert "device" in signal.dedupe_key

    def test_unsupported_status_metric_produces_no_signal(self) -> None:
        # An alert-worthy value on a metric the device does NOT support is a
        # capability state, never a signal (ADR-014: 不支持 -> 无信号): it must
        # not open, refresh or resolve anything.
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(
                metrics=(
                    _metric_signal("drive.status", "critical"),
                    _metric_signal("indicator.led", "critical"),
                ),
                supported=frozenset({"drive.status"}),
            )
        )
        status = [s for s in signals if s.rule_key == "status.problem"]
        assert len(status) == 1
        assert status[0].dedupe_key.endswith("drive.status")
        assert all("indicator.led" not in s.dedupe_key for s in status)


class TestAlertEvaluatorDataExpired:
    def test_expired_opens_warning_per_group(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(groups=(CapabilityGroupFreshness("SRV-MON-02", "expired"),))
        )
        signal = next(s for s in signals if s.rule_key == "data.expired")
        assert signal.severity == "warning"
        assert "SRV-MON-02" in signal.dedupe_key

    def test_fresh_resolves(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(groups=(CapabilityGroupFreshness("SRV-MON-02", "fresh"),))
        )
        signal = next(s for s in signals if s.rule_key == "data.expired")
        assert signal.resolve is True

    def test_stale_is_no_decision(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(groups=(CapabilityGroupFreshness("SRV-MON-02", "stale"),))
        )
        signal = next(s for s in signals if s.rule_key == "data.expired")
        assert signal.no_decision is True and signal.resolve is False

    def test_unknown_is_no_decision(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(
            _snapshot(groups=(CapabilityGroupFreshness("SRV-MON-02", "unknown"),))
        )
        signal = next(s for s in signals if s.rule_key == "data.expired")
        assert signal.no_decision is True

    def test_empty_groups_produce_no_signals(self) -> None:
        evaluator = AlertEvaluator()
        signals = evaluator.evaluate(_snapshot())
        assert all(signal.rule_key != "data.expired" for signal in signals)


class TestDecideAlertCounters:
    """open_after/resolve_after semantics with the durable signal_count."""

    def _rule(self, rule_key: str) -> object:
        return _rules()[rule_key]

    def test_open_after_one_opens_immediately(self) -> None:
        signal = AlertSignal(
            rule_key="device.health",
            dedupe_key="device.health:dev",
            title="t",
            evidence={},
            severity="critical",
        )
        decision = decide_alert(self._rule("device.health"), None, signal)
        assert decision.action == "open"
        assert decision.signal_count == 0

    def test_resolve_after_two_counts_then_resolves(self) -> None:
        rule = self._rule("device.health")
        good = AlertSignal(
            rule_key="device.health", dedupe_key="device.health:dev", title="t", evidence={}, resolve=True
        )
        first = decide_alert(rule, ActiveAlertView("device.health:dev", signal_count=0), good)
        assert first.action == "count"
        assert first.signal_count == 1
        second = decide_alert(rule, ActiveAlertView("device.health:dev", signal_count=1), good)
        assert second.action == "resolve"

    def test_no_decision_resets_streak_and_never_resolves(self) -> None:
        rule = self._rule("device.health")
        unknown = AlertSignal(
            rule_key="device.health", dedupe_key="device.health:dev", title="t", evidence={}, no_decision=True
        )
        decision = decide_alert(rule, ActiveAlertView("device.health:dev", signal_count=1), unknown)
        assert decision.action == "reset_count"
        assert decision.signal_count == 0
        assert decide_alert(rule, None, unknown).action == "none"

    def test_condition_counted_offline_resolves_immediately(self) -> None:
        rule = self._rule("device.offline")
        online = AlertSignal(
            rule_key="device.offline",
            dedupe_key="device.offline:dev",
            title="t",
            evidence={},
            resolve=True,
            condition_counted=True,
        )
        # resolve_after=2 but the reachability tracker already encoded the two
        # consecutive successes -> resolve on the first qualifying signal.
        decision = decide_alert(rule, ActiveAlertView("device.offline:dev", signal_count=0), online)
        assert decision.action == "resolve"

    def test_condition_counted_offline_opens_immediately(self) -> None:
        rule = self._rule("device.offline")
        offline = AlertSignal(
            rule_key="device.offline",
            dedupe_key="device.offline:dev",
            title="t",
            evidence={},
            severity="critical",
            condition_counted=True,
        )
        decision = decide_alert(rule, None, offline)
        assert decision.action == "open"

    def test_repeated_open_while_active_refreshes_and_resets_count(self) -> None:
        rule = self._rule("status.problem")
        critical = AlertSignal(
            rule_key="status.problem",
            dedupe_key="status.problem:dev:drive-0:drive.status",
            title="t",
            evidence={},
            severity="critical",
        )
        decision = decide_alert(
            rule, ActiveAlertView("status.problem:dev:drive-0:drive.status", signal_count=1), critical
        )
        assert decision.action == "refresh"
        assert decision.signal_count == 0

    def test_resolve_with_no_active_alert_is_none(self) -> None:
        rule = self._rule("data.expired")
        fresh = AlertSignal(
            rule_key="data.expired", dedupe_key="data.expired:dev:SRV-MON-02", title="t", evidence={}, resolve=True
        )
        assert decide_alert(rule, None, fresh).action == "none"

    def test_open_after_three_not_counted_waits(self) -> None:
        # Only device.offline has open_after>1 and it is condition-counted;
        # a hypothetical non-counted rule with open_after>1 must wait (no
        # durable counter exists before the alert row).
        rule = AlertRule(
            rule_key="hypothetical", source="metric", selector="x", severity="warning",
            severity_from_value=False, open_after=3, resolve_after=1, dedupe="device",
        )
        signal = AlertSignal(
            rule_key="hypothetical",
            dedupe_key="hypothetical:dev",
            title="t",
            evidence={},
            severity="warning",
        )
        assert decide_alert(rule, None, signal).action == "none"


from app.domain.contracts import AlertRule  # noqa: E402  (test-only synthetic rule)
