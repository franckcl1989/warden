"""Access Huawei VRP adapter contract suite — probe/discover/collect (M5T2).

Drives ``switch.huawei_vrp_access`` over REAL SNMP (UDP) against the
TEST-DEVICE switch simulator (access_s5735 profile) — never hardware
evidence. Pins the ACCESS-MON-01..05 mappings with exact values/units, the
PoE rules (percent only with the budget denominator, alarm only from the
device's own alarm state), the transceiver rx/tx-only uplink mapping, the
per-model mapping boundary (access never emits crc/drops/STP keys, core
never emits PoE) and the honest unknown-literal errors.
"""

from __future__ import annotations

import datetime

import pytest
from app.adapters.huawei.access import HuaweiVrpAccessAdapter
from app.adapters.huawei.base import AdapterError
from app.domain.adapter import CollectionRequest, Observation, ObservationError, Quality
from app.generated.capabilities import REQUIREMENTS
from tests.adapters.huawei.conftest import UTC

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

ADAPTER_KEY = "switch.huawei_vrp_access"
ACCESS_METRIC_KEYS = frozenset(
    {
        "system.cpu_percent",
        "system.memory_percent",
        "interface.admin_status",
        "interface.oper_status",
        "interface.in_bps",
        "interface.out_bps",
        "interface.errors",
        "transceiver.rx_dbm",
        "transceiver.tx_dbm",
        "psu.status",
        "fan.rpm",
        "fan.status",
        "temperature.system",
        "poe.port.status",
        "poe.port.power_w",
        "poe.total_power_w",
        "poe.power_budget_w",
        "poe.total_power_percent",
        "poe.total_power_alarm",
    }
)
ACCESS_OPERATION_KEYS = frozenset(
    {
        "device.restart",
        "interface.admin.set",
        "poe.port.set",
        "console.ssh.open",
        "console.web.open",
        "logs.collect",
        "config.backup",
        "config.restore",
        "firmware.update",
    }
)
STEP = 125_000


def _obs_by_key(batch: object, key: str, native: str | None = None) -> list[Observation]:
    return [
        obs
        for obs in batch.observations  # type: ignore[attr-defined]
        if obs.metric_key == key and (native is None or obs.component_native_id == native)
    ]


def _errors_for(batch: object, key: str) -> list[ObservationError]:
    return [
        err
        for err in batch.errors  # type: ignore[attr-defined]
        if err.key == key
    ]


def _collect_plain(h) -> object:
    adapter = HuaweiVrpAccessAdapter()
    session = h.session()
    return adapter.collect(session, h.request())


class TestProbeAndDiscover:
    def test_probe_accepts_the_access_model(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            result = HuaweiVrpAccessAdapter().probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok
            identity = next(stage for stage in result.stages if stage.stage == "identity")
            assert "S5735-L48P4S-A1" in (identity.detail_safe or "")
            assert result.identity_hint == {"vendor": "Huawei", "model": "S5735-L48P4S-A1"}

    def test_probe_refuses_core_model(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            result = HuaweiVrpAccessAdapter().probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok is False
            identity = next(stage for stage in result.stages if stage.stage == "identity")
            assert identity.ok is False and identity.error_code == "validation_failed"

    def test_discovery_covers_every_access_key(self, switch_agent) -> None:
        expected: set[str] = set()
        for requirement in REQUIREMENTS.values():
            if requirement.device_type != "access_switch":  # type: ignore[attr-defined]
                continue
            expected.update(requirement.metrics)  # type: ignore[attr-defined]
            expected.update(requirement.events)  # type: ignore[attr-defined]
            expected.update(op[0] for op in requirement.operations)  # type: ignore[attr-defined]
        with switch_agent(profile_key="access_s5735") as h:
            discovery = HuaweiVrpAccessAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
        assert discovery.model == "S5735-L48P4S-A1"
        assert discovery.firmware_version == "V200R019C10SPC600"
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert set(rows) == expected
        assert len(rows) == 28  # 19 metrics + 9 operations; access has no events
        for key in ACCESS_METRIC_KEYS:
            row = rows[key]
            assert row.support_state == "supported", (key, row.detail)
            assert row.discovery_method == ADAPTER_KEY and row.reason_code is None
        # Exact requirement attribution per type-unique key (one
        # representative per ACCESS-MON requirement).
        expected_requirement_id = {
            "system.cpu_percent": "ACCESS-MON-01",
            "interface.admin_status": "ACCESS-MON-02",
            "poe.port.status": "ACCESS-MON-03",
            "psu.status": "ACCESS-MON-04",
            "transceiver.rx_dbm": "ACCESS-MON-05",
        }
        for key, requirement_id in expected_requirement_id.items():
            assert rows[key].requirement_id == requirement_id, key
        # Wired CLI/SSH keys without a declared SSH endpoint are honest
        # not_configured; the M5T4 terminal key (console.ssh.open) likewise;
        # M5T5 console.web.open without a declared Web origin is
        # not_configured (web_console_unconfigured); still-unwired keys
        # stay unsupported.
        wired = HuaweiVrpAccessAdapter().ssh_operation_keys
        terminal = HuaweiVrpAccessAdapter().terminal_console_keys
        web_console = HuaweiVrpAccessAdapter().web_console_keys
        for key in ACCESS_OPERATION_KEYS:
            row = rows[key]
            if key in wired or key in terminal:
                assert row.support_state == "not_configured", (key, row.detail)
                assert row.reason_code == "ssh_unconfigured", (key, row.detail)
            elif key in web_console:
                assert row.support_state == "not_configured", (key, row.detail)
                assert row.reason_code == "web_console_unconfigured", (key, row.detail)
            else:
                assert row.support_state == "unsupported" and row.reason_code == "mapping_missing", key

    def test_discovery_inventory(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            discovery = HuaweiVrpAccessAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
        by_kind: dict[str, int] = {}
        for component in discovery.components:
            by_kind[component.kind] = by_kind.get(component.kind, 0) + 1
        assert by_kind["interface"] == 52
        assert by_kind["poe_port"] == 48  # PoE on the 48 GE downlinks
        assert by_kind["transceiver"] == 4  # 4 SFP uplinks
        assert by_kind["psu"] == 1 and by_kind["fan"] == 3 and by_kind["sensor"] == 1
        poe_ids = {c.native_id for c in discovery.components if c.kind == "poe_port"}
        assert "GigabitEthernet0/0/1" in poe_ids and "GigabitEthernet0/0/48" in poe_ids


class TestPoeMapping:
    def _collect(self, h):
        return _collect_plain(h)

    def test_poe_port_states_and_power_exact(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            batch = self._collect(h)
        states = {o.component_native_id: o.value for o in _obs_by_key(batch, "poe.port.status")}
        powers = {o.component_native_id: o.value for o in _obs_by_key(batch, "poe.port.power_w")}
        assert len(states) == 48 and len(powers) == 48
        assert states["GigabitEthernet0/0/1"] == "on"
        assert states["GigabitEthernet0/0/17"] == "denied"
        assert states["GigabitEthernet0/0/18"] == "fault"
        assert states["GigabitEthernet0/0/20"] == "off"
        assert powers["GigabitEthernet0/0/1"] == pytest.approx(5.0)
        assert powers["GigabitEthernet0/0/20"] == 0.0  # device-measured 0 W
        power_point = _obs_by_key(batch, "poe.port.power_w", native="GigabitEthernet0/0/1")[0]
        assert power_point.unit == "W"
        assert power_point.component_kind == "poe_port"

    def test_device_level_poe_values_and_percent(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            batch = self._collect(h)
        total = _obs_by_key(batch, "poe.total_power_w")
        budget = _obs_by_key(batch, "poe.power_budget_w")
        percent = _obs_by_key(batch, "poe.total_power_percent")
        alarm = _obs_by_key(batch, "poe.total_power_alarm")
        assert total[0].value == pytest.approx(80.0) and total[0].unit == "W"
        assert budget[0].value == pytest.approx(400.0) and budget[0].unit == "W"
        assert percent[0].value == pytest.approx(20.0) and percent[0].unit == "%"
        assert percent[0].quality is Quality.GOOD
        assert alarm[0].value == "normal"
        assert alarm[0].quality is Quality.GOOD

    def test_percent_requires_the_budget_denominator(self, switch_agent) -> None:
        """poe_no_budget knob: no denominator -> honest error, never a fake
        percent (ADR-016/025, DSM share rule mirror)."""
        with switch_agent(profile_key="access_s5735") as h:
            h.agent.set_poe_budget_present(False)
            batch = self._collect(h)
        assert _obs_by_key(batch, "poe.total_power_percent") == []
        errors = _errors_for(batch, "poe.total_power_percent")
        assert len(errors) == 1
        assert errors[0].error_code == "not_configured"
        assert "no_budget_denominator" in (errors[0].detail or "")
        assert _errors_for(batch, "poe.power_budget_w")  # budget value missing too
        # The other PoE values still flow (one family failure never hides the rest).
        assert _obs_by_key(batch, "poe.total_power_w")
        assert _obs_by_key(batch, "poe.total_power_alarm")

    def test_alarm_comes_only_from_device_state(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            h.agent.set_poe_alarm_state(2)
            batch = self._collect(h)
        alarm = _obs_by_key(batch, "poe.total_power_alarm")
        assert alarm[0].value == "warning" and alarm[0].quality is Quality.GOOD
        with switch_agent(profile_key="access_s5735") as h:
            h.agent.set_poe_alarm_state(3)
            batch = self._collect(h)
        assert _obs_by_key(batch, "poe.total_power_alarm")[0].value == "critical"

    def test_unknown_poe_literals_are_errors(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            h.agent.set_poe_port_state(1, 99)  # unmapped
            h.agent.set_poe_alarm_state(99)  # unmapped
            batch = self._collect(h)
        status_errors = _errors_for(batch, "poe.port.status")
        assert len(status_errors) == 1
        assert status_errors[0].component_native_id == "GigabitEthernet0/0/1"
        assert "无认证映射" in (status_errors[0].detail or "")
        alarm_errors = _errors_for(batch, "poe.total_power_alarm")
        assert len(alarm_errors) == 1
        # The port-state literal 5 (device "unknown") maps to the sentinel.
        with switch_agent(profile_key="access_s5735") as h:
            h.agent.set_poe_port_state(2, 5)
            batch = self._collect(h)
        unknown = _obs_by_key(batch, "poe.port.status", native="GigabitEthernet0/0/2")
        assert unknown[0].value == "unknown"
        assert unknown[0].quality is Quality.GOOD


class TestPerModelMappingBoundary:
    def test_access_never_emits_core_only_keys(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            adapter = HuaweiVrpAccessAdapter()
            session = h.session()
            base = datetime.datetime.now(UTC)
            adapter.collect(
                session,
                CollectionRequest(device_id=session.device_id, collection_type="metrics", now=base),
            )
            second = adapter.collect(
                session,
                CollectionRequest(
                    device_id=session.device_id,
                    collection_type="metrics",
                    now=base + datetime.timedelta(seconds=60),
                ),
            )
            batch = second
        keys = {obs.metric_key for obs in batch.observations}
        assert keys == ACCESS_METRIC_KEYS
        for banned in (
            "interface.crc_errors",
            "interface.drops",
            "loop.status",
            "broadcast_storm.status",
            "stp.port_state",
            "psu.present",
        ):
            assert banned not in keys

    def test_transceiver_uplink_rx_tx_only(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            batch = _collect_plain(h)
        rx = _obs_by_key(batch, "transceiver.rx_dbm", native="XGigabitEthernet0/0/1")
        tx = _obs_by_key(batch, "transceiver.tx_dbm", native="XGigabitEthernet0/0/1")
        assert rx[0].value == pytest.approx(-2.5) and rx[0].unit == "dBm"
        assert tx[0].value == pytest.approx(-1.8) and tx[0].unit == "dBm"
        keys = {obs.metric_key for obs in batch.observations}
        assert not (keys & {"transceiver.temperature_c", "transceiver.voltage_v", "transceiver.current_ma"})

    def test_rates_after_two_metrics_runs(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            adapter = HuaweiVrpAccessAdapter()
            session = h.session()
            base = datetime.datetime.now(UTC)
            first = adapter.collect(
                session, CollectionRequest(device_id=session.device_id, collection_type="metrics", now=base)
            )
            second = adapter.collect(
                session,
                CollectionRequest(
                    device_id=session.device_id,
                    collection_type="metrics",
                    now=base + datetime.timedelta(seconds=60),
                ),
            )
        assert not _obs_by_key(first, "interface.in_bps")
        expected = STEP * 8.0 / 60.0
        for point in _obs_by_key(second, "interface.in_bps"):
            assert point.value == pytest.approx(expected) and point.quality is Quality.GOOD
        assert _obs_by_key(second, "interface.out_bps")[0].unit == "bit/s"

    def test_reachability_and_unknown_type_boundary(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            adapter = HuaweiVrpAccessAdapter()
            session = h.session()
            batch = adapter.collect(
                session,
                CollectionRequest(
                    device_id=session.device_id,
                    collection_type="reachability",
                    now=datetime.datetime.now(UTC),
                ),
            )
            assert len(batch.observations) == 0 and len(batch.errors) == 0
            with pytest.raises(AdapterError):
                adapter.collect(
                    session,
                    CollectionRequest(device_id=session.device_id, collection_type="x", now=datetime.datetime.now(UTC)),
                )


class TestAccessHardware:
    def test_entity_mapping_values(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            batch = _collect_plain(h)
        # ACCESS-MON-04 has no psu.present key: the row must not appear even
        # though the entity exists (per-device mapping boundary).
        assert _obs_by_key(batch, "psu.status", native="PSU1")[0].value == "ok"
        assert not _obs_by_key(batch, "psu.present")
        assert _obs_by_key(batch, "fan.status", native="FAN1")[0].value == "ok"
        assert _obs_by_key(batch, "fan.rpm", native="FAN1")[0].value == 4800
        temp = _obs_by_key(batch, "temperature.system", native="SystemTemp")[0]
        assert temp.value == pytest.approx(36.5) and temp.unit == "Cel"

    def test_system_values(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            batch = _collect_plain(h)
        assert _obs_by_key(batch, "system.cpu_percent")[0].value == 5
        assert _obs_by_key(batch, "system.memory_percent")[0].value == 28
