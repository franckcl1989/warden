"""Core Huawei VRP adapter contract suite — probe/discover/collect (M5T2).

Drives ``switch.huawei_vrp_core`` over REAL SNMP (UDP) against the
TEST-DEVICE switch simulator — never hardware evidence
(tests/simulators/switch/README.md). Pins the CORE-MON-01..05 mappings
with exact values/units/enums, the rate-derivation semantics (cache miss =
ObservationError, rollover = partial, never negative), enum sentinel
semantics for unknown device literals, honest capability rows
(unsupported-with-reason for the M5T3 operation keys and for absent device
sources), absent-component handling (installed-but-absent PSU, ports
without optical modules) and the family error boundary.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.adapters.huawei.base import AdapterError, derive_rate_bps, parse_sys_descr
from app.adapters.huawei.core import CERTIFIED_CORE_MODELS, HuaweiVrpCoreAdapter
from app.domain.adapter import (
    CollectionRequest,
    Observation,
    ObservationError,
    Quality,
)
from app.generated.capabilities import REQUIREMENTS
from tests.adapters.huawei.conftest import UTC

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

ADAPTER_KEY = "switch.huawei_vrp_core"
CORE_METRIC_KEYS = frozenset(
    {
        "system.cpu_percent",
        "system.memory_percent",
        "interface.admin_status",
        "interface.oper_status",
        "interface.in_bps",
        "interface.out_bps",
        "interface.crc_errors",
        "interface.errors",
        "interface.drops",
        "transceiver.rx_dbm",
        "transceiver.tx_dbm",
        "transceiver.temperature_c",
        "transceiver.voltage_v",
        "transceiver.current_ma",
        "psu.present",
        "psu.status",
        "fan.rpm",
        "fan.status",
        "temperature.system",
        "loop.status",
        "broadcast_storm.status",
        "stp.port_state",
    }
)
CORE_EVENT_KEYS = frozenset({"event.port_flap", "event.device_restart", "event.auth_failure"})
CORE_OPERATION_KEYS = frozenset(
    {
        "device.restart",
        "interface.admin.set",
        "console.ssh.open",
        "console.telnet.open",
        "console.web.open",
        "logs.diagnostic.collect",
        "config.backup",
        "config.restore",
        "transceiver.diagnose",
        "firmware.update",
    }
)
STEP = 125_000  # per-pass octet counter advance (simulator AgentConfig)


def _port_names(count: int = 52) -> list[str]:
    names = [f"GigabitEthernet0/0/{index}" for index in range(1, 49)]
    names.extend(f"XGigabitEthernet0/0/{index}" for index in range(1, count - 48 + 1))
    return names


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


class TestProbe:
    def test_probe_accepts_certified_core_models(self, switch_agent) -> None:
        from app.adapters.huawei.core import MODEL_S5731S_S48P4X_A, MODEL_S5732_H48XUM2CC

        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            result = adapter.probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok
            stages = {stage.stage: stage for stage in result.stages}
            assert set(stages) == {"network", "auth", "identity", "capabilities"}
            assert stages["identity"].detail_safe is not None
            assert MODEL_S5732_H48XUM2CC in stages["identity"].detail_safe
            assert "V200R021C10SPC600" in stages["identity"].detail_safe
            assert result.identity_hint == {"vendor": "Huawei", "model": MODEL_S5732_H48XUM2CC}
        with switch_agent(profile_key="core_s5731s") as h:
            adapter = HuaweiVrpCoreAdapter()
            result = adapter.probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok
            assert result.identity_hint == {"vendor": "Huawei", "model": MODEL_S5731S_S48P4X_A}

    def test_probe_refuses_cross_model_device(self, switch_agent) -> None:
        """Core adapter on the access model -> identity failure (exact_model
        prevents cross-registration)."""
        with switch_agent(profile_key="access_s5735") as h:
            adapter = HuaweiVrpCoreAdapter()
            result = adapter.probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok is False
            identity = next(stage for stage in result.stages if stage.stage == "identity")
            assert identity.ok is False
            assert identity.error_code == "validation_failed"
            assert "S5732-H48XUM2CC" in (identity.detail_safe or "")  # expected models listed
            assert result.identity_hint is None

    def test_probe_access_adapter_refuses_core_model(self, switch_agent) -> None:
        from app.adapters.huawei.access import HuaweiVrpAccessAdapter

        with switch_agent(profile_key="core_s5732") as h:
            result = HuaweiVrpAccessAdapter().probe(h.profile(adapter_key="switch.huawei_vrp_access"))
            assert result.ok is False
            identity = next(stage for stage in result.stages if stage.stage == "identity")
            assert identity.ok is False and identity.error_code == "validation_failed"

    def test_probe_requires_a_vrp_version_marker(self, switch_agent) -> None:
        with switch_agent(
            profile_key="core_s5732",
            sys_descr_override="Huawei Technologies Co., Ltd. S5732-H48XUM2CC simulator, no VRP marker",
        ) as h:
            result = HuaweiVrpCoreAdapter().probe(h.profile(adapter_key=ADAPTER_KEY))
            assert result.ok is False
            identity = next(stage for stage in result.stages if stage.stage == "identity")
            assert identity.ok is False and identity.error_code == "validation_failed"
            assert "VRP" in (identity.detail_safe or "")

    def test_probe_v3_wrong_credentials_are_auth_failure(self, switch_agent) -> None:
        from dataclasses import replace

        with switch_agent(profile_key="core_s5732") as h:
            profile = h.profile(adapter_key=ADAPTER_KEY)
            wrong = dict(profile.credentials)
            snmp_section = dict(wrong["snmp"])  # type: ignore[arg-type]
            snmp_section["auth_key"] = "WRONG-KEY"
            wrong["snmp"] = snmp_section
            result = HuaweiVrpCoreAdapter().probe(replace(profile, credentials=wrong))
            assert result.ok is False
            stages = {stage.stage: stage for stage in result.stages}
            assert stages["network"].ok is True
            assert stages["auth"].ok is False
            assert stages["auth"].error_code == "authentication_failed"

    def test_probe_v2c_answers_with_weak_note(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732", v3_user=None) as h:
            result = HuaweiVrpCoreAdapter().probe(h.profile_v2c(adapter_key=ADAPTER_KEY))
            assert result.ok
            auth = next(stage for stage in result.stages if stage.stage == "auth")
            assert "v2c" in (auth.detail_safe or "")

    def test_parse_sys_descr_unit(self) -> None:
        model, version, failures = parse_sys_descr(
            (
                "Huawei Technologies Co., Ltd. S5732-H48XUM2CC simulator, "
                "VRP (R) software, Version V200R021C10SPC600 (S5732-H48XUM2CC)"
            ),
            CERTIFIED_CORE_MODELS,
        )
        assert model == "S5732-H48XUM2CC"
        assert version == "V200R021C10SPC600"
        assert failures == ()
        model, version, failures = parse_sys_descr("anything else", CERTIFIED_CORE_MODELS)
        assert model is None and version is None and len(failures) == 2


class TestDiscover:
    def test_discovery_rows_cover_every_core_key(self, switch_agent) -> None:
        expected_core_keys: set[str] = set()
        for requirement in REQUIREMENTS.values():
            if requirement.device_type != "core_switch":  # type: ignore[attr-defined]
                continue
            expected_core_keys.update(requirement.metrics)  # type: ignore[attr-defined]
            expected_core_keys.update(requirement.events)  # type: ignore[attr-defined]
            expected_core_keys.update(op[0] for op in requirement.operations)  # type: ignore[attr-defined]
        with switch_agent(profile_key="core_s5732") as h:
            discovery = HuaweiVrpCoreAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
            assert discovery.vendor == "Huawei"
            assert discovery.model == "S5732-H48XUM2CC"
            assert discovery.firmware_version == "V200R021C10SPC600"
            assert discovery.serial_number is None
            rows = {row.capability_key: row for row in discovery.capabilities}
            assert set(rows) == expected_core_keys
            assert len(rows) == 35  # 22 metrics + 3 events + 10 operations
            assert discovery.secrets_schema["required"] == ["snmp"]
            assert "ssh" in discovery.secrets_schema["properties"]  # type: ignore[operator]
            assert discovery.secrets_schema_version == 1

    def test_monitoring_rows_supported_and_operations_honest(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            discovery = HuaweiVrpCoreAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
            rows = {row.capability_key: row for row in discovery.capabilities}
            for key in CORE_METRIC_KEYS | CORE_EVENT_KEYS:
                row = rows[key]
                assert row.support_state == "supported", (key, row.detail)
                assert row.discovery_method == ADAPTER_KEY
                assert row.reason_code is None
                assert row.requirement_id.startswith("CORE-MON-")
            # Wired CLI/SSH keys without a declared SSH endpoint are honest
            # not_configured (ssh_unconfigured); M5T4 terminal console keys
            # without their config are not_configured too (ssh_unconfigured /
            # telnet_credential_missing); M5T5 console.web.open without a
            # declared Web origin is not_configured (web_console_unconfigured);
            # still-unwired keys (transceiver.diagnose) stay unsupported.
            wired = HuaweiVrpCoreAdapter().ssh_operation_keys
            terminal = HuaweiVrpCoreAdapter().terminal_console_keys
            web_console = HuaweiVrpCoreAdapter().web_console_keys
            for key in CORE_OPERATION_KEYS:
                row = rows[key]
                if key in wired:
                    assert row.support_state == "not_configured", (key, row.detail)
                    assert row.reason_code == "ssh_unconfigured", (key, row.detail)
                elif key in terminal:
                    assert row.support_state == "not_configured", (key, row.detail)
                    assert row.reason_code in (
                        "ssh_unconfigured",
                        "telnet_credential_missing",
                    ), (key, row.reason_code, row.detail)
                elif key in web_console:
                    assert row.support_state == "not_configured", (key, row.detail)
                    assert row.reason_code == "web_console_unconfigured", (
                        key,
                        row.reason_code,
                        row.detail,
                    )
                else:
                    assert row.support_state == "unsupported", (key, row.detail)
                    assert row.reason_code == "mapping_missing", (key, row.detail)
                assert row.discovery_method == ADAPTER_KEY

    def test_event_keys_not_configured_without_attributable_source(self, switch_agent) -> None:
        """Event keys are honest not_configured when the management endpoint
        cannot attribute syslog/trap sources (RISK R-14) — the pure decision
        against hostname endpoints + event_source_ips config (no agent)."""
        adapter = HuaweiVrpCoreAdapter()
        evidence: dict[str, object] = {
            "system": {"cpu": None, "memory": None},
            "interfaces": [],
            "entities": [],
            "optics": {},
        }
        for key in CORE_EVENT_KEYS:
            state, reason, _detail = adapter._capability_decision(  # noqa: SLF001
                "CORE-MON-06", key, "event", evidence, "switch.example.lan", {}
            )
            assert state == "not_configured", key
            assert reason == "event_source_unconfigured"
        # A declared event_source_ips entry makes the same rows supported
        # even for hostname endpoints (the ingest attribution contract).
        config: dict[str, object] = {"event_source_ips": ["10.0.0.1/32"]}
        for key in CORE_EVENT_KEYS:
            state, reason, _detail = adapter._capability_decision(  # noqa: SLF001
                "CORE-MON-06", key, "event", evidence, "switch.example.lan", config
            )
            assert state == "supported" and reason is None, key
        # With an IP-literal endpoint the rows are supported regardless.
        for key in CORE_EVENT_KEYS:
            state, reason, _detail = adapter._capability_decision(  # noqa: SLF001
                "CORE-MON-06", key, "event", evidence, "10.0.0.10", {}
            )
            assert state == "supported" and reason is None, key

    def test_discovery_inventory(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            discovery = HuaweiVrpCoreAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
        by_kind: dict[str, int] = {}
        for component in discovery.components:
            by_kind[component.kind] = by_kind.get(component.kind, 0) + 1
        assert by_kind["interface"] == 52
        assert by_kind["transceiver"] == 4  # 4 XGE uplink optics
        assert by_kind["psu"] == 2
        assert by_kind["fan"] == 4
        assert by_kind["sensor"] == 1
        ids = {component.native_id for component in discovery.components if component.kind == "interface"}
        assert "GigabitEthernet0/0/1" in ids and "XGigabitEthernet0/0/1" in ids

    def test_discover_rejects_cross_model(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            with pytest.raises(AdapterError) as raised:
                HuaweiVrpCoreAdapter().discover(h.profile(adapter_key=ADAPTER_KEY))
            assert raised.value.code == "validation_failed"


class TestCollectSystem:
    def test_system_cpu_memory_values_and_units(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            batch = adapter.collect(h.session(), h.request())
        cpu = _obs_by_key(batch, "system.cpu_percent")
        memory = _obs_by_key(batch, "system.memory_percent")
        assert len(cpu) == 1 and cpu[0].value == 12
        assert cpu[0].unit == "%" and cpu[0].quality is Quality.GOOD
        assert memory[0].value == 41 and memory[0].unit == "%"
        assert "[sim]" in (cpu[0].evidence or "")

    def test_system_variance_per_profile(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5731s") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "system.cpu_percent")[0].value == 8
        assert _obs_by_key(batch, "system.memory_percent")[0].value == 33


class TestCollectInterfaces:
    def _two_collects(self, h, adapter, seconds: int = 60):
        base = datetime.datetime.now(UTC)
        session = h.session()
        first = adapter.collect(
            session,
            CollectionRequest(device_id=session.device_id, collection_type="metrics", now=base),
        )
        second = adapter.collect(
            session,
            CollectionRequest(
                device_id=session.device_id,
                collection_type="metrics",
                now=base + datetime.timedelta(seconds=seconds),
            ),
        )
        return first, second

    def test_first_collect_has_no_bps_and_honest_errors(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            first, _second = self._two_collects(h, adapter)
        # Cache miss on the very first run: bps never fabricated.
        assert len(_errors_for(first, "interface.in_bps")) == 52
        assert len(_errors_for(first, "interface.out_bps")) == 52
        error = _errors_for(first, "interface.in_bps")[0]
        assert error.error_code == "not_configured"
        assert "rate_unavailable_first_sample" in (error.detail or "")
        assert not _obs_by_key(first, "interface.in_bps")

    def test_rates_appear_after_second_collect_exact(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            _first, second = self._two_collects(h, adapter)
        expected = STEP * 8.0 / 60.0
        for key in ("interface.in_bps", "interface.out_bps"):
            points = _obs_by_key(second, key)
            assert len(points) == 52
            for point in points:
                assert point.value == pytest.approx(expected)
                assert point.quality is Quality.GOOD
                assert point.unit == "bit/s"
                assert point.component_kind == "interface"
                assert "[rfc-2863]" in (point.evidence or "")
        values = {point.component_native_id for point in _obs_by_key(second, "interface.in_bps")}
        assert values == set(_port_names())

    def test_platform_restart_loses_one_interval_honestly(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            _first, second = self._two_collects(h, adapter)
            assert _obs_by_key(second, "interface.in_bps")
            # Simulated platform restart (process-local cache is empty again):
            # the next run must NOT fabricate rates from nothing.
            adapter.reset_rate_cache()
            third = adapter.collect(h.session(), h.request())
            assert not _obs_by_key(third, "interface.in_bps")
            assert len(_errors_for(third, "interface.in_bps")) == 52

    def test_counter_rollover_is_partial_never_negative(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732", hc_wrap_at=3 * STEP) as h:
            adapter = HuaweiVrpCoreAdapter()
            session = h.session()
            base = datetime.datetime.now(UTC)
            samples: list[object] = []
            for index in range(5):
                batch = adapter.collect(
                    session,
                    CollectionRequest(
                        device_id=session.device_id,
                        collection_type="metrics",
                        now=base + datetime.timedelta(seconds=60 * index),
                    ),
                )
                samples.append(batch)
            third, fourth, fifth = samples[2], samples[3], samples[4]
            # Pass 4 sample wrapped backwards vs pass 3 -> partial, never negative.
            rolled = _obs_by_key(fourth, "interface.in_bps")
            assert len(rolled) == 52
            assert all(point.quality is Quality.PARTIAL for point in rolled)
            assert all(point.value >= 0 for point in rolled)
            assert "counter_reset" in (rolled[0].evidence or "")
            # The following pass derives from the new baseline again: good.
            after = _obs_by_key(fifth, "interface.in_bps")
            assert all(point.quality is Quality.GOOD for point in after)
            assert len(_obs_by_key(third, "interface.in_bps")) == 52

    def test_counter_rollover_never_emits_a_negative_value_unit(self, switch_agent) -> None:
        """derive_rate_bps unit semantics: unsigned 64-bit wrap arithmetic."""
        delta, reset = derive_rate_bps(previous=2**64 - 500, current=1000)
        assert reset is True
        assert delta == 500 + 1000  # (2**64 - 500) wrapped: octets past the wrap
        assert delta > 0
        delta, reset = derive_rate_bps(previous=1000, current=2500)
        assert reset is False and delta == 1500

    def test_status_enums_and_counters_exact(self, switch_agent) -> None:
        with switch_agent(
            profile_key="core_s5732",
            counter_step_if_errors=2,
            counter_step_if_discards=3,
            counter_step_crc=4,
        ) as h:
            adapter = HuaweiVrpCoreAdapter()
            _first, second = self._two_collects(h, adapter)
        # Per pass every direction leaf advances its step once.
        errors = _obs_by_key(second, "interface.errors")
        drops = _obs_by_key(second, "interface.drops")
        crc = _obs_by_key(second, "interface.crc_errors")
        assert len(errors) == 52 and len(drops) == 52 and len(crc) == 52
        assert all(point.value == 8 for point in errors)  # (2+2) * 2 passes
        assert all(point.value == 12 for point in drops)  # (3+3) * 2 passes
        assert all(point.value == 8 for point in crc)  # 4 * 2 passes
        assert all(point.unit == "1" for point in errors)
        admin = _obs_by_key(second, "interface.admin_status")
        oper = _obs_by_key(second, "interface.oper_status")
        assert all(point.value == "up" for point in admin)
        assert all(point.value == "up" for point in oper)

    def test_admin_and_link_down_states_map(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            h.agent.set_admin_state(3, up=False)
            h.agent.set_link_state(4, up=False)
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "interface.admin_status", native="GigabitEthernet0/0/3")[0].value == "down"
        assert _obs_by_key(batch, "interface.oper_status", native="GigabitEthernet0/0/4")[0].value == "down"
        assert _obs_by_key(batch, "interface.admin_status", native="GigabitEthernet0/0/4")[0].value == "up"

    def test_components_carry_ifname_native_ids(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        interfaces = [component for component in batch.components if component.kind == "interface"]
        assert len(interfaces) == 52
        assert {component.native_id for component in interfaces} == set(_port_names())
        assert all(component.status == "unknown" for component in interfaces)


class TestCollectHardwareAndTransceivers:
    def test_entity_mapping_values(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "psu.present", native="PSU1")[0].value == "present"
        assert _obs_by_key(batch, "psu.status", native="PSU1")[0].value == "ok"
        assert _obs_by_key(batch, "fan.status", native="FAN1")[0].value == "ok"
        assert _obs_by_key(batch, "fan.rpm", native="FAN1")[0].value == 6200
        assert _obs_by_key(batch, "fan.rpm", native="FAN1")[0].unit == "r/min"
        temp = _obs_by_key(batch, "temperature.system", native="SystemTemp")
        assert temp[0].value == pytest.approx(34.2)
        assert temp[0].unit == "Cel"
        statuses = {c.native_id: c.status for c in batch.components if c.kind == "fan"}
        assert statuses["FAN1"] == "ok"

    def test_absent_psu_slot_is_honest(self, switch_agent) -> None:
        """core_s5731s profile: PSU2 slot installed-but-absent."""
        with switch_agent(profile_key="core_s5731s") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "psu.present", native="PSU2")[0].value == "absent"
        assert _obs_by_key(batch, "psu.status", native="PSU2")[0].value == "absent"
        psu_component = next(c for c in batch.components if c.kind == "psu" and c.native_id == "PSU2")
        assert psu_component.status == "absent"
        # PSU1 still present/normal.
        assert _obs_by_key(batch, "psu.status", native="PSU1")[0].value == "ok"

    def test_fan_fault_knob_reports_critical(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            h.agent.set_fan_fault(3, fault=True)  # FAN1 (slot 3 on core_s5732)
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "fan.status", native="FAN1")[0].value == "critical"
        fan_component = next(c for c in batch.components if c.kind == "fan" and c.native_id == "FAN1")
        assert fan_component.status == "critical"
        # The rpm measurement is still reported (device measures it).
        assert _obs_by_key(batch, "fan.rpm", native="FAN1")

    def test_optics_values_and_units(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "transceiver.rx_dbm", native="XGigabitEthernet0/0/1")[0].value == pytest.approx(-2.5)
        assert _obs_by_key(batch, "transceiver.tx_dbm", native="XGigabitEthernet0/0/1")[0].value == pytest.approx(-1.8)
        temp_point = _obs_by_key(batch, "transceiver.temperature_c", native="XGigabitEthernet0/0/1")[0]
        assert temp_point.value == pytest.approx(35.0)
        volt_point = _obs_by_key(batch, "transceiver.voltage_v", native="XGigabitEthernet0/0/1")[0]
        assert volt_point.value == pytest.approx(3.3)
        current_point = _obs_by_key(batch, "transceiver.current_ma", native="XGigabitEthernet0/0/1")[0]
        assert current_point.value == pytest.approx(7.2)
        for key, unit in (
            ("transceiver.rx_dbm", "dBm"),
            ("transceiver.temperature_c", "Cel"),
            ("transceiver.voltage_v", "V"),
            ("transceiver.current_ma", "mA"),
        ):
            assert _obs_by_key(batch, key)[0].unit == unit
        assert _obs_by_key(batch, "transceiver.rx_dbm", native="GigabitEthernet0/0/1") == []
        # No module on the GE ports: no component either.
        ge_transceivers = [c for c in batch.components if c.kind == "transceiver" and c.native_id.startswith("Gigabit")]
        assert ge_transceivers == []

    def test_transceiver_removal_drops_component_and_points(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            h.agent.set_transceiver_present(49, present=False)
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "transceiver.rx_dbm", native="XGigabitEthernet0/0/1") == []
        transceivers = [c for c in batch.components if c.kind == "transceiver"]
        assert {c.native_id for c in transceivers} == {
            f"XGigabitEthernet0/0/{index}" for index in range(2, 5)
        }
        # No fabricated 0 for the missing module.
        assert not any(obs.value == 0 for obs in _obs_by_key(batch, "transceiver.rx_dbm"))


class TestCollectLayer2:
    def test_default_layer2_states(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "loop.status")[0].value == "normal"
        assert _obs_by_key(batch, "broadcast_storm.status")[0].value == "normal"
        stp = _obs_by_key(batch, "stp.port_state")
        assert len(stp) == 52
        assert all(point.value == "forwarding" for point in stp)
        assert all(point.component_kind == "interface" for point in stp)

    def test_detection_knobs_and_stp_variants(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            h.agent.set_loop_detected(True)
            h.agent.set_storm_detected(True)
            h.agent.set_stp_state(1, 1)  # disabled
            h.agent.set_stp_state(2, 2)  # discarding
            h.agent.set_stp_state(3, 3)  # learning
            h.agent.set_stp_state(4, 5)  # broken
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        assert _obs_by_key(batch, "loop.status")[0].value == "detected"
        assert _obs_by_key(batch, "broadcast_storm.status")[0].value == "detected"
        states = {point.component_native_id: point.value for point in _obs_by_key(batch, "stp.port_state")}
        assert states["GigabitEthernet0/0/1"] == "disabled"
        assert states["GigabitEthernet0/0/2"] == "discarding"
        assert states["GigabitEthernet0/0/3"] == "learning"
        assert states["GigabitEthernet0/0/4"] == "broken"

    def test_unknown_literal_is_an_observation_error(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            h.agent.set_stp_state(1, 99)  # unmapped literal
            batch = HuaweiVrpCoreAdapter().collect(h.session(), h.request())
        errors = _errors_for(batch, "stp.port_state")
        assert len(errors) == 1
        assert errors[0].component_native_id == "GigabitEthernet0/0/1"
        assert "无认证映射" in (errors[0].detail or "")


class TestCollectBoundary:
    def test_reachability_run_reads_no_counter_and_succeeds(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            session = h.session()
            base = datetime.datetime.now(UTC)
            reach = adapter.collect(
                session, CollectionRequest(device_id=session.device_id, collection_type="reachability", now=base)
            )
            assert len(reach.observations) == 0 and len(reach.errors) == 0
            # The health/reachability pass must NOT advance the counters: the
            # rate window still spans exactly one counter advance per metrics
            # run (first at base, second at base+90s -> step*8/90).
            first = adapter.collect(
                session, CollectionRequest(device_id=session.device_id, collection_type="metrics", now=base)
            )
            adapter.collect(
                session,
                CollectionRequest(
                    device_id=session.device_id,
                    collection_type="reachability",
                    now=base + datetime.timedelta(seconds=45),
                ),
            )
            second = adapter.collect(
                session,
                CollectionRequest(
                    device_id=session.device_id,
                    collection_type="metrics",
                    now=base + datetime.timedelta(seconds=90),
                ),
            )
            expected = STEP * 8.0 / 90.0
            assert all(p.value == pytest.approx(expected) for p in _obs_by_key(second, "interface.in_bps"))
            del first

    def test_logs_and_discovery_runs_return_empty(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            session = h.session()
            for collection_type in ("logs", "discovery"):
                batch = adapter.collect(
                    session,
                    CollectionRequest(
                        device_id=session.device_id,
                        collection_type=collection_type,
                        now=datetime.datetime.now(UTC),
                    ),
                )
                assert len(batch.observations) == 0 and len(batch.errors) == 0

    def test_unknown_collection_type_is_rejected(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            adapter = HuaweiVrpCoreAdapter()
            with pytest.raises(AdapterError) as raised:
                adapter.collect(
                    h.session(),
                    CollectionRequest(
                        device_id=uuid.uuid4(),
                        collection_type="nonsense",
                        now=datetime.datetime.now(UTC),
                    ),
                )
            assert raised.value.code == "protocol_error"

    def test_offline_agent_fails_the_run_with_network_code(self, switch_agent) -> None:
        """A v2c wrong community is indistinguishable from silence at the
        wire level (v2c authenticates nothing): the agent never answers and
        the run fails with network_unreachable after bounded retries."""
        from app.domain.adapter import DeviceSession

        with switch_agent(profile_key="core_s5732", v3_user=None) as h:
            adapter = HuaweiVrpCoreAdapter()
            session = DeviceSession(
                device_id=uuid.uuid4(),
                management_endpoint="127.0.0.1",
                connection_config={"snmp_version": "v2c", "port": h.port},
                credentials={"snmp": {"community": "WRONG-COMMUNITY"}},
            )
            with pytest.raises(AdapterError) as raised:
                adapter.collect(
                    session,
                    CollectionRequest(
                        device_id=session.device_id,
                        collection_type="metrics",
                        now=datetime.datetime.now(UTC),
                    ),
                )
            assert raised.value.code == "network_unreachable"

    def test_operation_methods_without_ssh_config_are_honest_not_configured(self) -> None:
        """M5T3: the wired operation methods refuse without an SSH endpoint
        config / pinned fingerprint (not_configured — automation never
        first-connects); M5T4: terminal launch tickets refuse the same way
        (console.ssh.open needs the pinned fingerprint; console.telnet.open
        needs the device opt-in + credentials — honest not_configured, never
        a fabricated ticket)."""
        from app.adapters.huawei.core import HuaweiVrpCoreAdapter as Adapter
        from app.domain.adapter import DeviceSession

        adapter = Adapter()
        bare_session = DeviceSession(
            device_id=uuid.uuid4(),
            management_endpoint="127.0.0.1",
            connection_config={},
            credentials={},
        )
        session = DeviceSession(
            device_id=uuid.uuid4(),
            management_endpoint="127.0.0.1",
            connection_config={"ssh_port": 22},
            credentials={"ssh": {"username": "u", "password": "p"}},
        )
        plan = object()  # type: ignore[assignment]
        # No SSH endpoint/credentials at all.
        with pytest.raises(AdapterError) as raised:
            adapter.preflight_operation(bare_session, plan)  # type: ignore[arg-type]
        assert raised.value.code == "not_configured"
        assert "SSH" in raised.value.message
        # SSH declared but the host-key fingerprint is not pinned.
        with pytest.raises(AdapterError) as raised:
            adapter.preflight_operation(session, plan)  # type: ignore[arg-type]
        assert raised.value.code == "not_configured"
        assert "指纹" in raised.value.message or "首次信任" in raised.value.message
        # console.ssh.open (M5T4 terminal): port + credentials are present
        # but the fingerprint is unpinned -> honest not_configured.
        with pytest.raises(AdapterError) as raised:
            adapter.create_launch(session, "console.ssh.open")
        assert raised.value.code == "not_configured"
        assert "首次信任" in raised.value.message or "指纹" in raised.value.message
        # console.telnet.open: no telnet credentials -> not_configured.
        with pytest.raises(AdapterError) as raised:
            adapter.create_launch(session, "console.telnet.open")
        assert raised.value.code == "not_configured"
        # console.web.open (M5T5 URL descriptor): without a declared Web
        # origin (web_scheme + web_port) -> honest not_configured, never a
        # guessed homepage URL.
        with pytest.raises(AdapterError) as raised:
            adapter.create_launch(session, "console.web.open")
        assert raised.value.code == "not_configured"
        assert "web_scheme" in raised.value.message or "web_port" in raised.value.message
        # Unknown launch capabilities stay unsupported_capability.
        with pytest.raises(AdapterError) as raised:
            adapter.create_launch(bare_session, "console.kvm.open")
        assert raised.value.code == "unsupported_capability"

    def test_create_launch_web_console_descriptor_from_declared_origin(self) -> None:
        """M5T5 console.web.open: the descriptor URL is built ONLY from the
        operator-declared origin (web_scheme + web_port) — never guessed,
        never carrying credentials (ADR-006); scheme-default ports are
        omitted from the URL (standard URL formatting)."""
        from app.adapters.huawei.core import HuaweiVrpCoreAdapter as Adapter
        from app.domain.adapter import DeviceSession

        adapter = Adapter()
        base_session = DeviceSession(
            device_id=uuid.uuid4(),
            management_endpoint="10.0.0.10",
            connection_config={"web_scheme": "https", "web_port": 443},
            credentials={},
        )
        descriptor = adapter.create_launch(base_session, "console.web.open")
        assert descriptor.kind == "url"
        assert descriptor.url == "https://10.0.0.10"
        assert "HTTPS" in (descriptor.display_hint or "")
        # An explicit non-default port stays visible.
        session = DeviceSession(
            device_id=uuid.uuid4(),
            management_endpoint="10.0.0.10",
            connection_config={"web_scheme": "https", "web_port": 8443},
            credentials={"ssh": {"username": "u", "password": "SECRET"}},
        )
        descriptor = adapter.create_launch(session, "console.web.open")
        assert descriptor.url == "https://10.0.0.10:8443"
        # Credentials never enter the descriptor URL.
        assert "SECRET" not in descriptor.url
        # HTTP origin stays allowed with an explicit plaintext warning.
        http_session = DeviceSession(
            device_id=uuid.uuid4(),
            management_endpoint="10.0.0.10",
            connection_config={"web_scheme": "http", "web_port": 80},
            credentials={},
        )
        descriptor = adapter.create_launch(http_session, "console.web.open")
        assert descriptor.url == "http://10.0.0.10"
        assert "HTTP" in (descriptor.display_hint or "")
        assert "明文" in (descriptor.display_hint or "")

    def test_discovery_web_console_rows_flip_supported_with_declared_origin(self, switch_agent) -> None:
        """console.web.open rows: supported when the probe profile declares
        the web origin; not_configured (web_console_unconfigured) otherwise
        — the SNMP path never claims the browser-side web surface."""
        with switch_agent(profile_key="core_s5732") as h:
            from dataclasses import replace

            profile = h.profile(adapter_key=ADAPTER_KEY)
            profile = replace(
                profile,
                connection_config={
                    **dict(profile.connection_config),
                    "web_scheme": "https",
                    "web_port": 8443,
                },
            )
            discovery = HuaweiVrpCoreAdapter().discover(profile)
            rows = {row.capability_key: row for row in discovery.capabilities}
            row = rows["console.web.open"]
            assert row.support_state == "supported", row.detail
            assert row.reason_code is None
            assert "ADR-006" in (row.detail or "")
