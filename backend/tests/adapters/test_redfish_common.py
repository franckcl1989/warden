"""Common Redfish adapter contract suite (M3T2, docs/DEVICE_ADAPTERS.md 搂4.1).

The suite drives the registered ``server.redfish`` adapter against the
TEST-DEVICE simulator (booted per session in conftest.py; profiles/knobs
switched per test through its control endpoint). Assertions are mapping
tests: metric keys/units/enum values come ONLY from contracts/metrics.json +
events.json, status tables are one-directional, missing values are explicit
ObservationErrors 鈥?never 0/normal/passed (ADR-014). No thresholds are
invented (ADR-025): numbers are device-reported display values.
"""

from __future__ import annotations

import datetime
import uuid
from ipaddress import ip_address

import pytest
from app.adapters.redfish.common import RedfishCommonAdapter
from app.domain.adapter import (
    SUPPORT_STATES,
    AdapterError,
    CollectionRequest,
    ConnectionProfile,
    DeviceSession,
    Observation,
    ObservationBatch,
    ObservationError,
    Quality,
)
from app.generated.capabilities import REQUIREMENTS

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME, SimAccess

ADAPTER = RedfishCommonAdapter()
T0 = datetime.datetime(2026, 9, 3, 12, 0, 0, tzinfo=datetime.UTC)
SEL_EPOCH = datetime.datetime(2026, 9, 1, 0, 0, 0, tzinfo=datetime.UTC)
SERVER_KEYS = 31  # unique capability keys across the 15 server requirements

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]


# -- helpers ------------------------------------------------------------------


def sim_profile(sim: SimAccess, **config: object) -> ConnectionProfile:
    merged: dict[str, object] = {"protocol": "http", "port": sim.port}
    merged.update(config)
    return ConnectionProfile(
        adapter_key=ADAPTER.adapter_key,
        management_endpoint=SIM_HOST,
        port=sim.port,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
        verify_tls=True,
        tls_fingerprint_sha256=None,
        device_id=None,
        resolved_ip=ip_address(SIM_HOST),
    )


def sim_session(sim: SimAccess, **config: object) -> DeviceSession:
    merged: dict[str, object] = {"protocol": "http", "port": sim.port}
    merged.update(config)
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
    )


def collect_request(
    collection_type: str = "metrics",
    *,
    last_run_at: datetime.datetime | None = None,
    now: datetime.datetime = T0,
) -> CollectionRequest:
    return CollectionRequest(
        device_id=uuid.uuid4(),
        collection_type=collection_type,
        now=now,
        last_run_at=last_run_at,
    )


def obs_key(observation: Observation) -> tuple[str, str | None, str | None]:
    return (observation.metric_key, observation.component_kind, observation.component_native_id)


def obs_map(batch: ObservationBatch) -> dict[tuple[str, str | None, str | None], Observation]:
    return {obs_key(observation): observation for observation in batch.observations}


def err_map(batch: ObservationBatch) -> dict[tuple[str, str | None, str | None], ObservationError]:
    return {
        (error.key or "", error.component_kind, error.component_native_id): error for error in batch.errors
    }


def run_collect(sim: SimAccess, collection_type: str = "metrics") -> ObservationBatch:
    return ADAPTER.collect(sim_session(sim), collect_request(collection_type))


def assert_no_quality_rows(batch: ObservationBatch, key: str, bad_values: set[object]) -> None:
    for observation in batch.observations:
        if observation.metric_key == key:
            assert observation.value not in bad_values, f"{key} 涓嶅緱鍐欏叆浼€犲€?{observation.value}"


def server_keys() -> set[str]:
    keys: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != "server":
            continue
        keys.update(requirement.metrics)
        keys.update(requirement.events)
        keys.update(op[0] for op in requirement.operations)
    return keys


# -- probe --------------------------------------------------------------------


class TestProbe:
    def test_healthy_profile_all_stages_ok(self, sim: SimAccess) -> None:
        result = ADAPTER.probe(sim_profile(sim))
        assert result.ok
        assert [stage.stage for stage in result.stages] == [
            "network",
            "tls",
            "auth",
            "identity",
            "capabilities",
        ]
        assert all(stage.ok for stage in result.stages)
        assert result.identity_hint == {
            "manufacturer": "Warden Simulator",
            "model": "Warden SimServer 1U (simulated)",
        }

    def test_auth_fail_profile_marks_only_auth_stage(self, sim: SimAccess) -> None:
        sim.set(profile="auth_fail")
        result = ADAPTER.probe(sim_profile(sim))
        assert not result.ok
        by_stage = {stage.stage: stage for stage in result.stages}
        assert by_stage["network"].ok is True
        assert by_stage["tls"].ok is True
        assert by_stage["auth"].ok is False
        assert by_stage["auth"].error_code == "authentication_failed"
        # Stages after auth were NOT executed (never fabricated as ok).
        assert by_stage["identity"].ok is False
        assert by_stage["identity"].error_code is None
        assert by_stage["capabilities"].ok is False
        assert by_stage["capabilities"].error_code is None

    def test_pinned_fingerprint_tls_stage_not_configured(self, sim: SimAccess) -> None:
        result = ADAPTER.probe(
            sim_profile(sim, protocol="https", tls_fingerprint_sha256="a" * 64)
        )
        assert not result.ok
        by_stage = {stage.stage: stage for stage in result.stages}
        assert by_stage["network"].ok is True
        assert by_stage["tls"].ok is False
        assert by_stage["tls"].error_code == "not_configured"

    def test_network_unreachable_stage_fails_distinctly(self, sim: SimAccess) -> None:
        profile = sim_profile(sim)
        profile = ConnectionProfile(
            adapter_key=profile.adapter_key,
            management_endpoint="127.0.0.1",
            port=1,
            connection_config={"protocol": "http", "port": 1},
            credentials=profile.credentials,
            verify_tls=True,
            tls_fingerprint_sha256=None,
            device_id=None,
            resolved_ip=ip_address("127.0.0.1"),
        )
        result = ADAPTER.probe(profile)
        assert not result.ok
        by_stage = {stage.stage: stage for stage in result.stages}
        assert by_stage["network"].ok is False
        assert by_stage["network"].error_code == "network_unreachable"
        assert by_stage["tls"].ok is False
        assert by_stage["tls"].error_code is None


# -- discovery ----------------------------------------------------------------


class TestDiscover:
    def test_healthy_identity_and_full_inventory(self, sim: SimAccess) -> None:
        discovery = ADAPTER.discover(sim_profile(sim))
        assert discovery.vendor == "Warden Simulator"
        assert discovery.model == "Warden SimServer 1U (simulated)"
        assert discovery.serial_number == "WARDEN-SIM-0001"
        assert discovery.firmware_version == "SIM-BMC-1.0.0"
        assert discovery.secrets_schema == ADAPTER.secret_schema
        assert discovery.secrets_schema_version == ADAPTER.secret_schema_version
        kinds = {(c.kind, c.native_id) for c in discovery.components}
        assert {
            ("processor", "cpu-1"),
            ("processor", "cpu-2"),
            ("memory", "DIMM0"),
            ("memory", "DIMM4"),
            ("drive", "sda"),
            ("drive", "sdb"),
            ("raid", "RAID6_1"),
            ("psu", "PSU1"),
            ("psu", "PSU2"),
            ("fan", "FAN1"),
            ("fan", "FAN4"),
            ("sensor", "temp-0"),
            ("sensor", "temp-4"),
        } <= kinds
        by_key = {(c.kind, c.native_id): c for c in discovery.components}
        assert by_key[("memory", "DIMM4")].status == "absent"  # empty slot
        assert by_key[("memory", "DIMM0")].status == "ok"
        assert by_key[("memory", "DIMM0")].properties["capacity_mib"] == 16384
        assert by_key[("drive", "sda")].properties["media_type"] == "SSD"
        # properties stay minimal: no serials duplicated from asset data
        assert "serial_number" not in by_key[("drive", "sda")].properties

    def test_healthy_capability_rows_cover_all_server_keys_supported(
        self, sim: SimAccess
    ) -> None:
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert set(rows) == server_keys()
        assert len(rows) == SERVER_KEYS
        for key, row in rows.items():
            assert row.support_state in SUPPORT_STATES
            assert row.support_state == "supported", f"{key} 鍦ㄥ仴搴烽潰搴斿彈鏀寔"
            assert row.discovery_method == ADAPTER.adapter_key
            requirement = REQUIREMENTS[row.requirement_id]
            assert requirement.device_type == "server"
            declared = set(requirement.metrics) | set(requirement.events)
            declared.update(op[0] for op in requirement.operations)
            assert key in declared
        # Shared key: the first server requirement in the registry wins.
        assert rows["indicator.led"].requirement_id == "SRV-MON-01"

    def test_no_virtual_media_profile_unsupported_with_reason(self, sim: SimAccess) -> None:
        sim.set(no_virtual_media=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        for key in ("virtual_media.mount", "virtual_media.unmount"):
            assert rows[key].support_state == "unsupported"
            assert rows[key].reason_code == "no_virtual_media_service"
        assert rows["event.sel"].support_state == "supported"
        assert rows["firmware.update"].support_state == "supported"

    def test_missing_storage_partially_unsupported_with_reason(self, sim: SimAccess) -> None:
        sim.set(no_storage=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        expected_reasons = {
            "drive.status": "no_storage_drives",
            "drive.smart": "no_drive_smart_member",
            "drive.predictive_failure": "no_drive_predictive_member",
            "raid.status": "no_raid_volume",
        }
        for key, reason in expected_reasons.items():
            assert rows[key].support_state == "unsupported", key
            assert rows[key].reason_code == reason, key
            assert rows[key].detail
        # The rest of SRV-MON-04's neighbours stay supported.
        assert rows["memory.status"].support_state == "supported"

    def test_no_raid_volume_marks_only_raid_unsupported(self, sim: SimAccess) -> None:
        sim.set(no_raid_volume=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["raid.status"].support_state == "unsupported"
        assert rows["raid.status"].reason_code == "no_raid_volume"
        for key in ("drive.status", "drive.smart", "drive.predictive_failure"):
            assert rows[key].support_state == "supported", key

    def test_missing_memory_metrics_marks_ecc_unsupported(self, sim: SimAccess) -> None:
        sim.set(missing_memory_metrics=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["memory.ecc_errors"].support_state == "unsupported"
        assert rows["memory.ecc_errors"].reason_code == "no_ecc_counter_member"
        assert rows["memory.status"].support_state == "supported"

    def test_missing_system_status_marks_health_unsupported(self, sim: SimAccess) -> None:
        sim.set(missing_system_status=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["health.overall"].support_state == "unsupported"
        assert rows["health.overall"].reason_code == "no_system_status"
        assert rows["indicator.led"].support_state == "supported"  # chassis LED remains

    def test_drives_without_oem_marks_smart_unsupported(self, sim: SimAccess) -> None:
        sim.set(drives_without_oem=True)
        discovery = ADAPTER.discover(sim_profile(sim))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["drive.smart"].support_state == "unsupported"
        assert rows["drive.predictive_failure"].support_state == "unsupported"
        assert rows["drive.status"].support_state == "supported"


# -- collect: health ----------------------------------------------------------


class TestCollectHealth:
    def test_healthy_health_subset(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "health")
        points = obs_map(batch)
        assert points[("health.overall", None, None)].value == "healthy"
        assert points[("indicator.led", None, None)].value == "normal"
        assert points[("chassis.intrusion", None, None)].value == "normal"
        assert all(observation.quality is Quality.GOOD for observation in batch.observations)
        assert not batch.errors

    def test_critical_health_subset(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "health")
        points = obs_map(batch)
        assert points[("health.overall", None, None)].value == "critical"
        assert points[("indicator.led", None, None)].value == "critical"
        assert points[("chassis.intrusion", None, None)].value == "detected"
        assert_no_quality_rows(batch, "health.overall", {"healthy"})
        assert_no_quality_rows(batch, "indicator.led", {"normal"})

    def test_missing_system_status_is_error_not_healthy(self, sim: SimAccess) -> None:
        sim.set(missing_system_status=True)
        batch = run_collect(sim, "health")
        errors = err_map(batch)
        assert ("health.overall", None, None) in errors
        assert not any(observation.metric_key == "health.overall" for observation in batch.observations)
        assert_no_quality_rows(batch, "health.overall", {"healthy", "unknown"})
        # indicator.led still comes from the chassis panel.
        assert obs_map(batch)[("indicator.led", None, None)].value == "normal"


# -- collect: thermal (SRV-MON-02/06) ----------------------------------------


class TestCollectThermal:
    def test_healthy_temperature_classification_and_units(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("temperature.cpu", "processor", "cpu-1")].value == 42
        assert points[("temperature.cpu", "processor", "cpu-2")].value == 41
        assert points[("temperature.memory", "sensor", "temp-2")].value == 38
        assert points[("temperature.board", "sensor", "temp-3")].value == 35
        assert points[("temperature.inlet", "sensor", "temp-4")].value == 24
        assert points[("temperature.cpu", "processor", "cpu-1")].unit == "Cel"
        # CPU temperatures attach to per-processor components (per index).
        assert len([o for o in batch.observations if o.metric_key == "temperature.cpu"]) == 2

    def test_critical_cpu_temperature_is_display_only(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        # 93 C exceeds the device threshold 鈥?but the reading is display-only:
        # the STATUS comes from the device Status block, never invented from
        # the value (ADR-025). The critical sensor still maps its own Status.
        assert points[("temperature.cpu", "processor", "cpu-1")].value == 93

    def test_unknown_physical_context_is_observation_error(self, sim: SimAccess) -> None:
        sim.set(thermal_missing_context=True)
        batch = run_collect(sim, "metrics")
        errors = batch.errors
        assert any("Misc Zone Temp" in (error.detail or "") for error in errors)
        # The unclassifiable sensor reports no temperature point and no fake
        # metric-key attribution (key stays None).
        assert any(error.key is None and "Misc Zone Temp" in (error.detail or "") for error in errors)
        assert not any(observation.value == 33 for observation in batch.observations)
        assert not any(
            o.metric_key == "temperature.cpu" and o.component_native_id == "temp-5"
            for o in batch.observations
        )

    def test_healthy_fans_rpm_and_status(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("fan.rpm", "fan", "FAN1")].value == 7500
        assert points[("fan.rpm", "fan", "FAN1")].unit == "r/min"
        assert points[("fan.rpm", "fan", "FAN4")].value == 9000
        assert points[("fan.status", "fan", "FAN1")].value == "ok"
        assert points[("fan.status", "fan", "FAN4")].value == "ok"

    def test_critical_fan_low_rpm_uses_device_status_only(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("fan.rpm", "fan", "FAN3")].value == 800  # below device lower-critical
        assert points[("fan.status", "fan", "FAN3")].value == "critical"

    def test_missing_fan_reading_is_observation_error(self, sim: SimAccess) -> None:
        sim.set(missing_fan_reading=True)
        batch = run_collect(sim, "metrics")
        errors = err_map(batch)
        assert ("fan.rpm", "fan", "FAN1") in errors
        assert_no_quality_rows(batch, "fan.rpm", {0})
        # fan.status is independent of the rpm reading and still observed.
        assert obs_map(batch)[("fan.status", "fan", "FAN1")].value == "ok"


# -- collect: power/storage/memory (SRV-MON-03/04/05) -------------------------


class TestCollectPowerStorageMemory:
    def test_healthy_power_psu_readings(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        for native, load, voltage in (("PSU1", 260, 12.2), ("PSU2", 280, 12.3)):
            assert points[("psu.present", "psu", native)].value == "present"
            assert points[("psu.status", "psu", native)].value == "ok"
            assert points[("psu.load_w", "psu", native)].value == load
            assert points[("psu.load_w", "psu", native)].unit == "W"
            assert points[("psu.voltage_v", "psu", native)].value == pytest.approx(voltage)
            assert points[("psu.voltage_v", "psu", native)].unit == "V"

    def test_critical_absent_psu_has_no_fabricated_readings(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("psu.present", "psu", "PSU2")].value == "absent"
        assert points[("psu.status", "psu", "PSU2")].value == "absent"
        # No readings for the absent unit 鈥?and no zeros for PSU1 either.
        assert not any(
            o.metric_key in ("psu.load_w", "psu.voltage_v") and o.component_native_id == "PSU2"
            for o in batch.observations
        )
        assert points[("psu.load_w", "psu", "PSU1")].value == 260

    def test_healthy_memory_status_and_ecc(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        for index, ecc in enumerate((3, 4, 5, 6)):
            native = f"DIMM{index}"
            assert points[("memory.status", "memory", native)].value == "ok"
            assert points[("memory.ecc_errors", "memory", native)].value == ecc
            assert points[("memory.ecc_errors", "memory", native)].unit == "1"
        # The empty slot (DIMM4) is an absent component: NO memory points and
        # no errors for it.
        assert not any(o.component_native_id == "DIMM4" for o in batch.observations)
        assert not any(o.component_native_id == "DIMM4" for o in batch.errors)

    def test_critical_dimm_failure_state(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("memory.status", "memory", "DIMM1")].value == "critical"
        assert points[("memory.ecc_errors", "memory", "DIMM1")].value == 11

    def test_missing_ecc_counter_is_error_never_zero(self, sim: SimAccess) -> None:
        sim.set(missing_memory_metrics=True)
        batch = run_collect(sim, "metrics")
        errors = err_map(batch)
        for index in range(4):
            assert ("memory.ecc_errors", "memory", f"DIMM{index}") in errors
        assert not any(o.metric_key == "memory.ecc_errors" for o in batch.observations)
        assert_no_quality_rows(batch, "memory.ecc_errors", {0})

    def test_healthy_storage_drives(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        for native in ("sda", "sdb"):
            assert points[("drive.status", "drive", native)].value == "ok"
            assert points[("drive.smart", "drive", native)].value == "passed"
            assert points[("drive.predictive_failure", "drive", native)].value is False
        assert points[("raid.status", "raid", "RAID6_1")].value == "optimal"

    def test_critical_storage_state_and_raid_degraded(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "metrics")
        points = obs_map(batch)
        assert points[("drive.status", "drive", "sdb")].value == "critical"
        assert points[("drive.smart", "drive", "sdb")].value == "failed"
        assert points[("drive.predictive_failure", "drive", "sdb")].value is True
        assert points[("raid.status", "raid", "RAID6_1")].value == "degraded"

    def test_drive_without_smart_member_is_error_never_passed(self, sim: SimAccess) -> None:
        sim.set(drives_without_oem=True)
        batch = run_collect(sim, "metrics")
        errors = err_map(batch)
        assert ("drive.smart", "drive", "sda") in errors
        assert ("drive.predictive_failure", "drive", "sda") in errors
        assert not any(o.metric_key in ("drive.smart", "drive.predictive_failure") for o in batch.observations)
        assert_no_quality_rows(batch, "drive.smart", {"passed"})
        # drive.status is independent of the OEM members.
        assert obs_map(batch)[("drive.status", "drive", "sda")].value == "ok"

    def test_no_raid_volume_emits_no_raid_data_and_no_error(self, sim: SimAccess) -> None:
        sim.set(no_raid_volume=True)
        batch = run_collect(sim, "metrics")
        assert not any(o.metric_key == "raid.status" for o in batch.observations)
        assert not any(e.key == "raid.status" for e in batch.errors)
        assert obs_map(batch)[("drive.status", "drive", "sda")].value == "ok"

    def test_healthy_metrics_run_has_no_errors_and_full_inventory(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "metrics")
        assert not batch.errors
        kinds = {(c.kind, c.native_id) for c in batch.components}
        assert ("processor", "cpu-1") in kinds
        assert ("fan", "FAN1") in kinds
        assert ("sensor", "temp-4") in kinds
        assert ("raid", "RAID6_1") in kinds


# -- collect: logs (SRV-MON-08) -----------------------------------------------


class TestCollectLogs:
    def test_healthy_sel_events(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "logs")
        events = batch.events
        assert len(events) == 4
        assert [event.severity for event in events] == ["critical", "warning", "info", "info"]
        assert [event.native_event_id for event in events] == [
            "SEL000001",
            "SEL000002",
            "SEL000003",
            "SEL000004",
        ]
        assert events[0].source == "redfish_sel"
        assert events[0].event_type == "event.sel"
        assert events[0].occurred_at == SEL_EPOCH
        assert events[1].occurred_at == SEL_EPOCH + datetime.timedelta(minutes=13)
        assert events[0].message == "Simulated uncorrectable memory error detected"
        assert not batch.errors

    def test_sel_oem_timestamp_fallback(self, sim: SimAccess) -> None:
        sim.set(sel_oem_timestamps=True)
        batch = run_collect(sim, "logs")
        assert len(batch.events) == 4
        assert batch.events[0].occurred_at == SEL_EPOCH
        assert batch.events[0].native_event_id == "SEL000001"

    def test_empty_sel_is_honest_empty_delta(self, sim: SimAccess) -> None:
        sim.set(empty_sel=True)
        batch = run_collect(sim, "logs")
        assert not batch.events
        assert not any(e.key == "event.sel" for e in batch.errors)

    def test_delta_reads_only_new_entries(self, sim: SimAccess) -> None:
        first = run_collect(sim, "logs")
        assert len(first.events) == 4
        # A later pass with last_run_at after the newest entry reads nothing.
        later = ADAPTER.collect(
            sim_session(sim),
            collect_request("logs", last_run_at=T0),
        )
        assert not later.events
        assert not later.errors
        # Health observations are still part of a logs run.
        assert obs_map(later)[("health.overall", None, None)].value == "healthy"

    def test_delta_walks_old_pages_to_new_appended_tail(self, sim: SimAccess) -> None:
        # 150 base entries fill the first pages (20/page); appending 25
        # strictly-newer entries crosses the page boundary at $skip=150. A
        # delta cursor after the LAST base entry must still reach the
        # appended tail — stopping at the first all-old page would silently
        # return nothing (the regression this test pins).
        sim.set(profile="slow_paginated")
        sim.set(sel_append=25)
        base_newest = SEL_EPOCH + datetime.timedelta(minutes=13 * 149)
        tail_first = SEL_EPOCH + datetime.timedelta(minutes=13 * 150)
        cursor = base_newest + datetime.timedelta(minutes=1)
        assert cursor < tail_first
        batch = ADAPTER.collect(
            sim_session(sim),
            collect_request("logs", last_run_at=cursor),
        )
        assert [event.native_event_id for event in batch.events] == [
            f"SEL{index:06d}" for index in range(151, 176)
        ]
        assert batch.events[0].occurred_at == tail_first
        assert not batch.errors

    def test_nothing_new_on_paged_sel_returns_zero(self, sim: SimAccess) -> None:
        # The whole 150-entry paged head predates the cursor: the walk must
        # still complete to the tail and emit nothing (zero events, zero
        # errors) instead of failing or fabricating entries.
        sim.set(profile="slow_paginated")
        batch = ADAPTER.collect(
            sim_session(sim),
            collect_request("logs", last_run_at=T0),
        )
        assert not batch.events
        assert not batch.errors
        # Health observations are still part of a logs run.
        assert obs_map(batch)[("health.overall", None, None)].value == "healthy"

    def test_pagination_over_150_entries_completes(self, sim: SimAccess) -> None:
        sim.set(profile="slow_paginated")
        batch = ADAPTER.collect(
            sim_session(sim),
            collect_request("logs", last_run_at=None),
        )
        assert len(batch.events) == 150
        assert len({event.native_event_id for event in batch.events}) == 150

    def test_critical_profile_sel_severity_mapping(self, sim: SimAccess) -> None:
        sim.set(profile="critical")
        batch = run_collect(sim, "logs")
        assert len(batch.events) == 25
        assert "critical" in {event.severity for event in batch.events}


# -- collect: run shape -------------------------------------------------------


class TestCollectRunShape:
    def test_health_subset_present_in_every_collection_type(self, sim: SimAccess) -> None:
        for collection_type in ("reachability", "health", "metrics", "logs", "discovery"):
            batch = run_collect(sim, collection_type)
            assert obs_map(batch)[("health.overall", None, None)].value == "healthy", collection_type
            assert obs_map(batch)[("indicator.led", None, None)].value == "normal", collection_type
            assert obs_map(batch)[("chassis.intrusion", None, None)].value == "normal", collection_type

    def test_non_metrics_types_do_not_carry_metric_inventory(self, sim: SimAccess) -> None:
        batch = run_collect(sim, "discovery")
        assert not any(o.metric_key.startswith("temperature.") for o in batch.observations)
        assert not batch.components

    def test_unknown_collection_type_is_rejected(self, sim: SimAccess) -> None:
        with pytest.raises(AdapterError):
            ADAPTER.collect(sim_session(sim), collect_request("telemetry"))

    def test_metrics_batch_values_and_units_match_contracts(self, sim: SimAccess) -> None:
        from app.generated.metrics import METRIC_DEFINITIONS

        batch = run_collect(sim, "metrics")
        for observation in batch.observations:
            metric = METRIC_DEFINITIONS[observation.metric_key]
            if metric.unit is not None:
                assert observation.unit == metric.unit, observation.metric_key
            if metric.value_type == "enum":
                from app.generated.metrics import ENUM_SETS

                assert observation.value in ENUM_SETS[metric.enum_set or ""], observation.metric_key
            assert observation.observed_at == T0
