"""M4T2 DSM adapter contract suite (tests over the booted DSM simulator).

The suite drives ``nas.synology_dsm`` (probe/discover/collect) over REAL
HTTP against the TEST-DEVICE DSM simulator (tests/simulators/dsm/) — never
hardware evidence (module READMEs + fixtures provenance policy). Every
collect mapping is asserted with certified enum values/units, the honest
absence/denominator/basis edges are pinned, and psu.status is never
emitted (no source — discovery row unsupported).

Mapping semantics pinned here (TDD surface):
- certified enum tables only; unknown device literals -> ObservationError;
- fan rpm 0 is stored only when DEVICE-REPORTED (never fabricated);
- raid.rebuild_progress is read ONLY while the pool is rebuilding;
- usage percentages require a denominator (ADR-016: no bytes-as-percent);
- UPS absent -> no point and no component; psu.status -> never emitted;
- per-family failures degrade to per-key errors; auth/network/TLS fail the
  run (AdapterError) and never fabricate a connectivity=false.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx
import pytest
from app.adapters.dsm import (
    POOL_COMPONENT_STATUS,
    UPS_COMPONENT_STATUS,
    VOLUME_COMPONENT_STATUS,
    SynologyDsmAdapter,
    _add_pool,
    _add_volume,
)
from app.adapters.registry import get_adapter
from app.domain.adapter import (
    CollectionRequest,
    ConnectionProfile,
    DeviceSession,
    ObservationBatch,
)
from app.generated.capabilities import REQUIREMENTS
from app.generated.metrics import METRIC_DEFINITIONS

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.simulators.dsm.serving import serve_simulator

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

ADAPTER_KEY = "nas.synology_dsm"
NAS_REQUIREMENT_IDS = {
    "NAS-MON-01",
    "NAS-MON-02",
    "NAS-MON-03",
    "NAS-MON-04",
    "NAS-MON-05",
    "NAS-MON-06",
    "NAS-ACT-01",
    "NAS-ACT-02",
    "NAS-ACT-03",
    "NAS-ACT-04",
    "NAS-ACT-05",
    "NAS-ACT-06",
}


# All 24 unique synology_nas capability keys from capabilities.json.
def _nas_keys() -> set[str]:
    keys: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != "synology_nas":
            continue
        keys.update(requirement.metrics)
        keys.update(requirement.events)
        keys.update(op[0] for op in requirement.operations)
    return keys


def _metric_units() -> dict[str, str | None]:
    return {key: definition.unit for key, definition in METRIC_DEFINITIONS.items()}


class DSMControl:
    """Control handle for the booted DSM simulator (like SimAccess)."""

    def __init__(self, base_url: str, client: httpx.Client) -> None:
        self.base_url = base_url
        self.client = client

    @property
    def port(self) -> int:
        parsed = urlsplit(self.base_url)
        assert parsed.port is not None
        return parsed.port

    def set(self, **knobs: object) -> None:
        response = self.client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text

    def snapshot(self) -> dict[str, object]:
        response = self.client.get("/warden-sim/control")
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, dict)
        return body


@pytest.fixture(scope="module")
def dsm_server() -> Iterator[DSMControl]:
    with serve_simulator() as url, httpx.Client(base_url=url, timeout=10.0) as client:
        control = DSMControl(base_url=url, client=client)
        yield control


@pytest.fixture()
def dsm(dsm_server: DSMControl) -> Iterator[DSMControl]:
    """Per-test pristine state: profile + every knob + failure injections
    reset (module-scoped simulator; explicit repeatable per-test state)."""
    from tests.simulators.dsm.app import FAILURE_KEYS

    reset: dict[str, object] = {
        "profile": "ds224plus",
        "storage_degraded": False,
        "pool_rebuilding": False,
        "ups_on_battery": False,
        "ups_absent": False,
        "fan_broken": False,
        "fan_zero_rpm": False,
        "share_no_quota": False,
        "log_append": 0,
        "missing_apis": [],
    }
    dsm_server.set(**reset)
    dsm_server.set(failures=dict.fromkeys(FAILURE_KEYS, False))
    yield dsm_server


def _profile(control: DSMControl) -> ConnectionProfile:
    return ConnectionProfile(
        adapter_key=ADAPTER_KEY,
        management_endpoint=SIM_HOST,
        port=control.port,
        connection_config={"protocol": "http"},
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
        verify_tls=False,
        tls_fingerprint_sha256=None,
        device_id=None,
    )


def _session(control: DSMControl) -> DeviceSession:
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config={"protocol": "http", "port": control.port},
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
    )


def _request(
    control: DSMControl, collection_type: str, last_run_at: datetime.datetime | None = None
) -> CollectionRequest:
    del control
    return CollectionRequest(
        device_id=uuid.uuid4(),
        collection_type=collection_type,
        now=datetime.datetime.now(datetime.UTC),
        last_run_at=last_run_at,
    )


def _batch_by_key(batch: ObservationBatch) -> dict[tuple[str, str | None], object]:
    return {(obs.metric_key, obs.component_native_id): obs.value for obs in batch.observations}


def _values(batch: ObservationBatch, key: str) -> list[tuple[str | None, object]]:
    return [(obs.component_native_id, obs.value) for obs in batch.observations if obs.metric_key == key]


class TestProbe:
    def test_probe_stages_ok_on_ds224plus(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        result = adapter.probe(_profile(dsm))
        assert result.ok
        assert [stage.stage for stage in result.stages] == [
            "network",
            "tls",
            "auth",
            "identity",
            "capabilities",
        ]
        assert all(stage.ok for stage in result.stages)
        assert result.identity_hint == {"vendor": "Synology", "model": "DS224+ (simulated)"}

    def test_probe_auth_failure_reports_auth_stage_only(self, dsm: DSMControl) -> None:
        dsm.set(profile="auth_fail")
        adapter = get_adapter(ADAPTER_KEY)
        result = adapter.probe(_profile(dsm))
        assert not result.ok
        by_stage = {stage.stage: stage for stage in result.stages}
        assert by_stage["network"].ok is True
        assert by_stage["tls"].ok is True
        auth = by_stage["auth"]
        assert auth.ok is False
        assert auth.error_code == "authentication_failed"
        assert by_stage["identity"].ok is False and by_stage["identity"].error_code is None
        assert by_stage["capabilities"].ok is False and by_stage["capabilities"].error_code is None

    def test_probe_identity_gate_rejects_non_certified_model(self) -> None:
        from app.adapters import dsm as dsm_module

        assert dsm_module._identity_failures("DS220+ (simulated)")  # not a target
        assert dsm_module._identity_failures(None)
        assert dsm_module._identity_failures("DS224+") == ()
        assert dsm_module._identity_failures("ds225+ (simulated)") == ()
        assert dsm_module._identity_failures("DS224+ (simulated)") == ()


class TestDiscover:
    def test_discovery_identity_and_inventory_ds224plus(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        discovery = adapter.discover(_profile(dsm))
        assert discovery.vendor == "Synology"
        assert discovery.model == "DS224+ (simulated)"
        assert discovery.serial_number == "SIM-DS224P-0001"
        assert discovery.firmware_version == "7.2.1-69057-update5 (simulated)"
        assert discovery.secrets_schema == adapter.secret_schema
        assert discovery.secrets_schema_version == 1
        kinds = {(c.kind, c.native_id) for c in discovery.components}
        assert {
            ("disk", "sata1"),
            ("disk", "sata2"),
            ("storage_pool", "pool1"),
            ("volume", "vol1"),
            ("shared_folder", "homes"),
            ("fan", "1"),
            ("fan", "2"),
            ("ups", "ups1"),
            ("sensor", "system"),
        } <= kinds
        assert not any(c.kind == "psu" for c in discovery.components)

    def test_discovery_capability_rows_cover_all_nas_keys(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        discovery = adapter.discover(_profile(dsm))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert set(rows) == _nas_keys()
        assert len(rows) == 24
        assert all(
            row.support_state in ("supported", "unsupported", "not_configured") for row in discovery.capabilities
        )
        # NAS-MON monitoring keys are supported (certified API callable).
        for key in (
            "disk.status",
            "disk.smart",
            "disk.bad_sectors",
            "storage_pool.status",
            "raid.status",
            "raid.rebuild_progress",
            "temperature.system",
            "fan.rpm",
            "fan.status",
            "volume.usage_percent",
            "shared_folder.usage_percent",
            "ups.status",
            "connectivity.management",
            "event.system_log",
        ):
            assert rows[key].support_state == "supported", key
            assert "SYNO." in (rows[key].detail or ""), key  # (api, version) basis on the row
            assert rows[key].requirement_id in NAS_REQUIREMENT_IDS
        # psu.status: no certified WebAPI source -> unsupported, never a value.
        assert rows["psu.status"].support_state == "unsupported"
        assert rows["psu.status"].reason_code == "no_webapi_source"
        # NAS-ACT rows (M4T3): supported when the certified operation source
        # API is callable on the device; the row detail carries the mapping.
        for key in (
            "power.restart",
            "power.shutdown",
            "console.dsm.open",
            "logs.support_bundle.collect",
            "disk.smart_test.quick",
            "disk.smart_test.full",
            "backup.status.refresh",
            "firmware.update",
            "snmp.configure",
        ):
            assert rows[key].support_state == "supported", key
            assert rows[key].reason_code is None, key
            assert "SYNO." in (rows[key].detail or ""), key
            assert "[" in (rows[key].detail or ""), key  # [sim]/[guide] basis tag

    def test_discovery_api_map_missing_marks_affected_keys_unsupported(self, dsm: DSMControl) -> None:
        dsm.set(profile="api_map_missing")
        adapter = get_adapter(ADAPTER_KEY)
        discovery = adapter.discover(_profile(dsm))
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["disk.status"].support_state == "unsupported"
        assert rows["disk.status"].reason_code == "api_not_discovered"
        assert rows["storage_pool.status"].support_state == "unsupported"
        assert rows["volume.usage_percent"].support_state == "unsupported"
        # NAS-ACT SMART rows share the missing Storage family.
        assert rows["disk.smart_test.quick"].support_state == "unsupported"
        assert rows["disk.smart_test.quick"].reason_code == "api_not_discovered"
        assert rows["disk.smart_test.full"].support_state == "unsupported"
        # Families whose API is present stay supported.
        assert rows["temperature.system"].support_state == "supported"
        assert rows["ups.status"].support_state == "supported"
        assert rows["connectivity.management"].support_state == "supported"
        assert rows["power.restart"].support_state == "supported"
        assert rows["backup.status.refresh"].support_state == "supported"

    def test_discovery_missing_operation_family_apis_stay_honest(self, dsm: DSMControl) -> None:
        dsm.set(missing_apis=["SYNO.Core.Support", "SYNO.Core.Backup", "SYNO.Core.Network.SNMP"])
        adapter = get_adapter(ADAPTER_KEY)
        discovery = adapter.discover(_profile(dsm))
        rows = {row.capability_key: row for row in discovery.capabilities}
        for key, api in (
            ("logs.support_bundle.collect", "SYNO.Core.Support"),
            ("backup.status.refresh", "SYNO.Core.Backup"),
            ("snmp.configure", "SYNO.Core.Network.SNMP"),
        ):
            assert rows[key].support_state == "unsupported", key
            assert rows[key].reason_code == "api_not_discovered", key
            assert api in (rows[key].detail or ""), key
        # The remaining operation families are unaffected.
        assert rows["power.shutdown"].support_state == "supported"
        assert rows["firmware.update"].support_state == "supported"

    def test_discovery_ds225plus_identity(self, dsm: DSMControl) -> None:
        dsm.set(profile="ds225plus")
        adapter = get_adapter(ADAPTER_KEY)
        discovery = adapter.discover(_profile(dsm))
        assert discovery.model == "DS225+ (simulated)"
        assert discovery.serial_number == "SIM-DS225P-0001"
        assert discovery.firmware_version == "7.2.2-72806-update1 (simulated)"
        rows = {row.capability_key: row for row in discovery.capabilities}
        assert rows["disk.status"].support_state == "supported"


class TestCollectMetrics:
    def test_healthy_metrics_mapping(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        assert batch.errors == ()
        values = _batch_by_key(batch)
        assert values[("connectivity.management", None)] is True
        assert values[("temperature.system", "system")] == 41.0
        assert values[("disk.status", "sata1")] == "ok"
        assert values[("disk.status", "sata2")] == "ok"
        assert values[("disk.smart", "sata1")] == "passed"
        assert values[("disk.bad_sectors", "sata1")] == 0
        assert values[("storage_pool.status", "pool1")] == "optimal"
        assert values[("raid.status", "pool1")] == "optimal"
        assert values[("volume.usage_percent", "vol1")] == 37.5
        assert values[("shared_folder.usage_percent", "homes")] == 50.0
        assert values[("fan.rpm", "1")] == 2100.0
        assert values[("fan.status", "1")] == "ok"
        assert values[("ups.status", None)] == "normal"
        assert not any(obs.metric_key == "raid.rebuild_progress" for obs in batch.observations)
        assert not any(obs.metric_key == "psu.status" for obs in batch.observations)
        # Contract units on numeric readings.
        by_key = {obs.metric_key: obs for obs in batch.observations}
        assert by_key["temperature.system"].unit == "Cel"
        assert by_key["fan.rpm"].unit == "r/min"
        assert by_key["volume.usage_percent"].unit == "%"
        assert by_key["disk.bad_sectors"].unit == "1"
        assert by_key["disk.bad_sectors"].value == 0  # device-reported 0 is data
        # Basis tags on every mapping row ([guide]/[sim] + api + version).
        for obs in batch.observations:
            assert obs.evidence is not None and "[" in obs.evidence
            assert "SYNO." in obs.evidence
        # Components reflect the inventory.
        kinds = {(c.kind, c.native_id) for c in batch.components}
        assert {"disk", "storage_pool", "volume", "shared_folder", "fan", "ups", "sensor"} <= {k for k, _ in kinds}

    def test_degraded_metrics_mapping(self, dsm: DSMControl) -> None:
        dsm.set(profile="degraded")
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        values = _batch_by_key(batch)
        assert values[("disk.status", "sata2")] == "critical"
        assert values[("disk.smart", "sata2")] == "failed"
        assert values[("disk.bad_sectors", "sata2")] == 512
        assert values[("storage_pool.status", "pool1")] == "degraded"
        assert values[("raid.status", "pool1")] == "degraded"
        assert values[("ups.status", None)] == "on_battery"
        assert not any(obs.metric_key == "raid.rebuild_progress" for obs in batch.observations)
        # Fan 1 is broken: rpm 0 IS device-reported data (stored), fan.status
        # comes from the device text (Error -> critical) — not from rpm.
        fan1_rpm = next(
            obs for obs in batch.observations if obs.metric_key == "fan.rpm" and obs.component_native_id == "1"
        )
        assert fan1_rpm.value == 0.0
        assert fan1_rpm.quality.value == "good"
        fan1_status = next(
            obs for obs in batch.observations if obs.metric_key == "fan.status" and obs.component_native_id == "1"
        )
        assert fan1_status.value == "critical"
        fan2_rpm = next(
            obs for obs in batch.observations if obs.metric_key == "fan.rpm" and obs.component_native_id == "2"
        )
        assert fan2_rpm.value == 2100.0
        assert fan2_rpm.quality.value == "good"
        volume = _values(batch, "volume.usage_percent")
        assert 97.0 < float(volume[0][1]) < 98.0

    def test_fan_zero_rpm_with_normal_status_is_data_not_error(self, dsm: DSMControl) -> None:
        dsm.set(fan_zero_rpm=True)
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        assert batch.errors == ()
        rpm = _values(batch, "fan.rpm")
        assert len(rpm) == 2
        assert all(float(value) == 0.0 for _, value in rpm)
        statuses = _values(batch, "fan.status")
        assert all(value == "ok" for _, value in statuses)

    def test_rebuild_progress_only_while_rebuilding(self, dsm: DSMControl) -> None:
        dsm.set(pool_rebuilding=True)
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        assert batch.errors == ()
        values = _batch_by_key(batch)
        assert values[("storage_pool.status", "pool1")] == "rebuilding"
        assert values[("raid.status", "pool1")] == "rebuilding"
        assert values[("raid.rebuild_progress", "pool1")] == 45.0
        assert values[("disk.status", "sata1")] == "ok"  # healthy disks during rebuild

    def test_share_without_quota_is_observation_error_not_bytes_as_percent(self, dsm: DSMControl) -> None:
        dsm.set(share_no_quota=True)
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        # The quota'd share keeps its percentage; the quota-less share errors.
        assert any(
            obs.metric_key == "shared_folder.usage_percent" and obs.component_native_id == "homes"
            for obs in batch.observations
        )
        no_quota_errors = [
            error
            for error in batch.errors
            if error.key == "shared_folder.usage_percent" and error.component_native_id == "backup"
        ]
        assert len(no_quota_errors) == 1
        assert no_quota_errors[0].error_code == "not_configured"
        assert "no_quota_denominator" in (no_quota_errors[0].detail or "")

    def test_ups_absent_emits_no_point_and_no_component(self, dsm: DSMControl) -> None:
        dsm.set(ups_absent=True)
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        assert not any(obs.metric_key == "ups.status" for obs in batch.observations)
        assert not any(error.key == "ups.status" for error in batch.errors)
        assert not any(component.kind == "ups" for component in batch.components)
        assert not any(obs.metric_key == "psu.status" for obs in batch.observations)

    def test_missing_ups_api_degrades_to_per_key_error(self, dsm: DSMControl) -> None:
        dsm.set(missing_apis=["SYNO.Core.UPS"])
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        assert not any(obs.metric_key == "ups.status" for obs in batch.observations)
        ups_errors = [error for error in batch.errors if error.key == "ups.status"]
        assert ups_errors and ups_errors[0].error_code == "not_configured"
        # The rest of the batch still reads (one broken family never hides it).
        assert any(obs.metric_key == "disk.status" for obs in batch.observations)
        assert any(obs.metric_key == "connectivity.management" for obs in batch.observations)

    def test_auth_failure_raises_adapter_error_and_never_fabricates_false(self, dsm: DSMControl) -> None:
        dsm.set(profile="auth_fail")
        adapter = get_adapter(ADAPTER_KEY)
        with pytest.raises(Exception) as excinfo:
            adapter.collect(_session(dsm), _request(dsm, "metrics"))
        from app.domain.adapter import AdapterError

        assert isinstance(excinfo.value, AdapterError)
        assert excinfo.value.code == "authentication_failed"

    def test_health_run_emits_only_connectivity(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        for collection_type in ("reachability", "health", "discovery"):
            batch = adapter.collect(_session(dsm), _request(dsm, collection_type))
            keys = [obs.metric_key for obs in batch.observations]
            assert keys == ["connectivity.management"], collection_type
            assert batch.errors == ()
            assert all(obs.value is True for obs in batch.observations)

    def test_broken_management_api_emits_connectivity_false_not_run_failure(self, dsm: DSMControl) -> None:
        dsm.set(failures={"reads_500": True})
        adapter = get_adapter(ADAPTER_KEY)
        # health run: the System read fails non-fatally -> the honest
        # measurement is connectivity=false (quality good), never a raised
        # run failure and never a fabricated true.
        batch = adapter.collect(_session(dsm), _request(dsm, "health"))
        connectivity = [obs for obs in batch.observations if obs.metric_key == "connectivity.management"]
        assert len(connectivity) == 1
        assert connectivity[0].value is False
        assert connectivity[0].quality.value == "good"
        assert batch.errors == ()

    def test_collect_rejects_unknown_type(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        from app.domain.adapter import AdapterError

        with pytest.raises(AdapterError):
            adapter.collect(_session(dsm), _request(dsm, "nonsense"))

    def test_metrics_run_with_reads500_never_fabricates_values(self, dsm: DSMControl) -> None:
        dsm.set(failures={"reads_500": True})
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "metrics"))
        # No metric value may be fabricated when every family failed: the
        # only observation is the honest connectivity=false.
        assert all(obs.metric_key == "connectivity.management" for obs in batch.observations)
        assert all(obs.value is False for obs in batch.observations)
        error_keys = {error.key for error in batch.errors}
        assert {"disk.status", "ups.status", "shared_folder.usage_percent"} <= error_keys


class TestCollectLogs:
    def test_logs_delta_imports_and_dedupes(self, dsm: DSMControl) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        epoch = datetime.datetime(2026, 9, 3, tzinfo=datetime.UTC)
        first = adapter.collect(_session(dsm), _request(dsm, "logs"))
        assert len(first.events) == 24
        severities = {event.severity for event in first.events}
        assert severities <= {"info", "warning", "critical", "unknown"}
        assert severities == {"info", "warning"}
        assert all(event.source == "dsm_log" for event in first.events)
        assert all(event.event_type == "event.system_log" for event in first.events)
        assert {int(event.native_event_id or "0") for event in first.events} == set(range(1, 25))
        # Delta with a cursor past the log tail: nothing new.
        after_tail = adapter.collect(
            _session(dsm),
            _request(dsm, "logs", last_run_at=epoch + datetime.timedelta(seconds=30)),
        )
        assert after_tail.events == ()
        assert after_tail.errors == ()
        # Boundary re-emission at exactly the cursor (platform dedupes).
        boundary = adapter.collect(
            _session(dsm),
            _request(dsm, "logs", last_run_at=epoch + datetime.timedelta(seconds=24)),
        )
        assert {int(event.native_event_id or "0") for event in boundary.events} == {24}
        # Appended entries past the cursor are picked up across pages.
        dsm.set(log_append=3)
        appended = adapter.collect(
            _session(dsm),
            _request(dsm, "logs", last_run_at=epoch + datetime.timedelta(seconds=24)),
        )
        assert {int(event.native_event_id or "0") for event in appended.events} == {24, 25, 26, 27}

    def test_slow_paginated_logs_walk_to_tail(self, dsm: DSMControl) -> None:
        dsm.set(profile="slow_paginated")
        adapter = get_adapter(ADAPTER_KEY)
        batch = adapter.collect(_session(dsm), _request(dsm, "logs"))
        assert len(batch.events) == 150
        assert batch.errors == ()
        assert {int(event.native_event_id or "0") for event in batch.events} == set(range(1, 151))


class TestMappingEdgesUnit:
    """Crafted-payload edges (mapper-level unit semantics, TDD)."""

    def test_pool_without_rebuilding_state_never_reads_progress(self) -> None:
        bundle = _BundleHolder().bundle
        now = datetime.datetime.now(datetime.UTC)
        # The device sends rebuild_progress data even while NOT rebuilding:
        # the mapping must ignore it (progress is only read while rebuilding).
        _add_pool(bundle, {"id": "p1", "status": "Normal", "rebuild_progress": 45}, now=now)
        assert not any(obs.metric_key == "raid.rebuild_progress" for obs in bundle.observations)
        assert bundle.errors == []

    def test_rebuilding_pool_without_progress_is_error(self) -> None:
        bundle = _BundleHolder().bundle
        now = datetime.datetime.now(datetime.UTC)
        _add_pool(bundle, {"id": "p1", "status": "Rebuilding"}, now=now)
        assert any(error.key == "raid.rebuild_progress" for error in bundle.errors)
        assert not any(obs.metric_key == "raid.rebuild_progress" for obs in bundle.observations)

    def test_volume_without_denominator_is_error(self) -> None:
        bundle = _BundleHolder().bundle
        now = datetime.datetime.now(datetime.UTC)
        _add_volume(bundle, {"id": "v1", "status": "Normal", "used_bytes": 100, "total_bytes": 0}, now=now)
        assert not any(obs.metric_key == "volume.usage_percent" for obs in bundle.observations)
        assert any("no_quota_denominator" in (error.detail or "") for error in bundle.errors)

    def test_overshoot_volume_usage_is_error_never_clamped(self) -> None:
        bundle = _BundleHolder().bundle
        now = datetime.datetime.now(datetime.UTC)
        _add_volume(bundle, {"id": "v1", "status": "Normal", "used_bytes": 101, "total_bytes": 100}, now=now)
        assert not any(obs.metric_key == "volume.usage_percent" for obs in bundle.observations)
        assert len(bundle.errors) == 1


class _BundleHolder:
    def __init__(self) -> None:
        from app.adapters import dsm as dsm_module

        self.bundle = dsm_module._Bundle()


class TestComponentProjections:
    """Certified component-status projection tables stay in-contract."""

    def test_projection_values_are_component_status(self) -> None:
        component_status = {
            "unknown",
            "ok",
            "warning",
            "critical",
            "absent",
        }
        for table in (POOL_COMPONENT_STATUS, VOLUME_COMPONENT_STATUS, UPS_COMPONENT_STATUS):
            assert set(table.values()) <= component_status

    def test_unknown_device_text_projects_unknown(self) -> None:
        from app.adapters import dsm as dsm_module

        assert dsm_module._component_status_of(POOL_COMPONENT_STATUS, "Weird state") == "unknown"
        assert dsm_module._component_status_of(POOL_COMPONENT_STATUS, "Degraded") == "warning"
        assert dsm_module._component_status_of(UPS_COMPONENT_STATUS, "On Battery") == "warning"
        assert dsm_module._component_status_of(VOLUME_COMPONENT_STATUS, "Normal") == "ok"


class TestAdapterRegistration:
    def test_registered_key_and_schemas(self) -> None:
        adapter = get_adapter(ADAPTER_KEY)
        assert isinstance(adapter, SynologyDsmAdapter)
        assert adapter.supported_device_types == frozenset({"synology_nas"})
        assert adapter.secret_schema == {
            "type": "object",
            "required": ["username", "password"],
            "additionalProperties": False,
            "properties": {
                "username": {"type": "string", "minLength": 1},
                "password": {"type": "string", "minLength": 1},
            },
        }

    def test_certified_api_rows_have_versions_and_basis(self) -> None:
        from app.adapters import dsm as dsm_module
        from app.infrastructure.protocols.dsm.client import CERTIFIED_API_VERSIONS

        for api_name, basis in dsm_module.API_BASIS.items():
            assert api_name in CERTIFIED_API_VERSIONS, api_name
            assert basis.startswith("[guide]") or basis.startswith("[sim]"), api_name

    def test_metric_units_match_contracts(self) -> None:
        contract = _metric_units()
        # Spot-check the NAS numeric units against contracts/metrics.json.
        assert contract["temperature.system"] == "Cel"
        assert contract["fan.rpm"] == "r/min"
        assert contract["disk.bad_sectors"] == "1"
        assert contract["volume.usage_percent"] == "%"
        assert contract["shared_folder.usage_percent"] == "%"
        assert contract["raid.rebuild_progress"] == "%"


class TestSimulatorHonesty:
    def test_simulator_serves_share_and_profiles(self, dsm: DSMControl) -> None:
        snapshot = dsm.snapshot()
        assert snapshot["profile"] == "ds224plus"
        # A profile switch forces the profile-owned knobs to their presets;
        # knobs it does not own keep their live values (constructor knob
        # combinations preserved). The per-test fixture resets everything.
        dsm.set(profile="ds225plus", fan_zero_rpm=True)
        assert dsm.snapshot()["profile"] == "ds225plus"
        assert dsm.snapshot()["fan_zero_rpm"] is True
        dsm.set(profile="degraded")
        snapshot = dsm.snapshot()
        assert snapshot["profile"] == "degraded"
        assert snapshot["storage_degraded"] is True  # profile-owned preset
        assert snapshot["fan_zero_rpm"] is True  # not profile-owned: kept
        assert snapshot["ups_on_battery"] is True  # degraded preset
        dsm.set(profile="ds224plus")
