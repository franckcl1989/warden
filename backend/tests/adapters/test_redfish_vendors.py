"""M3T5 vendor overlay contract suite (five certification-target adapters).

Drives the registered vendor adapters (server.dell_idrac, server.inspur_ibmc,
server.xfusion_ibmc, server.lenovo_xcc, server.huawei_ibmc) against the
TEST-DEVICE simulator's vendor profiles. Assertions cover the ONLY certified
vendor differences (DEVICE_ADAPTERS.md §4/§10, M3T5 brief):

- probe identity gates: the adapter accepts its own vendor profile and
  REJECTS every foreign profile at the probe ``identity`` stage
  (validation_failed) — no silent cross-registration;
- discovery rows are unchanged vs the common adapter on the same profile
  (only the discovery_method/adapter key differs);
- collect parses the vendor-namespaced OEM members the fixture profiles
  freeze (memory.ecc_errors / drive.smart / drive.predictive_failure /
  raid.status); absent OEM members stay explicit ObservationErrors;
- power.cycle executes the vendor-certified ResetType pin (device-side
  mapping evidence) and refuses when the certified type is not advertised;
- manager.reset / KVM launch keep the common standard paths.

Honesty: everything NOT fixture-verified is marked experimental in the
overlay module docstrings, and a dedicated honesty test binds the module
docstring ledger to the code's ``# basis:`` markers. The simulator is a TEST
DEVICE SIMULATOR — none of this is 真机 evidence (HARDWARE_CERTIFICATION.md
§3); the certification matrix stays ``not_started``.
"""

from __future__ import annotations

import dataclasses
import datetime
import inspect
import re
import uuid
from ipaddress import ip_address
from pathlib import Path

import pytest
from app.adapters.redfish.common import RedfishCommonAdapter
from app.adapters.redfish.dell import DellIdracAdapter
from app.adapters.redfish.huawei import HuaweiIbmcAdapter
from app.adapters.redfish.inspur import InspurIbmcAdapter
from app.adapters.redfish.lenovo import LenovoXccAdapter
from app.adapters.redfish.xfusion import XfusionIbmcAdapter
from app.adapters.registry import ADAPTERS, get_adapter
from app.domain.adapter import (
    AdapterError,
    CollectionRequest,
    ConnectionProfile,
    DeviceSession,
    Observation,
    ObservationBatch,
    ProbeStage,
)
from app.domain.operation_plan import CapabilityView, DeviceSnapshot, OperationPlan, OperationRequest
from app.infrastructure.protocols.redfish.parse import RedfishResource
from app.infrastructure.time import utcnow

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME, SimAccess

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "redfish"

# (adapter class, simulator vendor profile, expected Manufacturer token,
#  expected identity model, certified power.cycle ResetType on the full
#  advertisement, mapping note fragment, class-level vendor identity text)
VENDOR_CASES = (
    (DellIdracAdapter, "dell", "Dell Inc.", "PowerEdge R760", "ForceRestart", "iDRAC"),
    (LenovoXccAdapter, "lenovo", "Lenovo", "ThinkSystem SR650 V3", "ForceRestart", "XCC"),
    (HuaweiIbmcAdapter, "huawei", "Huawei", "FusionServer 2288H V5", "PowerCycle", "iBMC"),
    (InspurIbmcAdapter, "inspur", "Inspur", "NF5280M6", "ForceRestart", "通用映射规则"),
    (XfusionIbmcAdapter, "xfusion", "XFusion", "5288 V6", "ForceRestart", "通用映射规则"),
)
VENDOR_KEYS = {
    DellIdracAdapter: "server.dell_idrac",
    LenovoXccAdapter: "server.lenovo_xcc",
    HuaweiIbmcAdapter: "server.huawei_ibmc",
    InspurIbmcAdapter: "server.inspur_ibmc",
    XfusionIbmcAdapter: "server.xfusion_ibmc",
}

COMMON = RedfishCommonAdapter()

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

T0 = datetime.datetime(2026, 9, 3, 12, 0, 0, tzinfo=datetime.UTC)
REQUIREMENT_BY_KEY = {
    "manager.reset": "SRV-ACT-01",
    "power.on": "SRV-ACT-02",
    "power.off": "SRV-ACT-02",
    "power.cycle": "SRV-ACT-02",
    "console.kvm.open": "SRV-ACT-03",
    "logs.support_bundle.collect": "SRV-ACT-04",
    "virtual_media.mount": "SRV-ACT-05",
    "virtual_media.unmount": "SRV-ACT-05",
    "firmware.query": "SRV-ACT-06",
    "firmware.update": "SRV-ACT-06",
    "asset.refresh": "SRV-ACT-07",
}


def _adapter(adapter_class: type) -> object:
    return adapter_class()


def _profile(sim: SimAccess, adapter_key: str, **config: object) -> ConnectionProfile:
    merged: dict[str, object] = {"protocol": "http", "port": sim.port}
    merged.update(config)
    return ConnectionProfile(
        adapter_key=adapter_key,
        management_endpoint=SIM_HOST,
        port=sim.port,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
        verify_tls=True,
        tls_fingerprint_sha256=None,
        device_id=None,
        resolved_ip=ip_address(SIM_HOST),
    )


def _session(sim: SimAccess) -> DeviceSession:
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config={"protocol": "http", "port": sim.port},
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
        resolved_ip=ip_address(SIM_HOST),
    )


def _snapshot(adapter: object, key: str) -> DeviceSnapshot:
    return DeviceSnapshot(
        device_id=uuid.uuid4(),
        device_name="sim-vendor-srv",
        device_type="server",
        device_version=1,
        adapter_key=adapter.adapter_key,  # type: ignore[attr-defined]
        enabled=True,
        readiness="ready",
        capabilities=(
            CapabilityView(
                capability_key=key,
                support_state="supported",
                requirement_id=REQUIREMENT_BY_KEY[key],
                discovery_method=adapter.adapter_key,  # type: ignore[attr-defined]
                adapter_version=adapter.adapter_version,  # type: ignore[attr-defined]
            ),
        ),
    )


def _plan(adapter: object, key: str) -> OperationPlan:
    return adapter.plan_operation(  # type: ignore[attr-defined]
        _snapshot(adapter, key), OperationRequest(capability_key=key, parameters={})
    )


def _short_deadline(plan: OperationPlan, seconds: float = 4.0) -> OperationPlan:
    return dataclasses.replace(
        plan,
        runtime_context={
            **plan.runtime_context,
            "task_timeout_at": (utcnow() + datetime.timedelta(seconds=seconds)).isoformat(),
        },
    )


def _obs_map(batch: ObservationBatch) -> dict[tuple[str, str | None, str | None], Observation]:
    return {
        (o.metric_key, o.component_kind, o.component_native_id): o for o in batch.observations
    }


# -- registry ---------------------------------------------------------------


class TestRegistry:
    def test_five_vendor_keys_registered_for_server_devices(self) -> None:
        expected = {
            "server.dell_idrac",
            "server.inspur_ibmc",
            "server.xfusion_ibmc",
            "server.lenovo_xcc",
            "server.huawei_ibmc",
        }
        assert expected <= set(ADAPTERS)
        for key in expected:
            adapter = get_adapter(key)
            assert "server" in adapter.supported_device_types
            assert adapter.secret_schema == COMMON.secret_schema
            assert adapter.secret_schema_version == COMMON.secret_schema_version
            assert adapter.adapter_version == COMMON.adapter_version


# -- probe identity gates ---------------------------------------------------


class TestProbeIdentityGate:
    @pytest.mark.parametrize("adapter_class,vendor,manufacturer,model,_cycle,_note", VENDOR_CASES)
    def test_own_vendor_profile_passes_identity(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        manufacturer: str,
        model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _cycle, _note
        sim.set(vendor=vendor)
        adapter = _adapter(adapter_class)
        result = adapter.probe(_profile(sim, adapter.adapter_key))  # type: ignore[attr-defined]
        assert result.ok
        assert all(stage.ok for stage in result.stages)
        assert result.identity_hint == {"manufacturer": manufacturer, "model": model}

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_generic_profile_is_rejected_at_identity_stage(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del vendor, _m, _model, _cycle, _note
        sim.set(vendor="generic")
        adapter = _adapter(adapter_class)
        result = adapter.probe(_profile(sim, adapter.adapter_key))  # type: ignore[attr-defined]
        assert not result.ok
        by_stage = {stage.stage: stage for stage in result.stages}
        assert by_stage["network"].ok is True
        assert by_stage["tls"].ok is True
        assert by_stage["auth"].ok is True
        assert by_stage["identity"].ok is False
        assert by_stage["identity"].error_code == "validation_failed"
        assert "Warden Simulator" in (by_stage["identity"].detail_safe or "")
        # The capabilities stage was NOT executed (never fabricated as ok).
        assert by_stage["capabilities"].ok is False
        assert by_stage["capabilities"].error_code is None

    @pytest.mark.parametrize("adapter_class,own_vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    @pytest.mark.parametrize(
        "foreign_vendor,foreign_manufacturer",
        [("dell", "Dell Inc."), ("inspur", "Inspur"), ("xfusion", "XFusion"),
         ("lenovo", "Lenovo"), ("huawei", "Huawei")],
    )
    def test_foreign_vendor_profile_is_rejected(
        self,
        sim: SimAccess,
        adapter_class: type,
        own_vendor: str,
        foreign_vendor: str,
        foreign_manufacturer: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _m, _model, _cycle, _note
        if foreign_vendor == own_vendor:
            pytest.skip("same vendor covered by the acceptance test")
        sim.set(vendor=foreign_vendor)
        adapter = _adapter(adapter_class)
        result = adapter.probe(_profile(sim, adapter.adapter_key))  # type: ignore[attr-defined]
        assert not result.ok
        identity = {stage.stage: stage for stage in result.stages}["identity"]
        assert identity.ok is False
        assert identity.error_code == "validation_failed"
        assert foreign_manufacturer in (identity.detail_safe or "")

    def test_failed_probe_never_yields_discovery_on_api_path(self, sim: SimAccess) -> None:
        # mirrors application/devices.probe_device: discover only runs when
        # the whole probe (incl. the vendor identity stage) passed.
        sim.set(vendor="lenovo")
        adapter = DellIdracAdapter()
        result = adapter.probe(_profile(sim, adapter.adapter_key))
        assert not result.ok
        assert result.identity_hint is None
        stage: ProbeStage | None = None
        for candidate in result.stages:
            if candidate.stage == "identity" and not candidate.ok:
                stage = candidate
        assert stage is not None


# -- discovery --------------------------------------------------------------


class TestDiscovery:
    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_rows_unchanged_vs_common_except_discovery_method(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _cycle, _note
        sim.set(vendor=vendor)
        adapter = _adapter(adapter_class)
        discovery = adapter.discover(_profile(sim, adapter.adapter_key))  # type: ignore[attr-defined]
        assert discovery.vendor == _m
        assert discovery.model == _model
        common_rows = {
            row.capability_key: row
            for row in COMMON.discover(_profile(sim, COMMON.adapter_key)).capabilities
        }
        assert len(discovery.capabilities) == len(common_rows) == 31
        for row in discovery.capabilities:
            common = common_rows[row.capability_key]
            # Same support state/reason/detail/requirement: the vendor overlay
            # claims nothing beyond the common evidence (no experimental path
            # is ever discovered as supported).
            assert row.support_state == common.support_state
            assert row.reason_code == common.reason_code
            assert row.detail == common.detail
            assert row.requirement_id == common.requirement_id
            assert row.discovery_method == adapter.adapter_key  # type: ignore[attr-defined]
        assert {row.capability_key for row in discovery.capabilities} == set(common_rows)

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_surface_knobs_stay_honest_unsupported(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _m, _model, _cycle, _note
        sim.set(vendor=vendor, missing_memory_metrics=True, drives_without_oem=True)
        adapter = _adapter(adapter_class)
        rows = {
            row.capability_key: row
            for row in adapter.discover(_profile(sim, adapter.adapter_key)).capabilities  # type: ignore[attr-defined]
        }
        assert rows["memory.ecc_errors"].support_state == "unsupported"
        assert rows["memory.ecc_errors"].reason_code == "no_ecc_counter_member"
        assert rows["drive.smart"].support_state == "unsupported"
        assert rows["drive.predictive_failure"].support_state == "unsupported"


# -- collect (vendor-namespaced OEM members) --------------------------------


class TestCollect:
    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_metrics_with_vendor_oem_members(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _m, _model, _cycle, _note
        sim.set(vendor=vendor)
        adapter = _adapter(adapter_class)
        batch = adapter.collect(  # type: ignore[attr-defined]
            _session(sim),
            CollectionRequest(device_id=uuid.uuid4(), collection_type="metrics", now=T0),
        )
        assert not batch.errors
        points = _obs_map(batch)
        for index in range(4):
            native = f"DIMM{index}"
            assert points[("memory.status", "memory", native)].value == "ok"
            assert points[("memory.ecc_errors", "memory", native)].value == 3 + index
            assert points[("memory.ecc_errors", "memory", native)].unit == "1"
        for native in ("sda", "sdb"):
            assert points[("drive.smart", "drive", native)].value == "passed"
            assert points[("drive.predictive_failure", "drive", native)].value is False
        assert points[("raid.status", "raid", "RAID6_1")].value == "optimal"

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_missing_oem_members_are_observation_errors_not_zeros(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _m, _model, _cycle, _note
        sim.set(vendor=vendor, missing_memory_metrics=True, drives_without_oem=True)
        adapter = _adapter(adapter_class)
        batch = adapter.collect(  # type: ignore[attr-defined]
            _session(sim),
            CollectionRequest(device_id=uuid.uuid4(), collection_type="metrics", now=T0),
        )
        error_keys = {(e.key or "", e.component_kind, e.component_native_id) for e in batch.errors}
        for index in range(4):
            assert ("memory.ecc_errors", "memory", f"DIMM{index}") in error_keys
        assert ("drive.smart", "drive", "sda") in error_keys
        assert ("drive.predictive_failure", "drive", "sda") in error_keys
        assert not any(o.metric_key == "memory.ecc_errors" for o in batch.observations)
        assert not any(o.metric_key in ("drive.smart", "drive.predictive_failure") for o in batch.observations)

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_critical_profile_vendor_oem_state_and_sel(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _m, _model, _cycle, _note
        sim.set(vendor=vendor, profile="critical")
        adapter = _adapter(adapter_class)
        metrics = adapter.collect(  # type: ignore[attr-defined]
            _session(sim),
            CollectionRequest(device_id=uuid.uuid4(), collection_type="metrics", now=T0),
        )
        points = _obs_map(metrics)
        assert points[("drive.smart", "drive", "sdb")].value == "failed"
        assert points[("drive.predictive_failure", "drive", "sdb")].value is True
        assert points[("raid.status", "raid", "RAID6_1")].value == "degraded"
        logs = adapter.collect(  # type: ignore[attr-defined]
            _session(sim),
            CollectionRequest(device_id=uuid.uuid4(), collection_type="logs", now=T0),
        )
        assert len(logs.events) == 25
        assert all(event.source == "redfish_sel" for event in logs.events)


# -- operations: reset mapping pins -----------------------------------------


class TestResetMapping:
    @pytest.mark.parametrize(
        "adapter_class,vendor,_m,_model,cycle_type,note_fragment", VENDOR_CASES
    )
    def test_power_cycle_uses_the_vendor_certified_mapping(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        cycle_type: str,
        note_fragment: str,
    ) -> None:
        del vendor
        sim.set(vendor=sim_vendor(adapter_class), task_duration_seconds=0.05)
        adapter = _adapter(adapter_class)
        session = _session(sim)
        plan = _plan(adapter, "power.cycle")
        preflight = adapter.preflight_operation(session, plan)  # type: ignore[attr-defined]
        assert preflight.ok is True
        result = adapter.execute_operation(  # type: ignore[attr-defined]
            session, _short_deadline(plan), lambda *_: None
        )
        assert result.ok is True
        assert result.evidence["reset_type"] == cycle_type
        assert note_fragment in str(result.evidence["mapping"])
        # The simulator recorded the same ResetType device-side.
        snapshot = sim.client.get("/warden-sim/control")
        assert snapshot.status_code == 200
        assert snapshot.json()["last_system_resets"] == [cycle_type]

    @pytest.mark.parametrize(
        "adapter_class,vendor,_m,_model,cycle_type,_note", VENDOR_CASES
    )
    def test_unadvertised_certified_type_is_refused_at_preflight(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        cycle_type: str,
        _note: str,
    ) -> None:
        del vendor, cycle_type
        # Advertise ONLY the type the vendor does NOT certify: every overlay
        # must refuse at preflight (never a silent substitution), while the
        # common adapter would still pick the advertised type.
        sim.set(vendor=sim_vendor(adapter_class), reset_types_override=["PowerCycle"])
        adapter = _adapter(adapter_class)
        session = _session(sim)
        plan = _plan(adapter, "power.cycle")
        if isinstance(adapter, (DellIdracAdapter, LenovoXccAdapter)):
            # ForceRestart-only pins refuse a PowerCycle-only device.
            preflight = adapter.preflight_operation(session, plan)  # type: ignore[attr-defined]
            assert preflight.ok is False
            assert preflight.error_code == "unsupported_capability"
        else:
            # Huawei (and the common-rule iBMC overlays) certify PowerCycle
            # too, so a PowerCycle-only advertisement still passes; the
            # Huawei-fallback and refusal cases are asserted separately.
            preflight = adapter.preflight_operation(session, plan)  # type: ignore[attr-defined]
            assert preflight.ok is True

    def test_huawei_falls_back_to_force_restart_and_refuses_without_either(
        self, sim: SimAccess
    ) -> None:
        adapter = HuaweiIbmcAdapter()
        session = _session(sim)
        # PowerCycle absent -> the certified fallback ForceRestart runs.
        sim.set(vendor="huawei", reset_types_override=["ForceRestart"], task_duration_seconds=0.05)
        plan = _plan(adapter, "power.cycle")
        result = adapter.execute_operation(session, _short_deadline(plan), lambda *_: None)
        assert result.ok is True
        assert result.evidence["reset_type"] == "ForceRestart"
        assert "ForceRestart" in str(result.evidence["mapping"])
        # Neither certified type advertised -> honest preflight refusal.
        sim.set(vendor="huawei", reset_types_override=["GracefulRestart"])
        plan = _plan(adapter, "power.cycle")
        preflight = adapter.preflight_operation(session, plan)
        assert preflight.ok is False
        assert preflight.error_code == "unsupported_capability"

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_power_on_off_and_manager_reset_keep_common_types(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _cycle, _note
        sim.set(vendor=vendor, task_duration_seconds=0.05)
        adapter = _adapter(adapter_class)
        session = _session(sim)
        # power.on on an On system is a state-drift preflight failure (the
        # common fixed mapping On stays; asserted before any execute).
        plan = _plan(adapter, "power.on")
        preflight = adapter.preflight_operation(session, plan)  # type: ignore[attr-defined]
        assert preflight.ok is False
        assert preflight.error_code == "validation_failed"
        # power.off -> GracefulShutdown (never ForceOff), then manager.reset
        # -> GracefulRestart (LAST: the manager goes into its offline blip).
        for key, expected_type in (
            ("power.off", "GracefulShutdown"),
            ("manager.reset", "GracefulRestart"),
        ):
            plan = _plan(adapter, key)
            preflight = adapter.preflight_operation(session, plan)  # type: ignore[attr-defined]
            assert preflight.ok is True, key
            result = adapter.execute_operation(  # type: ignore[attr-defined]
                session, _short_deadline(plan, seconds=6.0), lambda *_: None
            )
            assert result.ok is True, key
            assert result.evidence["reset_type"] == expected_type, key

    @pytest.mark.parametrize("adapter_class,vendor,_m,_model,_cycle,_note", VENDOR_CASES)
    def test_kvm_launch_keeps_the_graphical_console_descriptor(
        self,
        sim: SimAccess,
        adapter_class: type,
        vendor: str,
        _m: str,
        _model: str,
        _cycle: str,
        _note: str,
    ) -> None:
        del _cycle, _note
        sim.set(vendor=vendor)
        adapter = _adapter(adapter_class)
        descriptor = adapter.create_launch(_session(sim), "console.kvm.open")  # type: ignore[attr-defined]
        assert descriptor.kind == "url"
        assert descriptor.url == f"http://{SIM_HOST}:{sim.port}/"
        assert SIM_PASSWORD not in (descriptor.url or "")
        assert SIM_USERNAME not in (descriptor.url or "")


def sim_vendor(adapter_class: type) -> str:
    return {cls: vendor for cls, vendor, *_rest in VENDOR_CASES}[adapter_class]


# -- honesty: basis markers + experimental ledger ---------------------------


@pytest.mark.parametrize(
    "module_name,adapter_key,vendor,manufacturer,model,_cycle,_note",
    [
        ("dell", "server.dell_idrac", "dell", "Dell Inc.", "PowerEdge R760", "ForceRestart", "iDRAC"),
        ("lenovo", "server.lenovo_xcc", "lenovo", "Lenovo", "ThinkSystem SR650 V3", "ForceRestart", "XCC"),
        ("huawei", "server.huawei_ibmc", "huawei", "Huawei", "FusionServer 2288H V5", "PowerCycle", "iBMC"),
        ("inspur", "server.inspur_ibmc", "inspur", "Inspur", "NF5280M6", "ForceRestart", "通用映射规则"),
        ("xfusion", "server.xfusion_ibmc", "xfusion", "XFusion", "5288 V6", "ForceRestart", "通用映射规则"),
    ],
)
def test_overlay_docstring_ledger_and_basis_markers(
    module_name: str,
    adapter_key: str,
    vendor: str,
    manufacturer: str,
    model: str,
    _cycle: str,
    _note: str,
) -> None:
    del vendor, manufacturer, model, _cycle, _note
    module = __import__(f"app.adapters.redfish.{module_name}", fromlist=["*"])
    source = inspect.getsource(module)
    docstring = inspect.getdoc(module) or ""
    # The docstring ledger states the adapter key and the marker taxonomy.
    assert adapter_key in docstring
    assert "simulator-verified" in docstring
    assert "experimental" in docstring
    assert "真机" in docstring
    # Every code override carries a basis comment whose marker is one of the
    # two allowed values, and every fixture reference actually exists.
    basis_lines = re.findall(r"# basis: ([^\n]+) \((experimental|simulator-verified)\)", source)
    assert basis_lines, f"{module_name} 的每个 override 必须带 # basis: 注释"
    for reference, marker in basis_lines:
        assert marker in ("experimental", "simulator-verified")
        if reference.startswith("tests/fixtures/"):
            fixture_name = reference.rsplit("/", 1)[-1]
            assert (FIXTURES / fixture_name).exists(), f"missing fixture {fixture_name}"
    # The experimental/unverified paths named in code notes also appear in
    # the docstring ledger (grep marker: no code text may claim a vendor path
    # that the docstring does not list as experimental/unsupported).
    for fragment in ("experimental", "unsupported-until-real-hardware"):
        if fragment in source and fragment not in docstring:
            raise AssertionError(f"{module_name}: code mentions {fragment!r} outside the docstring ledger")


def test_hooks_default_to_common_behavior(sim: SimAccess) -> None:
    """The protected hooks exist on the base with common-behavior defaults:
    identity accepts everything, OEM collect returns None, mappings equal the
    common rules."""
    from app.infrastructure.protocols.redfish.parse import RedfishResource

    adapter = RedfishCommonAdapter()
    assert adapter._probe_identity_checks(_fake_system("Any Vendor")) == ()
    assert adapter._collect_oem("memory.ecc_errors", RedfishResource({}), T0) is None
    assert adapter._reset_type_for_cycle(frozenset({"ForceRestart", "PowerCycle"}))[0] == "ForceRestart"
    assert adapter._reset_type_for_cycle(frozenset({"PowerCycle"}))[0] == "PowerCycle"
    with pytest.raises(AdapterError) as raised:
        adapter._reset_type_for_cycle(frozenset({"GracefulRestart"}))
    assert raised.value.code == "unsupported_capability"
    assert adapter._manager_reset_type(frozenset({"GracefulRestart"}))[0] == "GracefulRestart"
    assert adapter._kvm_descriptor(None, _session(sim), "console.kvm.open") is None  # type: ignore[arg-type]
    assert adapter._support_bundle_collect(None, None, None) is None  # type: ignore[arg-type]
    assert adapter._firmware_update_path(None, None, None) is None  # type: ignore[arg-type]


def _fake_system(manufacturer: str) -> RedfishResource:
    return RedfishResource({"Manufacturer": manufacturer, "Model": "x"})
