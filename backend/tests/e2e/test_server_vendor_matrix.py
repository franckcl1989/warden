"""M3T6 M3 gate: five-vendor server adapter platform E2E matrix (integration).

Runs ALL FIVE registered vendor adapter keys (server.dell_idrac,
server.inspur_ibmc, server.xfusion_ibmc, server.lenovo_xcc,
server.huawei_ibmc) against their OWN TEST-DEVICE simulator vendor profile
through the real platform paths (real API server + real PostgreSQL + real
worker executor):

- onboard (probe identity gate accept -> save enabled ready, device row
  carries the vendor self-reported identity);
- a health collection run + a metrics collection run through the real
  claim/run path -> collection_runs succeeded, devices.reachability becomes
  online (hysteresis semantics: first success on an unknown device is
  positive evidence) and metric_latest carries the vendor-namespaced OEM
  members (memory.ecc_errors / drive.smart / raid.status) with healthy
  semantics;
- one low-risk operation (firmware.query) end-to-end via the API
  preview/confirm chain + the operation pool executor -> succeeded with the
  persisted firmware inventory evidence;
- ONE full power.cycle slice: the Huawei profile additionally runs the
  high-risk power.cycle confirm chain (reauth -> preview -> confirm) and the
  worker executes it with the certified Huawei ResetType pin (PowerCycle,
  the vendor's preferred mapping) recorded in the task evidence, the
  simulator records the same ResetType device-side (``last_system_resets``)
  and the task verification passes.

Why one full power.cycle slice suffices for the platform mechanics: power
actions are identical mechanics across vendor profiles (same
preview/confirm/fence/execute/read-back verification path — proven per
profile by the simulator). The ONLY per-vendor difference is the certified
ResetType pin, and each pin is unit-tested with device-side recording in
tests/adapters/test_redfish_vendors.py (TestResetMapping, all five keys,
incl. Dell/Lenovo ForceRestart-only and the Huawei PowerCycle->ForceRestart
fallback/refusal edges); the Dell ForceRestart pin is additionally proven
end-to-end on the same platform wiring by
tests/adapters/test_redfish_vendor_platform_slice.py. Huawei is chosen here
because its pin (PowerCycle) is the distinct certified mapping of the three
vendor-pinned adapters (Dell/Lenovo share ForceRestart), so the suite as a
whole records both pin families at platform level.

Foreign-vendor rejection (API level): onboarding a Dell-profile simulator
device with server.lenovo_xcc fails the probe identity gate with
``validation_failed`` (the adapter never accepts a foreign Manufacturer);
the failure token may only save the device as ``not_ready`` +
``enabled=false`` — the device can never be saved as enabled under a
mis-registered key.

Honest label: this module proves SIMULATOR-verified mechanics only — the
simulator is a TEST DEVICE SIMULATOR, never 真机 evidence
(HARDWARE_CERTIFICATION.md §3); the certification matrix stays
``not_started`` and no hardware-support claim is made anywhere in this file.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import text

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME
from tests.adapters.test_redfish_vendor_platform_slice import (
    PlatformRig,
    _control,
    _login,
)
from tests.api.auth_helpers import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.simulators.redfish.app import SimulatorConfig
from tests.simulators.redfish.serving import serve_simulator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"

# (simulator vendor profile, adapter key, self-reported Manufacturer,
#  self-reported Model, certified power.cycle pin on the full advertisement,
#  whether the matrix runs the full power.cycle slice for this vendor).
# Simulator-authored identity strings only — never real-device evidence.
VENDOR_CASES = (
    ("dell", "server.dell_idrac", "Dell Inc.", "PowerEdge R760", "ForceRestart", False),
    ("inspur", "server.inspur_ibmc", "Inspur", "NF5280M6", "ForceRestart", False),
    ("xfusion", "server.xfusion_ibmc", "XFusion", "5288 V6", "ForceRestart", False),
    ("lenovo", "server.lenovo_xcc", "Lenovo", "ThinkSystem SR650 V3", "ForceRestart", False),
    ("huawei", "server.huawei_ibmc", "Huawei", "FusionServer 2288H V5", "PowerCycle", True),
)

PIN_INDEX = 4  # position of the certified-pin column in VENDOR_CASES rows
CYCLE_SLICE_INDEX = 5  # position of the run-full-power.cycle-slice column


@contextmanager
def serve_vendor_simulator(vendor: str) -> Iterator[str]:
    with serve_simulator(SimulatorConfig(profile="healthy", vendor=vendor)) as url:
        yield url


def _sim_control(sim_url: str) -> dict[str, object]:
    with httpx.Client(base_url=sim_url, timeout=10.0) as client:
        response = client.get("/warden-sim/control")
        assert response.status_code == 200
        return response.json()


def _print_evidence(label: str, evidence: dict[str, object]) -> None:
    print(f"\n=== M3T6-MATRIX evidence: {label} ===")
    print(json.dumps(evidence, ensure_ascii=False, indent=2, default=str))


def _close_rig(rig: PlatformRig) -> None:
    """Dispose every engine the rig created (incl. the API factory engine the
    base class never disposes) so no psycopg connection survives the test."""
    rig.close()
    bind = getattr(rig.factory, "kw", {}).get("bind")
    if bind is not None:
        bind.dispose()


def _onboard(
    client: httpx.Client,
    csrf: str,
    sim_url: str,
    *,
    name: str,
    adapter_key: str,
    enabled: bool = True,
) -> dict[str, object]:
    """Probe + save against ``sim_url`` with the given adapter key."""
    port = int(urlsplit(sim_url).port or 0)
    probe = client.post(
        f"{API}/device-probes",
        json={
            "device_type": "server",
            "adapter_key": adapter_key,
            "management_endpoint": SIM_HOST,
            "port": port,
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, probe.text
    created = client.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": "server",
            "adapter_key": adapter_key,
            "management_endpoint": SIM_HOST,
            "port": port,
            "connection_config": {"protocol": "http"},
            "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
            "enabled": enabled,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _run_collection(rig: PlatformRig, device_id: uuid.UUID, collection_type: str) -> None:
    """Schedule, claim and run one collection of ``collection_type`` (real path)."""
    from app.application.collection import run_collection
    from app.infrastructure.observation_store import claim_collection_run
    from app.infrastructure.time import utcnow
    from app.models.observation import CollectionRun

    with rig.factory() as session:
        run = CollectionRun(
            device_id=device_id,
            collection_type=collection_type,
            scheduled_at=utcnow(),
            state="scheduled",
            attempt_count=0,
        )
        session.add(run)
        session.commit()
        run_id = run.id
    with rig.factory() as session:
        claimed = claim_collection_run(
            session, lease_owner="m3t6-matrix-worker", lease_seconds=300
        )
        assert claimed is not None and claimed.id == run_id
        session.commit()
    with rig.factory() as session:
        run_collection(session, run_id, settings=rig.settings, keyring=rig.keyring, now=utcnow())
        session.commit()
    with rig.factory() as session:
        row = session.execute(
            text("SELECT state, success_count, failure_count FROM collection_runs WHERE id = :id"),
            {"id": run_id},
        ).one()
        mapped = dict(row._mapping)
        _print_evidence(f"collection-{collection_type}", {"run_id": str(run_id), **mapped})
        assert mapped["state"] == "succeeded"
        assert mapped["failure_count"] == 0


def _confirm_operation(
    client: httpx.Client,
    csrf: str,
    device_id: str,
    *,
    capability_key: str,
    confirmation_text: str,
    idempotency_key: str,
) -> str:
    preview = client.post(
        f"{API}/devices/{device_id}/operation-previews",
        json={"capability_key": capability_key, "parameters": {}},
        headers={"X-CSRF-Token": csrf},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    token = str(body["preview_token"])
    assert body["risk_level"] == ("high" if capability_key == "power.cycle" else "low")
    confirmed = client.post(
        f"{API}/devices/{device_id}/operations",
        json={"preview_token": token, "confirmation_text": confirmation_text},
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": idempotency_key},
    )
    assert confirmed.status_code == 202, confirmed.text
    return str(confirmed.json()["id"])


def _audit_actions(rig: PlatformRig, task_id: uuid.UUID) -> set[str]:
    with rig.factory() as session:
        rows = session.execute(
            text("SELECT action FROM audit_logs WHERE task_id = :id"),
            {"id": task_id},
        ).all()
    return {str(row._mapping["action"]) for row in rows}


def _metric_rows_by_key(
    rig: PlatformRig, device_id: uuid.UUID
) -> dict[tuple[str, str | None, str | None], dict[str, object]]:
    with rig.factory() as session:
        rows = session.execute(
            text(
                "SELECT ml.metric_key, ml.value_double, ml.value_text, ml.unit, "
                "c.kind, c.native_id "
                "FROM metric_latest ml LEFT JOIN components c ON c.id = ml.component_id "
                "WHERE ml.device_id = :id"
            ),
            {"id": device_id},
        ).all()
    by_key: dict[tuple[str, str | None, str | None], dict[str, object]] = {}
    for row in rows:
        mapped = dict(row._mapping)
        kind = mapped["kind"] if isinstance(mapped["kind"], str) else None
        native = mapped["native_id"] if isinstance(mapped["native_id"], str) else None
        by_key[(str(mapped["metric_key"]), kind, native)] = mapped
    return by_key


# -- the five-vendor matrix -------------------------------------------------


@pytest.mark.parametrize(
    "vendor,adapter_key,manufacturer,model,cycle_pin,run_cycle",
    VENDOR_CASES,
)
def test_vendor_profile_matrix_slice(
    vendor: str,
    adapter_key: str,
    manufacturer: str,
    model: str,
    cycle_pin: str,
    run_cycle: bool,
    fresh_test_db_dsn: str,
    tmp_path,
    monkeypatch,
) -> None:
    """One vendor's full platform slice: onboard -> health+metrics collect ->
    firmware.query via API+worker; the Huawei case additionally runs the full
    power.cycle slice and asserts the certified pin in the task evidence."""
    with serve_vendor_simulator(vendor) as sim_url:
        _control(sim_url, task_duration_seconds=0.05, power_blip_seconds=0.4)
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=30.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                name = f"m3t6-{vendor}-srv"
                onboarded = _onboard(client, csrf, sim_url, name=name, adapter_key=adapter_key)
                device_id = uuid.UUID(onboarded["id"])
                assert onboarded["adapter_key"] == adapter_key
                assert onboarded["readiness"] == "ready"
                assert onboarded["enabled"] is True
                assert onboarded["vendor"] == manufacturer
                _print_evidence(
                    f"onboarded-{vendor}",
                    {
                        "adapter_key": adapter_key,
                        "vendor": onboarded["vendor"],
                        "model": onboarded["model"],
                    },
                )
                caps = client.get(f"{API}/devices/{device_id}/capabilities")
                assert caps.status_code == 200
                cap_items = caps.json()["items"]
                assert len(cap_items) == 31
                assert all(item["support_state"] == "supported" for item in cap_items)
                assert all(item["discovery_method"] == adapter_key for item in cap_items)

                with rig.factory() as session:
                    device = session.execute(
                        text(
                            "SELECT vendor, model, serial_number, firmware_version, "
                            "reachability FROM devices WHERE id = :id"
                        ),
                        {"id": device_id},
                    ).one()
                    identity = dict(device._mapping)
                    _print_evidence(f"device-row-{vendor}", identity)
                    assert identity["vendor"] == manufacturer
                    assert identity["model"] == model

                # Health collection: reachability + health semantics.
                _run_collection(rig, device_id, "health")
                with rig.factory() as session:
                    device = session.execute(
                        text("SELECT reachability, consecutive_successes FROM devices WHERE id = :id"),
                        {"id": device_id},
                    ).one()
                    mapped = dict(device._mapping)
                    assert mapped["reachability"] == "online"
                    assert mapped["consecutive_successes"] >= 1
                    _print_evidence(f"reachability-{vendor}", mapped)
                health_rows = _metric_rows_by_key(rig, device_id)
                assert health_rows[("health.overall", None, None)]["value_text"] == "healthy"

                # Metrics collection: vendor-namespaced OEM members.
                _run_collection(rig, device_id, "metrics")
                by_key = _metric_rows_by_key(rig, device_id)
                assert by_key[("health.overall", None, None)]["value_text"] == "healthy"
                assert by_key[("memory.ecc_errors", "memory", "DIMM0")]["value_double"] == 3
                assert by_key[("memory.ecc_errors", "memory", "DIMM0")]["unit"] == "1"
                assert by_key[("drive.smart", "drive", "sda")]["value_text"] == "passed"
                assert by_key[("raid.status", "raid", "RAID6_1")]["value_text"] == "optimal"
                _print_evidence(
                    f"metrics-after-collect-{vendor}",
                    {"rows": [dict(row) for _, row in sorted(by_key.items())]},
                )

                # Low-risk operation end-to-end (API confirm chain + worker).
                task_id = _confirm_operation(
                    client,
                    csrf,
                    str(device_id),
                    capability_key="firmware.query",
                    confirmation_text=name,
                    idempotency_key=f"m3t6-{vendor}-firmware-query-0001",
                )
                rig.rig.start_pool()
                try:
                    row = rig.rig.wait_terminal(uuid.UUID(task_id), states=("succeeded",))
                finally:
                    rig.rig.stop_pool()
                assert row.state == "succeeded"
                assert row.verification_state == "passed"
                execution = (row.evidence or {}).get("execution") or {}
                firmware_items = execution.get("firmware_items")
                assert isinstance(firmware_items, list)
                item_targets = {
                    item.get("target") for item in firmware_items if isinstance(item, dict)
                }
                assert item_targets == {"BMC", "BIOS"}
                assert all(
                    isinstance(item.get("version"), str) and item.get("version")
                    for item in firmware_items
                    if isinstance(item, dict)
                )
                assert execution.get("manager_firmware_version") == "SIM-BMC-1.0.0"
                audit = _audit_actions(rig, uuid.UUID(task_id))
                assert audit >= {"operation.create", "operation.start", "operation.finish"}
                _print_evidence(
                    f"firmware-query-{vendor}",
                    {
                        "task_id": task_id,
                        "verification_state": row.verification_state,
                        "firmware_items": firmware_items,
                        "manager_firmware_version": execution.get("manager_firmware_version"),
                        "audit_actions": sorted(audit),
                    },
                )

                if run_cycle:
                    # The Huawei full power.cycle slice: reauth -> confirm
                    # chain -> worker execution with the certified pin.
                    assert (
                        client.post(
                            f"{API}/auth/reauth",
                            json={"password": ADMIN_PASSWORD},
                            headers={"X-CSRF-Token": csrf},
                        ).status_code
                        == 200
                    )
                    cycle_task_id = _confirm_operation(
                        client,
                        csrf,
                        str(device_id),
                        capability_key="power.cycle",
                        confirmation_text=name,
                        idempotency_key=f"m3t6-{vendor}-cycle-0001",
                    )
                    rig.rig.start_pool()
                    try:
                        cycle_row = rig.rig.wait_terminal(
                            uuid.UUID(cycle_task_id), states=("succeeded",)
                        )
                    finally:
                        rig.rig.stop_pool()
                    assert cycle_row.state == "succeeded"
                    assert cycle_row.verification_state == "passed"
                    cycle_execution = (cycle_row.evidence or {}).get("execution") or {}
                    assert cycle_execution.get("reset_type") == cycle_pin
                    assert "PowerCycle" in str(cycle_execution.get("mapping"))
                    snapshot = _sim_control(sim_url)
                    assert snapshot["last_system_resets"] == [cycle_pin]
                    assert snapshot["system_power"] == "On"
                    audit = _audit_actions(rig, uuid.UUID(cycle_task_id))
                    assert audit >= {
                        "operation.create",
                        "operation.start",
                        "operation.finish",
                    }
                    _print_evidence(
                        f"power-cycle-{vendor}",
                        {
                            "task_id": cycle_task_id,
                            "reset_type": cycle_execution.get("reset_type"),
                            "mapping": cycle_execution.get("mapping"),
                            "verification_state": cycle_row.verification_state,
                            "simulator_last_system_resets": snapshot["last_system_resets"],
                            "simulator_system_power": snapshot["system_power"],
                            "audit_actions": sorted(audit),
                        },
                    )
        finally:
            _close_rig(rig)


# -- foreign-vendor rejection at the API level ------------------------------


def test_foreign_vendor_profile_is_rejected_at_onboarding(
    fresh_test_db_dsn: str,
    tmp_path,
    monkeypatch,
) -> None:
    """A Dell-profile device probed with server.lenovo_xcc fails the probe
    identity gate; the failure token may only save the device as not_ready
    with enabled=false (never enabled under a mis-registered adapter key)."""
    with serve_vendor_simulator("dell") as sim_url:
        rig = PlatformRig(fresh_test_db_dsn, tmp_path, monkeypatch, sim_url)
        try:
            with rig.serving() as base_url, httpx.Client(base_url=base_url, timeout=30.0) as client:
                csrf = _login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
                port = int(urlsplit(sim_url).port or 0)
                probe = client.post(
                    f"{API}/device-probes",
                    json={
                        "device_type": "server",
                        "adapter_key": "server.lenovo_xcc",
                        "management_endpoint": SIM_HOST,
                        "port": port,
                        "connection_config": {"protocol": "http"},
                        "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                assert probe.status_code == 200, probe.text
                body = probe.json()
                assert body["ok"] is False
                assert body["discovery"] is None
                assert body["probe_token"]
                stages = {item["stage"]: item for item in body["stages"]}
                identity = stages["identity"]
                assert identity["ok"] is False
                assert identity["error_code"] == "validation_failed"
                detail = identity["detail"] or ""
                assert "Dell Inc." in detail
                assert "server.lenovo_xcc" in detail
                assert stages["capabilities"]["ok"] is False
                assert stages["capabilities"]["error_code"] is None
                _print_evidence(
                    "foreign-probe-rejection",
                    {
                        "adapter_key": "server.lenovo_xcc",
                        "simulator_vendor_profile": "dell",
                        "identity_stage": identity,
                    },
                )
                # The failure token may only save as not_ready + disabled,
                # even when the caller asks for enabled=true.
                created = client.post(
                    f"{API}/devices",
                    json={
                        "name": "m3t6-foreign-dell-as-lenovo",
                        "device_type": "server",
                        "adapter_key": "server.lenovo_xcc",
                        "management_endpoint": SIM_HOST,
                        "port": port,
                        "connection_config": {"protocol": "http"},
                        "credentials": {"username": SIM_USERNAME, "password": SIM_PASSWORD},
                        "enabled": True,
                        "probe_token": body["probe_token"],
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                assert created.status_code == 201, created.text
                saved = created.json()
                assert saved["readiness"] == "not_ready"
                assert saved["enabled"] is False
                assert saved["vendor"] is None
                device_id = uuid.UUID(saved["id"])
                with rig.factory() as session:
                    capability_count = session.execute(
                        text("SELECT count(*) FROM device_capabilities WHERE device_id = :id"),
                        {"id": device_id},
                    ).scalar_one()
                    assert capability_count == 0
                _print_evidence(
                    "foreign-save-outcome",
                    {
                        "device_id": str(device_id),
                        "readiness": saved["readiness"],
                        "enabled": saved["enabled"],
                        "capability_rows": capability_count,
                    },
                )
        finally:
            _close_rig(rig)


# -- sanity of the matrix definition ----------------------------------------


def test_matrix_definition_pins_and_profiles() -> None:
    """The matrix row set stays the five registered certification targets."""
    from app.adapters.registry import ADAPTERS

    keys = {row[1] for row in VENDOR_CASES}
    assert keys == {
        "server.dell_idrac",
        "server.inspur_ibmc",
        "server.xfusion_ibmc",
        "server.lenovo_xcc",
        "server.huawei_ibmc",
    }
    assert keys <= set(ADAPTERS)
    cycle_rows = {row[1]: row[PIN_INDEX] for row in VENDOR_CASES}
    assert cycle_rows["server.huawei_ibmc"] == "PowerCycle"
    assert cycle_rows["server.dell_idrac"] == "ForceRestart"
    assert cycle_rows["server.lenovo_xcc"] == "ForceRestart"
    assert cycle_rows["server.inspur_ibmc"] == "ForceRestart"
    assert cycle_rows["server.xfusion_ibmc"] == "ForceRestart"
    # Exactly one vendor carries the full power.cycle slice (mechanics are
    # identical across profiles; the pins are unit-tested per vendor).
    assert sum(row[CYCLE_SLICE_INDEX] for row in VENDOR_CASES) == 1
    assert VENDOR_CASES[4][0] == "huawei"
