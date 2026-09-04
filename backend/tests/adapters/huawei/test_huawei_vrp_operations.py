"""Huawei VRP CLI/SSH operation suites (M5T3) — real VRP simulator.

Drives preflight/execute/verify of CORE-ACT-01/02/04/05/07 +
ACCESS-ACT-01/02/03/05/06 through the adapter boundary over REAL asyncssh:
restart (save-prompt never answered, blip reconnect, uptime reset,
ambiguity), interface.admin.set readback, poe.port.set on/off/cycle +
delayed-state ambiguity, diagnostics/config/log artifacts (completion
marker + stored-hash verification), config backup/restore (full-replace
strategy + fingerprint round trip + inject-marker mismatch) and
firmware.update (SFTP image, boot variable, version bump readback).

The simulator is a TEST DEVICE SIMULATOR — never hardware evidence; every
evidence record carries the [sim] template basis (ADR-018).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace

import pytest
from app.adapters.huawei import ops as huawei_ops
from app.adapters.huawei.access import HuaweiVrpAccessAdapter
from app.adapters.huawei.base import AdapterError
from app.adapters.huawei.core import CERTIFIED_CORE_MODELS, HuaweiVrpCoreAdapter
from app.domain.adapter import DeviceSession
from app.domain.operation_plan import (
    CapabilityView,
    DeviceSnapshot,
    OperationRequest,
    plan_operation,
)
from tests.simulators.vrp.device import SSH_PASSWORD, SSH_USERNAME
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

UTC = datetime.UTC
CORE_ADAPTER = HuaweiVrpCoreAdapter()
ACCESS_ADAPTER = HuaweiVrpAccessAdapter()
CORE_MODELS = CERTIFIED_CORE_MODELS
ACCESS_MODELS = ("S5735-L48P4S-A1",)


def _deadline_ctx(seconds_ahead: float = 60.0) -> dict[str, object]:
    return {
        "task_timeout_at": (datetime.datetime.now(UTC) + datetime.timedelta(seconds=seconds_ahead)).isoformat()
    }


def _session(handle, *, device_type: str = "core_switch") -> DeviceSession:
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint="127.0.0.1",
        connection_config={
            "ssh_port": handle.port,
            "ssh_host_fingerprint": handle.host_fingerprint,
        },
        credentials={"ssh": {"username": SSH_USERNAME, "password": SSH_PASSWORD}},
    )


def _ssh_profile(
    snmp_port: int,
    ssh_port: int,
    *,
    adapter_key: str,
    fingerprint: str | None,
    credentials: dict[str, object] | None = None,
):
    """A probe profile carrying SNMP + SSH endpoints (wizard shape)."""
    from app.domain.adapter import ConnectionProfile

    config: dict[str, object] = {
        "snmp_version": "v3",
        "ssh_port": ssh_port,
    }
    if fingerprint is not None:
        config["ssh_host_fingerprint"] = fingerprint
    creds: dict[str, object] = {
        "snmp": {"username": "monitor", "auth_key": "sim-auth-key-1", "privacy_key": "sim-priv-key-1"},
        "ssh": {"username": SSH_USERNAME, "password": SSH_PASSWORD},
    }
    if credentials is not None:
        creds = credentials
    return ConnectionProfile(
        adapter_key=adapter_key,
        management_endpoint="127.0.0.1",
        port=snmp_port,
        connection_config=config,
        credentials=creds,
        verify_tls=False,
        tls_fingerprint_sha256=None,
    )


def _plan(
    adapter_key: str,
    device_type: str,
    key: str,
    parameters: dict[str, object],
    runtime: dict[str, object] | None = None,
):
    """A real plan through the domain planner (contract validation + rows)."""
    requirement_id = "CORE-ACT-01" if device_type == "core_switch" else "ACCESS-ACT-01"
    if key == "interface.admin.set":
        requirement_id = "CORE-ACT-02" if device_type == "core_switch" else "ACCESS-ACT-02"
    elif key == "poe.port.set":
        requirement_id = "ACCESS-ACT-03"
    elif key in ("logs.diagnostic.collect",):
        requirement_id = "CORE-ACT-04"
    elif key == "logs.collect":
        requirement_id = "ACCESS-ACT-05"
    elif key == "config.backup" or key == "config.restore":
        requirement_id = "CORE-ACT-05" if device_type == "core_switch" else "ACCESS-ACT-05"
    elif key == "firmware.update":
        requirement_id = "CORE-ACT-07" if device_type == "core_switch" else "ACCESS-ACT-06"
    elif key == "device.restart":
        requirement_id = "CORE-ACT-01" if device_type == "core_switch" else "ACCESS-ACT-01"
    snapshot = DeviceSnapshot(
        device_id=uuid.uuid4(),
        device_name="sim-switch",
        device_type=device_type,
        device_version=1,
        adapter_key=adapter_key,
        enabled=True,
        readiness="ready",
        capabilities=(
            CapabilityView(
                capability_key=key,
                support_state="supported",
                requirement_id=requirement_id,
                discovery_method=adapter_key,
                adapter_version="0.1.0",
            ),
        ),
    )
    plan = plan_operation(snapshot, OperationRequest(capability_key=key, parameters=parameters))
    if runtime is not None:
        plan = replace(plan, runtime_context=runtime)
    return plan


@contextmanager
def _core_vrp() -> Iterator[object]:
    with running_vrp_server("core_s5732") as handle:
        yield handle


@contextmanager
def _access_vrp() -> Iterator[object]:
    with running_vrp_server("access_s5735") as handle:
        yield handle


def _progress_listener():
    calls: list[tuple[int, str | None]] = []

    def on_progress(percent: int, step: str | None) -> None:
        calls.append((percent, step))

    return on_progress, calls


# ---------------------------------------------------------------------------
# restart


class TestRestart:
    def test_restart_full_flow_uptime_reset(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.restart_blip_seconds = 0.7
            session = _session(handle)
            plan = _plan("switch.huawei_vrp_core", "core_switch", "device.restart", {}, _deadline_ctx(60))
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is True, pre.detail
            progress, calls = _progress_listener()
            result = CORE_ADAPTER.execute_operation(session, plan, progress)
            assert result.ok and result.disconnected
            assert result.evidence["action"] == "reboot"
            assert calls and calls[-1][0] >= 90
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded, verdict.evidence
            assert verdict.evidence["disconnect_observed"] is True
            assert verdict.evidence["uptime_reset_seconds"] < 300
            assert verdict.evidence["identity_verified"]["serial"] == "SIM-S5732-0001"

    def test_restart_blocked_on_unsaved_configuration(self) -> None:
        with _core_vrp() as handle:
            handle.device.set_interface_admin("GigabitEthernet0/0/2", up=False)
            session = _session(handle)
            plan = _plan("switch.huawei_vrp_core", "core_switch", "device.restart", {}, _deadline_ctx(60))
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is False
            assert pre.error_code == "validation_failed"
            assert "未保存配置" in (pre.detail or "")

    def test_restart_save_prompt_is_never_answered(self) -> None:
        with _core_vrp() as handle:
            device = handle.device
            device.knobs.save_prompt = True
            device.set_interface_admin("GigabitEthernet0/0/3", up=False)
            session = _session(handle)
            plan = _plan("switch.huawei_vrp_core", "core_switch", "device.restart", {}, _deadline_ctx(60))
            # Preflight blocks dirty configs; the race (dirty between the
            # preflight and the fenced execute) hits the save prompt: the
            # executor must abort WITHOUT answering Y.
            with pytest.raises(AdapterError) as raised:
                CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert raised.value.code == "validation_failed"
            assert "不自动保存" in raised.value.message
            snapshot = device.snapshot()
            assert snapshot["dirty"] is True
            assert snapshot["uptime_seconds"] >= 3600  # never rebooted

    def test_restart_long_blip_is_ambiguous(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.restart_long = True
            session = _session(handle)
            # Small task deadline: the verify budget ends quickly -> ambiguous
            # (never failed + auto-replay).
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "device.restart",
                {},
                _deadline_ctx(7),
            )
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok and result.disconnected
            started = time.monotonic()
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded is False and verdict.ambiguous is True
            assert time.monotonic() - started < 30

    def test_restart_uptime_reset_without_offline_window_is_bounded_ambiguous(
        self, monkeypatch
    ) -> None:
        """Regression: the missed-offline-window corner must NOT spin forever.

        The reboot happens with no reachable offline window from the
        observer's perspective (blip 0: the device is already back and the
        uptime reset at the first reconnect). The verify loop must stop at
        its budget and report ambiguous_result — never an unbounded
        sleep/continue. The reconnect cap is overridden small so the test
        completes quickly even without a tight task deadline.
        """
        monkeypatch.setattr(huawei_ops, "VRP_RECONNECT_CAP_SECONDS", 3.0)
        with _core_vrp() as handle:
            handle.device.knobs.restart_blip_seconds = 0.0
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "device.restart",
                {},
                _deadline_ctx(60),
            )
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is True, pre.detail
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok and result.disconnected
            started = time.monotonic()
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            elapsed = time.monotonic() - started
            assert verdict.succeeded is False and verdict.ambiguous is True
            assert verdict.error_code == "ambiguous_result"
            assert "no offline window" in (verdict.evidence.get("reason") or "")
            # Bounded by the budget (~3 s), not a hang (the old code never
            # returned here).
            assert elapsed < 15

    def test_ssh_target_hostname_without_resolved_ip_is_refused(self) -> None:
        """SSRF guard parity with the DSM/Redfish boundary: the automation
        SSH channel must never resolve a hostname inside the adapter. A
        session whose management endpoint is a hostname and whose
        ``resolved_ip`` is absent is refused before any connect attempt."""
        with _core_vrp() as handle:
            session = _session(handle)
            session = replace(session, management_endpoint="switch-1.mgmt.example")
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "device.restart",
                {},
                _deadline_ctx(60),
            )
            with pytest.raises(AdapterError) as raised:
                CORE_ADAPTER.preflight_operation(session, plan)
            assert raised.value.code == "not_configured"
            assert "resolved_ip" in raised.value.message
            # A resolved policy IP is the accepted form (same endpoint text,
            # resolved_ip present): the refusal is about SSRF policy, not
            # about the endpoint spelling.
            session = replace(
                session, resolved_ip=ipaddress.ip_address("127.0.0.1")
            )
            assert CORE_ADAPTER.preflight_operation(session, plan).ok is True


# ---------------------------------------------------------------------------
# interface.admin.set


class TestInterfaceAdmin:
    def test_shutdown_and_undo_with_readback(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "interface.admin.set",
                {"interface_id": "GigabitEthernet0/0/2", "enabled": False},
                _deadline_ctx(30),
            )
            assert CORE_ADAPTER.preflight_operation(session, plan).ok
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok
            assert result.evidence["model"] == "S5732-H48XUM2CC"
            assert result.evidence["vrp_version"] == "V200R021C10SPC600"
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded, verdict.evidence
            assert verdict.evidence["admin_state_readback"] == "down"
            # Re-enable.
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "interface.admin.set",
                {"interface_id": "GigabitEthernet0/0/2", "enabled": True},
                _deadline_ctx(30),
            )
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.evidence["model"] == "S5732-H48XUM2CC"
            assert result.evidence["vrp_version"] == "V200R021C10SPC600"
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded
            assert verdict.evidence["admin_state_readback"] == "up"

    def test_unknown_interface_preflight_refused(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "interface.admin.set",
                {"interface_id": "GigabitEthernet0/0/99", "enabled": False},
                _deadline_ctx(30),
            )
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is False and pre.error_code == "validation_failed"


# ---------------------------------------------------------------------------
# poe.port.set (access)


class TestPoePortSet:
    def test_poe_on_off_and_cycle_with_off_transition_proof(self) -> None:
        with _access_vrp() as handle:
            session = _session(handle, device_type="access_switch")
            adapter = ACCESS_ADAPTER
            for mode, params in (
                ("on", {}),
                ("off", {}),
            ):
                plan = _plan(
                    "switch.huawei_vrp_access",
                    "access_switch",
                    "poe.port.set",
                    {"interface_id": "GigabitEthernet0/0/4", "mode": mode, **params},
                    _deadline_ctx(30),
                )
                assert adapter.preflight_operation(session, plan).ok
                result = adapter.execute_operation(session, plan, _progress_listener()[0])
                assert result.ok
                assert result.evidence["model"] == "S5735-L48P4S-A1"
                assert result.evidence["vrp_version"] == "V200R019C10SPC600"
                verdict = adapter.verify_operation(session, plan, result)
                assert verdict.succeeded, verdict.evidence
                assert verdict.evidence["poe_state_readback"] == mode
            # cycle: off_seconds=5 (contract minimum) then final on; the
            # execution evidence must show the off transition BEFORE on.
            plan = _plan(
                "switch.huawei_vrp_access",
                "access_switch",
                "poe.port.set",
                {"interface_id": "GigabitEthernet0/0/4", "mode": "cycle", "off_seconds": 5},
                _deadline_ctx(60),
            )
            result = adapter.execute_operation(session, plan, _progress_listener()[0])
            transitions = result.evidence["poe_transitions"]
            assert [t["readback"] for t in transitions] == ["off", "on"]
            verdict = adapter.verify_operation(session, plan, result)
            assert verdict.succeeded, verdict.evidence
            assert verdict.evidence["poe_state_readback"] == "on"

    def test_poe_on_non_poe_port_is_refused(self) -> None:
        with _access_vrp() as handle:
            session = _session(handle, device_type="access_switch")
            plan = _plan(
                "switch.huawei_vrp_access",
                "access_switch",
                "poe.port.set",
                {"interface_id": "XGigabitEthernet0/0/1", "mode": "on"},
                _deadline_ctx(30),
            )
            pre = ACCESS_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is False and pre.error_code == "validation_failed"

    def test_poe_delayed_state_is_ambiguous(self) -> None:
        with _access_vrp() as handle:
            handle.device.knobs.poe_delayed_seconds = 60.0
            session = _session(handle, device_type="access_switch")
            plan = _plan(
                "switch.huawei_vrp_access",
                "access_switch",
                "poe.port.set",
                {"interface_id": "GigabitEthernet0/0/5", "mode": "on"},
                _deadline_ctx(10),
            )
            with pytest.raises(AdapterError) as raised:
                ACCESS_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert raised.value.code == "ambiguous_result"


# ---------------------------------------------------------------------------
# diagnostics / logs / config backup (artifacts)


def _stored_proof(evidence: dict[str, object]) -> dict[str, object]:
    """The worker merges the stored file-row proof into the evidence
    (application/files.py store_operation_artifact) before verification."""
    merged = dict(evidence)
    merged["artifact_stored"] = {
        "file_id": str(uuid.uuid4()),
        "file_type": merged.get("artifact_kind", "operation_log"),
        "sha256": merged["artifact_sha256"],
        "encrypted": True,
        "status": "ready",
        "size_bytes": merged["artifact_bytes"],
    }
    return merged


class TestArtifactOperations:
    def test_diagnostics_collect_artifact_and_completion(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "logs.diagnostic.collect",
                {},
                _deadline_ctx(60),
            )
            assert CORE_ADAPTER.preflight_operation(session, plan).ok
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok
            assert len(result.artifacts) == 1
            artifact = result.artifacts[0]
            assert artifact.file_type == "operation_log"
            assert b"End of diagnostic information" in artifact.content_bytes
            assert result.evidence["completion_marker"] == "prompt_returned"
            verdict = CORE_ADAPTER.verify_operation(
                session, plan, replace(result, evidence=_stored_proof(result.evidence))
            )
            assert verdict.succeeded, verdict.evidence

    def test_logs_collect_on_access(self) -> None:
        with _access_vrp() as handle:
            session = _session(handle, device_type="access_switch")
            plan = _plan(
                "switch.huawei_vrp_access",
                "access_switch",
                "logs.collect",
                {},
                _deadline_ctx(60),
            )
            result = ACCESS_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            artifact = result.artifacts[0]
            assert artifact.file_type == "operation_log"
            assert b"End of log buffer" in artifact.content_bytes
            verdict = ACCESS_ADAPTER.verify_operation(
                session,
                plan,
                replace(result, evidence=_stored_proof(result.evidence)),
            )
            assert verdict.succeeded

    def test_artifact_hash_mismatch_fails_verification(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "logs.diagnostic.collect",
                {},
                _deadline_ctx(60),
            )
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            evidence = _stored_proof(result.evidence)
            evidence["artifact_stored"] = dict(evidence["artifact_stored"])
            evidence["artifact_stored"]["sha256"] = "0" * 64  # tampered store
            verdict = CORE_ADAPTER.verify_operation(
                session, plan, replace(result, evidence=evidence)
            )
            assert verdict.succeeded is False and verdict.error_code == "operation_failed"

    def test_config_backup_artifact_parse_and_hash(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "config.backup",
                {},
                _deadline_ctx(60),
            )
            assert CORE_ADAPTER.preflight_operation(session, plan).ok
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok
            artifact = result.artifacts[0]
            assert artifact.file_type == "config_backup"
            text = artifact.content_bytes.decode("utf-8")
            assert text.startswith("#\nsysname sim-s5732")
            assert result.evidence["parse_ok"] is True
            assert artifact.manifest["model"] == "S5732-H48XUM2CC"
            # The artifact content is the normalized text; its hash is the
            # restore comparison fingerprint.
            expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
            assert result.evidence["artifact_sha256"] == expected
            verdict = CORE_ADAPTER.verify_operation(
                session, plan, replace(result, evidence=_stored_proof(result.evidence))
            )
            assert verdict.succeeded, verdict.evidence


# ---------------------------------------------------------------------------
# config restore (single certified strategy: full replace)


class TestConfigRestore:
    def _backup(self, handle) -> tuple[bytes, str, str]:
        """Run a config.backup like the worker would (round trip source)."""
        session = _session(handle)
        plan = _plan(
            "switch.huawei_vrp_core", "core_switch", "config.backup", {}, _deadline_ctx(60)
        )
        result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
        artifact = result.artifacts[0]
        return artifact.content_bytes, artifact.manifest["model"], artifact.manifest["vrp_version"]

    def test_restore_round_trip_fingerprint_matches(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.restart_blip_seconds = 0.7
            content, model, vrp = self._backup(handle)
            session = _session(handle)
            fingerprint = hashlib.sha256(content).hexdigest()
            runtime = {
                **_deadline_ctx(90),
                "restore": {
                    "file_id": str(uuid.uuid4()),
                    "content_b64": base64.b64encode(content).decode("ascii"),
                    "model": model,
                    "vrp_major": "V200R021C10",
                    "sha256": fingerprint,
                },
            }
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "config.restore",
                {"file_id": str(uuid.uuid4())},
                runtime,
            )
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok, pre.detail
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok and result.disconnected
            assert result.evidence["certified_strategy"] == "full_replace_via_startup_config_and_reboot"
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded, verdict.evidence
            assert verdict.evidence["config_fingerprint"] == fingerprint
            # The device really runs the restored config now.
            assert handle.device.snapshot()["dirty"] is False

    def test_restore_identity_gate_rejects_foreign_backup(self) -> None:
        with _core_vrp() as handle:
            session = _session(handle)
            content = b"#\nsysname other-device\n#\nreturn\n"
            runtime = {
                **_deadline_ctx(60),
                "restore": {
                    "file_id": str(uuid.uuid4()),
                    "content_b64": base64.b64encode(content).decode("ascii"),
                    "model": "S5732-H48XUM2CC",
                    "vrp_major": "V200R021C10",
                    "sha256": hashlib.sha256(content).hexdigest(),
                },
            }
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "config.restore",
                {"file_id": str(uuid.uuid4())},
                runtime,
            )
            # Wrong model metadata -> refused pre-fence.
            wrong_model = dict(runtime)
            wrong_model["restore"] = dict(runtime["restore"])
            wrong_model["restore"]["model"] = "S5735-L48P4S-A1"
            plan2 = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "config.restore",
                {"file_id": str(uuid.uuid4())},
                wrong_model,
            )
            pre = CORE_ADAPTER.preflight_operation(session, plan2)
            assert pre.ok is False and pre.error_code == "validation_failed"
            assert "不匹配" in (pre.detail or "")
            del plan

    def test_restore_injected_config_mismatch_fails(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.config_inject_marker = True
            handle.device.knobs.restart_blip_seconds = 0.7
            content, model, _vrp = self._backup(handle)
            session = _session(handle)
            fingerprint = hashlib.sha256(content).hexdigest()
            runtime = {
                **_deadline_ctx(90),
                "restore": {
                    "file_id": str(uuid.uuid4()),
                    "content_b64": base64.b64encode(content).decode("ascii"),
                    "model": model,
                    "vrp_major": "V200R021C10",
                    "sha256": fingerprint,
                },
            }
            plan = _plan(
                "switch.huawei_vrp_core",
                "core_switch",
                "config.restore",
                {"file_id": str(uuid.uuid4())},
                runtime,
            )
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok and result.disconnected
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded is False
            assert verdict.error_code == "operation_failed"
            assert "fingerprint" in (verdict.evidence.get("reason") or "")


# ---------------------------------------------------------------------------
# firmware.update


def _image_bytes(model: str, version: str) -> bytes:
    header = (
        "WARDEN-SIM-FW " + json.dumps({"model": model, "version": version}) + "\n"
    )
    return (header + "padding-bytes-for-the-upgrade-image\n").encode("utf-8")


class TestFirmwareUpdate:
    def _firmware_plan(self, handle, *, expected_version: str, sha256: str, image: bytes):
        def stream() -> Iterator[bytes]:
            for index in range(0, len(image), 4096):
                yield image[index : index + 4096]

        runtime = {
            **_deadline_ctx(120),
            "file": {
                "file_id": str(uuid.uuid4()),
                "expected_model": "S5732-H48XUM2CC",
                "expected_version": expected_version,
                "sha256": sha256,
                "stream": stream,
            },
        }
        return _plan(
            "switch.huawei_vrp_core",
            "core_switch",
            "firmware.update",
            {"file_id": str(uuid.uuid4())},
            runtime,
        )

    def test_firmware_update_version_and_boot_image_readback(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.restart_blip_seconds = 0.7
            image = _image_bytes("S5732-H48XUM2CC", "V200R021C10SPC610")
            sha = hashlib.sha256(image).hexdigest()
            session = _session(handle)
            plan = self._firmware_plan(handle, expected_version="V200R021C10SPC610", sha256=sha, image=image)
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok, pre.detail
            result = CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert result.ok and result.disconnected
            assert result.evidence["image_file"] == "firmware-V200R021C10SPC610.bin"
            verdict = CORE_ADAPTER.verify_operation(session, plan, result)
            assert verdict.succeeded, verdict.evidence
            assert verdict.evidence["version_readback"] == "V200R021C10SPC610"
            assert verdict.evidence["boot_image_readback"] == "firmware-V200R021C10SPC610.bin"

    def test_firmware_preflight_blocks_unsaved_config(self) -> None:
        with _core_vrp() as handle:
            handle.device.set_interface_admin("GigabitEthernet0/0/2", up=False)
            image = _image_bytes("S5732-H48XUM2CC", "V200R021C10SPC610")
            sha = hashlib.sha256(image).hexdigest()
            session = _session(handle)
            plan = self._firmware_plan(handle, expected_version="V200R021C10SPC610", sha256=sha, image=image)
            pre = CORE_ADAPTER.preflight_operation(session, plan)
            assert pre.ok is False
            assert "未保存配置" in (pre.detail or "")

    def test_firmware_sftp_failure_is_operation_failed(self) -> None:
        with _core_vrp() as handle:
            handle.device.knobs.sftp_fail = True
            image = _image_bytes("S5732-H48XUM2CC", "V200R021C10SPC610")
            sha = hashlib.sha256(image).hexdigest()
            session = _session(handle)
            plan = self._firmware_plan(handle, expected_version="V200R021C10SPC610", sha256=sha, image=image)
            with pytest.raises(AdapterError) as raised:
                CORE_ADAPTER.execute_operation(session, plan, _progress_listener()[0])
            assert raised.value.code == "operation_failed"

# ---------------------------------------------------------------------------
# probe ssh stage + discovery rows with SSH declared (dual sims)


class TestSshProbeStageAndDiscovery:
    def test_probe_includes_ssh_stage_with_pinned_fingerprint(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h, running_vrp_server("core_s5732") as v:
            profile = _ssh_profile(
                h.port,
                v.port,
                adapter_key="switch.huawei_vrp_core",
                fingerprint=v.host_fingerprint,
            )
            result = CORE_ADAPTER.probe(profile)
            assert result.ok, [s.detail_safe for s in result.stages]
            stages = {stage.stage: stage for stage in result.stages}
            assert set(stages) == {"network", "auth", "ssh", "identity", "capabilities"}
            assert stages["ssh"].ok is True
            assert "指纹校验通过" in (stages["ssh"].detail_safe or "")

    def test_probe_ssh_stage_reports_first_connect_capture(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h, running_vrp_server("core_s5732") as v:
            profile = _ssh_profile(
                h.port, v.port, adapter_key="switch.huawei_vrp_core", fingerprint=None
            )
            result = CORE_ADAPTER.probe(profile)
            assert result.ok, [s.detail_safe for s in result.stages]
            ssh = next(stage for stage in result.stages if stage.stage == "ssh")
            assert "实际指纹" in (ssh.detail_safe or "")
            assert v.host_fingerprint in (ssh.detail_safe or "")

    def test_probe_ssh_host_key_mismatch_fails_onboarding(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h, running_vrp_server("core_s5732") as v:
            profile = _ssh_profile(
                h.port,
                v.port,
                adapter_key="switch.huawei_vrp_core",
                fingerprint="SHA256:" + "A" * 43,
            )
            result = CORE_ADAPTER.probe(profile)
            assert result.ok is False
            ssh = next(stage for stage in result.stages if stage.stage == "ssh")
            assert ssh.ok is False and ssh.error_code == "validation_failed"
            assert "host_key_mismatch" in (ssh.detail_safe or "")
            # Stages after the ssh failure are honestly not executed.
            tail = [stage for stage in result.stages if stage.error_code is None and not stage.ok]
            assert any(stage.stage == "identity" for stage in tail)

    def test_discovery_operation_rows_flip_supported_with_ssh_configured(self, switch_agent) -> None:
        with switch_agent(profile_key="core_s5732") as h:
            fingerprint = "SHA256:" + "A" * 43
            profile = _ssh_profile(
                h.port, 22, adapter_key="switch.huawei_vrp_core", fingerprint=fingerprint
            )
            discovery = CORE_ADAPTER.discover(profile)
            rows = {row.capability_key: row for row in discovery.capabilities}
            wired = CORE_ADAPTER.ssh_operation_keys
            for key in wired:
                assert rows[key].support_state == "supported", (key, rows[key].detail)
                assert rows[key].reason_code is None
                assert "[sim]" in (rows[key].detail or ""), key
            # M5T4: console.ssh.open is wired and flips supported with the
            # SSH config; console.telnet.open still needs telnet credentials
            # + the device opt-in; M5T5 console.web.open needs a declared
            # Web origin (not_configured here — the profile has none);
            # transceiver.diagnose stays honest unsupported.
            ssh_terminal = rows["console.ssh.open"]
            assert ssh_terminal.support_state == "supported", ssh_terminal.detail
            assert ssh_terminal.reason_code is None
            telnet_terminal = rows["console.telnet.open"]
            assert telnet_terminal.support_state == "not_configured", telnet_terminal.detail
            assert telnet_terminal.reason_code == "telnet_credential_missing"
            web_console = rows["console.web.open"]
            assert web_console.support_state == "not_configured", web_console.detail
            assert web_console.reason_code == "web_console_unconfigured", web_console.detail
            diagnose = rows["transceiver.diagnose"]
            assert diagnose.support_state == "unsupported", diagnose.detail
            assert diagnose.reason_code == "mapping_missing", diagnose.detail

    def test_discovery_without_fingerprint_is_not_configured(self, switch_agent) -> None:
        with switch_agent(profile_key="access_s5735") as h:
            profile = _ssh_profile(
                h.port, 22, adapter_key="switch.huawei_vrp_access", fingerprint=None
            )
            discovery = ACCESS_ADAPTER.discover(profile)
            rows = {row.capability_key: row for row in discovery.capabilities}
            row = rows["poe.port.set"]
            assert row.support_state == "not_configured"
            assert row.reason_code == "ssh_host_fingerprint_missing"
