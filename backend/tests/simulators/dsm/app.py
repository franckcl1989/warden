"""Configurable Synology DSM test-device simulator (ASGI).

THIS IS A TEST DEVICE SIMULATOR — a fake DSM for repeatable automated
tests. It is NOT evidence of hardware support for DS224+/DS225+ or any real
DSM: fixtures captured from it must state their 模拟器来源 (module README +
fixtures README), and the hardware certification matrix
(hardware-targets.json / HARDWARE_CERTIFICATION.md §3) stays ``not_started``
until real-device runs exist (ADR-018 — real DSM behavior requires
target-model certification). API names served beyond the Login-guide
documented pair (SYNO.API.Info/SYNO.API.Auth) are simulator-invented
placeholders for the DSM control-panel/Storage-Manager families; the module
README lists every name's basis.

Served DSM WebAPI surface (envelopes ``{"success", "data|error"}`` per the
DSM Login Web API guide; common error codes 100..108 = guide block):

- ``/webapi/query.cgi`` SYNO.API.Info.Query (``query=all``) -> the API map;
- ``/webapi/auth.cgi`` SYNO.API.Auth login/logout -> ``sid`` sessions
  (login failures: 401 wrong credentials; 403 two-step required);
- ``/webapi/entry.cgi`` authenticated family APIs: SYNO.Core.System
  (info/shutdown/restart), SYNO.Storage.CGI.Storage (load_info, async
  SMART test via taskid), SYNO.Core.Share (list — shared folders with
  usage bytes + quota bytes), SYNO.Core.UPS (get), SYNO.Core.System.Log
  (paged), SYNO.Core.Upgrade (async update job via taskid, PAT fetch +
  reboot + version bump), SYNO.Core.Support (export — generated support
  bundle downloaded from a device-origin URL), SYNO.Core.Backup (list —
  backup/snapshot package + job statuses) and SYNO.Core.Network.SNMP
  (get/set — trap enable + platform receiver address).
- ``/`` — the DSM web origin (the console.dsm.open launch target);
  ``/support/export/<token>.zip`` — raw support-bundle downloads.

Device lifecycle (M4T3, power/system methods): a restart clears sessions and
tasks and makes every non-control endpoint answer HTTP 503 for
``restart_blip_seconds`` (the reconnect window); a shutdown powers the
device off (503 until ``power_on`` control); a DSM update installs for
``upgrade_duration_seconds``, then reboots for ``upgrade_offline_seconds``
before serving the new firmware version. ``restart_ignored`` /
``shutdown_ignored`` accept without the effect (ambiguous verify paths),
``restart_identity_changes`` swaps the serial after a restart (identity
drift), ``smart_test_never_completes`` / ``update_never_completes`` keep the
job running forever (deadline -> verification_required), and
``upgrade_fetch_required`` makes the update fetch the platform PAT ticket
URL (recorded as device-fetch evidence) and apply the header version.

Profiles (constructor ``SimulatorConfig`` or the live control endpoint):

- ``healthy`` (default), ``ds224plus``/``ds225plus`` (the M4T2 vendor-model
  profiles naming the hardware-targets units — identity only, model/serial/
  DSM version differ; always ``(simulated)``-marked),
  ``degraded`` (degraded pool + broken/failed disk, UPS on battery, fan 1
  broken at 0 rpm, near-full volume usage data), ``auth_fail`` (login always
  rejected), ``api_map_missing`` (the monitoring-critical Storage API absent
  from the map), ``slow_paginated`` (150 log entries, page size 20).

Live control (no auth): ``GET /warden-sim/control`` for state;
``POST /warden-sim/control`` with ``{"profile": ...}``,
``{"storage_degraded": bool}``, ``{"pool_rebuilding": bool}``,
``{"ups_on_battery": bool}``, ``{"ups_absent": bool}``,
``{"fan_broken": bool}``, ``{"fan_zero_rpm": bool}``,
``{"share_no_quota": bool}``, ``{"log_append": int}``,
``{"storage_maintenance": bool}``, ``{"backup_no_jobs": bool}``,
``{"backup_snapshot_available": bool}``,
``{"upgrade_fetch_required": bool}``, ``{"upgrade_target_version": str}``,
``{"smart_quick_duration_seconds": ...}``,
``{"smart_full_duration_seconds": ...}``, ``{"upgrade_duration_seconds":
...}``, ``{"upgrade_offline_seconds": ...}``, ``{"restart_blip_seconds":
...}``, ``{"power_on": true}``, ``{"snmp_config": {...}}``,
``{"missing_apis": [..]}``, ``{"storage_max_version": int}``,
``{"failures": {...}}`` or ``{"expire_sessions": true}``. Profile switches
force the profile-owned knobs to their presets and reset the runtime state
(sessions/tasks/power/firmware/trap config — constructor knob combinations
are preserved).

Failure injection keys: ``login_reject`` (401), ``login_otp`` (403
two-step), ``reads_500`` (HTTP 500), ``error_unknown_2100`` (unmapped DSM
code 2100 — the client must preserve it, never guess),
``sessions_reject_106`` (every authenticated call answers 106 even after
re-login — bounded re-login must fail honestly), ``smart_test_fails``,
``smart_test_never_completes``, ``update_fails``, ``update_never_completes``,
``restart_ignored``, ``shutdown_ignored``, ``restart_identity_changes``.
"""

from __future__ import annotations

import hmac
import json
import time
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx

from tests.simulators.dsm import payloads
from tests.simulators.dsm.payloads import SimulatorConfig, TaskRecord

CONTROL_PATH = "/warden-sim/control"

# Parameters every DSM API request carries.
API_PARAM = "api"
METHOD_PARAM = "method"
VERSION_PARAM = "version"
SID_PARAM = "_sid"

PROFILE_KEYS = frozenset({"profile"})
FAILURE_KEYS = frozenset(
    {
        "login_reject",
        "login_otp",
        "reads_500",
        "error_unknown_2100",
        "sessions_reject_106",
        "smart_test_fails",
        "smart_test_never_completes",
        "update_fails",
        "update_never_completes",
        "restart_ignored",
        "shutdown_ignored",
        "restart_identity_changes",
    }
)
BOOL_KNOB_KEYS = frozenset(
    {
        "storage_degraded",
        "pool_rebuilding",
        "ups_on_battery",
        "ups_absent",
        "fan_broken",
        "fan_zero_rpm",
        "share_no_quota",
        "storage_maintenance",
        "backup_no_jobs",
        "backup_snapshot_available",
        "upgrade_fetch_required",
    }
)
FLOAT_KNOB_KEYS = frozenset(
    {
        "smart_quick_duration_seconds",
        "smart_full_duration_seconds",
        "upgrade_duration_seconds",
        "upgrade_offline_seconds",
        "restart_blip_seconds",
    }
)
STRING_KNOB_KEYS = frozenset({"upgrade_target_version"})
INT_KNOB_KEYS = frozenset({"log_append"})

# The DSM web origin served at ``/`` while the device is on line.
WEB_INDEX = (
    b"<!doctype html><html><head><title>DSM (simulated)</title></head>"
    b"<body><h1>DSM WebAPI origin (simulated test device)</h1>"
    b"<p>This is the console.dsm.open launch target of the Warden DSM test "
    b"simulator - never hardware evidence.</p></body></html>"
)


def _offline_status(state: _SimulatorState, now: float) -> int | None:
    """HTTP status for device-level unavailability (None = online).

    DSM power-off, the restart blip window and the update reboot window all
    make every non-control endpoint answer 503 — the adapter's
    expected_disconnect verify treats that as the offline window.
    """
    if state.power == "off":
        return 503
    if state.restart_until > now:
        return 503
    for task in state.tasks.values():
        if task.kind != "update" or task.fails or task.never_completes or task.reboot_seconds <= 0:
            continue
        elapsed = now - task.created_monotonic
        if task.duration_seconds <= elapsed < task.duration_seconds + task.reboot_seconds:
            return 503
    return None


class _SimulatorState:
    def __init__(self, cfg: SimulatorConfig) -> None:
        self.cfg = cfg
        self.failures: dict[str, bool] = dict.fromkeys(FAILURE_KEYS, False)
        self.sessions: dict[str, float] = {}  # sid -> created monotonic
        self.session_counter = 0
        self.tasks: dict[int, TaskRecord] = {}
        self.task_counter = 0
        self.storage_max_version: int | None = None
        self.power = "on"
        self.restart_until = 0.0
        self.firmware_override: str | None = None
        self.serial_override: str | None = None
        self.pending_serial_change = False
        self.applied_updates: set[int] = set()
        self.snmp_enabled = False
        self.snmp_receiver = ""
        self.traps: list[dict[str, object]] = []
        self.exported_bundles: dict[str, bytes] = {}
        self.device_fetches: list[str] = []
        self.device_fetch_attempts: list[dict[str, object]] = []

    @property
    def effective_firmware(self) -> str:
        if self.firmware_override is not None:
            return self.firmware_override
        return payloads.identity_firmware_version(self.cfg)

    def reset_dynamic(self) -> None:
        """Drop runtime state (sessions/tasks/power/identity/traps) after
        profile switches — a profile switch means a FRESH test device."""
        self.sessions.clear()
        self.session_counter = 0
        self.tasks.clear()
        self.task_counter = 0
        self.power = "on"
        self.restart_until = 0.0
        self.firmware_override = None
        self.serial_override = None
        self.pending_serial_change = False
        self.applied_updates.clear()
        self.snmp_enabled = False
        self.snmp_receiver = ""
        self.traps.clear()
        self.exported_bundles.clear()
        self.device_fetches.clear()
        self.device_fetch_attempts.clear()

    def finalize_reboots(self) -> None:
        """Apply the effects of finished update reboots (version bump) and
        restart windows (identity-change failure knob) — lazily on the first
        request served after the device is back."""
        now = time.monotonic()
        for task in self.tasks.values():
            if task.kind != "update" or task.never_completes or task.fails:
                continue
            if task.task_id in self.applied_updates:
                continue
            elapsed = now - task.created_monotonic
            if elapsed < task.duration_seconds + task.reboot_seconds:
                continue
            if task.target_version is not None:
                self.firmware_override = task.target_version
            self.applied_updates.add(task.task_id)
        if self.pending_serial_change and self.restart_until <= now:
            self.serial_override = "SIM-DS224P-CHANGED (simulated)"
            self.pending_serial_change = False

    def api_map(self) -> dict[str, dict[str, object]]:
        return self.cfg.inflated_map(storage_max_version=self.storage_max_version)

    def snapshot(self) -> dict[str, object]:
        return {
            "profile": self.cfg.profile,
            "username": self.cfg.username,
            "smart_quick_duration_seconds": self.cfg.smart_quick_duration_seconds,
            "smart_full_duration_seconds": self.cfg.smart_full_duration_seconds,
            "upgrade_duration_seconds": self.cfg.upgrade_duration_seconds,
            "upgrade_offline_seconds": self.cfg.upgrade_offline_seconds,
            "restart_blip_seconds": self.cfg.restart_blip_seconds,
            "log_total": self.cfg.log_total,
            "log_page_size": self.cfg.log_page_size,
            "log_append": self.cfg.log_append,
            "storage_degraded": self.cfg.storage_degraded,
            "pool_rebuilding": self.cfg.pool_rebuilding,
            "ups_on_battery": self.cfg.ups_on_battery,
            "ups_absent": self.cfg.ups_absent,
            "fan_broken": self.cfg.fan_broken,
            "fan_zero_rpm": self.cfg.fan_zero_rpm,
            "share_no_quota": self.cfg.share_no_quota,
            "storage_maintenance": self.cfg.storage_maintenance,
            "backup_no_jobs": self.cfg.backup_no_jobs,
            "backup_snapshot_available": self.cfg.backup_snapshot_available,
            "upgrade_fetch_required": self.cfg.upgrade_fetch_required,
            "upgrade_target_version": self.cfg.upgrade_target_version,
            "missing_apis": sorted(self.cfg.missing_apis),
            "storage_max_version": self.storage_max_version,
            "failures": dict(self.failures),
            "power": self.power,
            "firmware": self.effective_firmware,
            "serial": self.serial_override
            if self.serial_override is not None
            else payloads.identity_of(self.cfg)["serial"],
            "snmp": {"enabled": self.snmp_enabled, "receiver_address": self.snmp_receiver},
            "traps": [dict(trap) for trap in self.traps],
            "exported_bundles": len(self.exported_bundles),
            "device_fetches": list(self.device_fetches),
            "device_fetch_attempts": [dict(attempt) for attempt in self.device_fetch_attempts],
            "logins": self.session_counter,
            "sessions": len(self.sessions),
            "tasks": len(self.tasks),
        }

    def apply_control(self, body: object) -> dict[str, object]:
        """Apply a control mutation; raises ValueError on unknown keys."""
        if not isinstance(body, dict):
            msg = "control body must be a JSON object"
            raise ValueError(msg)
        for key, value in body.items():
            if key == "profile":
                if value not in payloads.PROFILES:
                    msg = f"unknown profile {value!r}"
                    raise ValueError(msg)
                if value != self.cfg.profile:
                    self.cfg = payloads.profile_config(value, base=self.cfg)
                    self.reset_dynamic()
            elif key == "reset_state":
                if not isinstance(value, bool):
                    msg = "reset_state must be a boolean"
                    raise ValueError(msg)
                if value:
                    self.reset_dynamic()
            elif key == "power_on":
                if not isinstance(value, bool):
                    msg = "power_on must be a boolean"
                    raise ValueError(msg)
                if value and self.power == "off":
                    self.power = "on"
                    self.restart_until = 0.0
            elif key == "snmp_config":
                if not isinstance(value, dict):
                    msg = "snmp_config must be an object"
                    raise ValueError(msg)
                enabled = value.get("enabled")
                receiver = value.get("receiver_address")
                if not isinstance(enabled, bool) or not isinstance(receiver, str):
                    msg = "snmp_config needs boolean enabled and string receiver_address"
                    raise ValueError(msg)
                self.snmp_enabled = enabled
                self.snmp_receiver = receiver if enabled else ""
            elif key in FLOAT_KNOB_KEYS:
                if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                    msg = f"{key} must be a positive number"
                    raise ValueError(msg)
                self.cfg = replace(self.cfg, **{key: float(value)})
            elif key in STRING_KNOB_KEYS:
                if not isinstance(value, str):
                    msg = f"{key} must be a string"
                    raise ValueError(msg)
                self.cfg = replace(self.cfg, **{key: value})
            elif key in BOOL_KNOB_KEYS:
                self.cfg = replace(self.cfg, **{key: bool(value)})
            elif key in INT_KNOB_KEYS:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    msg = f"{key} must be a non-negative integer"
                    raise ValueError(msg)
                self.cfg = replace(self.cfg, **{key: int(value)})
            elif key == "missing_apis":
                if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                    msg = "missing_apis must be a list of API names"
                    raise ValueError(msg)
                self.cfg = replace(self.cfg, missing_apis=tuple(value))
            elif key == "storage_max_version":
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    msg = "storage_max_version must be a positive integer"
                    raise ValueError(msg)
                self.storage_max_version = value
            elif key == "expire_sessions":
                if not isinstance(value, bool):
                    msg = "expire_sessions must be a boolean"
                    raise ValueError(msg)
                if value:
                    self.sessions.clear()
            elif key == "failures":
                if not isinstance(value, dict):
                    msg = "failures must be an object"
                    raise ValueError(msg)
                unknown = set(value) - FAILURE_KEYS
                if unknown:
                    msg = f"unknown failure keys: {sorted(unknown)}"
                    raise ValueError(msg)
                for failure_key, enabled in value.items():
                    self.failures[failure_key] = bool(enabled)
            else:
                msg = f"unknown control key {key!r}"
                raise ValueError(msg)
        return self.snapshot()


# -- request handling --------------------------------------------------------


@dataclass
class _Request:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body_object: object = None
    body: dict[str, list[str]] | None = None


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    return values[0]


def _as_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _as_bool(raw: str | None) -> bool | None:
    if raw in ("true", "1"):
        return True
    if raw in ("false", "0"):
        return False
    return None


def _disk_ids(state: _SimulatorState) -> set[str]:
    """The disk ids the current storage payload serves (any profile)."""
    body = payloads.storage_payload(state.cfg)
    data = body.get("data")
    if not isinstance(data, dict):
        return set()
    raw_disks = data.get("disk")
    if not isinstance(raw_disks, list):
        return set()
    ids: set[str] = set()
    for disk in raw_disks:
        if isinstance(disk, dict) and isinstance(disk.get("id"), str):
            ids.add(disk["id"])
    return ids


class _Dispatcher:
    def __init__(self, state: _SimulatorState) -> None:
        self.state = state

    # -- main dispatch ------------------------------------------------------

    def handle(self, request: _Request) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        path = "/" + request.path.strip("/") if request.path.strip("/") else "/"
        # Apply finished update reboots / restart windows on every request so
        # control snapshots and WebAPI reads agree after a boot.
        state.finalize_reboots()

        # The control endpoint is exempt from device power/lifecycle gates
        # (tests must be able to inspect and power the device back on).
        if path == CONTROL_PATH and request.method in ("GET", "POST"):
            if request.method == "GET":
                return 200, state.snapshot(), {}
            try:
                snapshot = state.apply_control(request.body_object)
            except ValueError:
                return 400, payloads.error(101), {}
            return 200, snapshot, {}

        # DSM web origin: served while the device is on line only.
        if path == "/" and request.method == "GET":
            if _offline_status(state, time.monotonic()) is not None:
                return 503, None, {}
            return 200, WEB_INDEX, {"content-type": "text/html; charset=utf-8"}

        # Raw support-bundle download endpoint (device origin, no session).
        if path.startswith("/support/export/") and request.method == "GET":
            name = path.rsplit("/", 1)[-1]
            token = name[:-4] if name.endswith(".zip") else name
            content = state.exported_bundles.get(token)
            if content is None:
                return 404, None, {}
            return 200, content, {"content-type": "application/zip"}

        if not path.startswith(payloads.BASE):
            return 404, None, {}
        if _offline_status(state, time.monotonic()) is not None:
            # DSM is powered off / restarting / applying an update: every
            # WebAPI endpoint answers HTTP 503 (the expected_disconnect
            # window the operation verify loops poll through).
            return 503, None, {}
        params = self._combined_params(request)
        api = _first(params, API_PARAM)
        method = _first(params, METHOD_PARAM)
        if api is None or method is None:
            return 200, payloads.error(101), {}

        # Version enforcement per the advertised map (common code 104): a
        # caller above/below the device's range is told so honestly.
        version = _as_int(_first(params, VERSION_PARAM))
        if version is not None:
            entry = state.api_map().get(api)
            if entry is not None:
                lo = int(entry["minVersion"])
                hi = int(entry["maxVersion"])
                if version < lo or version > hi:
                    return 200, payloads.error(104), {}

        # SYNO.API.Info.Query is anonymous (documented); everything else
        # needs a valid session (the DSM session model).
        if api == "SYNO.API.Info":
            if method != "query":
                return 200, payloads.error(103), {}
            return 200, payloads.api_info_payload(state.api_map()), {}

        if api not in state.api_map():
            return 200, payloads.error(102), {}
        if api == "SYNO.API.Auth":
            return self._auth(api, method, params)
        if self._authenticated(params) is None:
            return 200, payloads.error(106), {}
        if state.failures["sessions_reject_106"]:
            return 200, payloads.error(106), {}
        return self._family_api(api, method, params)

    def _combined_params(self, request: _Request) -> dict[str, list[str]]:
        combined: dict[str, list[str]] = {}
        for source in (request.query, request.body or {}):
            for key, values in source.items():
                combined.setdefault(key, []).extend(values)
        return combined

    # -- auth ---------------------------------------------------------------

    def _auth(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        if method == "login":
            return self._login(params)
        if method == "logout":
            sid = _first(params, SID_PARAM)
            if sid is not None:
                state.sessions.pop(sid, None)
            return 200, payloads.logout_payload(), {}
        return 200, payloads.error(103), {}

    def _login(self, params: dict[str, list[str]]) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        account = _first(params, "account")
        passwd = _first(params, "passwd")
        if account is None or passwd is None:
            return 200, payloads.error(101), {}
        if state.failures["login_otp"]:
            # Two-step verification required on the account: honest 403
            # (simulator DSL row; real-DSM login codes certified in M4T2).
            return 200, payloads.error(403), {}
        if state.failures["login_reject"] or state.cfg.profile == "auth_fail":
            return 200, payloads.error(401), {}
        if not (hmac.compare_digest(account, state.cfg.username) and hmac.compare_digest(passwd, state.cfg.password)):
            return 200, payloads.error(401), {}
        state.session_counter += 1
        sid = uuid.uuid4().hex
        state.sessions[sid] = time.monotonic()
        return 200, payloads.login_payload(sid), {}

    def _authenticated(self, params: dict[str, list[str]]) -> str | None:
        state = self.state
        sid = _first(params, SID_PARAM)
        if sid is not None and sid in state.sessions:
            return state.cfg.username
        return None

    # -- family APIs --------------------------------------------------------

    def _family_api(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        if state.failures["reads_500"]:
            return 500, payloads.error(100), {}
        if state.failures["error_unknown_2100"]:
            return 200, payloads.error(2100), {}
        if api == "SYNO.Core.System":
            return self._system(api, method, params)
        if api == "SYNO.Storage.CGI.Storage":
            return self._storage(api, method, params)
        if api == "SYNO.Core.Share":
            if method != "list":
                return 200, payloads.error(103), {}
            return 200, payloads.share_payload(state.cfg), {}
        if api == "SYNO.Core.UPS":
            if method != "get":
                return 200, payloads.error(103), {}
            return 200, payloads.ups_payload(state.cfg), {}
        if api == "SYNO.Core.System.Log":
            return self._log(api, method, params)
        if api == "SYNO.Core.Upgrade":
            return self._upgrade(api, method, params)
        if api == "SYNO.Core.Support":
            return self._support(api, method, params)
        if api == "SYNO.Core.Backup":
            if method != "list":
                return 200, payloads.error(103), {}
            return 200, payloads.backup_payload(state.cfg), {}
        if api == "SYNO.Core.Network.SNMP":
            return self._snmp(api, method, params)
        return 200, payloads.error(102), {}

    def _system(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        if method == "info":
            body = payloads.system_info_payload(state.cfg)
            if not isinstance(body, dict):
                return 200, payloads.error(100), {}
            data = body.get("data")
            if isinstance(data, dict):
                # Runtime identity: the upgrade version bump and the
                # restart-identity-change failure knob patch the canned
                # profile payload.
                if state.firmware_override is not None:
                    data["firmware"] = state.firmware_override
                if state.serial_override is not None:
                    data["serial"] = state.serial_override
            return 200, body, {}
        if method == "shutdown":
            if state.failures["shutdown_ignored"]:
                # The device accepted but never powers down: the verify
                # window must end ambiguous (honest, never a fake success).
                return 200, payloads.success({}), {}
            state.sessions.clear()
            state.tasks.clear()
            state.power = "off"
            state.restart_until = 0.0
            state.pending_serial_change = False
            return 200, payloads.success({}), {}
        if method == "restart":
            if state.failures["restart_ignored"]:
                return 200, payloads.success({}), {}
            state.sessions.clear()
            state.tasks.clear()
            state.restart_until = time.monotonic() + state.cfg.restart_blip_seconds
            if state.failures["restart_identity_changes"]:
                state.pending_serial_change = True
            else:
                state.pending_serial_change = False
                state.serial_override = None
            return 200, payloads.success({}), {}
        return 200, payloads.error(103), {}

    def _storage(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        if method == "load_info":
            body = payloads.storage_payload(state.cfg)
            # Report every RUNNING device job on load_info (absent when none
            # run — honest device state the operation preflights read).
            running: list[dict[str, object]] = []
            for task in state.tasks.values():
                status, _progress = task.state_at(time.monotonic())
                if status != "running":
                    continue
                row: dict[str, object] = {"kind": task.kind, "taskid": task.task_id}
                if task.disk is not None:
                    row["disk"] = task.disk
                running.append(row)
            data = body.get("data")
            if isinstance(data, dict) and running:
                data["active_jobs"] = running
            return 200, body, {}
        if method == "smart_test":
            disk = _first(params, "disk")
            smart_type = _first(params, "type")
            if disk is None or smart_type not in ("quick", "full"):
                return 200, payloads.error(101), {}
            if disk not in _disk_ids(state):
                return 200, payloads.error(101), {}
            state.task_counter += 1
            task_id = state.task_counter
            duration = (
                state.cfg.smart_quick_duration_seconds
                if smart_type == "quick"
                else state.cfg.smart_full_duration_seconds
            )
            state.tasks[task_id] = TaskRecord(
                task_id=task_id,
                kind="smart",
                created_monotonic=time.monotonic(),
                duration_seconds=duration,
                fails=state.failures["smart_test_fails"],
                never_completes=state.failures["smart_test_never_completes"],
                disk=disk,
            )
            return 200, payloads.smart_test_payload(task_id), {}
        if method == "smart_task_status":
            task = self._task(params)
            if task is None:
                return 200, payloads.error(101), {}
            status, progress = task.state_at(time.monotonic())
            return 200, payloads.smart_task_status_payload(task.task_id, status, progress), {}
        return 200, payloads.error(103), {}

    def _support(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        del params
        state = self.state
        if method != "export":
            return 200, payloads.error(103), {}
        content = payloads.support_bundle_bytes(state.cfg)
        token = uuid.uuid4().hex
        state.exported_bundles[token] = content
        # The download path is DEVICE-ORIGIN ONLY (a relative path on the
        # same host/port): the M4T3 adapter refuses absolute/foreign URLs.
        return 200, payloads.success({"file": f"/support/export/{token}.zip"}), {}

    def _snmp(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        if method == "get":
            return 200, payloads.snmp_config_payload(state.snmp_enabled, state.snmp_receiver), {}
        if method == "set":
            enabled_raw = _first(params, "enabled")
            receiver = _first(params, "receiver_address")
            enabled = _as_bool(enabled_raw)
            if enabled is None or receiver is None:
                return 200, payloads.error(101), {}
            if enabled and not receiver:
                return 200, payloads.error(101), {}
            if enabled:
                state.snmp_enabled = True
                state.snmp_receiver = receiver
                # The DSL "test trap" emission record: the platform ingest
                # receiver (M5) will attribute real traps; nothing here
                # fabricates a received trap for the platform.
                state.traps.append(
                    {
                        "at": datetime.now(UTC).isoformat(),
                        "receiver_address": receiver,
                        "enabled": True,
                    }
                )
            else:
                state.snmp_enabled = False
                state.snmp_receiver = ""
            return 200, payloads.snmp_config_payload(state.snmp_enabled, state.snmp_receiver), {}
        return 200, payloads.error(103), {}

    def _task(self, params: dict[str, list[str]]) -> TaskRecord | None:
        task_id = _as_int(_first(params, "taskid"))
        if task_id is None:
            return None
        return self.state.tasks.get(task_id)

    def _log(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        if method != "list":
            return 200, payloads.error(103), {}
        offset = _as_int(_first(params, "offset")) or 0
        limit = _as_int(_first(params, "limit")) or self.state.cfg.log_page_size
        if offset < 0 or limit <= 0:
            return 200, payloads.error(101), {}
        return 200, payloads.log_entries_payload(self.state.cfg, offset=offset, limit=limit), {}

    def _upgrade(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, Any, dict[str, str]]:
        state = self.state
        if method == "upgrade":
            state.task_counter += 1
            task_id = state.task_counter
            url = _first(params, "url")
            target_version: str | None = None
            fails = state.failures["update_fails"]
            never = state.failures["update_never_completes"]
            if not never and not fails:
                target_version = self._resolve_update_target(url)
                if target_version is None and state.cfg.upgrade_fetch_required:
                    # A required PAT fetch that failed is a DEVICE-side
                    # failure of the accepted job (honest status, never a
                    # fabricated bump).
                    fails = True
            state.tasks[task_id] = TaskRecord(
                task_id=task_id,
                kind="update",
                created_monotonic=time.monotonic(),
                duration_seconds=state.cfg.upgrade_duration_seconds,
                fails=fails,
                never_completes=never,
                target_version=target_version,
                reboot_seconds=state.cfg.upgrade_offline_seconds if target_version is not None else 0.0,
            )
            return 200, payloads.upgrade_payload(task_id), {}
        if method == "update_task_status":
            task = self._task(params)
            if task is None:
                return 200, payloads.error(101), {}
            status, progress = task.state_at(time.monotonic())
            return 200, payloads.update_task_status_payload(task.task_id, status, progress), {}
        return 200, payloads.error(103), {}

    def _resolve_update_target(self, url: str | None) -> str | None:
        """The version the update job will apply: the fetched PAT header
        version when ``upgrade_fetch_required``, else the bump knob."""
        state = self.state
        if not state.cfg.upgrade_fetch_required:
            override = state.cfg.upgrade_target_version.strip()
            if override:
                return override
            return payloads.bump_firmware_version(state.effective_firmware)
        if url is None or not url.startswith(("http://", "https://")):
            return None
        attempt: dict[str, object] = {"url": url, "at": time.monotonic(), "ok": False}
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False) as http:
                response = http.get(url)
                attempt["status"] = response.status_code
                if response.status_code != 200:
                    self.state.device_fetch_attempts.append(attempt)
                    return None
                content = response.content
        except httpx.HTTPError:
            self.state.device_fetch_attempts.append(attempt)
            return None
        attempt["ok"] = True
        self.state.device_fetch_attempts.append(attempt)
        self.state.device_fetches.append(url)
        header = self._pat_header(content)
        if header is None:
            return None
        model = header.get("model")
        version = header.get("version")
        if not (isinstance(model, str) and isinstance(version, str) and model and version):
            return None
        if model != payloads.identity_of(self.state.cfg)["model"]:
            return None
        return version

    @staticmethod
    def _pat_header(content: bytes) -> dict[str, object] | None:
        """The warden-sim PAT header (first line) the platform also parses.

        DSL shape only: ``WARDEN-SIM-PAT <json>`` with ``model``/``version``
        members — real Synology PAT metadata parsing is vendor_private
        ([sim] basis until target-model certification, ADR-018).
        """
        marker = b"WARDEN-SIM-PAT "
        line, _, _ = content.partition(b"\n")
        if not line.startswith(marker):
            return None
        try:
            payload = json.loads(line[len(marker) :].strip().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return payload if isinstance(payload, dict) else None


# -- ASGI -------------------------------------------------------------------


async def _receive_body(receive: Any) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] != "http.request":
            continue
        body.extend(message.get("body", b""))
        if not message.get("more_body"):
            return bytes(body)


class SimulatorASGI:
    """ASGI adapter around the dispatcher (plain ASGI: no server dependency)."""

    def __init__(self, state: _SimulatorState) -> None:
        self._state = state
        self._dispatcher = _Dispatcher(state)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if scope["type"] != "http":
            return
        raw_body = await _receive_body(receive)
        content_type = ""
        for name, value in scope.get("headers", []):
            if name.decode("latin-1").lower() == "content-type":
                content_type = value.decode("latin-1")
        body: object = None
        form: dict[str, list[str]] | None = None
        if raw_body:
            if "application/x-www-form-urlencoded" in content_type:
                form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
            else:
                try:
                    body = json.loads(raw_body)
                except ValueError:
                    body = None
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("utf-8")
        headers: dict[str, str] = {}
        for name, value in scope.get("headers", []):
            headers[name.decode("latin-1").lower()] = value.decode("latin-1")
        request = _Request(
            method=scope.get("method", "GET"),
            path=unquote(path),
            query=parse_qs(query_string, keep_blank_values=True),
            headers=headers,
            body_object=body,
            body=form,
        )
        status, payload, extra_headers = self._dispatcher.handle(request)
        await self._respond(send, status, payload, extra_headers)

    @staticmethod
    async def _respond(
        send: Any,
        status: int,
        payload: dict[str, Any] | bytes | None,
        extra_headers: dict[str, str],
    ) -> None:
        response_headers: list[tuple[bytes, bytes]] = []
        content_type = "application/json"
        if isinstance(payload, bytes):
            content_type = extra_headers.get("content-type", "application/octet-stream")
        response_headers.append((b"content-type", content_type.encode("latin-1")))
        for key, value in extra_headers.items():
            if key == "content-type":
                continue
            response_headers.append((key.encode("latin-1"), value.encode("latin-1")))
        body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload).encode("utf-8")
            if payload is not None
            else b""
        )
        response_headers.append((b"content-length", str(len(body)).encode("ascii")))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_simulator(config: SimulatorConfig | None = None) -> SimulatorASGI:
    """Create the simulator ASGI app (one state per app instance).

    A constructor profile is normalized to its preset knobs (same code path
    as the live ``profile`` control switch).
    """
    base = config if config is not None else SimulatorConfig()
    normalized = payloads.profile_config(base.profile, base=base)
    return SimulatorASGI(_SimulatorState(normalized))
