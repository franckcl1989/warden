"""Configurable Redfish test-device simulator (ASGI).

THIS IS A TEST DEVICE SIMULATOR — a fake BMC for repeatable automated tests.
It is NOT evidence of hardware support: fixtures captured from it must state
their 模拟器来源 (module README + fixtures README), and the hardware
certification matrix (hardware-targets.json / HARDWARE_CERTIFICATION.md §3)
stays ``not_started`` until real-device runs exist. Vendor OEM blocks here are
neutral stubs; vendor overlays (M3T5) define the real per-vendor shapes from
certification fixtures.

Served Redfish surface (DSP2046 shape, driven by the M3 needs of
DEVICE_ADAPTERS.md §4): ServiceRoot, Systems/1 (ComputerSystem + Reset,
Memory with OEM ECC counters, Storage/Drives/Volumes with OEM SMART/RAID
state), Chassis/1 (Thermal sensors+fans, Power PSUs, PhysicalSecurity,
IndicatorLED), Managers/1 (Manager + Reset, LogServices/SEL with paginated
Entries, VirtualMedia with InsertMedia/EjectMedia), UpdateService
(FirmwareInventory + SimpleUpdate), SessionService/AccountService, and a
TaskService with 202+Location tasks (Running 50% -> Completed, or Exception
under failure injection).

Profiles (constructor ``SimulatorConfig`` or the live control endpoint):

- ``healthy``: all statuses OK, sensors inside thresholds;
- ``critical``: overall/critical component statuses, intrusion detected,
  blinking indicator, PSU absent, predictive-failing drive, ECC errors;
- ``auth_fail``: login is always rejected with 401;
- ``slow_paginated``: 150 SEL entries served in pages of 20
  (``sel_append`` grows the SEL by extra strictly-newer tail entries).

``SimulatorConfig.absolute_links`` (control key ``absolute_links``) rewrites
every path-only link the simulator emits (``@odata.id``, ``@odata.nextLink``,
action ``target``, ``Location``, ``TaskMonitor``) into absolute same-origin
URIs built from the request's own origin — a spec-legal style real managers
use, which the client must accept.

Failure injection (``POST /warden-sim/control {"failures": {...}}``):
``login_401``, ``reads_500``, ``reads_403``, ``reads_429``,
``reset_rejected_400``, ``reset_forbidden_403``, ``reset_task_fails``.
Control also switches ``profile``/``vendor``/``pagination``/
``task_duration_seconds``, the SRV-MON surface knobs (``SimulatorConfig``
booleans + integer ``sel_append``), and reports the live state on
``GET /warden-sim/control``.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

from tests.simulators.redfish import payloads
from tests.simulators.redfish.payloads import SimulatorConfig, _View

CONTROL_PATH = "/warden-sim/control"
PROFILE_PROPERTIES = frozenset({"profile", "vendor", "pagination", "task_duration_seconds"})
FAILURE_KEYS = frozenset(
    {
        "login_401",
        "reads_500",
        "reads_403",
        "reads_429",
        "reset_rejected_400",
        "reset_forbidden_403",
        "reset_task_fails",
        "update_task_fails",
    }
)
# M3T2 SRV-MON surface knobs (SimulatorConfig booleans switchable via control).
SURFACE_KNOB_KEYS = frozenset(
    {
        "missing_memory_metrics",
        "no_raid_volume",
        "empty_sel",
        "thermal_missing_context",
        "no_virtual_media",
        "no_storage",
        "missing_system_status",
        "sel_oem_timestamps",
        "missing_fan_reading",
        "drives_without_oem",
        "no_graphical_console",
        # M3T3 operation knobs (booleans).
        "power_readback_stale",
        "media_insert_rejects_foreign_url",
        "media_fetch_required",
        "media_insert_delayed",
        "update_fetch_required",
        "update_reboot_loop",
        "reset_never_completes",
        "update_never_completes",
        "no_graceful_shutdown",
    }
)
# Integer-valued surface knobs (per-test reset mirrors booleans with 0).
INT_KNOB_KEYS = frozenset({"sel_append"})
# Float-valued operation knobs + their pristine defaults (conftest reset).
FLOAT_KNOB_KEYS = frozenset({"power_blip_seconds", "manager_blip_seconds"})
FLOAT_KNOB_DEFAULTS: dict[str, float] = {"power_blip_seconds": 0.5, "manager_blip_seconds": 1.2}
# String-valued operation knobs.
STRING_KNOB_KEYS = frozenset({"firmware_update_version"})
STRING_KNOB_DEFAULTS: dict[str, str] = {"firmware_update_version": ""}

_NEVER_COMPLETES_DURATION = 1e9

_IMAGE_HEADER_MARKER = b"WARDEN-SIM-FW "
_IMAGE_HEADER_MAX = 4096

# How long a delayed InsertMedia takes to apply to the slot state
# (media_insert_delayed knob): long enough that the FIRST verify read-back
# still observes an empty slot, short enough that the second bounded re-poll
# proves the insert.
MEDIA_INSERT_DELAY_SECONDS = 2.0

_FAIL_ACTION_MESSAGE = "Simulated reset failure (test device simulator)"


@dataclass
class TaskRecord:
    task_id: str
    name: str
    created_monotonic: float
    duration_seconds: float
    fails: bool = False
    effect: str | None = None
    effect_target: str | None = None
    effect_version: str | None = None
    applied: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def state_at(self, now: float) -> tuple[str, str, int]:
        """(TaskState, TaskStatus, percent) at monotonic ``now``."""
        elapsed = now - self.created_monotonic
        if elapsed < self.duration_seconds:
            return "Running", "Running", 50
        if self.fails:
            return "Exception", "Exception", 50
        return "Completed", "OK", 100


def _image_header_version(content: bytes) -> str | None:
    """Target firmware version declared in a warden-sim image header.

    The warden-sim firmware image format (test-device convention only) starts
    with ``WARDEN-SIM-FW <json>`` on its first line; the JSON carries the
    package's declared ``version`` (plus model/target metadata the platform
    parses for its preflight checks). Real vendor images are overlay
    territory (M3T5) — never parsed here.
    """
    line, _, _ = content.partition(b"\n")
    if not line.startswith(_IMAGE_HEADER_MARKER):
        return None
    raw = line[len(_IMAGE_HEADER_MARKER) :].strip()
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(decoded, dict) and isinstance(decoded.get("version"), str) and decoded["version"]:
        return decoded["version"]
    return None


class _SimulatorState:
    def __init__(self, cfg: SimulatorConfig) -> None:
        self.cfg = cfg
        self.uuid = str(uuid.uuid4())
        self.failures: dict[str, bool] = dict.fromkeys(FAILURE_KEYS, False)
        self.sessions: dict[str, str] = {}  # token -> session id
        self.session_counter = 0
        self.media = payloads.media_records()
        self.pending_media: dict[str, dict[str, object]] = {}
        self.tasks: dict[str, TaskRecord] = {}
        self.task_counter = 0
        self.task_fail_counter = 0
        # M3T3 runtime operation state (reset/update effects).
        self.power_target = "On"  # the settled system power state
        self.power_reboot_until = 0.0  # monotonic: system reports Off during a reboot blip
        self.manager_restart_until = 0.0  # monotonic: every Redfish request 503s
        self.versions = {"BMC": "SIM-BMC-1.0.0", "BIOS": "SIM-BIOS-2.0"}
        self.device_fetches: list[str] = []  # image URLs the "device" fetched
        self.device_fetch_attempts: list[dict[str, object]] = []

    @property
    def view(self) -> _View:
        return _View(self.cfg)

    def reset_dynamic(self) -> None:
        """Drop runtime state (sessions/tasks/media) after profile switches."""
        self.sessions.clear()
        self.session_counter = 0
        self.media = payloads.media_records()
        self.pending_media = {}
        self.tasks.clear()
        self.task_counter = 0
        self.power_target = "On"
        self.power_reboot_until = 0.0
        self.manager_restart_until = 0.0
        self.versions = {"BMC": "SIM-BMC-1.0.0", "BIOS": "SIM-BIOS-2.0"}
        self.device_fetches = []
        self.device_fetch_attempts = []

    def media_slot_state(self, media_id: str) -> dict[str, Any]:
        """The live slot record, applying a due delayed InsertMedia first."""
        pending = self.pending_media.get(media_id)
        if pending is not None and time.monotonic() >= float(pending["until"]):
            record = self.media.get(media_id)
            if record is not None:
                record["inserted"] = True
                record["image"] = pending["image"]
                record["image_name"] = pending["image_name"]
            self.pending_media.pop(media_id, None)
        return self.media[media_id]

    def schedule_media_insert(self, media_id: str, image: str) -> None:
        """Apply an InsertMedia after the asynchronous staging delay."""
        self.pending_media[media_id] = {
            "image": image,
            "image_name": image.rsplit("/", 1)[-1],
            "until": time.monotonic() + MEDIA_INSERT_DELAY_SECONDS,
        }

    def power_state_now(self) -> str:
        """The PowerState a GET observes right now (Off during a reboot blip)."""
        if time.monotonic() < self.power_reboot_until:
            return "Off"
        return self.power_target

    def manager_down(self) -> bool:
        """True while the manager restart window is active (device offline)."""
        return time.monotonic() < self.manager_restart_until

    def apply_system_power_effect(self, effect: str) -> None:
        """Apply a terminal system-reset effect to the runtime power state.

        ``power_readback_stale`` freezes every power transition so read-back
        verification can never observe the target state (ambiguous outcome).
        """
        if self.cfg.power_readback_stale:
            return
        if effect == "power_on":
            self.power_target = "On"
            self.power_reboot_until = 0.0
        elif effect == "power_off":
            self.power_target = "Off"
            self.power_reboot_until = 0.0
        elif effect == "power_reboot":
            self.power_target = "On"
            self.power_reboot_until = time.monotonic() + self.cfg.power_blip_seconds

    def snapshot(self) -> dict[str, object]:
        return {
            "profile": self.cfg.profile,
            "vendor": self.cfg.vendor,
            "pagination": self.cfg.pagination,
            "task_duration_seconds": self.cfg.task_duration_seconds,
            "absolute_links": self.cfg.absolute_links,
            "missing_memory_metrics": self.cfg.missing_memory_metrics,
            "no_raid_volume": self.cfg.no_raid_volume,
            "empty_sel": self.cfg.empty_sel,
            "thermal_missing_context": self.cfg.thermal_missing_context,
            "no_virtual_media": self.cfg.no_virtual_media,
            "no_storage": self.cfg.no_storage,
            "missing_system_status": self.cfg.missing_system_status,
            "sel_oem_timestamps": self.cfg.sel_oem_timestamps,
            "missing_fan_reading": self.cfg.missing_fan_reading,
            "drives_without_oem": self.cfg.drives_without_oem,
            "sel_append": self.cfg.sel_append,
            "failures": dict(self.failures),
            "media_hosts_required": self.cfg.media_hosts_required,
            "media_hosts": list(self.cfg.media_hosts),
            "sessions": len(self.sessions),
            "tasks": len(self.tasks),
            "power_blip_seconds": self.cfg.power_blip_seconds,
            "manager_blip_seconds": self.cfg.manager_blip_seconds,
            "firmware_update_version": self.cfg.firmware_update_version,
            "power_readback_stale": self.cfg.power_readback_stale,
            "media_insert_rejects_foreign_url": self.cfg.media_insert_rejects_foreign_url,
            "media_fetch_required": self.cfg.media_fetch_required,
            "media_insert_delayed": self.cfg.media_insert_delayed,
            "update_fetch_required": self.cfg.update_fetch_required,
            "update_reboot_loop": self.cfg.update_reboot_loop,
        "reset_never_completes": self.cfg.reset_never_completes,
        "update_never_completes": self.cfg.update_never_completes,
        "no_graceful_shutdown": self.cfg.no_graceful_shutdown,
            "system_power": self.power_state_now(),
            "manager_down": self.manager_down(),
            "versions": dict(self.versions),
            "device_fetches": list(self.device_fetches),
            "device_fetch_attempts": [dict(attempt) for attempt in self.device_fetch_attempts],
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
                    self.cfg = _replace(
                        self.cfg,
                        profile=value,  # type: ignore[arg-type]
                    )
                    self.reset_dynamic()
            elif key == "vendor":
                if value not in payloads.VENDORS:
                    msg = f"unknown vendor {value!r}"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, vendor=value)  # type: ignore[arg-type]
            elif key == "pagination":
                if value not in ("skip", "next_link"):
                    msg = f"unknown pagination {value!r}"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, pagination=value)  # type: ignore[arg-type]
            elif key == "task_duration_seconds":
                if not isinstance(value, (int, float)) or value <= 0:
                    msg = "task_duration_seconds must be a positive number"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, task_duration_seconds=float(value))  # type: ignore[arg-type]
            elif key == "absolute_links":
                self.cfg = _replace(self.cfg, absolute_links=bool(value))  # type: ignore[arg-type]
            elif key in FLOAT_KNOB_KEYS:
                if not isinstance(value, (int, float)) or value < 0:
                    msg = f"{key} must be a non-negative number"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, **{key: float(value)})  # type: ignore[arg-type]
            elif key in STRING_KNOB_KEYS:
                if not isinstance(value, str):
                    msg = f"{key} must be a string"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, **{key: value})  # type: ignore[arg-type]
            elif key in INT_KNOB_KEYS:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    msg = f"{key} must be a non-negative integer"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, **{key: int(value)})  # type: ignore[arg-type]
            elif key in SURFACE_KNOB_KEYS:
                self.cfg = _replace(self.cfg, **{key: bool(value)})  # type: ignore[arg-type]
            elif key == "media_hosts_required":
                self.cfg = _replace(self.cfg, media_hosts_required=bool(value))  # type: ignore[arg-type]
            elif key == "media_hosts":
                if not isinstance(value, list) or not all(isinstance(host, str) for host in value):
                    msg = "media_hosts must be a list of host names"
                    raise ValueError(msg)
                self.cfg = _replace(self.cfg, media_hosts=tuple(value))  # type: ignore[arg-type]
            elif key == "reset_state":
                if not isinstance(value, bool):
                    msg = "reset_state must be a boolean"
                    raise ValueError(msg)
                if value:
                    self.reset_dynamic()
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


def _replace(cfg: SimulatorConfig, **changes: object) -> SimulatorConfig:
    values = {name: getattr(cfg, name) for name in SimulatorConfig.__dataclass_fields__}
    values.update(changes)
    return SimulatorConfig(**values)  # type: ignore[arg-type]


# -- responses --------------------------------------------------------------

# Payload keys whose values are device-relative URI paths; with
# ``absolute_links`` these are rewritten into absolute same-origin hrefs.
_ABSOLUTE_LINK_KEYS = frozenset({"@odata.id", "@odata.nextLink", "target", "TaskMonitor"})


def _absolutize_payload(value: object, origin: str) -> object:
    """Deep-copy ``value`` rewriting path-only link values to absolute URIs."""
    if isinstance(value, dict):
        return {
            key: (
                f"{origin}{item}"
                if key in _ABSOLUTE_LINK_KEYS and isinstance(item, str) and item.startswith("/")
                else _absolutize_payload(item, origin)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_absolutize_payload(item, origin) for item in value]
    return value


def _error_body(code: str, message: str, extended: list[dict[str, str]] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if extended:
        info = [
            {
                "@odata.type": "#Message.v1_1_2.Message",
                "MessageId": member["MessageId"],
                "Message": member.get("Message", message),
                "Severity": "Critical",
                "Resolution": member.get("Resolution", "None"),
            }
            for member in extended
        ]
        error["@Message.ExtendedInfo"] = info
    return {"error": error}


def _base_error(status: int) -> tuple[int, dict[str, Any]]:
    bodies: dict[int, dict[str, Any]] = {
        400: _error_body(
            "Base.1.13.GeneralError",
            "The request could not be processed (simulated).",
            [{"MessageId": "Base.1.13.GeneralError", "Message": "The request could not be processed (simulated)."}],
        ),
        401: _error_body("Base.1.13.GeneralError", "No valid session or credentials were provided."),
        403: _error_body(
            "Base.1.13.GeneralError",
            "The account lacks the required privilege.",
            [{"MessageId": "Base.1.13.InsufficientPrivilege", "Message": "The account lacks the required privilege."}],
        ),
        404: _error_body(
            "Base.1.13.GeneralError",
            "The requested URI was not found on the simulated device.",
            [{"MessageId": "Base.1.13.ResourceMissingAtURI", "Message": "The requested URI was not found."}],
        ),
        500: _error_body(
            "Base.1.13.GeneralError",
            "Simulated internal error.",
            [{"MessageId": "Base.1.13.InternalError", "Message": "Simulated internal error."}],
        ),
    }
    return status, bodies[status]


def _base_error_response(status: int) -> tuple[int, dict[str, Any], dict[str, str]]:
    """3-tuple form of ``_base_error`` for dispatcher returns."""
    code, body = _base_error(status)
    return code, body, {}


# -- request handling -------------------------------------------------------


@dataclass
class _Request:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    scheme: str = "http"
    body: object | None = None


class _Dispatcher:
    def __init__(self, state: _SimulatorState) -> None:
        self.state = state

    # authentication --------------------------------------------------------

    def _basic_credentials(self, request: _Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        username, _, password = decoded.partition(":")
        if hmac.compare_digest(username, self.state.cfg.username) and hmac.compare_digest(
            password, self.state.cfg.password
        ):
            return username
        return None

    def _authenticated_user(self, request: _Request) -> str | None:
        if self.state.cfg.profile == "auth_fail":
            return None
        token = request.headers.get("x-auth-token")
        if token and token in self.state.sessions:
            return self.state.cfg.username
        return self._basic_credentials(request)

    # routing ----------------------------------------------------------------

    def handle(self, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """Route the request, then rewrite links to absolute same-origin URIs when configured."""
        return self._apply_absolute_links(request, self._route(request))

    def _apply_absolute_links(
        self,
        request: _Request,
        response: tuple[int, dict[str, Any] | None, dict[str, str]],
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        if not self.state.cfg.absolute_links:
            return response
        host = request.headers.get("host") or "localhost"
        origin = f"{request.scheme}://{host}"
        status, payload, headers = response
        rewritten_payload = _absolutize_payload(payload, origin) if isinstance(payload, dict) else payload
        rewritten_headers = {
            key: (f"{origin}{value}" if key.lower() == "location" and value.startswith("/") else value)
            for key, value in headers.items()
        }
        return status, rewritten_payload, rewritten_headers  # type: ignore[return-value]

    def _route(self, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """Return (status, json payload, extra headers) for an HTTP request."""
        path = "/" + request.path.strip("/") if request.path.strip("/") else "/"
        state = self.state

        if path == CONTROL_PATH and request.method in ("GET", "POST"):
            if request.method == "GET":
                return 200, state.snapshot(), {}
            try:
                snapshot = state.apply_control(request.body)
            except ValueError as exc:
                return 400, _error_body("Base.1.13.GeneralError", str(exc)), {}
            return 200, snapshot, {}

        if not path.startswith(payloads.BASE):
            return _base_error_response(404)
        # Session login is the only anonymous endpoint under /redfish/v1.
        if path == f"{payloads.BASE}/SessionService/Sessions" and request.method == "POST":
            return self._login(request)
        if state.manager_down():
            # M3T3: the manager is mid-restart — the whole device is offline.
            # Simulated as a 503 window (the test harness cannot drop TCP).
            return 503, _error_body("Base.1.13.GeneralError", "Manager is restarting (simulated)."), {}
        user = self._authenticated_user(request)
        if user is None:
            return _base_error_response(401)
        if request.method == "GET":
            if state.failures["reads_429"]:
                return 429, _error_body("Base.1.13.GeneralError", "Simulated rate limit."), {"Retry-After": "1"}
            if state.failures["reads_500"]:
                return _base_error_response(500)
            if state.failures["reads_403"]:
                return _base_error_response(403)
            return self._get(path, request)
        if request.method == "POST":
            return self._post(path, request)
        if request.method == "DELETE":
            return self._delete(path, request)
        return _base_error_response(404)

    # auth endpoints ---------------------------------------------------------

    def _login(self, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        if state.failures["login_401"] or state.cfg.profile == "auth_fail":
            return 401, _error_body("Base.1.13.GeneralError", "Invalid username or password (simulated)."), {}
        body = request.body
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("UserName"), str)
            or not isinstance(body.get("Password"), str)
        ):
            return 400, _error_body("Base.1.13.GeneralError", "UserName and Password are required."), {}
        if not (
            hmac.compare_digest(body["UserName"], state.cfg.username)
            and hmac.compare_digest(body["Password"], state.cfg.password)
        ):
            return 401, _error_body("Base.1.13.GeneralError", "Invalid username or password (simulated)."), {}
        state.session_counter += 1
        session_id = str(state.session_counter)
        token = uuid.uuid4().hex
        state.sessions[token] = session_id
        headers = {
            "Location": f"{payloads.BASE}/SessionService/Sessions/{session_id}",
            "X-Auth-Token": token,
        }
        return 201, payloads.session(session_id, state.cfg.username), headers

    def _delete(self, path: str, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        prefix = f"{payloads.BASE}/SessionService/Sessions/"
        if path.startswith(prefix):
            session_id = path[len(prefix) :]
            token = request.headers.get("x-auth-token")
            if token in state.sessions and state.sessions[token] == session_id:
                del state.sessions[token]
                return 204, None, {}
            if self._basic_credentials(request) is not None and session_id in state.sessions.values():
                tokens = [t for t, sid in state.sessions.items() if sid == session_id]
                for token in tokens:
                    del state.sessions[token]
                return 204, None, {}
            return _base_error_response(403)
        if path.startswith(f"{payloads.BASE}/TaskService/Tasks/"):
            task_id = path[len(f"{payloads.BASE}/TaskService/Tasks/") :]
            if task_id in state.tasks:
                del state.tasks[task_id]
                return 204, None, {}
            return _base_error_response(404)
        return _base_error_response(404)

    # GET dispatch -----------------------------------------------------------

    def _get(self, path: str, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        view = state.view
        now = datetime.now(UTC)
        routes: dict[str, Any] = {
            f"{payloads.BASE}": payloads.service_root(view, date_time=now),
            f"{payloads.BASE}/": payloads.service_root(view, date_time=now),
            f"{payloads.BASE}/Systems": payloads.systems_collection(),
            f"{payloads.BASE}/Systems/1": payloads.system(
                view, power_state=state.power_state_now(), bios_version=state.versions["BIOS"]
            ),
            f"{payloads.BASE}/Systems/1/Memory": payloads.memory_collection(),
            f"{payloads.BASE}/Systems/1/Storage": payloads.storage_collection(),
            f"{payloads.BASE}/Systems/1/Storage/SATA1": payloads.storage_sata1(view),
            f"{payloads.BASE}/Systems/1/Storage/SATA1/Drives": payloads.drives_collection(),
            f"{payloads.BASE}/Systems/1/Storage/SATA1/Volumes": payloads.volumes_collection(view),
            f"{payloads.BASE}/Chassis": payloads.chassis_collection(),
            f"{payloads.BASE}/Chassis/1": payloads.chassis(view),
            f"{payloads.BASE}/Chassis/1/Thermal": payloads.thermal(view),
            f"{payloads.BASE}/Chassis/1/Power": payloads.power(view),
            f"{payloads.BASE}/Managers": payloads.managers_collection(),
            f"{payloads.BASE}/Managers/1": payloads.manager(
                view, date_time=now, firmware_version=state.versions["BMC"]
            ),
            f"{payloads.BASE}/Managers/1/LogServices": payloads.log_services_collection(),
            f"{payloads.BASE}/Managers/1/LogServices/SEL": payloads.sel_log_service(view),
            f"{payloads.BASE}/Managers/1/VirtualMedia": payloads.virtual_media_collection(),
            f"{payloads.BASE}/UpdateService": payloads.update_service(view),
            f"{payloads.BASE}/UpdateService/FirmwareInventory": payloads.firmware_inventory_collection(),
            f"{payloads.BASE}/SessionService": payloads.session_service(),
            f"{payloads.BASE}/SessionService/Sessions": payloads.sessions_collection(list(state.sessions.values())),
            f"{payloads.BASE}/AccountService": payloads.account_service(),
            f"{payloads.BASE}/AccountService/Accounts": payloads.accounts_collection(),
            f"{payloads.BASE}/AccountService/Accounts/1": payloads.account(state.cfg.username),
            f"{payloads.BASE}/TaskService": payloads.task_service(),
            f"{payloads.BASE}/TaskService/Tasks": payloads.tasks_collection(list(state.tasks)),
        }
        if path in routes:
            return 200, routes[path], {}

        # Memory DIMMs
        dimm = self._match(f"{payloads.BASE}/Systems/1/Memory/", path)
        if dimm is not None and dimm in ("DIMM0", "DIMM1", "DIMM2", "DIMM3", "DIMM4"):
            return 200, payloads.memory_dimm(view, dimm), {}

        # Drives
        drive = self._match(f"{payloads.BASE}/Systems/1/Storage/SATA1/Drives/", path)
        if drive is not None and drive in ("sda", "sdb"):
            return 200, payloads.drive(view, drive), {}

        # Volumes
        volume = self._match(f"{payloads.BASE}/Systems/1/Storage/SATA1/Volumes/", path)
        if volume is not None and volume == "RAID6_1":
            return 200, payloads.volume(view), {}

        # Firmware inventory
        inventory = self._match(f"{payloads.BASE}/UpdateService/FirmwareInventory/", path)
        if inventory is not None and inventory in ("BMC", "BIOS"):
            return 200, payloads.firmware_inventory(inventory, version=state.versions[inventory]), {}

        # SEL entries (paginated)
        entries_prefix = f"{payloads.BASE}/Managers/1/LogServices/SEL/Entries"
        if path == entries_prefix or path.startswith(entries_prefix + "?"):
            skip = _query_int(request.query, "$skip") or 0
            top = _query_int(request.query, "$top") or view.sel_page_size
            return 200, payloads.sel_entries_page(view, skip=skip, top=top), {}

        # Sessions
        session_path = f"{payloads.BASE}/SessionService/Sessions/"
        if path.startswith(session_path):
            session_id = path[len(session_path) :]
            if session_id in state.sessions.values():
                return 200, payloads.session(session_id, state.cfg.username), {}

        # Virtual media
        media = self._match(f"{payloads.BASE}/Managers/1/VirtualMedia/", path)
        if media is not None and media in state.media:
            record = state.media_slot_state(media)
            return 200, payloads.virtual_media(media, record), {}

        # Tasks + monitors
        task_path = f"{payloads.BASE}/TaskService/Tasks/"
        if path.startswith(task_path):
            remainder = path[len(task_path) :]
            task_id, _, suffix = remainder.partition("/")
            record = state.tasks.get(task_id)
            if record is not None:
                task_state, task_status, percent = record.state_at(time.monotonic())
                if task_state == "Completed" and record.effect is not None and not record.applied:
                    # M3T3: apply the deferred device effect exactly once when
                    # the task is first observed terminal (never re-applied).
                    self._apply_task_effect(record)
                    record.applied = True
                    task_state, task_status, percent = record.state_at(time.monotonic())
                if suffix == "":
                    messages = None
                    if task_state == "Exception":
                        messages = [
                            {
                                "MessageId": "Base.1.13.GeneralError",
                                "Message": _FAIL_ACTION_MESSAGE,
                                "Severity": "Critical",
                            }
                        ]
                    return (
                        200,
                        payloads.task(
                            task_id,
                            record.name,
                            created_at=record.created_at,
                            state=task_state,
                            status=task_status,
                            messages=messages,
                        ),
                        {},
                    )
                if suffix == "TaskMonitor":
                    return 200, payloads.task_monitor(task_id, state=task_state, percent=percent), {}
        return _base_error_response(404)

    @staticmethod
    def _match(prefix: str, path: str) -> str | None:
        if path.startswith(prefix):
            return path[len(prefix) :]
        return None

    # POST dispatch ----------------------------------------------------------

    def _create_task(
        self,
        name: str,
        fails: bool,
        *,
        effect: str | None = None,
        effect_target: str | None = None,
        effect_version: str | None = None,
        never_completes: bool = False,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        state = self.state
        state.task_counter += 1
        duration = _NEVER_COMPLETES_DURATION if never_completes else state.cfg.task_duration_seconds
        record = TaskRecord(
            task_id=str(state.task_counter),
            name=name,
            created_monotonic=time.monotonic(),
            duration_seconds=duration,
            fails=fails,
            effect=effect,
            effect_target=effect_target,
            effect_version=effect_version,
        )
        state.tasks[record.task_id] = record
        headers = {"Location": f"{payloads.BASE}/TaskService/Tasks/{record.task_id}"}
        task_state, task_status, percent = record.state_at(time.monotonic())
        messages = None
        if task_state == "Exception":
            messages = [
                {
                    "MessageId": "Base.1.13.GeneralError",
                    "Message": _FAIL_ACTION_MESSAGE,
                    "Severity": "Critical",
                }
            ]
        return (
            202,
            payloads.task(
                record.task_id,
                name,
                created_at=record.created_at,
                state=task_state,
                status=task_status,
                messages=messages,
            ),
            headers,
        )

    def _apply_task_effect(self, record: TaskRecord) -> None:
        """Apply a terminal task effect to the runtime state (exactly once)."""
        state = self.state
        if record.effect in ("power_on", "power_off", "power_reboot"):
            state.apply_system_power_effect(record.effect)
        elif record.effect == "firmware_update":
            if state.cfg.update_reboot_loop:
                # The "device" reboots forever after the update task: no
                # version bump and a fresh reboot blip per completion read.
                state.power_target = "On"
                state.power_reboot_until = time.monotonic() + state.cfg.power_blip_seconds
                return
            if record.effect_target is not None and record.effect_version is not None:
                state.versions[record.effect_target] = record.effect_version

    def _fetch_image(self, image_url: str) -> bytes | None:
        """Emulate the device fetching an image (InsertMedia/SimpleUpdate).

        The platform ticket route must be live and reachable from the
        simulator (integration slices); a failed fetch returns None and the
        caller rejects the action — a device that cannot reach the image
        never claims a successful mount/update. Every attempt is recorded in
        the control snapshot (``device_fetch_attempts``) for test evidence.
        """
        attempt: dict[str, object] = {"url": image_url}
        try:
            with httpx.Client(timeout=5.0, follow_redirects=False) as http:
                response = http.get(image_url)
        except httpx.HTTPError as exc:
            attempt["error"] = type(exc).__name__
            self.state.device_fetch_attempts.append(attempt)
            return None
        attempt["status"] = response.status_code
        self.state.device_fetch_attempts.append(attempt)
        if response.status_code != 200 or not response.content:
            return None
        self.state.device_fetches.append(image_url)
        return response.content

    def _post(self, path: str, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        body = request.body if isinstance(request.body, dict) else {}

        if path == f"{payloads.BASE}/Systems/1/Actions/ComputerSystem.Reset":
            return self._system_reset_action(body)
        if path == f"{payloads.BASE}/Managers/1/Actions/Manager.Reset":
            return self._manager_reset_action(body)
        if path == f"{payloads.BASE}/UpdateService/Actions/UpdateService.SimpleUpdate":
            return self._simple_update_action(body)

        media = self._match(f"{payloads.BASE}/Managers/1/VirtualMedia/", path)
        if media is not None:
            media_id, separator, action_path = media.partition("/")
            if separator and media_id in state.media:
                record = state.media_slot_state(media_id)
                if action_path == "Actions/VirtualMedia.InsertMedia":
                    image = body.get("Image")
                    if not isinstance(image, str):
                        return (
                            400,
                            _error_body(
                                "Base.1.13.GeneralError",
                                "Image is required.",
                                [{"MessageId": "Base.1.13.ActionParameterMissing", "Message": "Image is required."}],
                            ),
                            {},
                        )
                    parts = urlsplit(image)
                    if parts.scheme not in ("http", "https") or not parts.hostname:
                        return (
                            400,
                            _error_body(
                                "Base.1.13.GeneralError",
                                "Image must be an http(s) URL reachable by the device.",
                                [
                                    {
                                        "MessageId": "Base.1.13.ActionParameterValueFormatError",
                                        "Message": "Image must be an http(s) URL.",
                                    }
                                ],
                            ),
                            {},
                        )
                    allowlist = (
                        state.cfg.media_hosts_required or state.cfg.media_insert_rejects_foreign_url
                    )
                    if allowlist and parts.hostname not in state.cfg.media_hosts:
                        return (
                            400,
                            _error_body(
                                "Base.1.13.GeneralError",
                                "Image host is not in the allowed media host list.",
                                [
                                    {
                                        "MessageId": "Base.1.13.ActionParameterValueNotInList",
                                        "Message": "Image host is not allowed.",
                                    }
                                ],
                            ),
                            {},
                        )
                    if state.cfg.media_fetch_required and self._fetch_image(image) is None:
                        return (
                            400,
                            _error_body(
                                "Base.1.13.GeneralError",
                                "The image URL is not reachable by the device.",
                                [
                                    {
                                        "MessageId": "Base.1.13.ActionParameterValueFormatError",
                                        "Message": "Image URL unreachable.",
                                    }
                                ],
                            ),
                            {},
                        )
                    if state.cfg.media_insert_delayed:
                        # A real manager may stage the insert asynchronously
                        # after the 204 acceptance: the slot keeps reporting
                        # Inserted=false until the delay elapses.
                        state.schedule_media_insert(media_id, image)
                    else:
                        record["inserted"] = True
                        record["image"] = image
                        record["image_name"] = image.rsplit("/", 1)[-1]
                    return 204, None, {}
                if action_path == "Actions/VirtualMedia.EjectMedia":
                    if not record["inserted"]:
                        return (
                            400,
                            _error_body(
                                "Base.1.13.GeneralError",
                                "No media is currently inserted.",
                                [
                                    {
                                        "MessageId": "Base.1.13.GeneralError",
                                        "Message": "No media is currently inserted.",
                                    }
                                ],
                            ),
                            {},
                        )
                    record["inserted"] = False
                    record["image"] = None
                    record["image_name"] = None
                    return 204, None, {}
        return _base_error_response(404)

    def _system_reset_action(self, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """POST ComputerSystem.Reset: validate, then create the reset task.

        The task carries the deferred power effect; the effect is applied
        exactly once when the task is first observed ``Completed`` (system
        power On/Off immediately, restart/cycle through a brief Off blip).
        """
        state = self.state
        reset_type = body.get("ResetType")
        allowed = (
            "On",
            "ForceOff",
            "GracefulShutdown",
            "GracefulRestart",
            "ForceRestart",
            "PowerCycle",
            "Nmi",
            "PushPowerButton",
        )
        if reset_type not in allowed:
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    f"ResetType must be one of {allowed}.",
                    [
                        {
                            "MessageId": "Base.1.13.ActionParameterValueNotInList",
                            "Message": f"ResetType must be one of {allowed}.",
                        }
                    ],
                ),
                {},
            )
        if state.cfg.no_graceful_shutdown and reset_type == "GracefulShutdown":
            # power.off prohibition scenario: the graceful action is not
            # available on this device — the adapter must NOT fall back to
            # ForceOff.
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "GracefulShutdown is not supported on this simulated device.",
                    [{"MessageId": "Base.1.13.ActionNotSupported", "Message": "GracefulShutdown is not supported."}],
                ),
                {},
            )
        if state.failures["reset_rejected_400"]:
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "The action is not supported on this simulated device.",
                    [{"MessageId": "Base.1.13.ActionNotSupported", "Message": "The action is not supported."}],
                ),
                {},
            )
        if state.failures["reset_forbidden_403"]:
            return _base_error_response(403)
        effect: str | None
        if reset_type in ("On",):
            effect = "power_on"
        elif reset_type in ("GracefulShutdown", "ForceOff"):
            effect = "power_off"
        elif reset_type in ("GracefulRestart", "ForceRestart", "PowerCycle", "PushPowerButton"):
            effect = "power_reboot"
        else:  # Nmi
            effect = None
        fails = state.failures["reset_task_fails"]
        return self._create_task(
            "Reset System", fails=fails, effect=effect, never_completes=state.cfg.reset_never_completes
        )

    def _manager_reset_action(self, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """POST Manager.Reset: cold-manager restart semantics (simulated).

        The reset is accepted as a task, but the manager goes down right away
        (session invalidation + a full 503 window) and the reset task record
        vanishes with the reboot — a manager restart wipes its own task list.
        Read-backs therefore see the device offline, then the task 404, and
        verify identity over a FRESH session (never a stale one).
        """
        state = self.state
        reset_type = body.get("ResetType")
        allowed = ("GracefulRestart", "ForceRestart")
        if reset_type not in allowed:
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    f"ResetType must be one of {allowed}.",
                    [
                        {
                            "MessageId": "Base.1.13.ActionParameterValueNotInList",
                            "Message": f"ResetType must be one of {allowed}.",
                        }
                    ],
                ),
                {},
            )
        if state.failures["reset_rejected_400"]:
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "The action is not supported on this simulated device.",
                    [{"MessageId": "Base.1.13.ActionNotSupported", "Message": "The action is not supported."}],
                ),
                {},
            )
        if state.failures["reset_forbidden_403"]:
            return _base_error_response(403)
        task_response = self._create_task("Manager Reset", fails=False)
        # The manager restarts immediately: sessions die and the reboot
        # window starts; the just-created task row is wiped by the reboot.
        state.sessions.clear()
        state.manager_restart_until = time.monotonic() + state.cfg.manager_blip_seconds
        task_id = task_response[1]["Id"] if isinstance(task_response[1], dict) else None
        if task_id is not None:
            state.tasks.pop(task_id, None)
        return task_response

    def _simple_update_action(self, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """POST UpdateService.SimpleUpdate: ImageURI + Targets -> update task.

        The device fetch emulation (``update_fetch_required``) downloads the
        image at accept time and reads the warden-sim image header for the
        target version; without a fetch the ``firmware_update_version`` knob
        declares the bump. The task applies the version on completion
        (``update_task_fails`` -> Exception, ``update_never_completes`` ->
        Running forever, ``update_reboot_loop`` -> no bump + reboot).
        """
        state = self.state
        image_uri = body.get("ImageURI")
        if not isinstance(image_uri, str):
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "ImageURI is required.",
                    [{"MessageId": "Base.1.13.ActionParameterMissing", "Message": "ImageURI is required."}],
                ),
                {},
            )
        parts = urlsplit(image_uri)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "ImageURI must be an http(s) URL reachable by the device.",
                    [
                        {
                            "MessageId": "Base.1.13.ActionParameterValueFormatError",
                            "Message": "ImageURI must be an http(s) URL.",
                        }
                    ],
                ),
                {},
            )
        raw_targets = body.get("Targets")
        if not isinstance(raw_targets, list) or not raw_targets:
            single = body.get("Target")
            raw_targets = [single] if isinstance(single, str) else []
        allowed = (
            f"{payloads.BASE}/UpdateService/FirmwareInventory/BMC",
            f"{payloads.BASE}/UpdateService/FirmwareInventory/BIOS",
        )
        targets = [target for target in raw_targets if isinstance(target, str) and target in allowed]
        if not targets or len(targets) != len(raw_targets):
            return (
                400,
                _error_body(
                    "Base.1.13.GeneralError",
                    "A supported Target is required.",
                    [
                        {
                            "MessageId": "Base.1.13.ActionParameterValueNotInList",
                            "Message": "A supported Target is required.",
                        }
                    ],
                ),
                {},
            )
        target = targets[0]
        effect_target = target.rsplit("/", 1)[-1]
        effect_version: str | None = state.cfg.firmware_update_version or None
        if state.cfg.update_fetch_required:
            content = self._fetch_image(image_uri)
            if content is None:
                return (
                    400,
                    _error_body(
                        "Base.1.13.GeneralError",
                        "The image URL is not reachable by the device.",
                        [
                            {
                                "MessageId": "Base.1.13.ActionParameterValueFormatError",
                                "Message": "Image URL unreachable.",
                            }
                        ],
                    ),
                    {},
                )
            header_version = _image_header_version(content)
            if header_version is None:
                return (
                    400,
                    _error_body(
                        "Base.1.13.GeneralError",
                        "The image carries no readable warden-sim version header.",
                        [{"MessageId": "Base.1.13.GeneralError", "Message": "Unreadable image header."}],
                    ),
                    {},
                )
            effect_version = header_version
        fails = state.failures["update_task_fails"]
        return self._create_task(
            "Firmware Update",
            fails=fails,
            effect="firmware_update",
            effect_target=effect_target,
            effect_version=effect_version,
            never_completes=state.cfg.update_never_completes,
        )


def _query_int(query: dict[str, list[str]], key: str) -> int | None:
    raw = query.get(key, [None])[0]
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


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
        body: object | None = None
        if raw_body:
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
            scheme=str(scope.get("scheme", "http")),
            body=body,
        )
        status, payload, extra_headers = self._dispatcher.handle(request)
        await self._respond(send, status, payload, extra_headers)

    @staticmethod
    async def _respond(
        send: Any,
        status: int,
        payload: dict[str, Any] | None,
        extra_headers: dict[str, str],
    ) -> None:
        response_headers = [
            (b"content-type", b"application/json"),
        ]
        for key, value in extra_headers.items():
            response_headers.append((key.encode("latin-1"), value.encode("latin-1")))
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            response_headers.append((b"content-length", str(len(body)).encode("ascii")))
        else:
            response_headers.append((b"content-length", b"0"))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": response_headers,
            }
        )
        if body:
            await send({"type": "http.response.body", "body": body})
        else:
            await send({"type": "http.response.body", "body": b""})


def create_simulator(config: SimulatorConfig | None = None) -> SimulatorASGI:
    """Create the simulator ASGI app (one state per app instance)."""
    return SimulatorASGI(_SimulatorState(config if config is not None else SimulatorConfig()))
