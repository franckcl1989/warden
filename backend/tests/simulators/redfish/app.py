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
- ``slow_paginated``: 150 SEL entries served in pages of 20.

Failure injection (``POST /warden-sim/control {"failures": {...}}``):
``login_401``, ``reads_500``, ``reads_429``, ``reset_rejected_400``,
``reset_forbidden_403``, ``reset_task_fails``. Control also switches
``profile``/``vendor``/``pagination``/``task_duration_seconds`` and reports
the live state on ``GET /warden-sim/control``.
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

from tests.simulators.redfish import payloads
from tests.simulators.redfish.payloads import SimulatorConfig, _View

CONTROL_PATH = "/warden-sim/control"
PROFILE_PROPERTIES = frozenset({"profile", "vendor", "pagination", "task_duration_seconds"})
FAILURE_KEYS = frozenset(
    {
        "login_401",
        "reads_500",
        "reads_429",
        "reset_rejected_400",
        "reset_forbidden_403",
        "reset_task_fails",
    }
)

_FAIL_ACTION_MESSAGE = "Simulated reset failure (test device simulator)"


@dataclass
class TaskRecord:
    task_id: str
    name: str
    created_monotonic: float
    duration_seconds: float
    fails: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def state_at(self, now: float) -> tuple[str, str, int]:
        """(TaskState, TaskStatus, percent) at monotonic ``now``."""
        elapsed = now - self.created_monotonic
        if elapsed < self.duration_seconds:
            return "Running", "Running", 50
        if self.fails:
            return "Exception", "Exception", 50
        return "Completed", "OK", 100


class _SimulatorState:
    def __init__(self, cfg: SimulatorConfig) -> None:
        self.cfg = cfg
        self.uuid = str(uuid.uuid4())
        self.failures: dict[str, bool] = dict.fromkeys(FAILURE_KEYS, False)
        self.sessions: dict[str, str] = {}  # token -> session id
        self.session_counter = 0
        self.media = payloads.media_records()
        self.tasks: dict[str, TaskRecord] = {}
        self.task_counter = 0
        self.task_fail_counter = 0

    @property
    def view(self) -> _View:
        return _View(self.cfg)

    def reset_dynamic(self) -> None:
        """Drop runtime state (sessions/tasks/media) after profile switches."""
        self.sessions.clear()
        self.session_counter = 0
        self.media = payloads.media_records()
        self.tasks.clear()
        self.task_counter = 0

    def snapshot(self) -> dict[str, object]:
        return {
            "profile": self.cfg.profile,
            "vendor": self.cfg.vendor,
            "pagination": self.cfg.pagination,
            "task_duration_seconds": self.cfg.task_duration_seconds,
            "failures": dict(self.failures),
            "media_hosts_required": self.cfg.media_hosts_required,
            "media_hosts": list(self.cfg.media_hosts),
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
                    self.cfg = SimulatorConfig(
                        username=self.cfg.username,
                        password=self.cfg.password,
                        profile=value,  # type: ignore[arg-type]
                        vendor=self.cfg.vendor,
                        pagination=self.cfg.pagination,
                        sel_total=self.cfg.sel_total,
                        sel_page_size=self.cfg.sel_page_size,
                        task_duration_seconds=self.cfg.task_duration_seconds,
                        media_hosts_required=self.cfg.media_hosts_required,
                        media_hosts=self.cfg.media_hosts,
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

        # Session login is the only anonymous endpoint under /redfish/v1.
        if path == f"{payloads.BASE}/SessionService/Sessions" and request.method == "POST":
            return self._login(request)

        if not path.startswith(payloads.BASE):
            return _base_error_response(404)
        user = self._authenticated_user(request)
        if user is None:
            return _base_error_response(401)
        if request.method == "GET":
            if state.failures["reads_429"]:
                return 429, _error_body("Base.1.13.GeneralError", "Simulated rate limit."), {"Retry-After": "1"}
            if state.failures["reads_500"]:
                return _base_error_response(500)
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
            f"{payloads.BASE}/Systems/1": payloads.system(view),
            f"{payloads.BASE}/Systems/1/Memory": payloads.memory_collection(),
            f"{payloads.BASE}/Systems/1/Storage": payloads.storage_collection(),
            f"{payloads.BASE}/Systems/1/Storage/SATA1": payloads.storage_sata1(view),
            f"{payloads.BASE}/Systems/1/Storage/SATA1/Drives": payloads.drives_collection(),
            f"{payloads.BASE}/Systems/1/Storage/SATA1/Volumes": payloads.volumes_collection(),
            f"{payloads.BASE}/Chassis": payloads.chassis_collection(),
            f"{payloads.BASE}/Chassis/1": payloads.chassis(view),
            f"{payloads.BASE}/Chassis/1/Thermal": payloads.thermal(view),
            f"{payloads.BASE}/Chassis/1/Power": payloads.power(view),
            f"{payloads.BASE}/Managers": payloads.managers_collection(),
            f"{payloads.BASE}/Managers/1": payloads.manager(view, date_time=now),
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
        if dimm is not None and dimm in ("DIMM0", "DIMM1", "DIMM2", "DIMM3"):
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
            return 200, payloads.firmware_inventory(inventory), {}

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
            return 200, payloads.virtual_media(media, state.media[media]), {}

        # Tasks + monitors
        task_path = f"{payloads.BASE}/TaskService/Tasks/"
        if path.startswith(task_path):
            remainder = path[len(task_path) :]
            task_id, _, suffix = remainder.partition("/")
            record = state.tasks.get(task_id)
            if record is not None:
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

    def _create_task(self, name: str, fails: bool) -> tuple[int, dict[str, Any], dict[str, str]]:
        state = self.state
        state.task_counter += 1
        record = TaskRecord(
            task_id=str(state.task_counter),
            name=name,
            created_monotonic=time.monotonic(),
            duration_seconds=state.cfg.task_duration_seconds,
            fails=fails,
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

    def _post(self, path: str, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        body = request.body if isinstance(request.body, dict) else {}

        if path == f"{payloads.BASE}/Systems/1/Actions/ComputerSystem.Reset":
            return self._reset_action(body, name="Reset System")
        if path == f"{payloads.BASE}/Managers/1/Actions/Manager.Reset":
            return self._reset_action(body, name="Manager Reset")
        if path == f"{payloads.BASE}/UpdateService/Actions/UpdateService.SimpleUpdate":
            target = body.get("Target")
            allowed = (
                f"{payloads.BASE}/UpdateService/FirmwareInventory/BMC",
                f"{payloads.BASE}/UpdateService/FirmwareInventory/BIOS",
            )
            if target not in allowed:
                return (
                    400,
                    _error_body(
                        "Base.1.13.GeneralError",
                        "A supported Target is required.",
                        [
                            {
                                "MessageId": "Base.1.13.ActionParameterMissing",
                                "Message": "A supported Target is required.",
                            }
                        ],
                    ),
                    {},
                )
            return self._create_task("Firmware Update", fails=False)

        media = self._match(f"{payloads.BASE}/Managers/1/VirtualMedia/", path)
        if media is not None:
            media_id, separator, action_path = media.partition("/")
            if separator and media_id in state.media:
                record = state.media[media_id]
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
                    if state.cfg.media_hosts_required and parts.hostname not in state.cfg.media_hosts:
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

    def _reset_action(self, body: dict[str, Any], *, name: str) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        reset_type = body.get("ResetType")
        allowed = ("On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart", "Nmi", "PushPowerButton")
        if name == "Manager Reset":
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
        fails = state.failures["reset_task_fails"]
        return self._create_task(name, fails=fails)


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
