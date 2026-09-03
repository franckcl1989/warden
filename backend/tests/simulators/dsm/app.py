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
  (paged), SYNO.Core.Upgrade (async update job via taskid).

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
``{"missing_apis": [..]}``, ``{"storage_max_version": int}``,
``{"task_duration_seconds": ...}``, ``{"failures": {...}}`` or
``{"expire_sessions": true}``. Profile switches force the profile-owned
knobs to their presets (constructor knob combinations are preserved).

Failure injection keys: ``login_reject`` (401), ``login_otp`` (403
two-step), ``reads_500`` (HTTP 500), ``error_unknown_2100`` (unmapped DSM
code 2100 — the client must preserve it, never guess),
``sessions_reject_106`` (every authenticated call answers 106 even after
re-login — bounded re-login must fail honestly), ``smart_test_fails``,
``update_fails``.
"""

from __future__ import annotations

import hmac
import json
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import parse_qs, unquote

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
        "update_fails",
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
    }
)
INT_KNOB_KEYS = frozenset({"log_append"})


class _SimulatorState:
    def __init__(self, cfg: SimulatorConfig) -> None:
        self.cfg = cfg
        self.failures: dict[str, bool] = dict.fromkeys(FAILURE_KEYS, False)
        self.sessions: dict[str, float] = {}  # sid -> created monotonic
        self.session_counter = 0
        self.tasks: dict[int, TaskRecord] = {}
        self.task_counter = 0
        self.storage_max_version: int | None = None

    def reset_dynamic(self) -> None:
        """Drop runtime state (sessions/tasks) after profile switches."""
        self.sessions.clear()
        self.session_counter = 0
        self.tasks.clear()
        self.task_counter = 0

    def api_map(self) -> dict[str, dict[str, object]]:
        return self.cfg.inflated_map(storage_max_version=self.storage_max_version)

    def snapshot(self) -> dict[str, object]:
        return {
            "profile": self.cfg.profile,
            "username": self.cfg.username,
            "task_duration_seconds": self.cfg.task_duration_seconds,
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
            "missing_apis": sorted(self.cfg.missing_apis),
            "storage_max_version": self.storage_max_version,
            "failures": dict(self.failures),
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
            elif key == "task_duration_seconds":
                if not isinstance(value, (int, float)) or value <= 0:
                    msg = "task_duration_seconds must be a positive number"
                    raise ValueError(msg)
                self.cfg = replace(self.cfg, task_duration_seconds=float(value))
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


class _Dispatcher:
    def __init__(self, state: _SimulatorState) -> None:
        self.state = state

    # -- main dispatch ------------------------------------------------------

    def handle(self, request: _Request) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        path = "/" + request.path.strip("/") if request.path.strip("/") else "/"

        if path == CONTROL_PATH and request.method in ("GET", "POST"):
            if request.method == "GET":
                return 200, state.snapshot(), {}
            try:
                snapshot = state.apply_control(request.body_object)
            except ValueError:
                return 400, payloads.error(101), {}
            return 200, snapshot, {}

        if not path.startswith(payloads.BASE):
            return 404, None, {}
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
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
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
        return 200, payloads.error(102), {}

    def _system(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        if method == "info":
            return 200, payloads.system_info_payload(state.cfg), {}
        if method in ("shutdown", "restart"):
            # Side effects: accepted once; the "device" ends the session.
            state.sessions.clear()
            return 200, payloads.success({}), {}
        return 200, payloads.error(103), {}

    def _storage(
        self, api: str, method: str, params: dict[str, list[str]]
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        if method == "load_info":
            return 200, payloads.storage_payload(state.cfg), {}
        if method == "smart_test":
            disk = _first(params, "disk")
            smart_type = _first(params, "type")
            if disk is None or smart_type not in ("quick", "full"):
                return 200, payloads.error(101), {}
            state.task_counter += 1
            task_id = state.task_counter
            state.tasks[task_id] = TaskRecord(
                task_id=task_id,
                kind="smart",
                created_monotonic=time.monotonic(),
                duration_seconds=state.cfg.task_duration_seconds,
                fails=state.failures["smart_test_fails"],
            )
            return 200, payloads.smart_test_payload(task_id), {}
        if method == "smart_task_status":
            task = self._task(params)
            if task is None:
                return 200, payloads.error(101), {}
            status, progress = task.state_at(time.monotonic())
            return 200, payloads.smart_task_status_payload(task.task_id, status, progress), {}
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
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        state = self.state
        if method == "upgrade":
            state.task_counter += 1
            task_id = state.task_counter
            state.tasks[task_id] = TaskRecord(
                task_id=task_id,
                kind="update",
                created_monotonic=time.monotonic(),
                duration_seconds=state.cfg.task_duration_seconds,
                fails=state.failures["update_fails"],
            )
            return 200, payloads.upgrade_payload(task_id), {}
        if method == "update_task_status":
            task = self._task(params)
            if task is None:
                return 200, payloads.error(101), {}
            status, progress = task.state_at(time.monotonic())
            return 200, payloads.update_task_status_payload(task.task_id, status, progress), {}
        return 200, payloads.error(103), {}


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
        await send({"type": "http.response.body", "body": body})


def create_simulator(config: SimulatorConfig | None = None) -> SimulatorASGI:
    """Create the simulator ASGI app (one state per app instance).

    A constructor profile is normalized to its preset knobs (same code path
    as the live ``profile`` control switch).
    """
    base = config if config is not None else SimulatorConfig()
    normalized = payloads.profile_config(base.profile, base=base)
    return SimulatorASGI(_SimulatorState(normalized))
