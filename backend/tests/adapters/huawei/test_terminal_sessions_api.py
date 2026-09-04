"""Browser-terminal WS/API integration tests (M5T4, real PostgreSQL).

End-to-end over the real API against the VRP simulators (SNMP agent for
onboarding + asyncssh SSH server with telnet variant): console.ssh.open /
console.telnet.open tickets (gates, WS url), the WebSocket lifecycle
(ticket single-use + expiry + user binding + device-version binding,
concurrency caps, idle/max bounds, close endpoint, audit, and the
never-log-content rule with a canary string). ``TestWebConsoleLaunchSlice``
additionally covers the M5T5 console.web.open URL-descriptor launch
(declared web origin, single-use consume, audit).

Refusal-delivery contract (M5T4 review fix): the endpoint accepts FIRST
and refuses ticket/gate/dial failures POST-accept with one machine JSON
frame ``{"type":"refused","code":..,"reason":..}`` followed by the close
code — a real ASGI server cannot deliver close codes before the 101
upgrade (a pre-accept close is an HTTP 403 handshake denial). The
TestClient cases here assert the frame + code as the browser sees them;
``TestRealAsgiRefusalDelivery`` repeats the refusals over a REAL uvicorn
server (loopback TCP) to pin the delivery contract at the ASGI boundary.
The simulators are TEST DEVICES — never hardware evidence
(tests/simulators/vrp/README.md).
"""

from __future__ import annotations

import asyncio
import io
import json
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import pytest
import uvicorn
import websockets
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
from app.infrastructure.session_tokens import SESSION_COOKIE_NAME
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from starlette.websockets import WebSocketDisconnect
from tests.adapters.huawei.conftest import SIM_HOST, V3_AUTH_KEY, V3_PRIV_KEY, V3_USERNAME
from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login_csrf,
)
from tests.simulators.vrp.device import SSH_PASSWORD, SSH_USERNAME
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

API = "/api/v1"
WS_BASE = f"{API}/terminal/sessions"
CORE_ADAPTER_KEY = "switch.huawei_vrp_core"
WS_ORIGIN = "http://localhost"

CLOSE_UNAUTHENTICATED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_TICKET_UNAVAILABLE = 4404
CLOSE_CAPACITY = 4429
CLOSE_HANDSHAKE_FAILED = 4101
CLOSE_INTERNAL_ERROR = 4500

#: Post-accept refusal reason keys of the ``refused`` control frame
#: (application/terminal_sessions.py + routes/terminal.py).
REASON_TICKET_UNAVAILABLE = "ticket_unavailable"
REASON_CAPACITY_USER = "capacity_user"
REASON_CAPACITY_DEVICE = "capacity_device"
REASON_HANDSHAKE_FAILED = "handshake_failed"
REASON_INTERNAL_ERROR = "internal_error"

CANARY = "M5T4-CANARY-s3cret-t3rminal"


def _resolve_endpoint_factory(port: int):
    def resolve(
        self: DeviceEndpointPolicy,
        host: str,
        requested_port: int,
        allowed_ports: object,
    ) -> tuple[object, int]:
        del self, host, requested_port, allowed_ports
        import ipaddress

        return ipaddress.ip_address(SIM_HOST), port

    return resolve


def _credentials(*, ssh_password: str = SSH_PASSWORD) -> dict[str, object]:
    return {
        "snmp": {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY},
        "ssh": {"username": SSH_USERNAME, "password": ssh_password},
        "telnet": {"username": SSH_USERNAME, "password": ssh_password},
    }


def _settings(
    fresh_test_db_dsn: str,
    tmp_path,
    *,
    telnet_enabled: bool = False,
    idle_seconds: int = 900,
    max_seconds: int = 7200,
) -> WardenSettings:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs=f"{SIM_HOST}/32",
        credential_master_key_file=key_file,
        session_secret_file=session_file,
        telnet_enabled=telnet_enabled,
        terminal_session_idle_seconds=idle_seconds,
        terminal_session_max_seconds=max_seconds,
    )


class TerminalRig:
    """One terminal test environment: real app + DB over one sim pair."""

    def __init__(
        self,
        fresh_test_db_dsn: str,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
        snmp_port: int,
        *,
        telnet_enabled: bool = False,
        idle_seconds: int = 900,
        max_seconds: int = 7200,
    ) -> None:
        self.settings = _settings(
            fresh_test_db_dsn,
            tmp_path,
            telnet_enabled=telnet_enabled,
            idle_seconds=idle_seconds,
            max_seconds=max_seconds,
        )
        self.app = create_app(self.settings)
        self.factory = create_session_factory(
            create_engine(dsn_with_psycopg_dialect(fresh_test_db_dsn), pool_pre_ping=True)
        )
        key_material = self.settings.credential_master_key.get_secret_value().encode("utf-8")
        self.keyring = CredentialKeyring.from_current(CredentialCipher(key_material))
        with self.factory() as session:
            exists = session.execute(
                text("SELECT 1 FROM users WHERE username = 'admin'")
            ).scalar_one_or_none()
            if exists is None:
                create_admin(session)
        monkeypatch.setattr(
            DeviceEndpointPolicy, "resolve_endpoint", _resolve_endpoint_factory(snmp_port)
        )

    def close(self) -> None:
        engine = self.app.state.engine
        if engine is not None:
            engine.dispose()

    def audit_rows(self, action: str) -> list[dict[str, object]]:
        with self.factory() as session:
            rows = session.execute(
                text(
                    "SELECT resource_id, device_id, result, detail_jsonb FROM audit_logs "
                    "WHERE action = :action ORDER BY created_at"
                ),
                {"action": action},
            ).all()
        return [
            {
                "resource_id": str(row.resource_id) if row.resource_id is not None else None,
                "device_id": str(row.device_id) if row.device_id is not None else None,
                "result": row.result,
                "detail_jsonb": row.detail_jsonb,
            }
            for row in rows
        ]

    def scalar(self, statement: str, **params: object) -> object:
        with self.factory() as session:
            return session.execute(text(statement), params).scalar_one()

    def exec(self, statement: str, **params: object) -> None:
        with self.factory() as session:
            session.execute(text(statement), params)
            session.commit()


def _onboard(
    http: TestClient,
    *,
    name: str,
    snmp_port: int,
    ssh_port: int,
    credentials: dict[str, object],
    vrp_fingerprint: str,
    connection_config: dict[str, object] | None = None,
) -> dict[str, object]:
    response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    config: dict[str, object] = {
        "snmp_version": "v3",
        "port": snmp_port,
        "ssh_port": ssh_port,
        "ssh_host_fingerprint": vrp_fingerprint,
    }
    if connection_config is not None:
        config.update(connection_config)
    probe = http.post(
        f"{API}/device-probes",
        json={
            "device_type": "core_switch",
            "adapter_key": CORE_ADAPTER_KEY,
            "management_endpoint": SIM_HOST,
            "connection_config": config,
            "credentials": credentials,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, body
    created = http.post(
        f"{API}/devices",
        json={
            "name": name,
            "device_type": "core_switch",
            "adapter_key": CORE_ADAPTER_KEY,
            "management_endpoint": SIM_HOST,
            "connection_config": config,
            "credentials": credentials,
            "enabled": True,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _csrf(http: TestClient, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD) -> str:
    response, csrf = login_csrf(http, username, password)
    assert response.status_code == 200
    return csrf


def _launch(http: TestClient, csrf: str, device_id: str, capability_key: str) -> object:
    return http.post(
        f"{API}/devices/{device_id}/launches",
        json={"capability_key": capability_key},
        headers={"X-CSRF-Token": csrf},
    )


def _ws_url(ticket_id: str) -> str:
    return f"{WS_BASE}/{ticket_id}"


@contextmanager
def _rig_env(
    switch_agent,
    fresh_test_db_dsn,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    telnet_enabled: bool = False,
    idle_seconds: int = 900,
    max_seconds: int = 7200,
) -> Iterator[tuple[TerminalRig, object, object, TestClient]]:
    with switch_agent(profile_key="core_s5732") as snmp_handle, running_vrp_server(
        "core_s5732", telnet_enabled=True
    ) as vrp_handle:
        rig = TerminalRig(
            fresh_test_db_dsn,
            tmp_path,
            monkeypatch,
            snmp_handle.port,
            telnet_enabled=telnet_enabled,
            idle_seconds=idle_seconds,
            max_seconds=max_seconds,
        )
        try:
            with TestClient(rig.app) as http:
                yield rig, snmp_handle, vrp_handle, http
        finally:
            rig.close()


def _onboarded_id(http: TestClient, *, name: str, snmp_handle, vrp_handle, **kwargs: object) -> str:
    onboarded = _onboard(
        http,
        name=name,
        snmp_port=int(snmp_handle.port),
        ssh_port=int(vrp_handle.port),
        credentials=_credentials(),
        vrp_fingerprint=vrp_handle.host_fingerprint,
        **kwargs,  # type: ignore[arg-type]
    )
    return str(onboarded["id"])


def _connect_expecting_close(
    http: TestClient, ticket: str, *, origin: str = WS_ORIGIN
) -> tuple[WebSocketDisconnect | None, list[object]]:
    """Open the WS and consume until ready or the expected close code."""
    messages: list[object] = []
    try:
        with http.websocket_connect(_ws_url(ticket), headers={"Origin": origin}) as websocket:
            while True:
                message = websocket.receive()
                if message.get("type") == "websocket.send":
                    if "text" in message:
                        messages.append(json.loads(message["text"]))
                    else:
                        messages.append(message["bytes"])
                elif message.get("type") in ("websocket.close", "websocket.disconnect"):
                    raise WebSocketDisconnect(code=int(message.get("code") or 1000))
    except WebSocketDisconnect as exc:
        return exc, messages
    return None, messages


def _expect_disconnect_code(
    http: TestClient, ticket: str, code: int, *, origin: str = WS_ORIGIN
) -> WebSocketDisconnect:
    exc, _messages = _connect_expecting_close(http, ticket, origin=origin)
    assert exc is not None, "expected a disconnect"
    assert int(exc.code) == code
    return exc


def _refused_frames(messages: list[object]) -> list[dict[str, object]]:
    return [
        message
        for message in messages
        if isinstance(message, dict) and message.get("type") == "refused"
    ]


def _expect_refusal(
    http: TestClient,
    ticket: str,
    code: int,
    reason: str,
    *,
    origin: str = WS_ORIGIN,
) -> list[dict[str, object]]:
    """Assert the post-accept refusal contract: a machine ``refused`` text
    frame precedes the close (code + reason), then the close code lands."""
    exc, messages = _connect_expecting_close(http, ticket, origin=origin)
    assert exc is not None, "expected a disconnect"
    assert int(exc.code) == code
    refused = _refused_frames(messages)
    assert refused, f"expected a refused frame, got {messages!r}"
    frame = refused[-1]
    assert frame["reason"] == reason, frame
    assert frame["code"] == code, frame
    return refused


def _wait_closed(rig: TerminalRig, session_id: str, *, timeout: float = 15.0) -> str:
    """Poll the session row until it is closed (the bridge finalizes
    asynchronously after a client-side disconnect); returns close_reason."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = rig.scalar(
            "SELECT close_reason FROM terminal_sessions WHERE id = :id",
            id=uuid.UUID(session_id),
        )
        if state is not None:
            return str(state)
        time.sleep(0.1)
    raise AssertionError(f"terminal session {session_id} did not close within {timeout}s")


def _wait_audit_count(
    rig: TerminalRig, action: str, expected: int, *, timeout: float = 15.0
) -> list[dict[str, object]]:
    """Poll until ``action`` has ``expected`` audit rows (the bridge writes
    the close audit right after the row close �?inside the live session)."""
    deadline = time.monotonic() + timeout
    rows: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        rows = rig.audit_rows(action)
        if len(rows) >= expected:
            return rows
        time.sleep(0.1)
    raise AssertionError(f"expected {expected} audit rows for {action}, got {len(rows)}")


def _recv_text(websocket, *, timeout: float = 20.0) -> dict[str, object]:
    """Receive until a TEXT control frame arrives (binary terminal frames
    in between are dropped); raises on disconnect."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        message = websocket.receive()
        if message.get("type") == "websocket.send":
            if "text" in message:
                return json.loads(message["text"])
            continue  # binary terminal frames are drained
        if message.get("type") in ("websocket.close", "websocket.disconnect"):
            raise WebSocketDisconnect(code=int(message.get("code") or 1000))
    raise AssertionError("no text frame received")


def _expect_server_close(websocket) -> None:
    """Consume the server's close message (raw in TestClient)."""
    message = websocket.receive()
    assert message.get("type") == "websocket.close", message


class TestTicketGates:
    def test_telnet_global_off_is_not_configured_and_ssh_ticket_is_ws_url(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch, telnet_enabled=False
        ) as (rig, snmp_handle, vrp, http):
            assert vrp.telnet_port is not None
            # The device is fully telnet-configured (opt-in + port + creds):
            # its capability row is supported �?the GLOBAL deployment gate is
            # what refuses the ticket (missing=telnet_enabled).
            telnet_config: dict[str, object] = {"telnet": True, "telnet_port": int(vrp.telnet_port)}
            device_id = _onboarded_id(
                http,
                name="gate-ssh",
                snmp_handle=snmp_handle,
                vrp_handle=vrp,
                connection_config=telnet_config,
            )
            csrf = _csrf(http)
            ssh = _launch(http, csrf, device_id, "console.ssh.open")
            assert ssh.status_code == 201, ssh.text
            body = ssh.json()
            assert body["url"].endswith(f"/api/v1/terminal/sessions/{body['launch_id']}")
            telnet = _launch(http, csrf, device_id, "console.telnet.open")
            assert telnet.status_code == 422
            error = telnet.json()["error"]
            assert error["code"] == "not_configured"
            assert error["details"]["missing"] == "telnet_enabled"
            # The descriptor GET must NOT consume a terminal ticket (the
            # ssh ticket above is still issued �?a refused read never
            # consumes, and the GET of a terminal ticket is a uniform 404).
            launch_id = body["launch_id"]
            consumed = http.get(f"{API}/launches/{launch_id}", headers={"Accept": "application/json"})
            assert consumed.status_code == 404
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "issued"
            # The ticket row binds the device configuration version.
            version = rig.scalar("SELECT version FROM devices WHERE id = :id", id=uuid.UUID(device_id))
            bound = rig.scalar(
                "SELECT device_version FROM launch_sessions WHERE id = :id",
                id=uuid.UUID(launch_id),
            )
            assert bound == version
            assert len(rig.audit_rows("launch.create")) == 1

    def test_telnet_launch_requires_device_optin_and_audits_enabling(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch, telnet_enabled=True
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="gate-telnet", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            # Telnet credentials exist but NO device opt-in/port: honest
            # not_configured from the capability gate (telnet_disabled).
            telnet = _launch(http, csrf, device_id, "console.telnet.open")
            assert telnet.status_code == 422
            error = telnet.json()["error"]
            assert error["code"] == "not_configured"
            assert error["details"]["capability_key"] == "console.telnet.open"
            # Opt in via a fresh probe + PATCH (config change path).
            assert vrp.telnet_port is not None
            config: dict[str, object] = {
                "snmp_version": "v3",
                "port": int(snmp_handle.port),
                "ssh_port": int(vrp.port),
                "ssh_host_fingerprint": vrp.host_fingerprint,
                "telnet": True,
                "telnet_port": int(vrp.telnet_port),
            }
            response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
            assert response.status_code == 200
            # Re-probe the NEW profile at the top-level probe endpoint (the
            # token binds the full fingerprint incl. the telnet opt-in).
            probe = http.post(
                f"{API}/device-probes",
                json={
                    "device_type": "core_switch",
                    "adapter_key": CORE_ADAPTER_KEY,
                    "management_endpoint": SIM_HOST,
                    "connection_config": config,
                    "credentials": _credentials(),
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert probe.status_code == 200, probe.text
            probe_body = probe.json()
            assert probe_body["ok"] is True, probe_body
            current_version = rig.scalar(
                "SELECT version FROM devices WHERE id = :id", id=uuid.UUID(device_id)
            )
            assert current_version is not None
            patched = http.patch(
                f"{API}/devices/{device_id}",
                json={
                    "connection_config": config,
                    "credentials": _credentials(),
                    "probe_token": probe_body["probe_token"],
                },
                headers={
                    "X-CSRF-Token": csrf,
                    "If-Match": str(current_version),
                },
            )
            assert patched.status_code == 200, patched.text
            # The weak-protocol opt-in fired the security audit (M1T4
            # denylist key ``telnet`` -> security.config_changed).
            config_changes = rig.audit_rows("security.config_changed")
            assert any(
                "telnet" in json.dumps(row, ensure_ascii=False) for row in config_changes
            ), config_changes
            telnet = _launch(http, csrf, device_id, "console.telnet.open")
            assert telnet.status_code == 201, telnet.text
            assert telnet.json()["url"].endswith(
                f"/api/v1/terminal/sessions/{telnet.json()['launch_id']}"
            )


class TestTerminalWebSocket:
    def test_ssh_session_echoes_command_and_content_never_leaks(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        # Capture EVERY structlog event of the terminal bridge into a buffer
        # (metadata-only by design); the canary streamed through the session
        # must never appear in logs, audit rows or terminal rows.
        import structlog
        from app.api.routes import terminal as terminal_route

        capture = io.StringIO()
        terminal_route._log = structlog.wrap_logger(  # noqa: SLF001 - test sink
            structlog.PrintLogger(file=capture)
        )
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-ssh", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()[
                "launch_id"
            ]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                assert ready["type"] == "ready"
                session_id = ready["session_id"]
                assert ready["protocol"] == "ssh"
                # The canary travels into the device as raw bytes; it must
                # NEVER surface in logs, audit rows or terminal rows (the
                # sim does not echo typed SSH input, so the stream stays
                # canary-free too).
                websocket.send_bytes(f"{CANARY}\r".encode())
                websocket.send_bytes(b"display version\r")
                output = b""
                while b"V200R021C10SPC600" not in output:
                    output += websocket.receive_bytes()
                assert CANARY.encode("utf-8") not in output
                state = rig.scalar(
                    "SELECT status FROM terminal_sessions WHERE id = :id",
                    id=uuid.UUID(session_id),
                )
                assert state == "open"
                # Client-side disconnect: the bridge finalizes inside the
                # live session (the with-exit would cancel the app task);
                # wait for the row + close audit here.
                websocket.close()
                assert _wait_closed(rig, session_id) == "client_disconnected"
                closed_audits = _wait_audit_count(rig, "terminal.closed", 1)
                assert closed_audits[0]["detail_jsonb"]["reason"] == "client_disconnected"
                # Ticket single-use consumed.
                assert rig.scalar(
                    "SELECT status FROM launch_sessions WHERE id = :id",
                    id=uuid.UUID(launch_id),
                ) == "consumed"
            # CANARY absent from every terminal audit row and row.
            audit_text = json.dumps(
                rig.audit_rows("terminal.handshake_ok") + rig.audit_rows("terminal.closed"),
                ensure_ascii=False,
            )
            assert CANARY not in audit_text
            row_text = rig.scalar(
                "SELECT to_jsonb(t) FROM terminal_sessions t WHERE id = :id",
                id=uuid.UUID(session_id),
            )
            assert CANARY not in json.dumps(row_text, ensure_ascii=False)
        rendered = capture.getvalue()
        assert CANARY not in rendered
        assert "terminal_session_closed" in rendered  # metadata logs happened
    def test_unexpected_dial_failure_closes_row_with_internal_error_and_audits(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        """Review fix: an unexpected exception between the claim and the
        accepted bridge must close the open row NOW (internal_error) with a
        terminal.closed audit �?never leave it for the retention sweep."""
        from app.api.routes import terminal as terminal_route

        async def _dial_boom(websocket, *, terminal_row):
            del websocket, terminal_row
            raise RuntimeError("simulated unexpected dial failure")

        monkeypatch.setattr(terminal_route, "_dial", _dial_boom)
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-dial-boom", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            _expect_refusal(http, launch_id, CLOSE_INTERNAL_ERROR, REASON_INTERNAL_ERROR)
            # The row was closed immediately with internal_error and the
            # consumed ticket cannot replay.
            assert rig.scalar(
                "SELECT close_reason FROM terminal_sessions WHERE launch_session_id = :id",
                id=uuid.UUID(launch_id),
            ) == "internal_error"
            assert rig.scalar(
                "SELECT status FROM terminal_sessions WHERE launch_session_id = :id",
                id=uuid.UUID(launch_id),
            ) == "closed"
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "consumed"
            closed_audits = rig.audit_rows("terminal.closed")
            assert len(closed_audits) == 1
            assert closed_audits[0]["detail_jsonb"]["reason"] == "internal_error"
            assert rig.audit_rows("terminal.handshake_ok") == []
            assert rig.audit_rows("terminal.handshake_failed") == []

    def test_handshake_failure_is_audited_and_closes(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-hs-fail", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            # The sim refuses authentication during the restart blip: the
            # connect handshake fails like a credential/availability failure.
            vrp.device.knobs.restart_blip_seconds = 60.0
            vrp.device.perform_reboot()
            # Post-accept refusal contract: machine frame + close code 4101.
            _expect_refusal(http, launch_id, CLOSE_HANDSHAKE_FAILED, REASON_HANDSHAKE_FAILED)
            failed = rig.audit_rows("terminal.handshake_failed")
            assert len(failed) == 1
            assert failed[0]["result"] == "failure"
            assert failed[0]["detail_jsonb"]["error_code"] in (
                "network_unreachable",
                "authentication_failed",
            )
            assert rig.scalar(
                "SELECT close_reason FROM terminal_sessions WHERE launch_session_id = :id",
                id=uuid.UUID(launch_id),
            ) == "handshake_failed"
            # The ticket was consumed: a failed handshake never replays.
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "consumed"
            assert rig.audit_rows("terminal.handshake_ok") == []
            # Audit pin (M5T4 review): a session that never opened audits
            # ONLY terminal.handshake_failed �?no terminal.closed row (the
            # close-reason vocabulary is carried by the handshake audit).
            assert rig.audit_rows("terminal.closed") == []

    def test_ticket_single_use_and_cross_user_refusal(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-single", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                assert ready["type"] == "ready"
                websocket.send_bytes(b"display version\r")
                while b"V200R021C10SPC600" not in websocket.receive_bytes():
                    pass
                websocket.close()
                assert _wait_closed(rig, ready["session_id"]) == "client_disconnected"
            # Reuse of the same consumed ticket: uniform 4404 refusal.
            _expect_refusal(http, launch_id, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT count(*) FROM terminal_sessions WHERE launch_session_id = :id",
                id=uuid.UUID(launch_id),
            ) == 1
            # A fresh ticket for the same user/device opens fine.
            second = _launch(http, csrf, device_id, "console.ssh.open")
            assert second.status_code == 201
            second_id = second.json()["launch_id"]
            with http.websocket_connect(
                _ws_url(second_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                assert ready["type"] == "ready"
                websocket.close()
                assert _wait_closed(rig, ready["session_id"]) == "client_disconnected"
            # Cross-user: another operator's WS is a uniform 4404 and the
            # ticket stays issued.
            with rig.factory() as session:
                create_user(
                    session,
                    username="op-ws2",
                    password="Op!pass-2026-Strong",
                    role="operator",
                )
            foreign = _launch(http, csrf, device_id, "console.ssh.open")
            assert foreign.status_code == 201
            foreign_id = foreign.json()["launch_id"]
            login = http.post(
                f"{API}/auth/login",
                json={"username": "op-ws2", "password": "Op!pass-2026-Strong"},
                headers={"Origin": WS_ORIGIN},
            )
            assert login.status_code == 200
            _expect_refusal(http, foreign_id, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id",
                id=uuid.UUID(foreign_id),
            ) == "issued"

    def test_expired_and_device_version_changed_tickets_are_uniform_4404(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-expiry", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            rig.exec(
                "UPDATE launch_sessions SET expires_at = now() - interval '1 minute' WHERE id = :id",
                id=uuid.UUID(launch_id),
            )
            _expect_refusal(http, launch_id, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "issued"
            # Device re-configured (version bumped) after issue: refused.
            second = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            rig.exec("UPDATE devices SET version = version + 1 WHERE id = :id", id=uuid.UUID(device_id))
            _expect_refusal(http, second, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(second)
            ) == "issued"

    def test_origin_and_session_checks(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-origin", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            _expect_disconnect_code(
                http, launch_id, CLOSE_FORBIDDEN, origin="http://evil.example"
            )
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "issued"
            # Logged out: unauthenticated close (HTTP-level pre-accept
            # denial �?no refused frame, only the close code the TestClient
            # surfaces for the refused upgrade).
            http.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
            _expect_disconnect_code(http, launch_id, CLOSE_UNAUTHENTICATED)
            # Unknown ticket (authenticated): post-accept uniform 4404
            # refusal frame + code.
            _csrf(http)
            _expect_refusal(http, str(uuid.uuid4()), CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)

    def test_idle_bound_closes_with_reason(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent,
            fresh_test_db_dsn,
            tmp_path,
            monkeypatch,
            idle_seconds=1,
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(http, name="ws-idle", snmp_handle=snmp_handle, vrp_handle=vrp)
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                session_id = ready["session_id"]
                closed = _recv_text(websocket)
                assert closed["type"] == "closed"
                assert closed["reason"] == "idle_timeout"
                _expect_server_close(websocket)
            assert rig.scalar(
                "SELECT close_reason FROM terminal_sessions WHERE id = :id",
                id=uuid.UUID(session_id),
            ) == "idle_timeout"
            assert any(
                row["detail_jsonb"].get("reason") == "idle_timeout"
                for row in rig.audit_rows("terminal.closed")
            )

    def test_max_bound_closes_busy_session(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        # The 2h default is injected as 2 s for the test.
        with _rig_env(
            switch_agent,
            fresh_test_db_dsn,
            tmp_path,
            monkeypatch,
            idle_seconds=900,
            max_seconds=2,
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(http, name="ws-max", snmp_handle=snmp_handle, vrp_handle=vrp)
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                session_id = ready["session_id"]
                closed = _recv_text(websocket)
                assert closed["type"] == "closed"
                assert closed["reason"] == "max_duration"
            assert rig.scalar(
                "SELECT close_reason FROM terminal_sessions WHERE id = :id",
                id=uuid.UUID(session_id),
            ) == "max_duration"

    def test_close_endpoint_closes_live_session_and_is_idempotent(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-close-ep", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launch_id = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                session_id = ready["session_id"]
                websocket.send_bytes(b"display version\r")
                while b"V200R021C10SPC600" not in websocket.receive_bytes():
                    pass
                closed = http.post(
                    f"{API}/terminal/sessions/{session_id}/close",
                    headers={"X-CSRF-Token": csrf},
                )
                assert closed.status_code == 200, closed.text
                body = closed.json()
                assert body["session_id"] == session_id
                assert body["close_reason"] == "user_closed"
                frame = _recv_text(websocket)
                assert frame["type"] == "closed"
                assert frame["reason"] == "user_closed"
                _expect_server_close(websocket)
            assert _wait_closed(rig, session_id) == "user_closed"
            assert len(rig.audit_rows("terminal.closed")) == 1
            again = http.post(
                f"{API}/terminal/sessions/{session_id}/close",
                headers={"X-CSRF-Token": csrf},
            )
            assert again.status_code == 200
            assert len(rig.audit_rows("terminal.closed")) == 1
            # Foreign user close: uniform 404 (no audit).
            with rig.factory() as session:
                create_user(
                    session,
                    username="op-ws3",
                    password="Op!pass-2026-Strong",
                    role="operator",
                )
            login = http.post(
                f"{API}/auth/login",
                json={"username": "op-ws3", "password": "Op!pass-2026-Strong"},
                headers={"Origin": WS_ORIGIN},
            )
            assert login.status_code == 200
            foreign = http.post(
                f"{API}/terminal/sessions/{session_id}/close",
                headers={"X-CSRF-Token": _csrf(http, "op-ws3", "Op!pass-2026-Strong")},
            )
            assert foreign.status_code == 404
            assert len(rig.audit_rows("terminal.closed")) == 1

    def test_concurrency_caps_at_issue_and_claim(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-caps", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            # 1) Issue-time device cap: an OPEN session blocks a new ticket
            #    for the same device (429 device scope).
            open_ticket = _launch(http, csrf, device_id, "console.ssh.open")
            assert open_ticket.status_code == 201
            open_ticket_id = open_ticket.json()["launch_id"]
            with http.websocket_connect(
                _ws_url(open_ticket_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())  # ready frame
                session_id = ready["session_id"]
                second = _launch(http, csrf, device_id, "console.ssh.open")
                assert second.status_code == 429
                assert second.json()["error"]["details"]["scope"] == "launch_session_device"
                websocket.close()
                assert _wait_closed(rig, session_id) == "client_disconnected"
            # 2) After the session closes, the device slot is released.
            released = _launch(http, csrf, device_id, "console.ssh.open")
            assert released.status_code == 201
            valid_ticket = released.json()["launch_id"]
            # 3) Claim-time user cap (defense in depth): while the user's
            #    ticket is still valid, three other active interactions
            #    appear (direct seeding �?only reachable through concurrent
            #    claim races); the claim closes 4429 and never consumes.
            with rig.factory() as session:
                user_id = session.execute(
                    text("SELECT id FROM users WHERE username = 'admin'")
                ).scalar_one()
                web_session_id = session.execute(
                    text("SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1")
                ).scalar_one()
                device_uuid = uuid.UUID(device_id)
                for _index in range(2):
                    extra_ticket = uuid.uuid4()
                    session.execute(
                        text(
                            "INSERT INTO launch_sessions (id, device_id, capability_key, "
                            " requirement_id, user_id, session_id, protocol, descriptor_data, "
                            " status, expires_at, device_version, version) "
                            "VALUES (:id, :device_id, 'console.ssh.open', 'CORE-ACT-03', "
                            " :user_id, :session_id, 'ssh', '{}'::jsonb, 'issued', "
                            " now() + interval '60 seconds', 1, 1)"
                        ),
                        {
                            "id": extra_ticket,
                            "device_id": device_uuid,
                            "user_id": user_id,
                            "session_id": web_session_id,
                        },
                    )
                    session.execute(
                        text(
                            "INSERT INTO terminal_sessions (id, launch_session_id, device_id, "
                            " user_id, protocol, capability_key, requirement_id, status, "
                            " opened_at, last_activity_at) "
                            "VALUES (:id, :ticket_id, :device_id, :user_id, 'ssh', "
                            " 'console.ssh.open', 'CORE-ACT-03', 'open', now(), now())"
                        ),
                        {
                            "id": uuid.uuid4(),
                            "ticket_id": extra_ticket,
                            "device_id": device_uuid,
                            "user_id": user_id,
                        },
                    )
                session.commit()
            _expect_refusal(http, valid_ticket, CLOSE_CAPACITY, REASON_CAPACITY_USER)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id",
                id=uuid.UUID(valid_ticket),
            ) == "issued"

    def test_terminal_lifecycle_evidence(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        """psql-style lifecycle evidence (report record): ticket issue ->
        WS claim -> open row -> command echo -> close endpoint -> closed row
        + audit rows (metadata only, no content)."""
        import datetime as _dt

        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, http):
            device_id = _onboarded_id(
                http, name="ws-evidence", snmp_handle=snmp_handle, vrp_handle=vrp
            )
            csrf = _csrf(http)
            launched = _launch(http, csrf, device_id, "console.ssh.open")
            assert launched.status_code == 201
            launch_id = launched.json()["launch_id"]
            started = _dt.datetime.now(_dt.UTC)
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                session_id = ready["session_id"]
                websocket.send_bytes(b"display version\r")
                output = b""
                while b"V200R021C10SPC600" not in output:
                    output += websocket.receive_bytes()
                opened = rig.scalar(
                    "SELECT to_jsonb(t) FROM terminal_sessions t WHERE id = :id",
                    id=uuid.UUID(session_id),
                )
                assert opened is not None
                import json as _json

                evidence = {
                    "ticket": {
                        "id": launch_id,
                        "protocol": "ssh",
                        "status": rig.scalar(
                            "SELECT status FROM launch_sessions WHERE id = :id",
                            id=uuid.UUID(launch_id),
                        ),
                    },
                    "terminal_session": {
                        "id": session_id,
                        "protocol": _json.loads(_json.dumps(opened))["protocol"],
                        "status": "open",
                        "content_never_stored": "V200R021C10SPC600"
                        not in _json.dumps(opened, ensure_ascii=False),
                    },
                    "echo_ok": b"VRP (R) software, Version V200R021C10SPC600" in output,
                }
                closed = http.post(
                    f"{API}/terminal/sessions/{session_id}/close",
                    headers={"X-CSRF-Token": csrf},
                )
                assert closed.status_code == 200
                frame = _recv_text(websocket)
                assert frame["type"] == "closed"
                _expect_server_close(websocket)
            finished = _dt.datetime.now(_dt.UTC)
            with rig.factory() as session:
                row = session.execute(
                    text(
                        "SELECT to_jsonb(t) FROM terminal_sessions t WHERE id = :id"
                    ),
                    {"id": uuid.UUID(session_id)},
                ).scalar_one()
                audits = session.execute(
                    text(
                        "SELECT action, result, detail_jsonb FROM audit_logs "
                        "WHERE action LIKE 'terminal.%' ORDER BY created_at"
                    )
                ).all()
            evidence["terminal_session"]["status"] = "closed"
            evidence["duration_seconds"] = max(
                1, int((finished - started).total_seconds())
            )
            evidence["rows"] = _json.loads(_json.dumps(row))
            evidence["audit"] = [
                {
                    "action": a.action,
                    "result": a.result,
                    "detail_jsonb": a.detail_jsonb,
                }
                for a in audits
            ]
            evidence["ticket"]["status"] = rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id",
                id=uuid.UUID(launch_id),
            )
            print("\n=== terminal-lifecycle evidence ===")
            print(_json.dumps(evidence, ensure_ascii=False, indent=2))
            print("=== end evidence ===\n")

    def test_telnet_session_echoes_command_with_both_gates(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch, telnet_enabled=True
        ) as (rig, snmp_handle, vrp, http):
            assert vrp.telnet_port is not None
            config: dict[str, object] = {
                "snmp_version": "v3",
                "port": int(snmp_handle.port),
                "ssh_port": int(vrp.port),
                "ssh_host_fingerprint": vrp.host_fingerprint,
                "telnet": True,
                "telnet_port": int(vrp.telnet_port),
            }
            response, csrf = login_csrf(http, ADMIN_USERNAME, ADMIN_PASSWORD)
            assert response.status_code == 200
            probe = http.post(
                f"{API}/device-probes",
                json={
                    "device_type": "core_switch",
                    "adapter_key": CORE_ADAPTER_KEY,
                    "management_endpoint": SIM_HOST,
                    "connection_config": config,
                    "credentials": _credentials(),
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert probe.status_code == 200, probe.text
            body = probe.json()
            assert body["ok"] is True, body
            created = http.post(
                f"{API}/devices",
                json={
                    "name": "ws-telnet",
                    "device_type": "core_switch",
                    "adapter_key": CORE_ADAPTER_KEY,
                    "management_endpoint": SIM_HOST,
                    "connection_config": config,
                    "credentials": _credentials(),
                    "enabled": True,
                    "probe_token": body["probe_token"],
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert created.status_code == 201, created.text
            device_id = str(created.json()["id"])
            launch_id = _launch(http, csrf, device_id, "console.telnet.open").json()["launch_id"]
            with http.websocket_connect(
                _ws_url(launch_id), headers={"Origin": WS_ORIGIN}
            ) as websocket:
                ready = json.loads(websocket.receive_text())
                assert ready["type"] == "ready"
                session_id = ready["session_id"]
                assert ready["protocol"] == "telnet"
                # The login conversation happened during the dial; the
                # banner arrived with the first streamed bytes.
                websocket.send_bytes(b"display version\r")
                output = b""
                while b"V200R021C10SPC600" not in output:
                    output += websocket.receive_bytes()
                assert b"sim-s5732" in output  # banner prompt echoed
                websocket.close()
                assert _wait_closed(rig, session_id) == "client_disconnected"
            assert rig.scalar(
                "SELECT protocol FROM terminal_sessions WHERE id = :id",
                id=uuid.UUID(session_id),
            ) == "telnet"
            handshake = rig.audit_rows("terminal.handshake_ok")
            assert len(handshake) == 1
            assert handshake[0]["detail_jsonb"]["protocol"] == "telnet"


# ---------------------------------------------------------------------------
# Uvicorn-level refusal delivery (M5T4 review fix #1)
#
# A real ASGI server answers a pre-accept ``websocket.close()`` with an
# HTTP 403 handshake denial — the close code NEVER reaches the client (the
# browser sees error + close 1006). The terminal endpoint therefore accepts
# FIRST and refuses ticket/gate/dial failures post-accept: a machine
# ``refused`` JSON frame followed by a private-use close code. These tests
# boot a real uvicorn server over loopback TCP and assert exactly what a
# real client observes for each refusal class: a successful 101 upgrade,
# the refused frame with the specific reason, and the specific close code —
# NOT a bare HTTP 403 (pre-fix, every one of these connects failed with
# HTTP 403 and no code).
# ---------------------------------------------------------------------------


def _start_real_asgi_server(
    app,
) -> tuple[uvicorn.Server, threading.Thread, list[BaseException], int]:
    """Boot one real uvicorn server on a loopback OS-assigned port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        ws="websockets",
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config=config)
    failures: list[BaseException] = []
    thread = threading.Thread(
        target=_run_server_threadsafe(server, sock, failures),
        daemon=True,
        name="uvicorn-terminal-test",
    )
    thread.start()
    deadline = time.monotonic() + 20.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        if failures:
            raise AssertionError(f"real ASGI (uvicorn) server failed: {failures[0]!r}")
        raise AssertionError("real ASGI (uvicorn) server did not start")
    return server, thread, failures, port


def _run_server_threadsafe(
    server: uvicorn.Server, sock: socket.socket, failures: list[BaseException]
):
    def run() -> None:
        try:
            server.run(sockets=[sock])
        except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
            failures.append(exc)

    return run


@contextmanager
def _real_asgi_env(
    switch_agent,
    fresh_test_db_dsn: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    telnet_enabled: bool = False,
) -> Iterator[tuple[TerminalRig, object, object, int]]:
    """One terminal rig served by a REAL uvicorn process thread (no
    TestClient anywhere on the request path)."""
    with switch_agent(profile_key="core_s5732") as snmp_handle, running_vrp_server(
        "core_s5732", telnet_enabled=True
    ) as vrp_handle:
        rig = TerminalRig(
            fresh_test_db_dsn,
            tmp_path,
            monkeypatch,
            snmp_handle.port,
            telnet_enabled=telnet_enabled,
        )
        server, thread, failures, port = _start_real_asgi_server(rig.app)
        try:
            yield rig, snmp_handle, vrp_handle, port
        finally:
            server.should_exit = True
            thread.join(timeout=15.0)
            if failures:
                raise AssertionError(
                    f"real ASGI (uvicorn) server failed at runtime: {failures[0]!r}"
                )
            rig.close()


def _real_login(
    client: httpx.Client,
    *,
    username: str = ADMIN_USERNAME,
    password: str = ADMIN_PASSWORD,
) -> str:
    """Real-HTTP login; returns the per-session CSRF token (the cookie
    stays in the client's jar for the WebSocket handshake)."""
    response = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["csrf_token"])


def _real_onboard(
    client: httpx.Client,
    csrf: str,
    *,
    name: str,
    snmp_port: int,
    ssh_port: int,
    vrp_fingerprint: str,
    connection_config: dict[str, object] | None = None,
) -> str:
    """Real-HTTP probe + create; returns the device id."""
    config: dict[str, object] = {
        "snmp_version": "v3",
        "port": snmp_port,
        "ssh_port": ssh_port,
        "ssh_host_fingerprint": vrp_fingerprint,
    }
    if connection_config is not None:
        config.update(connection_config)
    payload = {
        "device_type": "core_switch",
        "adapter_key": CORE_ADAPTER_KEY,
        "management_endpoint": SIM_HOST,
        "connection_config": config,
        "credentials": _credentials(),
    }
    probe = client.post("/device-probes", json=payload, headers={"X-CSRF-Token": csrf})
    assert probe.status_code == 200, probe.text
    body = probe.json()
    assert body["ok"] is True, body
    created = client.post(
        "/devices",
        json={
            "name": name,
            "device_type": "core_switch",
            "adapter_key": CORE_ADAPTER_KEY,
            "management_endpoint": SIM_HOST,
            "connection_config": config,
            "credentials": _credentials(),
            "enabled": True,
            "probe_token": body["probe_token"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    return str(created.json()["id"])


def _real_launch(client: httpx.Client, csrf: str, device_id: str, capability_key: str) -> str:
    response = client.post(
        f"/devices/{device_id}/launches",
        json={"capability_key": capability_key},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["launch_id"])


async def _real_ws_observe(
    port: int,
    ticket: str,
    *,
    cookie: str | None,
    origin: str = "http://localhost",
) -> tuple[int | None, list[dict[str, object]]]:
    """One real client WS connect over uvicorn: collect text frames until
    the server closes; returns (close_code, parsed text frames)."""
    uri = f"ws://127.0.0.1:{port}/api/v1/terminal/sessions/{ticket}"
    headers = [("Cookie", f"{SESSION_COOKIE_NAME}={cookie}")] if cookie else []
    frames: list[dict[str, object]] = []
    close_code: int | None = None
    async with websockets.connect(uri, origin=origin, additional_headers=headers) as ws:
        while True:
            try:
                message = await asyncio.wait_for(ws.recv(), timeout=15.0)
            except websockets.ConnectionClosed as exc:
                close_code = exc.rcvd.code if exc.rcvd is not None else None
                break
            except TimeoutError:
                raise AssertionError(f"no close within 15 s; frames so far: {frames!r}") from None
            if isinstance(message, str):
                frames.append(json.loads(message))
    return close_code, frames


def _assert_real_refusal(
    frames: list[dict[str, object]], code: int, reason: str
) -> None:
    refused = [frame for frame in frames if frame.get("type") == "refused"]
    assert refused, f"expected a refused frame, got {frames!r}"
    assert refused[-1]["reason"] == reason, frames
    assert refused[-1]["code"] == code, frames


class TestRealAsgiRefusalDelivery:
    """What a REAL client observes for every terminal refusal class.

    Pre-fix, all of these were pre-accept closes: uvicorn answered each
    with HTTP 403 (no close code, no reason frame) — the per-code Chinese
    mapping was dead code in production. Post-fix each refusal must be a
    deliverable post-accept close (frame + code) while the security
    semantics stay identical (a refused ticket is never consumed).
    """

    # uvicorn 0.52's bundled websockets server protocol imports the
    # deprecated ``websockets.legacy`` implementation and warns about it
    # (both warnings fire inside the server thread); pytest's -W error
    # would turn them into a server crash. The client side of these tests
    # uses the current websockets API — only the uvicorn implementation is
    # legacy (uvicorn 0.52 + websockets is the only ws option without new
    # dependencies: no websockets-sansio/wsproto in the lockfile).
    pytestmark = [
        pytest.mark.filterwarnings("ignore:websockets.legacy is deprecated.*:DeprecationWarning"),
        pytest.mark.filterwarnings(
            "ignore:The `websockets` implementation is deprecated.*:uvicorn.config.UvicornDeprecationWarning"
        ),
        # websockets.legacy warns per connection when uvicorn wraps its
        # ws_handler for the removed second argument.
        pytest.mark.filterwarnings("ignore:remove second argument of ws_handler:DeprecationWarning"),
    ]

    @pytest.fixture(autouse=True)
    def _collect_garbage_inside_the_item(self) -> Iterator[None]:
        """Finalize GC objects within the item scope.

        The uvicorn/websockets/psycopg objects of these tests carry
        finalizers (``__del__``) that warn when they are collected while
        still open/not closed cleanly. If collection only happens at
        session cleanup, pytest replays the unraisable AFTER the summary —
        outside every item's ``filterwarnings`` scope — which flips the
        exit code. Collecting deterministically at item teardown keeps the
        finalizers inside the module's warning filters.
        """
        import gc

        yield
        gc.collect()

    async def test_expired_ticket_refusal_is_a_post_accept_close(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _real_asgi_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, port):
            with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as client:
                csrf = _real_login(client)
                device_id = _real_onboard(
                    client,
                    csrf,
                    name="real-expiry",
                    snmp_port=int(snmp_handle.port),
                    ssh_port=int(vrp.port),
                    vrp_fingerprint=vrp.host_fingerprint,
                )
                ticket = _real_launch(client, csrf, device_id, "console.ssh.open")
                rig.exec(
                    "UPDATE launch_sessions SET expires_at = now() - interval '1 minute' "
                    "WHERE id = :id",
                    id=uuid.UUID(ticket),
                )
                close_code, frames = await _real_ws_observe(
                    port, ticket, cookie=client.cookies.get(SESSION_COOKIE_NAME)
                )
            assert close_code == CLOSE_TICKET_UNAVAILABLE
            _assert_real_refusal(frames, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(ticket)
            ) == "issued"

    async def test_cross_user_ticket_refusal_is_a_post_accept_close(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _real_asgi_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, port):
            with rig.factory() as session:
                create_user(
                    session,
                    username="real-op",
                    password="Op!pass-2026-Strong",
                    role="operator",
                )
            with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as admin:
                csrf = _real_login(admin)
                device_id = _real_onboard(
                    admin,
                    csrf,
                    name="real-cross",
                    snmp_port=int(snmp_handle.port),
                    ssh_port=int(vrp.port),
                    vrp_fingerprint=vrp.host_fingerprint,
                )
                ticket = _real_launch(admin, csrf, device_id, "console.ssh.open")
                with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as foreign:
                    _real_login(foreign, username="real-op", password="Op!pass-2026-Strong")
                    close_code, frames = await _real_ws_observe(
                        port, ticket, cookie=foreign.cookies.get(SESSION_COOKIE_NAME)
                    )
            assert close_code == CLOSE_TICKET_UNAVAILABLE
            _assert_real_refusal(frames, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(ticket)
            ) == "issued"

    async def test_device_version_drift_refusal_is_a_post_accept_close(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _real_asgi_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, port):
            with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as client:
                csrf = _real_login(client)
                device_id = _real_onboard(
                    client,
                    csrf,
                    name="real-drift",
                    snmp_port=int(snmp_handle.port),
                    ssh_port=int(vrp.port),
                    vrp_fingerprint=vrp.host_fingerprint,
                )
                ticket = _real_launch(client, csrf, device_id, "console.ssh.open")
                rig.exec(
                    "UPDATE devices SET version = version + 1 WHERE id = :id",
                    id=uuid.UUID(device_id),
                )
                close_code, frames = await _real_ws_observe(
                    port, ticket, cookie=client.cookies.get(SESSION_COOKIE_NAME)
                )
            assert close_code == CLOSE_TICKET_UNAVAILABLE
            _assert_real_refusal(frames, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(ticket)
            ) == "issued"

    async def test_telnet_gate_closed_at_claim_is_a_post_accept_close(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        # The device launches a telnet ticket with BOTH gates on, then the
        # per-device opt-in disappears before the claim: the claim re-gate
        # refuses — deliverable post-accept, ticket never consumed.
        with _real_asgi_env(
            switch_agent,
            fresh_test_db_dsn,
            tmp_path,
            monkeypatch,
            telnet_enabled=True,
        ) as (rig, snmp_handle, vrp, port):
            assert vrp.telnet_port is not None
            telnet_config: dict[str, object] = {
                "telnet": True,
                "telnet_port": int(vrp.telnet_port),
            }
            with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as client:
                csrf = _real_login(client)
                device_id = _real_onboard(
                    client,
                    csrf,
                    name="real-telnet-gate",
                    snmp_port=int(snmp_handle.port),
                    ssh_port=int(vrp.port),
                    vrp_fingerprint=vrp.host_fingerprint,
                    connection_config=telnet_config,
                )
                ticket = _real_launch(client, csrf, device_id, "console.telnet.open")
                # Device opt-in revoked between issue and claim (raw config
                # change — the device VERSION is untouched, so only the
                # telnet gate can refuse).
                rig.exec(
                    "UPDATE devices SET connection_config = connection_config - 'telnet' "
                    "WHERE id = :id",
                    id=uuid.UUID(device_id),
                )
                close_code, frames = await _real_ws_observe(
                    port, ticket, cookie=client.cookies.get(SESSION_COOKIE_NAME)
                )
            assert close_code == CLOSE_TICKET_UNAVAILABLE
            _assert_real_refusal(frames, CLOSE_TICKET_UNAVAILABLE, REASON_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(ticket)
            ) == "issued"

    async def test_concurrency_refusal_is_a_post_accept_close(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _real_asgi_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (rig, snmp_handle, vrp, port):
            with httpx.Client(base_url=f"http://127.0.0.1:{port}/api/v1", timeout=httpx.Timeout(30.0)) as client:
                csrf = _real_login(client)
                device_id = _real_onboard(
                    client,
                    csrf,
                    name="real-cap",
                    snmp_port=int(snmp_handle.port),
                    ssh_port=int(vrp.port),
                    vrp_fingerprint=vrp.host_fingerprint,
                )
                ticket = _real_launch(client, csrf, device_id, "console.ssh.open")
                # Defense-in-depth claim-time user cap: while the user's
                # ticket is still valid, two other open interactions appear
                # (direct seeding — the issue-time caps already passed).
                with rig.factory() as session:
                    user_id = session.execute(
                        text("SELECT id FROM users WHERE username = 'admin'")
                    ).scalar_one()
                    web_session_id = session.execute(
                        text("SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1")
                    ).scalar_one()
                    device_uuid = uuid.UUID(device_id)
                    for _index in range(2):
                        extra_ticket = uuid.uuid4()
                        session.execute(
                            text(
                                "INSERT INTO launch_sessions (id, device_id, capability_key, "
                                " requirement_id, user_id, session_id, protocol, descriptor_data, "
                                " status, expires_at, device_version, version) "
                                "VALUES (:id, :device_id, 'console.ssh.open', 'CORE-ACT-03', "
                                " :user_id, :session_id, 'ssh', '{}'::jsonb, 'issued', "
                                " now() + interval '60 seconds', 1, 1)"
                            ),
                            {
                                "id": extra_ticket,
                                "device_id": device_uuid,
                                "user_id": user_id,
                                "session_id": web_session_id,
                            },
                        )
                        session.execute(
                            text(
                                "INSERT INTO terminal_sessions (id, launch_session_id, device_id, "
                                " user_id, protocol, capability_key, requirement_id, status, "
                                " opened_at, last_activity_at) "
                                "VALUES (:id, :ticket_id, :device_id, :user_id, 'ssh', "
                                " 'console.ssh.open', 'CORE-ACT-03', 'open', now(), now())"
                            ),
                            {
                                "id": uuid.uuid4(),
                                "ticket_id": extra_ticket,
                                "device_id": device_uuid,
                                "user_id": user_id,
                            },
                        )
                    session.commit()
                close_code, frames = await _real_ws_observe(
                    port, ticket, cookie=client.cookies.get(SESSION_COOKIE_NAME)
                )
            assert close_code == CLOSE_CAPACITY
            _assert_real_refusal(frames, CLOSE_CAPACITY, REASON_CAPACITY_USER)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(ticket)
            ) == "issued"

    async def test_pre_accept_auth_denials_stay_http_level(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        """Origin/session conditions close BEFORE accept on purpose: a real
        client observes an HTTP 403 handshake denial (no code) — that is
        the documented HTTP-level behavior, unlike ticket refusals."""
        with _real_asgi_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
        ) as (_rig, _snmp, _vrp, port):
            uri = f"ws://127.0.0.1:{port}/api/v1/terminal/sessions/{uuid.uuid4()}"
            with pytest.raises(websockets.exceptions.InvalidStatus) as excinfo:
                async with websockets.connect(uri, origin="http://localhost"):
                    pass  # pragma: no cover - the handshake must be denied
            assert excinfo.value.response.status_code == 403
            with pytest.raises(websockets.exceptions.InvalidStatus) as excinfo:
                async with websockets.connect(
                    uri,
                    origin="http://evil.example",
                    additional_headers=[("Cookie", "warden_session=bogus")],
                ):
                    pass  # pragma: no cover - the handshake must be denied
            assert excinfo.value.response.status_code == 403


class TestWebConsoleLaunchSlice:
    """M5T5 console.web.open end-to-end over the real API + real PostgreSQL.

    The device is onboarded with the operator-declared web origin
    (web_scheme/web_port in connection_config); the launch issues a
    one-time URL descriptor that GET /launches/{id} consumes exactly once
    (ADR-006: browser-side page, no credentials, no guessed port). psql
    evidence: launch_sessions lifecycle + launch.create / launch.consume
    audit rows. No web server exists in the rig — the descriptor targets
    the declared origin and the adapter never claims a device-side web
    answer it cannot probe over SNMP (honest declaration-driven URL).
    """

    def test_web_console_launch_issues_consumes_once_and_audits(
        self, switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch
    ) -> None:
        with _rig_env(
            switch_agent, fresh_test_db_dsn, tmp_path, monkeypatch, telnet_enabled=False
        ) as (rig, snmp_handle, vrp, http):
            web_config: dict[str, object] = {
                "web_scheme": "https",
                "web_port": 8443,
            }
            device_id = _onboarded_id(
                http,
                name="web-console",
                snmp_handle=snmp_handle,
                vrp_handle=vrp,
                connection_config=web_config,
            )
            # The capability row flipped supported at onboarding (declared
            # origin) with the honest requirement map.
            capabilities = http.get(f"{API}/devices/{device_id}/capabilities")
            assert capabilities.status_code == 200
            by_key = {item["capability_key"]: item for item in capabilities.json()["items"]}
            row = by_key["console.web.open"]
            assert row["support_state"] == "supported", row
            assert row["requirement_id"] == "CORE-ACT-03"

            csrf = _csrf(http)
            created = _launch(http, csrf, device_id, "console.web.open")
            assert created.status_code == 201, created.text
            body = created.json()
            launch_id = body["launch_id"]
            # URL-kind tickets consume through GET /launches/{id} (the SPA
            # navigates to this single-use same-origin URL) — NOT the
            # terminal WS path.
            assert body["url"].endswith(f"/api/v1/launches/{launch_id}")
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "issued"
            assert rig.scalar(
                "SELECT protocol FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "web"

            consumed = http.get(
                f"{API}/launches/{launch_id}", headers={"Accept": "application/json"}
            )
            assert consumed.status_code == 200, consumed.text
            payload = consumed.json()
            descriptor = payload["descriptor"]
            # The declared origin, default-port-free and WITHOUT credentials.
            assert descriptor["kind"] == "url"
            assert descriptor["url"] == "https://127.0.0.1:8443"
            assert "password" not in descriptor["url"]
            assert payload["capability_key"] == "console.web.open"
            # Single-use: the second read is a uniform 404.
            again = http.get(f"{API}/launches/{launch_id}", headers={"Accept": "application/json"})
            assert again.status_code == 404
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "consumed"

            # A device whose web origin is REMOVED afterwards goes through
            # the launch gate honestly: re-probe + PATCH the SAME device
            # without web_scheme/web_port -> the launch is refused
            # (capability or live adapter gate) and NO new row is created.
            config_without_web: dict[str, object] = {
                "snmp_version": "v3",
                "port": int(snmp_handle.port),
                "ssh_port": int(vrp.port),
                "ssh_host_fingerprint": vrp.host_fingerprint,
            }
            probe = http.post(
                f"{API}/device-probes",
                json={
                    "device_type": "core_switch",
                    "adapter_key": CORE_ADAPTER_KEY,
                    "management_endpoint": SIM_HOST,
                    "connection_config": config_without_web,
                    "credentials": _credentials(),
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert probe.status_code == 200, probe.text
            probe_body = probe.json()
            assert probe_body["ok"] is True, probe_body
            current_version = rig.scalar(
                "SELECT version FROM devices WHERE id = :id", id=uuid.UUID(device_id)
            )
            assert current_version is not None
            patched = http.patch(
                f"{API}/devices/{device_id}",
                json={
                    "connection_config": config_without_web,
                    "credentials": _credentials(),
                    "probe_token": probe_body["probe_token"],
                },
                headers={
                    "X-CSRF-Token": csrf,
                    "If-Match": str(current_version),
                },
            )
            assert patched.status_code == 200, patched.text
            refused = _launch(http, csrf, device_id, "console.web.open")
            assert refused.status_code == 422
            error = refused.json()["error"]
            assert error["code"] == "not_configured"
            assert error["details"]["capability_key"] == "console.web.open"
            assert (
                rig.scalar(
                    "SELECT count(*) FROM launch_sessions WHERE device_id = :id",
                    id=uuid.UUID(device_id),
                )
                == 1
            )

            # Audit trail: one issue + one consume for the web launch; the
            # refused launch writes no launch row and no launch audit.
            issues = rig.audit_rows("launch.create")
            consumes = rig.audit_rows("launch.consume")
            assert len(issues) == 1 and len(consumes) == 1
            assert issues[0]["resource_id"] == launch_id
            assert consumes[0]["resource_id"] == launch_id
            assert "console.web.open" in json.dumps(issues[0]["detail_jsonb"], ensure_ascii=False)

