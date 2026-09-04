"""Browser-terminal WS/API integration tests (M5T4, real PostgreSQL).

End-to-end over the real API against the VRP simulators (SNMP agent for
onboarding + asyncssh SSH server with telnet variant): console.ssh.open /
console.telnet.open tickets (gates, WS url), the WebSocket lifecycle
(ticket single-use + expiry + user binding + device-version binding,
concurrency caps, idle/max bounds, close endpoint, audit, and the
never-log-content rule with a canary string). The simulators are TEST
DEVICES — never hardware evidence (tests/simulators/vrp/README.md).
"""

from __future__ import annotations

import io
import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.network_policy import DeviceEndpointPolicy
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
    the close audit right after the row close — inside the live session)."""
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
            # its capability row is supported — the GLOBAL deployment gate is
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
            # ssh ticket above is still issued — a refused read never
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
            _expect_disconnect_code(http, launch_id, CLOSE_HANDSHAKE_FAILED)
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
            # Reuse of the same consumed ticket: uniform 4404.
            _expect_disconnect_code(http, launch_id, CLOSE_TICKET_UNAVAILABLE)
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
            _expect_disconnect_code(http, foreign_id, CLOSE_TICKET_UNAVAILABLE)
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
            _expect_disconnect_code(http, launch_id, CLOSE_TICKET_UNAVAILABLE)
            assert rig.scalar(
                "SELECT status FROM launch_sessions WHERE id = :id", id=uuid.UUID(launch_id)
            ) == "issued"
            # Device re-configured (version bumped) after issue: refused.
            second = _launch(http, csrf, device_id, "console.ssh.open").json()["launch_id"]
            rig.exec("UPDATE devices SET version = version + 1 WHERE id = :id", id=uuid.UUID(device_id))
            _expect_disconnect_code(http, second, CLOSE_TICKET_UNAVAILABLE)
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
            # Logged out: unauthenticated close.
            http.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
            _expect_disconnect_code(http, launch_id, CLOSE_UNAUTHENTICATED)
            # Unknown ticket (authenticated): uniform 4404.
            _csrf(http)
            _expect_disconnect_code(http, str(uuid.uuid4()), CLOSE_TICKET_UNAVAILABLE)

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
            #    appear (direct seeding — only reachable through concurrent
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
            _expect_disconnect_code(http, valid_ticket, CLOSE_CAPACITY)
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
