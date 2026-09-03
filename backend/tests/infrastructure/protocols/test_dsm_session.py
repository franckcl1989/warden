"""DSMSession tests: login/logout/lifetime, honesty rows, sid hygiene.

docs/DEVICE_ADAPTERS.md §5/§7; SECURITY.md §5: the sid is never logged and
never rendered; a 2FA-required login is a ``not_configured missing=otp``
credential gap (automation uses a dedicated non-2FA account).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import structlog
from app.infrastructure.logging import redact_sensitive_values
from app.infrastructure.protocols.dsm.discovery import ApiCallSpec
from app.infrastructure.protocols.dsm.errors import DSMError
from app.infrastructure.protocols.dsm.session import DSMCredentials, DSMSession

NAS = "http://dsm.test"
BASE = "/webapi"
AUTH_SPEC = ApiCallSpec(api_name="SYNO.API.Auth", path="auth.cgi", version=6)
USER = "sim-admin"
PASSWORD = "sim-password-secret"
SID = "sim-sid-secret-1234567890"


class Recorder:
    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[dict[str, Any]] = []
        self._responder = responder

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.url.params),
                "body": _form_body(request),
            }
        )
        return self._responder(request)


def _form_body(request: httpx.Request) -> dict[str, str]:
    if not request.content:
        return {}
    parsed: dict[str, str] = {}
    for key, values in parse_qs(request.content.decode("utf-8"), keep_blank_values=True).items():
        parsed[key] = values[0]
    return parsed


def make_http(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=NAS,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )


def login_ok() -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": {"sid": SID}})


def login_error(code: int) -> httpx.Response:
    return httpx.Response(200, json={"success": False, "error": {"code": code}})


def captured_logger() -> tuple[structlog.BoundLogger, list[str]]:
    lines: list[str] = []

    class _Sink:
        def write(self, data: str) -> None:
            lines.append(data)

        def flush(self) -> None:
            return None

    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=_Sink()),
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_sensitive_values,
            structlog.processors.JSONRenderer(),
        ],
    )
    return logger, lines


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_session(
    recorder: Recorder,
    *,
    lifetime: float = 1800.0,
    clock: Callable[[], float] | None = None,
    logger: structlog.BoundLogger | None = None,
) -> DSMSession:
    return DSMSession(
        make_http(recorder.handler),
        base_path=BASE,
        auth_spec=AUTH_SPEC,
        credentials=DSMCredentials(username=USER, password=PASSWORD),
        logger=logger if logger is not None else structlog.get_logger(),
        session_lifetime=lifetime,
        clock=clock,
    )


class TestLogin:
    def test_login_posts_form_params_and_holds_sid(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        session = make_session(recorder)
        session.login()
        assert session.has_session
        assert session.sid_param() == {"_sid": SID}
        (call,) = recorder.requests
        assert call["method"] == "POST"
        assert call["path"] == "/webapi/auth.cgi"
        assert call["body"]["api"] == "SYNO.API.Auth"
        assert call["body"]["version"] == "6"
        assert call["body"]["method"] == "login"
        assert call["body"]["account"] == USER
        assert call["body"]["passwd"] == PASSWORD
        assert call["body"]["session"] == "DiskStation"
        assert call["body"]["format"] == "sid"

    def test_ensure_alive_reuses_session_within_lifetime(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        clock = FakeClock()
        session = make_session(recorder, clock=clock)
        session.ensure_alive()
        clock.now += 100
        session.ensure_alive()
        logins = [r for r in recorder.requests if r["body"].get("method") == "login"]
        assert len(logins) == 1

    def test_session_re_login_after_bounded_lifetime(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        clock = FakeClock()
        logger, lines = captured_logger()
        session = make_session(recorder, lifetime=1800.0, clock=clock, logger=logger)
        session.ensure_alive()
        clock.now += 1801
        session.ensure_alive()
        logins = [r for r in recorder.requests if r["body"].get("method") == "login"]
        assert len(logins) == 2
        assert any("dsm.session.expired" in line for line in lines)

    def test_wrong_password_is_authentication_failed(self) -> None:
        recorder = Recorder(lambda request: login_error(401))
        session = make_session(recorder)
        with pytest.raises(DSMError) as exc:
            session.login()
        assert exc.value.code == "authentication_failed"
        assert session.has_session is False

    def test_two_factor_required_is_not_configured_missing_otp(self) -> None:
        recorder = Recorder(lambda request: login_error(403))
        session = make_session(recorder)
        with pytest.raises(DSMError) as exc:
            session.login()
        assert exc.value.code == "not_configured"
        assert exc.value.missing == "otp"
        assert session.has_session is False

    def test_login_success_without_sid_is_protocol_error(self) -> None:
        recorder = Recorder(lambda request: httpx.Response(200, json={"success": True, "data": {}}))
        session = make_session(recorder)
        with pytest.raises(DSMError) as exc:
            session.login()
        assert exc.value.code == "protocol_error"
        assert session.has_session is False

    def test_closed_session_refuses_login(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        session = make_session(recorder)
        session.close()
        with pytest.raises(DSMError) as exc:
            session.ensure_alive()
        assert exc.value.code == "authentication_failed"


class TestLogout:
    def test_logout_posts_sid_and_clears_state(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        session = make_session(recorder)
        session.login()
        recorder.requests.clear()
        session.logout()
        assert session.has_session is False
        (call,) = recorder.requests
        assert call["body"]["method"] == "logout"
        assert call["body"]["_sid"] == SID
        assert call["body"]["session"] == "DiskStation"

    def test_close_logs_out_once(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        session = make_session(recorder)
        session.login()
        session.close()
        session.close()
        logouts = [r for r in recorder.requests if r["body"].get("method") == "logout"]
        assert len(logouts) == 1

    def test_logout_transport_failure_is_best_effort(self) -> None:
        def failing(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("device gone")

        recorder = Recorder(failing)
        session = make_session(recorder)
        # Seed the sid without a real login (login would fail on transport).
        session._sid = SID  # noqa: SLF001
        session._created_at = 0.0
        session.logout()  # must not raise
        assert session.has_session is False


class TestHygiene:
    def test_credentials_repr_redacts_password(self) -> None:
        credentials = DSMCredentials(username=USER, password=PASSWORD)
        rendered = repr(credentials)
        assert PASSWORD not in rendered
        assert USER in rendered

    def test_sid_never_logged(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        logger, lines = captured_logger()
        session = make_session(recorder, logger=logger)
        session.login()
        session.ensure_alive()
        session.on_session_rejected()
        session.close()
        rendered = "\n".join(lines)
        assert SID not in rendered
        assert PASSWORD not in rendered

    def test_login_record_callback_reports_exact_basis(self) -> None:
        recorder = Recorder(lambda request: login_ok())
        session = make_session(recorder)
        seen: list[tuple[str, str, str, int]] = []
        session.on_call = lambda api, method, path, version: seen.append((api, method, path, version))
        session.login()
        session.logout()
        assert seen == [
            ("SYNO.API.Auth", "login", "auth.cgi", 6),
            ("SYNO.API.Auth", "logout", "auth.cgi", 6),
        ]
