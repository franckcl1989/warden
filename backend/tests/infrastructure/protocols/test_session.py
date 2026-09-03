"""Redfish session auth tests (docs/SECURITY.md §6, DEVICE_ADAPTERS.md §10).

Session lifecycle: create on demand via /SessionService/Sessions, reuse within
a bounded lifetime, delete on close; HTTP Basic ONLY when ``auth_mode=basic``
was declared explicitly — never a silent downgrade. Tokens and credentials
never appear in logs.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
import structlog
from app.infrastructure.logging import redact_sensitive_values
from app.infrastructure.protocols.redfish.errors import RedfishError
from app.infrastructure.protocols.redfish.session import (
    AuthMode,
    BasicAuth,
    RedfishCredentials,
    SessionAuth,
)
from structlog.contextvars import clear_contextvars

BMC = "http://bmc.test"
BASE = "/redfish/v1"
USER = "sim-admin"
PASSWORD = "sim-password-secret"


def make_http(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=BMC,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )


def ok_login_response() -> httpx.Response:
    return httpx.Response(
        201,
        headers={"X-Auth-Token": "tok-12345", "Location": f"{BASE}/SessionService/Sessions/42"},
        json={"@odata.id": f"{BASE}/SessionService/Sessions/42"},
    )


class Recorder:
    def __init__(self, responder: Callable[[str], httpx.Response]) -> None:
        self.requests: list[dict[str, Any]] = []
        self._responder = responder

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "headers": {key.lower(): value for key, value in request.headers.items()},
                "body": json.loads(request.content) if request.content else None,
            }
        )
        return self._responder(request.url.path)


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


@pytest.fixture(autouse=True)
def clear_log_context() -> Iterator[None]:
    clear_contextvars()
    yield
    clear_contextvars()


class TestSessionLogin:
    @pytest.mark.unit
    def test_login_posts_credentials_and_reuses_token(self) -> None:
        recorder = Recorder(lambda path: ok_login_response() if path.endswith("/Sessions") else httpx.Response(404))
        http = make_http(recorder.handler)
        auth = SessionAuth(
            http,
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        assert auth.headers() == {"X-Auth-Token": "tok-12345"}
        auth.prepare()  # within lifetime: reused, no second login
        login_calls = [r for r in recorder.requests if r["path"].endswith("/Sessions")]
        assert len(login_calls) == 1
        assert login_calls[0]["method"] == "POST"
        assert login_calls[0]["body"] == {"UserName": USER, "Password": PASSWORD}

    @pytest.mark.unit
    def test_login_without_expiry_keeps_token(self) -> None:
        recorder = Recorder(lambda path: ok_login_response() if path.endswith("/Sessions") else httpx.Response(404))
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        auth.prepare()
        auth.prepare()
        assert len([r for r in recorder.requests if r["path"].endswith("/Sessions")]) == 1

    @pytest.mark.unit
    def test_expired_session_logs_in_again(self) -> None:
        times = iter([100.0, 100.0, 100.0, 2600.0, 2600.0])

        def responder(path: str) -> httpx.Response:
            return ok_login_response() if path.endswith("/Sessions") else httpx.Response(404)

        auth = SessionAuth(
            make_http(Recorder(responder).handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            session_lifetime=1800.0,
            clock=lambda: next(times),
            logger=captured_logger()[0],
        )
        auth.prepare()  # 100s: login, created_at=100
        first_token = auth.headers()["X-Auth-Token"]
        auth.prepare()  # 100s: still within 1800s, reuse
        assert auth.headers()["X-Auth-Token"] == first_token
        auth.prepare()  # 2600s: expired -> fresh login
        assert auth.headers()["X-Auth-Token"] == "tok-12345"

    @pytest.mark.unit
    def test_close_deletes_session_with_token(self) -> None:
        recorder = Recorder(
            lambda path: (
                ok_login_response()
                if path.endswith("/Sessions")
                else httpx.Response(204)
                if "/Sessions/42" in path
                else httpx.Response(404)
            )
        )
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        auth.close()
        delete_calls = [r for r in recorder.requests if r["method"] == "DELETE"]
        assert len(delete_calls) == 1
        assert delete_calls[0]["path"] == f"{BASE}/SessionService/Sessions/42"
        assert delete_calls[0]["headers"].get("x-auth-token") == "tok-12345"

    @pytest.mark.unit
    def test_close_without_session_uri_does_not_call_device(self) -> None:
        recorder = Recorder(lambda path: ok_login_response() if path.endswith("/Sessions") else httpx.Response(404))
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth._session_uri = None  # device gave no Location and no body odata.id
        auth._token = "tok-x"
        auth.close()
        assert not [r for r in recorder.requests if r["method"] == "DELETE"]

    @pytest.mark.unit
    def test_absolute_same_origin_location_is_deleted_as_a_path(self) -> None:
        # A spec-legal absolute same-origin Location must never carry the
        # token off the client's base URL: close() normalizes it to a path.
        recorder = Recorder(
            lambda path: (
                httpx.Response(
                    201,
                    headers={
                        "X-Auth-Token": "tok-12345",
                        "Location": f"{BMC}{BASE}/SessionService/Sessions/42",
                    },
                    json={},
                )
                if path.endswith("/Sessions")
                else httpx.Response(204)
                if "/Sessions/42" in path
                else httpx.Response(404)
            )
        )
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        auth.close()
        delete_calls = [r for r in recorder.requests if r["method"] == "DELETE"]
        assert len(delete_calls) == 1
        assert delete_calls[0]["path"] == f"{BASE}/SessionService/Sessions/42"
        assert delete_calls[0]["headers"].get("x-auth-token") == "tok-12345"

    @pytest.mark.unit
    def test_foreign_absolute_location_is_never_contacted_with_the_token(self) -> None:
        # A hostile/broken device Location pointing off-origin must not carry
        # X-Auth-Token anywhere: the URI is dropped and close() sends no DELETE.
        recorder = Recorder(
            lambda path: (
                httpx.Response(
                    201,
                    headers={
                        "X-Auth-Token": "tok-12345",
                        "Location": "http://evil.example/redfish/v1/SessionService/Sessions/42",
                    },
                    json={},
                )
                if path.endswith("/Sessions")
                else httpx.Response(404)
            )
        )
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        assert auth.headers() == {"X-Auth-Token": "tok-12345"}
        auth.close()
        assert not [r for r in recorder.requests if r["method"] == "DELETE"]

    @pytest.mark.unit
    def test_absolute_same_origin_body_odata_id_is_deleted_as_a_path(self) -> None:
        # No Location header: the body @odata.id is the session URI and is
        # normalized the same way.
        recorder = Recorder(
            lambda path: (
                httpx.Response(
                    201,
                    headers={"X-Auth-Token": "tok-12345"},
                    json={"@odata.id": f"{BMC}{BASE}/SessionService/Sessions/42"},
                )
                if path.endswith("/Sessions")
                else httpx.Response(204)
                if "/Sessions/42" in path
                else httpx.Response(404)
            )
        )
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        auth.close()
        delete_calls = [r for r in recorder.requests if r["method"] == "DELETE"]
        assert len(delete_calls) == 1
        assert delete_calls[0]["path"] == f"{BASE}/SessionService/Sessions/42"

    @pytest.mark.unit
    def test_login_rejection_maps_authentication_failed(self) -> None:
        body = {
            "error": {
                "code": "Base.1.13.GeneralError",
                "message": "invalid user or password",
                "@Message.ExtendedInfo": [
                    {
                        "@odata.type": "#Message.v1_1_2.Message",
                        "MessageId": "Base.1.13.GeneralError",
                        "Message": "invalid user or password",
                    }
                ],
            }
        }
        recorder = Recorder(lambda path: httpx.Response(401, json=body))
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        with pytest.raises(RedfishError) as exc:
            auth.prepare()
        assert exc.value.code == "authentication_failed"

    @pytest.mark.unit
    def test_session_service_missing_never_downgrades_silently(self) -> None:
        # Old manager without SessionService: POST yields 404/405/501. With
        # auth_mode=session there is NO silent fallback to HTTP Basic.
        recorder = Recorder(lambda path: httpx.Response(404, json={}))
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        with pytest.raises(RedfishError) as exc:
            auth.prepare()
        assert exc.value.code == "authentication_failed"
        assert auth.headers() == {}
        assert all("Authorization" not in r["headers"] for r in recorder.requests)

    @pytest.mark.unit
    def test_login_without_token_header_is_protocol_error(self) -> None:
        recorder = Recorder(lambda path: httpx.Response(201, json={}))
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        with pytest.raises(RedfishError) as exc:
            auth.prepare()
        assert exc.value.code == "protocol_error"


class TestBasicAndNone:
    @pytest.mark.unit
    def test_basic_mode_sends_authorization_without_any_session_call(self) -> None:
        recorder = Recorder(lambda path: httpx.Response(404))
        auth = BasicAuth(
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        auth.prepare()
        expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        assert auth.headers() == {"Authorization": expected}
        assert recorder.requests == []

    @pytest.mark.unit
    def test_basic_has_no_reauth_and_never_logs_password(self) -> None:
        auth = BasicAuth(
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=captured_logger()[0],
        )
        assert auth.can_reauth is False
        assert PASSWORD not in repr(auth)
        assert PASSWORD not in str(auth.headers())


class TestCredentialHygiene:
    @pytest.mark.unit
    def test_session_login_never_logs_token_or_password(self) -> None:
        recorder = Recorder(lambda path: ok_login_response() if path.endswith("/Sessions") else httpx.Response(404))
        logger, lines = captured_logger()
        auth = SessionAuth(
            make_http(recorder.handler),
            base_path=BASE,
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=logger,
        )
        auth.prepare()
        logger.info("auth headers attached", **auth.headers())
        auth.close()
        combined = "\n".join(lines)
        assert "tok-12345" not in combined
        assert PASSWORD not in combined
        assert "tok-12345" not in repr(auth)
        assert PASSWORD not in repr(auth)


class TestAuthModeEnum:
    @pytest.mark.unit
    def test_auth_mode_values(self) -> None:
        assert AuthMode("session") is AuthMode.SESSION
        assert AuthMode("basic") is AuthMode.BASIC
        assert AuthMode("none") is AuthMode.NONE

    @pytest.mark.unit
    def test_credentials_repr_hides_password(self) -> None:
        credentials = RedfishCredentials(username=USER, password=PASSWORD)
        assert PASSWORD not in repr(credentials)
        assert USER in repr(credentials)
