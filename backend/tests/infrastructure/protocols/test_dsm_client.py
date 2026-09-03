"""DSMClient tests: envelope calls, bounded re-login, retries, ledger.

docs/DEVICE_ADAPTERS.md §5/§7/§8/§9 + ADR-018: safe (GET) calls retry with
bounded backoff; side-effect (POST) calls are never retried; a mid-call
session-timeout re-logs in at most once; the ADR-018 call ledger records the
exact (api, method, path, version) of every platform call; sid and
credentials never reach logs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import structlog
from app.infrastructure.logging import redact_sensitive_values
from app.infrastructure.protocols.dsm.client import CERTIFIED_API_VERSIONS, DSMClient, DSMEndpoint
from app.infrastructure.protocols.dsm.discovery import AUTH_API_NAME, INFO_API_NAME
from app.infrastructure.protocols.dsm.errors import DSMError
from app.infrastructure.protocols.dsm.session import DSMCredentials

NAS = "http://dsm.test"
BASE = "/webapi"
USER = "sim-admin"
PASSWORD = "sim-password-secret"
SID = "sim-sid-secret-1234567890"

INFO_MAP: dict[str, dict[str, object]] = {
    "SYNO.API.Info": {"path": "query.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 6},
    "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
    "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 9},
    "SYNO.Core.UPS": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.System.Log": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
}


def info_ok() -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": INFO_MAP})


def login_ok() -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": {"sid": SID}})


def login_error(code: int) -> httpx.Response:
    return httpx.Response(200, json={"success": False, "error": {"code": code}})


def data_ok(data: object) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data})


def dsm_error(code: int) -> httpx.Response:
    return httpx.Response(200, json={"success": False, "error": {"code": code}})


class Recorder:
    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[dict[str, Any]] = []
        self._responder = responder

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "params": _params_of(request),
            }
        )
        return self._responder(request)


def _params_of(request: httpx.Request) -> dict[str, str]:
    if request.method == "GET":
        return dict(request.url.params)
    if not request.content:
        return {}
    return {key: values[0] for key, values in parse_qs(request.content.decode("utf-8")).items()}


def make_http(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=NAS,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )


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


class _Server:
    """Scriptable DSM server: routing by (api, method) with per-key overrides."""

    def __init__(self) -> None:
        self.logins = 0
        self.login_answer: httpx.Response | None = None
        self.call_answer: httpx.Response | None = None
        self.authed_calls = 0
        self.sid = SID

    def handler(self, request: httpx.Request) -> httpx.Response:
        params = _params_of(request)
        api = params.get("api")
        method = params.get("method")
        if api == INFO_API_NAME and method == "query":
            return info_ok()
        if api == AUTH_API_NAME and method == "login":
            self.logins += 1
            if self.login_answer is not None:
                return self.login_answer
            return login_ok()
        if api == AUTH_API_NAME and method == "logout":
            return data_ok({})
        self.authed_calls += 1
        if self.call_answer is not None:
            return self.call_answer
        return data_ok({"echo": {"api": api, "method": method}})


def make_client(
    recorder: Recorder,
    server: _Server,
    *,
    logger: structlog.BoundLogger | None = None,
    **kwargs: Any,
) -> DSMClient:
    return DSMClient(
        make_http(recorder.handler),
        base_path=BASE,
        endpoint=DSMEndpoint(host="dsm.test", port=80, base_path=BASE, scheme="http"),
        credentials=DSMCredentials(username=USER, password=PASSWORD),
        logger=logger,
        **kwargs,
    )


class TestCallFlow:
    def test_discovery_then_call_attaches_sid_and_returns_data(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        client = make_client(recorder, server)
        with client:
            result = client.call("SYNO.Core.System", "info", safe=True)
            assert result == {"echo": {"api": "SYNO.Core.System", "method": "info"}}
        calls = {r["params"].get("method"): r for r in recorder.requests}
        assert calls["query"]["params"]["api"] == INFO_API_NAME
        authed = calls["info"]
        assert authed["method"] == "GET"
        assert authed["path"] == "/webapi/entry.cgi"
        assert authed["params"]["_sid"] == SID
        assert authed["params"]["api"] == "SYNO.Core.System"
        assert authed["params"]["version"] == "2"
        logout = calls["logout"]
        assert logout["method"] == "POST"
        assert logout["params"]["_sid"] == SID

    def test_login_never_retried_but_flows_once(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            client.call("SYNO.Core.UPS", "get", safe=True)
            assert server.logins == 1

    def test_wrong_password_is_authentication_failed(self) -> None:
        server = _Server()
        server.login_answer = login_error(401)
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "authentication_failed"

    def test_two_factor_required_is_not_configured_missing_otp(self) -> None:
        server = _Server()
        server.login_answer = login_error(403)
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "not_configured"
            assert exc.value.missing == "otp"

    def test_mid_call_session_timeout_relogs_in_once_and_recovers(self) -> None:
        server = _Server()

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            if server.authed_calls == 0:
                # The FIRST authenticated call arrives with a dead sid.
                server.authed_calls += 1
                return dsm_error(106)
            server.authed_calls += 1
            return data_ok({"after": "relogin"})

        recorder = Recorder(handler)
        with make_client(recorder, server) as client:
            result = client.call("SYNO.Core.System", "info", safe=True)
            assert result == {"after": "relogin"}
            assert server.logins == 2
            assert server.authed_calls == 2

    def test_persistent_session_timeout_fails_bounded_after_one_relogin(self) -> None:
        server = _Server()

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            server.authed_calls += 1
            return dsm_error(106)

        recorder = Recorder(handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "authentication_failed"
            assert exc.value.dsm_code == 106
            # Bounded: exactly one re-login happened, no login loop.
            assert server.logins == 2
            assert server.authed_calls == 2

    def test_session_timeout_on_side_effect_never_retries(self) -> None:
        server = _Server()

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            server.authed_calls += 1
            return dsm_error(106)

        recorder = Recorder(handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.System", "shutdown", safe=False)
            assert exc.value.code == "authentication_failed"
            assert server.logins == 1
            assert server.authed_calls == 1


class TestRetries:
    def test_safe_call_retries_transport_failures_up_to_two(self) -> None:
        server = _Server()
        attempts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            attempts.append("call")
            if len(attempts) < 3:
                raise httpx.ConnectError("flaky")
            return data_ok({"after": "retries"})

        recorder = Recorder(handler)
        client = make_client(recorder, server, backoff=lambda attempt: 0.0)
        with client:
            result = client.call("SYNO.Core.UPS", "get", safe=True)
            assert result == {"after": "retries"}
            assert len(attempts) == 3

    def test_side_effect_call_never_retries_transport_failures(self) -> None:
        server = _Server()
        attempts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            attempts.append("call")
            raise httpx.ConnectError("device gone")

        recorder = Recorder(handler)
        client = make_client(recorder, server, backoff=lambda attempt: 0.0)
        with client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.System", "restart", safe=False)
            assert exc.value.code == "network_unreachable"
            assert len(attempts) == 1

    def test_safe_call_retries_server_500_once_then_raises(self) -> None:
        server = _Server()
        attempts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                server.logins += 1
                return login_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            attempts.append("call")
            return httpx.Response(500, json={"success": False, "error": {"code": 100}})

        recorder = Recorder(handler)
        client = make_client(recorder, server, backoff=lambda attempt: 0.0, max_server_retries=1)
        with client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "operation_failed"
            assert len(attempts) == 2  # initial + exactly one server retry


class TestVersionNegotiation:
    def test_call_never_uses_version_above_certified(self) -> None:
        # INFO_MAP advertises Storage maxVersion 9; the certified ledger row
        # is 1 — the wire version must be the certified one.
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            result = client.call("SYNO.Storage.CGI.Storage", "load_info", safe=True)
            assert result is not None
        call = next(
            r
            for r in recorder.requests
            if r["params"].get("api") == "SYNO.Storage.CGI.Storage" and r["params"].get("method") == "load_info"
        )
        assert call["params"]["version"] == "1"

    def test_negotiated_spec_is_exposed_for_evidence(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            client.call("SYNO.Storage.CGI.Storage", "load_info", safe=True)
            spec = client.call_spec("SYNO.Storage.CGI.Storage")
            assert spec is not None
            assert spec.version == 1
            assert spec.path == "entry.cgi"
            auth_spec = client.call_spec(AUTH_API_NAME)
            assert auth_spec is not None
            assert auth_spec.version == CERTIFIED_API_VERSIONS[AUTH_API_NAME]


class TestGapsAndLedger:
    def test_missing_api_is_an_explicit_gap(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            client.discover()
            gaps = client.missing_required_apis(
                frozenset({"SYNO.Core.System", "SYNO.Storage.CGI.Storage", "SYNO.Core.Share"})
            )
            assert gaps == ("SYNO.Core.Share",)

    def test_uncallable_api_raises_not_configured_with_reason(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.Share", "load_info", safe=True)
            assert exc.value.code == "not_configured"
            assert exc.value.detail_safe == "reason:not_discovered"

    def test_uncertified_api_is_refused_before_wire(self) -> None:
        # The device advertises an API the platform ledger has no certified
        # version for: the client refuses instead of guessing a version.
        map_with_extra = dict(INFO_MAP)
        map_with_extra["SYNO.Core.BrandNew"] = {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1}

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == INFO_API_NAME:
                return httpx.Response(200, json={"success": True, "data": map_with_extra})
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                return login_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            return data_ok({})

        recorder = Recorder(handler)
        with make_client(recorder, _Server()) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.BrandNew", "info", safe=True)
            assert exc.value.code == "not_configured"
            assert exc.value.detail_safe == "reason:not_certified"
            assert exc.value.missing == "certified_version"

    def test_call_ledger_records_exact_basis_per_call(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            client.call("SYNO.Core.System", "info", safe=True)
            client.call("SYNO.Storage.CGI.Storage", "smart_test", safe=False, params={"disk": "sata1", "type": "quick"})
        rows = client.call_ledger()
        bases = {(row.api_name, row.method, row.path, row.version) for row in rows}
        assert (INFO_API_NAME, "query", "query.cgi", 1) in bases
        assert (AUTH_API_NAME, "login", "auth.cgi", 6) in bases
        assert ("SYNO.Core.System", "info", "entry.cgi", 2) in bases
        assert ("SYNO.Storage.CGI.Storage", "smart_test", "entry.cgi", 1) in bases
        assert (AUTH_API_NAME, "logout", "auth.cgi", 6) in bases


class TestHygiene:
    def test_sid_and_password_never_logged(self) -> None:
        server = _Server()
        recorder = Recorder(server.handler)
        logger, lines = captured_logger()
        client = make_client(recorder, server, logger=logger)
        with client:
            client.call("SYNO.Core.UPS", "get", safe=True)
        rendered = "\n".join(lines)
        assert SID not in rendered
        assert PASSWORD not in rendered

    def test_credentials_required(self) -> None:
        with pytest.raises(ValueError):
            DSMClient(
                make_http(lambda request: info_ok()),
                base_path=BASE,
                credentials=None,
            )

    def test_malformed_envelope_is_protocol_error(self) -> None:
        server = _Server()

        def handler(request: httpx.Request) -> httpx.Response:
            params = _params_of(request)
            if params.get("api") == INFO_API_NAME:
                return info_ok()
            if params.get("api") == AUTH_API_NAME and params.get("method") == "login":
                return login_ok()
            if params.get("api") == AUTH_API_NAME:
                return data_ok({})
            return httpx.Response(200, json={"unexpected": True})

        recorder = Recorder(handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "protocol_error"
            assert exc.value.stage == "parse"

    def test_unknown_dsm_code_preserved_not_guessed(self) -> None:
        server = _Server()
        server.call_answer = dsm_error(2100)
        recorder = Recorder(server.handler)
        with make_client(recorder, server) as client:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "protocol_error"
            assert exc.value.dsm_code == 2100
