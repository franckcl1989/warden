"""RedfishClient tests: retries, auth integration, error mapping, hygiene.

docs/DEVICE_ADAPTERS.md §7/§8: reads retry with bounded exponential backoff
(connection failures up to 2 retries); POST actions are NEVER retried; 429
honors Retry-After; tokens/credentials/device text never logged.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.infrastructure.logging import redact_sensitive_values
from app.infrastructure.protocols.redfish.client import RedfishClient, RedfishEndpoint
from app.infrastructure.protocols.redfish.errors import RedfishError, RedfishHttpError
from app.infrastructure.protocols.redfish.parse import FieldSentinel
from app.infrastructure.protocols.redfish.session import RedfishCredentials

BMC = "http://bmc.test"
BASE = "/redfish/v1"
USER = "sim-admin"
PASSWORD = "sim-password-secret"
SECRET_BODY_TEXT = "device body top secret text"
TOKEN = "tok-secret-value-999"

LOGIN_PATH = f"{BASE}/SessionService/Sessions"


class Recorder:
    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
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
        return self._responder(request)


def make_http(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=BMC,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )


def login_ok() -> httpx.Response:
    return httpx.Response(
        201,
        headers={"X-Auth-Token": TOKEN, "Location": f"{BASE}/SessionService/Sessions/42"},
        json={"@odata.id": f"{BASE}/SessionService/Sessions/42"},
    )


def captured_logger() -> structlog.BoundLogger:
    lines: list[str] = []

    class _Sink:
        def write(self, data: str) -> None:
            lines.append(data)

        def flush(self) -> None:
            return None

    return structlog.wrap_logger(
        structlog.PrintLogger(file=_Sink()),
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_sensitive_values,
            structlog.processors.JSONRenderer(),
        ],
    )


def system_ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "@odata.id": f"{BASE}/Systems/1",
            "@odata.type": "#ComputerSystem.v1_16_0.ComputerSystem",
            "PowerState": "On",
        },
    )


class Build:
    """Routing helper: dispatch by path+method to preset responses."""

    def __init__(self, routes: dict[str, Callable[[httpx.Request], httpx.Response]]) -> None:
        self.recorder = Recorder(lambda request: self._route(request))
        self._routes = routes

    def _route(self, request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        handler = self._routes.get(key)
        if handler is None:
            raise AssertionError(f"no route for {key}")
        return handler(request)

    def client(self, *, mode: str = "none", **kwargs: Any) -> RedfishClient:
        credentials = RedfishCredentials(username=USER, password=PASSWORD) if mode != "none" else None
        return RedfishClient(
            http=make_http(self.recorder.handler),
            base_path=BASE,
            auth_mode=mode,
            credentials=credentials,
            logger=captured_logger(),
            **kwargs,
        )


class TestConstruction:
    @pytest.mark.unit
    def test_default_headers_and_base_path(self) -> None:
        builder = Build(
            {
                ("GET", f"{BASE}/Systems/1"): lambda r: system_ok(),
            }
        )
        client = builder.client()
        client.get(f"{BASE}/Systems/1")
        request = builder.recorder.requests[0]
        assert request["headers"]["accept"] == "application/json"
        assert "authorization" not in request["headers"]
        assert "x-auth-token" not in request["headers"]

    @pytest.mark.unit
    def test_session_mode_requires_credentials(self) -> None:
        builder = Build({})
        with pytest.raises(ValueError):
            RedfishClient(
                http=make_http(builder.recorder.handler),
                base_path=BASE,
                auth_mode="session",
                credentials=None,
                logger=captured_logger(),
            )

    @pytest.mark.unit
    def test_endpoint_mismatch_with_http_base_url_is_rejected(self) -> None:
        builder = Build({})
        endpoint = RedfishEndpoint(host="192.168.10.5", port=8443)
        with pytest.raises(ValueError, match="192.168.10.5"):
            RedfishClient(
                http=make_http(builder.recorder.handler),
                endpoint=endpoint,
                logger=captured_logger(),
            )

    @pytest.mark.unit
    def test_relative_path_without_slash_is_rejected(self) -> None:
        builder = Build({})
        client = builder.client()
        with pytest.raises(RedfishError):
            client.get("Systems/1")

    @pytest.mark.unit
    def test_base_origin_is_derived_from_the_http_base_url(self) -> None:
        builder = Build({})
        client = builder.client()
        # The parser (parse.py _absolute_url) relies on this public attribute
        # to accept spec-legal absolute same-origin @odata.id links.
        assert client.base_origin == BMC

    @pytest.mark.unit
    def test_absolute_same_origin_url_is_accepted_and_routed_by_path(self) -> None:
        builder = Build({("GET", f"{BASE}/Systems/1"): lambda r: system_ok()})
        client = builder.client()
        resource = client.get(f"{BMC}{BASE}/Systems/1")
        assert resource is not None
        assert resource.schema_family == "ComputerSystem"
        assert builder.recorder.requests[0]["path"] == f"{BASE}/Systems/1"

    @pytest.mark.unit
    def test_cross_origin_absolute_url_is_rejected(self) -> None:
        builder = Build({})
        client = builder.client()
        with pytest.raises(RedfishError) as exc:
            client.get("http://evil.example/redfish/v1/Systems/1")
        assert exc.value.code == "protocol_error"


class TestGetSemantics:
    @pytest.mark.unit
    def test_get_returns_redfish_resource_with_metadata(self) -> None:
        builder = Build({("GET", f"{BASE}/Systems/1"): lambda r: system_ok()})
        resource = builder.client().get(f"{BASE}/Systems/1")
        assert resource is not None
        assert resource.schema_family == "ComputerSystem"
        assert resource.get_text("PowerState") == "On"
        assert resource.get_text("Nope") is FieldSentinel.MISSING

    @pytest.mark.unit
    def test_get_empty_body_returns_none(self) -> None:
        builder = Build({("GET", f"{BASE}/Systems/1"): lambda r: httpx.Response(200)})
        assert builder.client().get(f"{BASE}/Systems/1") is None

    @pytest.mark.unit
    def test_get_invalid_json_is_protocol_error(self) -> None:
        builder = Build(
            {
                ("GET", f"{BASE}/Systems/1"): lambda r: httpx.Response(
                    200, content=b"{not json", headers={"content-type": "application/json"}
                )
            }
        )
        with pytest.raises(RedfishError) as exc:
            builder.client().get(f"{BASE}/Systems/1")
        assert exc.value.code == "protocol_error"

    @pytest.mark.unit
    def test_get_404_maps_unsupported_capability(self) -> None:
        body = {"error": {"code": "Base.1.13.GeneralError", "message": SECRET_BODY_TEXT}}
        builder = Build({("GET", f"{BASE}/Systems/1"): lambda r: httpx.Response(404, json=body)})
        with pytest.raises(RedfishHttpError) as exc:
            builder.client().get(f"{BASE}/Systems/1")
        assert exc.value.code == "unsupported_capability"
        assert SECRET_BODY_TEXT not in str(exc.value)


class TestReadRetries:
    @pytest.mark.unit
    def test_connect_failure_retried_twice_then_network_unreachable(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            raise httpx.ConnectError("down")

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(backoff=lambda attempt: 0.0)
        with pytest.raises(RedfishError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "network_unreachable"
        assert count["n"] == 3  # initial + 2 retries

    @pytest.mark.unit
    def test_transient_connect_failure_recovers(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            if count["n"] <= 2:
                raise httpx.ConnectError("flaky")
            return system_ok()

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(backoff=lambda attempt: 0.0)
        resource = client.get(f"{BASE}/Systems/1")
        assert resource is not None
        assert count["n"] == 3

    @pytest.mark.unit
    def test_read_timeout_is_retried(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            raise httpx.ReadTimeout("slow device")

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(backoff=lambda attempt: 0.0)
        with pytest.raises(RedfishError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "network_unreachable"
        assert count["n"] == 3

    @pytest.mark.unit
    def test_retry_backoff_is_exponential_and_capped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        sleeps: list[float] = []
        client = builder.client(sleep=sleeps.append)
        with pytest.raises(RedfishError):
            client.get(f"{BASE}/Systems/1")
        assert sleeps == [1.0, 2.0]

    @pytest.mark.unit
    def test_server_500_on_read_retried_once(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            if count["n"] == 1:
                return httpx.Response(500, json={"error": {"code": "Base.1.13.GeneralError"}})
            return system_ok()

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(backoff=lambda attempt: 0.0)
        assert client.get(f"{BASE}/Systems/1") is not None
        assert count["n"] == 2

    @pytest.mark.unit
    def test_server_500_persistent_maps_operation_failed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": {"code": "Base.1.13.GeneralError"}})

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(backoff=lambda attempt: 0.0)
        with pytest.raises(RedfishHttpError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "operation_failed"
        assert len(builder.recorder.requests) == 2

    @pytest.mark.unit
    def test_429_honors_retry_after_once_then_rate_limited(self) -> None:
        sleeps: list[float] = []
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            if count["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0.01"})
            return system_ok()

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(sleep=sleeps.append)
        resource = client.get(f"{BASE}/Systems/1")
        assert resource is not None
        assert count["n"] == 2
        assert sleeps == [0.01]

    @pytest.mark.unit
    def test_429_persistent_raises_rate_limited_with_retry_after(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"Retry-After": "5"})

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(sleep=lambda _seconds: None)
        with pytest.raises(RedfishHttpError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "rate_limited"
        assert exc.value.retry_after_seconds == 5.0


class TestPostNeverRetried:
    @pytest.mark.unit
    def test_post_connect_error_is_single_attempt(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            raise httpx.ConnectError("down")

        builder = Build({("POST", f"{BASE}/Systems/1/Actions/ComputerSystem.Reset"): handler})
        client = builder.client()
        with pytest.raises(RedfishError) as exc:
            client.post(f"{BASE}/Systems/1/Actions/ComputerSystem.Reset", json_body={"ResetType": "GracefulRestart"})
        assert exc.value.code == "network_unreachable"
        assert count["n"] == 1

    @pytest.mark.unit
    def test_post_500_is_single_attempt(self) -> None:
        count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            count["n"] += 1
            return httpx.Response(500, json={"error": {"code": "Base.1.13.GeneralError"}})

        builder = Build({("POST", f"{BASE}/Systems/1/Actions/ComputerSystem.Reset"): handler})
        client = builder.client()
        with pytest.raises(RedfishHttpError) as exc:
            client.post(f"{BASE}/Systems/1/Actions/ComputerSystem.Reset", json_body={"ResetType": "GracefulRestart"})
        assert exc.value.code == "operation_failed"
        assert count["n"] == 1

    @pytest.mark.unit
    def test_post_action_not_supported_maps_unsupported_capability(self) -> None:
        body = {
            "error": {
                "code": "Base.1.13.GeneralError",
                "message": "not supported",
                "@Message.ExtendedInfo": [
                    {
                        "@odata.type": "#Message.v1_1_2.Message",
                        "MessageId": "Base.1.13.ActionNotSupported",
                        "Message": "not supported",
                    }
                ],
            }
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json=body)

        builder = Build({("POST", f"{BASE}/Systems/1/Actions/ComputerSystem.Reset"): handler})
        client = builder.client()
        with pytest.raises(RedfishHttpError) as exc:
            client.post(f"{BASE}/Systems/1/Actions/ComputerSystem.Reset", json_body={"ResetType": "ForceRestart"})
        assert exc.value.code == "unsupported_capability"


class TestAuthWithClient:
    @pytest.mark.unit
    def test_session_login_attaches_token_then_reads(self) -> None:
        routes = {
            ("POST", LOGIN_PATH): lambda r: login_ok(),
            ("GET", f"{BASE}/Systems/1"): lambda r: system_ok(),
        }
        builder = Build(routes)
        client = builder.client(mode="session")
        resource = client.get(f"{BASE}/Systems/1")
        assert resource is not None
        get_request = [r for r in builder.recorder.requests if r["method"] == "GET"][0]
        assert get_request["headers"]["x-auth-token"] == TOKEN

    @pytest.mark.unit
    def test_401_reads_relogin_once_and_retries(self) -> None:
        get_count = {"n": 0}

        def get_handler(request: httpx.Request) -> httpx.Response:
            get_count["n"] += 1
            if get_count["n"] == 1:
                return httpx.Response(401, json={"error": {"code": "Base.1.13.GeneralError"}})
            return system_ok()

        routes = {
            ("POST", LOGIN_PATH): lambda r: login_ok(),
            ("GET", f"{BASE}/Systems/1"): get_handler,
        }
        builder = Build(routes)
        client = builder.client(mode="session")
        assert client.get(f"{BASE}/Systems/1") is not None
        assert get_count["n"] == 2
        logins = [r for r in builder.recorder.requests if r["method"] == "POST"]
        assert len(logins) == 2  # initial + after the 401

    @pytest.mark.unit
    def test_session_401_persistent_maps_authentication_failed(self) -> None:
        routes = {
            ("POST", LOGIN_PATH): lambda r: login_ok(),
            ("GET", f"{BASE}/Systems/1"): lambda r: httpx.Response(
                401, json={"error": {"code": "Base.1.13.GeneralError"}}
            ),
        }
        builder = Build(routes)
        client = builder.client(mode="session")
        with pytest.raises(RedfishHttpError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "authentication_failed"

    @pytest.mark.unit
    def test_basic_401_is_authentication_failed_without_relogin(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"code": "Base.1.13.GeneralError"}})

        builder = Build({("GET", f"{BASE}/Systems/1"): handler})
        client = builder.client(mode="basic")
        with pytest.raises(RedfishHttpError) as exc:
            client.get(f"{BASE}/Systems/1")
        assert exc.value.code == "authentication_failed"
        assert not [r for r in builder.recorder.requests if r["method"] == "POST"]

    @pytest.mark.unit
    def test_client_close_deletes_session(self) -> None:
        routes = {
            ("POST", LOGIN_PATH): lambda r: login_ok(),
            ("GET", f"{BASE}/Systems/1"): lambda r: system_ok(),
            ("DELETE", f"{BASE}/SessionService/Sessions/42"): lambda r: httpx.Response(204),
        }
        builder = Build(routes)
        client = builder.client(mode="session")
        client.get(f"{BASE}/Systems/1")
        client.close()
        methods = [r["method"] for r in builder.recorder.requests]
        assert "DELETE" in methods


class TestClientLogHygiene:
    @pytest.mark.unit
    def test_token_password_and_device_text_never_logged(self) -> None:
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

        def get_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/Sessions") and request.method == "POST":
                return login_ok()
            return httpx.Response(500, json={"error": {"code": "Base.1.13.GeneralError", "message": SECRET_BODY_TEXT}})

        recorder = Recorder(get_handler)
        client = RedfishClient(
            http=make_http(recorder.handler),
            base_path=BASE,
            auth_mode="session",
            credentials=RedfishCredentials(username=USER, password=PASSWORD),
            logger=logger,
            backoff=lambda attempt: 0.0,
        )
        try:
            with pytest.raises(RedfishHttpError):
                client.get(f"{BASE}/Systems/1")
        finally:
            client.close()
        combined = "\n".join(lines)
        assert TOKEN not in combined
        assert PASSWORD not in combined
        assert SECRET_BODY_TEXT not in combined
