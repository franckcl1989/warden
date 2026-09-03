"""Redfish protocol client (docs/DEVICE_ADAPTERS.md §7/§8, SECURITY.md §6/§7).

``RedfishClient`` wraps an already policy-managed ``httpx.Client`` (M1T2
``build_managed_client`` for CA-validated endpoints — resolved IP, port
whitelist, 5 s connect / 30 s request timeouts, redirects disabled). Pinned
TLS cannot run inside httpx (post-handshake check, ``tls.py``), so pinned
sessions are wired through ``PinnedTlsConnection`` at the adapter layer and
must not build an httpx client here; this class refuses no other unsafe
configuration because it never constructs transports.

Behaviour contract:

- read idempotent GETs retry with bounded exponential backoff: connection
  failures up to 2 retries, server-status failures (502/503/504) 1 retry,
  429 honors Retry-After once — never on POST actions (a 401-triggered
  re-login retry is NOT a retry of a failed action: a 401 proves the device
  never executed the request);
- every URL must share the client origin (SECURITY.md §7): ``base_origin``
  (``scheme://netloc`` derived from the injected http client's base URL) is
  public so the parser can validate absolute same-origin ``@odata.id`` links;
- response JSON decode failures are ``protocol_error`` (stage parse);
- auth headers come from the session/basic/none strategies in ``session.py``;
  tokens, credentials and device body text are never logged.

Requests return ``HttpReply`` (status + decoded payload + headers) so task
pollers can honor Location/Retry-After; ``get``/``post`` are conveniences.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import structlog

from app.infrastructure.protocols.redfish.errors import (
    RedfishError,
    classify_transport_error,
    map_http_error,
)
from app.infrastructure.protocols.redfish.parse import HttpReply, RedfishResource
from app.infrastructure.protocols.redfish.session import (
    RedfishCredentials,
    build_auth,
)

DEFAULT_BASE_PATH = "/redfish/v1"
CONNECT_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_NETWORK_RETRIES = 2
MAX_SERVER_RETRIES = 1
RETRY_AFTER_CAP_SECONDS = 10.0
_BACKOFF_CAP_SECONDS = 10.0


@dataclass(frozen=True)
class RedfishEndpoint:
    """Policy-resolved device endpoint (host is the RESOLVED IP, never a name).

    ``scheme`` must be https in production (credentials); tests talk to a
    simulator over http via an injected transport.
    """

    host: str
    port: int
    base_path: str = DEFAULT_BASE_PATH
    scheme: str = "https"


def _default_backoff(attempt: int) -> float:
    return min(2.0**attempt, _BACKOFF_CAP_SECONDS)


def _retry_after_of(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _body_of(response: httpx.Response) -> object | None:
    """Decoded JSON body; None for empty bodies."""
    if not response.content:
        return None
    try:
        decoded: object = json.loads(response.content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RedfishError(
            "protocol_error",
            "device returned an unparseable JSON body",
            stage="parse",
        ) from exc
    return decoded


def _origin_of(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


class RedfishClient:
    """Sync Redfish client over an injected, policy-managed httpx client."""

    def __init__(
        self,
        http: httpx.Client,
        *,
        base_path: str = DEFAULT_BASE_PATH,
        endpoint: RedfishEndpoint | None = None,
        auth_mode: str = "session",
        credentials: RedfishCredentials | None = None,
        logger: structlog.BoundLogger | None = None,
        session_lifetime: float = 1800.0,
        clock: Callable[[], float] | None = None,
        backoff: Callable[[int], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        max_network_retries: int = MAX_NETWORK_RETRIES,
        max_server_retries: int = MAX_SERVER_RETRIES,
    ) -> None:
        if endpoint is not None:
            _validate_endpoint_matches(http, endpoint, base_path)
        self._http = http
        self.base_origin = _origin_of(str(http.base_url))
        self._base_path = base_path
        self._logger = logger if logger is not None else structlog.get_logger("warden.protocols.redfish")
        self._backoff = backoff if backoff is not None else _default_backoff
        self._sleep = sleep if sleep is not None else time.sleep
        self._max_network_retries = max_network_retries
        self._max_server_retries = max_server_retries
        self._auth = build_auth(
            http,
            base_path=base_path,
            auth_mode=auth_mode,
            credentials=credentials,
            logger=self._logger,
            session_lifetime=session_lifetime,
            clock=clock,
        )
        self._closed = False

    # -- public API ---------------------------------------------------------

    def get(self, url: str) -> RedfishResource | None:
        """GET a resource; None for empty bodies; non-object payloads fail."""
        reply = self.request("GET", url)
        if reply.payload is None:
            return None
        return RedfishResource(reply.payload)

    def post(self, url: str, *, json_body: object | None = None) -> HttpReply:
        """POST an action; never retried on failure (DEVICE_ADAPTERS.md §9)."""
        return self.request("POST", url, json_body=json_body)

    def request(self, method: str, url: str, *, json_body: object | None = None) -> HttpReply:
        """Low-level request returning ``HttpReply``; raises mapped errors."""
        if self._closed:
            msg = "client is closed"
            raise RedfishError("protocol_error", msg, stage="request")
        href = self._normalize_href(url)
        context = "read" if method == "GET" else "action"
        reauthenticated = False
        network_budget = self._max_network_retries if method == "GET" else 0
        server_budget = self._max_server_retries if method == "GET" else 0
        attempt = 0
        while True:
            self._auth.prepare()
            headers: dict[str, str] = {"Accept": "application/json"}
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            headers.update(self._auth.headers())
            try:
                response = self._http.request(
                    method,
                    href,
                    headers=headers,
                    content=json.dumps(json_body) if json_body is not None else None,
                )
            except httpx.TransportError as exc:
                failure = classify_transport_error(exc)
                if method == "GET" and failure.code == "network_unreachable" and network_budget > 0:
                    network_budget -= 1
                    self._sleep(self._backoff(attempt))
                    attempt += 1
                    continue
                raise failure from exc
            if response.status_code == 401 and self._auth.can_reauth and not reauthenticated:
                # A 401 proves the request was never executed: re-issue the
                # credential and retry exactly once (safe for actions too).
                reauthenticated = True
                self._auth.on_unauthorized()
                continue
            if response.status_code < 400:
                return HttpReply(
                    status_code=response.status_code,
                    payload=_body_of(response),
                    headers=response.headers,
                )
            retry_after = _retry_after_of(response)
            if method == "GET" and response.status_code == 429 and retry_after is not None and server_budget > 0:
                server_budget -= 1
                self._sleep(min(retry_after, RETRY_AFTER_CAP_SECONDS))
                attempt += 1
                continue
            if method == "GET" and response.status_code in (500, 502, 503, 504) and server_budget > 0:
                server_budget -= 1
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            # Error mapping keys on the status code: an unparseable ERROR body
            # keeps the stable code instead of becoming a protocol error.
            error_body: object | None = None
            with contextlib.suppress(RedfishError):
                error_body = _body_of(response)
            raise map_http_error(
                response.status_code,
                error_body,
                context=context,
                retry_after_seconds=retry_after,
            )

    def close(self) -> None:
        """Delete the device session (session auth) and mark the client closed."""
        if self._closed:
            return
        self._closed = True
        self._auth.close()

    def __enter__(self) -> RedfishClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    # -- internals ----------------------------------------------------------

    def _normalize_href(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            if _origin_of(url) != self.base_origin:
                raise RedfishError(
                    "protocol_error",
                    "refusing a device link outside the client origin",
                    stage="parse",
                )
            return url
        if not url.startswith("/"):
            raise RedfishError(
                "protocol_error",
                "request URL must be an absolute path",
                stage="parse",
            )
        return url


def _validate_endpoint_matches(http: httpx.Client, endpoint: RedfishEndpoint, base_path: str) -> None:
    base = urlsplit(str(http.base_url))
    expected_port = base.port if base.port is not None else (443 if base.scheme == "https" else 80)
    if base.scheme != endpoint.scheme or base.hostname != endpoint.host or expected_port != endpoint.port:
        msg = (
            "endpoint does not match the http client base URL: "
            f"endpoint={endpoint.scheme}://{endpoint.host}:{endpoint.port} "
            f"base_url={base.scheme}://{base.netloc}"
        )
        raise ValueError(msg)
    if base_path != endpoint.base_path:
        msg = "base_path does not match the endpoint base_path"
        raise ValueError(msg)
