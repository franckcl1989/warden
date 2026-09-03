"""DSM WebAPI protocol client (docs/DEVICE_ADAPTERS.md §5/§7/§8, ADR-018).

``DSMClient`` wraps an already policy-managed ``httpx.Client`` (M1T2
``build_managed_client`` for CA-validated HTTPS endpoints — resolved IP,
port whitelist, 5 s connect / 30 s request timeouts, redirects disabled;
pinned TLS stays outside httpx, see ``app/infrastructure/tls.py``). The
client never constructs transports.

Behaviour contract:

- discovery via the anonymous ``SYNO.API.Info.Query`` (query.cgi); every
  platform call is version-negotiated against the platform's certified
  version ledger (``CERTIFIED_API_VERSIONS``) — the client NEVER calls an
  API at a version above its certified row, whatever the device advertises;
- DSM WebAPI methods are invoked with the DSM ``method=`` parameter. Safe
  (idempotent read) calls travel as HTTP GET and retry with bounded
  exponential backoff (connection failures up to 2 retries, server-status
  failures 1 retry, 429 honors Retry-After once); side-effect calls travel
  as HTTP POST and are NEVER retried (DEVICE_ADAPTERS.md §9);
- a mid-call session-timeout answer (DSM error 106) drops the sid and
  re-logs in AT MOST once per logical call, retrying only safe calls; a
  second 106 surfaces as ``authentication_failed`` (bounded, no login loop);
- every platform call is recorded in the ADR-018 call ledger (exact API
  name, path and version) for the adapter's discovery/audit evidence;
- sid, credentials and request parameters are never logged.

Requests return the decoded ``data`` member of the success envelope.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx
import structlog

from app.infrastructure.protocols.dsm.discovery import (
    AUTH_API_NAME,
    INFO_API_NAME,
    INFO_CERTIFIED_VERSION,
    ApiCallSpec,
    DiscoveryEvidence,
    Negotiation,
    negotiate,
    parse_api_map,
)
from app.infrastructure.protocols.dsm.errors import (
    DSMError,
    classify_transport_error,
    envelope_data,
    raise_envelope_error,
    raise_http_error,
)
from app.infrastructure.protocols.dsm.session import (
    DSMCredentials,
    DSMSession,
)

DEFAULT_BASE_PATH = "/webapi"
CONNECT_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_NETWORK_RETRIES = 2
MAX_SERVER_RETRIES = 1
RETRY_AFTER_CAP_SECONDS = 10.0
_BACKOFF_CAP_SECONDS = 10.0

# --- certified version ledger ------------------------------------------------
# The DSM API versions THIS codebase's parsers are fixture-certified against
# (ADR-018 precise-version evidence). Every row is simulator-fixture
# certified in M4T1; real-DSM certification lands in M4T2. The client
# refuses any call above the row's version regardless of the device map.
CERTIFIED_API_VERSIONS: dict[str, int] = {
    INFO_API_NAME: INFO_CERTIFIED_VERSION,  # documented at v1 (Login guide)
    AUTH_API_NAME: 6,  # documented at v6 (Login guide)
    "SYNO.Core.System": 2,  # [sim] fixture-certified v2
    "SYNO.Storage.CGI.Storage": 1,  # [sim] fixture-certified v1
    "SYNO.Core.Share": 1,  # [sim] fixture-certified v1 (M4T2 share usage/quota rows)
    "SYNO.Core.UPS": 1,  # [sim] fixture-certified v1
    "SYNO.Core.System.Log": 1,  # [sim] fixture-certified v1
    "SYNO.Core.Upgrade": 1,  # [sim] fixture-certified v1
    "SYNO.Core.Support": 1,  # [sim] fixture-certified v1 (M4T3 NAS-ACT-03 export)
    "SYNO.Core.Backup": 1,  # [sim] fixture-certified v1 (M4T3 NAS-ACT-05 status)
    "SYNO.Core.Network.SNMP": 1,  # [sim] fixture-certified v1 (M4T3 NAS-ACT-06 trap config)
}


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


@dataclass(frozen=True)
class DSMEndpoint:
    """Policy-resolved device endpoint (host is the RESOLVED IP, never a name)."""

    host: str
    port: int
    base_path: str = DEFAULT_BASE_PATH
    scheme: str = "https"


@dataclass(frozen=True)
class ApiCallRecord:
    """One platform call's exact basis (ADR-018 evidence unit)."""

    api_name: str
    method: str
    path: str
    version: int
    safe: bool


class DSMClient:
    """Sync DSM WebAPI client over an injected, policy-managed httpx client."""

    def __init__(
        self,
        http: httpx.Client,
        *,
        base_path: str = DEFAULT_BASE_PATH,
        endpoint: DSMEndpoint | None = None,
        credentials: DSMCredentials | None = None,
        logger: structlog.BoundLogger | None = None,
        session_lifetime: float = 1800.0,
        clock: Callable[[], float] | None = None,
        backoff: Callable[[int], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        max_network_retries: int = MAX_NETWORK_RETRIES,
        max_server_retries: int = MAX_SERVER_RETRIES,
        certified_versions: Mapping[str, int] | None = None,
    ) -> None:
        if endpoint is not None:
            _validate_endpoint_matches(http, endpoint, base_path)
        self._http = http
        self._base_path = base_path.rstrip("/")
        self._logger = logger if logger is not None else structlog.get_logger("warden.protocols.dsm")
        self._backoff = backoff if backoff is not None else _default_backoff
        self._sleep = sleep if sleep is not None else time.sleep
        self._max_network_retries = max_network_retries
        self._max_server_retries = max_server_retries
        self._certified_versions = (
            dict(certified_versions) if certified_versions is not None else dict(CERTIFIED_API_VERSIONS)
        )
        if credentials is None:
            msg = "dsm client requires device credentials (login-based protocol)"
            raise ValueError(msg)
        self._credentials = credentials
        self._session_lifetime = session_lifetime
        self._clock = clock
        self._negotiated: dict[str, Negotiation] = {}
        self._evidence: DiscoveryEvidence | None = None
        self._session: DSMSession | None = None
        self._ledger: list[ApiCallRecord] = []
        self._closed = False

    # -- public API ---------------------------------------------------------

    def discover(self) -> DiscoveryEvidence:
        """Run SYNO.API.Info.Query and freeze the discovery evidence.

        The anonymous query is the versioned basis every later negotiation
        uses (ADR-018). It is recorded in the call ledger like any platform
        call. Raises mapped DSMErrors when the device has no usable map.
        """
        self._record_call(INFO_API_NAME, "query", "query.cgi", INFO_CERTIFIED_VERSION, safe=True)
        path = f"{self._base_path}/query.cgi"
        params = {
            "api": INFO_API_NAME,
            "version": str(INFO_CERTIFIED_VERSION),
            "method": "query",
            "query": "all",
        }
        try:
            response = self._http.request("GET", path, params=params)
        except httpx.TransportError as exc:
            raise classify_transport_error(exc) from exc
        if response.status_code >= 400:
            raise_http_error(
                response.status_code,
                context="read",
                api_name=INFO_API_NAME,
                method="query",
            )
        body = _decoded_body(response, api_name=INFO_API_NAME, method="query")
        success, data, error_code = envelope_data(body)
        if not success:
            raise_envelope_error(
                api_name=INFO_API_NAME,
                method="query",
                code=error_code if error_code is not None else 100,
            )
        api_map = parse_api_map(data)
        if not api_map:
            raise DSMError(
                "protocol_error",
                "device discovery returned an empty API map",
                stage="discovery",
                api_name=INFO_API_NAME,
                method="query",
            )
        self._evidence = DiscoveryEvidence.from_map(api_map)
        self._negotiated = {name: negotiate(info, self._certified_versions.get(name)) for name, info in api_map.items()}
        # The session is created once per client: SYNO.API.Auth's discovered
        # path/version is the login basis (auth.cgi on real DSM).
        if self._session is None:
            auth_negotiation = self._negotiated.get(AUTH_API_NAME)
            if auth_negotiation is not None and auth_negotiation.spec is not None:
                self._session = DSMSession(
                    self._http,
                    base_path=self._base_path,
                    auth_spec=auth_negotiation.spec,
                    credentials=self._credentials,
                    logger=self._logger,
                    session_lifetime=self._session_lifetime,
                    clock=self._clock,
                )
                self._session.on_call = self._session_call_record
        return self._evidence

    def call(
        self,
        api_name: str,
        method: str,
        *,
        safe: bool,
        params: Mapping[str, object] | None = None,
    ) -> object:
        """Invoke one DSM API method; returns the success envelope ``data``.

        ``safe=False`` marks a side-effect call (HTTP POST, never retried);
        ``safe=True`` marks an idempotent read (HTTP GET with bounded
        retries). Raises mapped ``DSMError`` on refusal.
        """
        if self._closed:
            raise DSMError("protocol_error", "client is closed", stage="request")
        if self._evidence is None:
            self.discover()
        if self._session is None:
            raise DSMError(
                "not_configured",
                "cannot authenticate: SYNO.API.Auth is not callable on this device",
                stage="auth",
                missing="auth_api",
            )
        negotiation = self._negotiated.get(api_name)
        if negotiation is None or not negotiation.callable or negotiation.spec is None:
            raise self._uncallable(api_name, negotiation)
        spec = negotiation.spec
        href = f"{self._base_path}/{spec.path}"
        context = "read" if safe else "action"
        reauthenticated = False
        network_budget = self._max_network_retries if safe else 0
        server_budget = self._max_server_retries if safe else 0
        attempt = 0
        while True:
            self._session.ensure_alive()
            self._record_call(spec.api_name, method, spec.path, spec.version, safe=safe)
            query: dict[str, str] = {}
            query.update(_stringify_params(params))
            query.update(
                {
                    "api": spec.api_name,
                    "version": str(spec.version),
                    "method": method,
                }
            )
            query.update(self._session.sid_param())
            try:
                if safe:
                    response = self._http.request("GET", href, params=query)
                else:
                    response = self._http.request(
                        "POST",
                        href,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        content=urlencode(query),
                    )
            except httpx.TransportError as exc:
                failure = classify_transport_error(exc)
                if safe and failure.code == "network_unreachable" and network_budget > 0:
                    network_budget -= 1
                    self._sleep(self._backoff(attempt))
                    attempt += 1
                    continue
                raise failure from exc
            retry_after = _retry_after_of(response)
            if response.status_code < 400:
                body = _decoded_body(response, api_name=spec.api_name, method=method)
                success, data, error_code = envelope_data(body)
                if success:
                    return data
                # An envelope error with the DSM session-timeout code is the
                # one device-side condition that proves the sid died.
                if error_code == 106:
                    self._session.on_session_rejected()
                    if safe and not reauthenticated:
                        # Bounded: re-login ONCE and retry exactly once.
                        reauthenticated = True
                        self._logger.info("dsm.session.relogin", api=spec.api_name, version=spec.version)
                        continue
                raise_envelope_error(
                    api_name=spec.api_name,
                    method=method,
                    code=error_code if error_code is not None else 100,
                    stage="request",
                )
            if safe and response.status_code == 429 and retry_after is not None and server_budget > 0:
                server_budget -= 1
                self._sleep(min(retry_after, RETRY_AFTER_CAP_SECONDS))
                attempt += 1
                continue
            if safe and response.status_code in (500, 502, 503, 504) and server_budget > 0:
                server_budget -= 1
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            raise_http_error(
                response.status_code,
                context=context,
                api_name=spec.api_name,
                method=method,
                retry_after_seconds=retry_after,
            )

    def call_spec(self, api_name: str) -> ApiCallSpec | None:
        """The negotiated call spec for an API (or None when uncallable)."""
        negotiation = self._negotiated.get(api_name)
        if negotiation is None or negotiation.spec is None:
            return None
        return negotiation.spec

    def negotiation_reason(self, api_name: str) -> str | None:
        """Stable reason an API is uncallable (None when callable/unknown)."""
        negotiation = self._negotiated.get(api_name)
        if negotiation is None:
            return None
        return negotiation.reason

    def missing_required_apis(self, required: frozenset[str]) -> tuple[str, ...]:
        """Required API names absent from the discovered device map (sorted)."""
        if self._evidence is None:
            return tuple(sorted(required))
        discovered = {name for name, *_ in self._evidence.api_map}
        return tuple(sorted(required - discovered))

    def discovery_evidence(self) -> DiscoveryEvidence | None:
        """The frozen discovery evidence (None before ``discover()``)."""
        return self._evidence

    def call_ledger(self) -> tuple[ApiCallRecord, ...]:
        """Every platform call's (api, method, path, version) basis so far."""
        return tuple(self._ledger)

    def close(self) -> None:
        """End the device session (best-effort logout) and seal the client."""
        if self._closed:
            return
        self._closed = True
        if self._session is not None:
            self._session.close()

    def __enter__(self) -> DSMClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    # -- internals ----------------------------------------------------------

    def _uncallable(self, api_name: str, negotiation: Negotiation | None) -> DSMError:
        reason = negotiation.reason if negotiation is not None else "not_discovered"
        label = str(reason).replace("_", " ")
        return DSMError(
            "not_configured",
            f"dsm api {api_name} is not callable: {label}",
            stage="discovery",
            detail_safe=f"reason:{reason}",
            missing="certified_version" if reason == "not_certified" else None,
            api_name=api_name,
        )

    def _record_call(self, api_name: str, method: str, path: str, version: int, *, safe: bool) -> None:
        self._ledger.append(ApiCallRecord(api_name=api_name, method=method, path=path, version=version, safe=safe))

    def _session_call_record(self, api_name: str, method: str, path: str, version: int) -> None:
        # Login/logout are POSTed side effects and are never retried.
        self._ledger.append(ApiCallRecord(api_name=api_name, method=method, path=path, version=version, safe=False))


def _decoded_body(response: httpx.Response, *, api_name: str, method: str) -> object | None:
    """Decoded JSON body; empty bodies are a protocol_error (no fake ok)."""
    if not response.content:
        raise DSMError(
            "protocol_error",
            "device returned an empty response body",
            stage="parse",
            api_name=api_name,
            method=method,
        )
    try:
        decoded: object = response.json()
    except ValueError as exc:
        raise DSMError(
            "protocol_error",
            "device returned an unparseable JSON body",
            stage="parse",
            api_name=api_name,
            method=method,
        ) from exc
    return decoded


def _origin_of(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


def _stringify_params(params: Mapping[str, object] | None) -> dict[str, str]:
    """DSM call parameters to wire strings; non-scalar values are refused.

    Parameters are single-valued (api/method/version/_sid/...): a list or
    object value would silently produce a wrong request, so it raises
    instead of being guessed into a string.
    """
    if params is None:
        return {}
    wire: dict[str, str] = {}
    for key, value in params.items():
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            msg = f"dsm parameter {key!r} must be a scalar string/number"
            raise ValueError(msg)
        wire[key] = str(value)
    return wire


def _validate_endpoint_matches(http: httpx.Client, endpoint: DSMEndpoint, base_path: str) -> None:
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
