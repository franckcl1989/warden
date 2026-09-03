"""DSM session management via SYNO.API.Auth (DSM Login Web API guide).

Login uses the discovered ``SYNO.API.Auth`` path (auth.cgi on real DSM) with
``method=login, session=DiskStation, format=sid`` and holds the returned
``sid`` for the session lifetime; ``logout`` on close ends the session
(DELETE-style session end). The ``sid`` travels as the ``_sid`` parameter on
every authenticated call and is NEVER logged, rendered by ``repr`` or leaked
into exception text (SECURITY.md §5/§7).

Session semantics (honest boundaries, never guessed):

- a wrong-password login answer maps to ``authentication_failed``;
- a login answer requiring a two-factor code maps to ``not_configured``
  with ``missing="otp"``: DSM 2FA on the automation account is a credential
  configuration gap, and automation must use a dedicated non-2FA account
  with minimal privileges (SECURITY.md §5). This is a decision, not a
  silent workaround;
- DSM has no documented session ping API, so "keep-alive" is bounded
  re-login: a session older than ``session_lifetime`` is re-issued before
  the next call, and a mid-call session-timeout answer (error 106) triggers
  AT MOST one re-login per logical request (see DSMClient);
- a login that never yields a ``sid`` is ``protocol_error`` (never treated
  as success).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import structlog

from app.infrastructure.protocols.dsm.discovery import ApiCallSpec
from app.infrastructure.protocols.dsm.errors import (
    DSMError,
    classify_transport_error,
    envelope_data,
    raise_envelope_error,
    raise_http_error,
)

LOGIN_METHOD = "login"
LOGOUT_METHOD = "logout"
SESSION_NAME = "DiskStation"
FORMAT_SID = "sid"


@dataclass(frozen=True)
class DSMCredentials:
    """Plaintext credentials valid only inside the adapter call boundary."""

    username: str
    password: str

    def __repr__(self) -> str:
        return f"DSMCredentials(username={self.username!r}, password=<redacted>)"


class DSMSession:
    """Owns the device ``sid``: issue, bounded reuse, rejection, logout.

    ``http`` must be the SAME ``httpx.Client`` the DSM protocol client uses
    (raw transport access for the anonymous login/logout calls). ``clock``
    returns seconds (default ``time.monotonic``).
    """

    def __init__(
        self,
        http: httpx.Client,
        *,
        base_path: str,
        auth_spec: ApiCallSpec,
        credentials: DSMCredentials,
        logger: structlog.BoundLogger,
        session_lifetime: float = 1800.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not credentials.username or not credentials.password:
            msg = "dsm session auth requires username and password credentials"
            raise ValueError(msg)
        self._http = http
        self._base_path = base_path.rstrip("/")
        self._auth_spec = auth_spec
        self._credentials = credentials
        self._logger = logger
        self._session_lifetime = session_lifetime
        self._clock = clock if clock is not None else time.monotonic
        self._sid: str | None = None
        self._created_at: float | None = None
        self._closed = False
        # Recorded on every platform call this session makes (login/logout)
        # so the adapter's discovery evidence carries the exact API names
        # and versions used (ADR-018).
        self.on_call: Callable[[str, str, str, int], None] | None = None

    # -- state --------------------------------------------------------------

    @property
    def has_session(self) -> bool:
        return self._sid is not None

    def sid_param(self) -> dict[str, str]:
        """The ``_sid`` parameter for an authenticated call (empty when none)."""
        if self._sid is None:
            return {}
        return {"_sid": self._sid}

    def ensure_alive(self) -> None:
        """Issue a session when missing or older than the bounded lifetime."""
        if self._closed:
            raise DSMError("authentication_failed", "dsm session is closed", stage="auth")
        now = self._clock()
        if self._sid is not None and self._created_at is not None:
            if now - self._created_at < self._session_lifetime:
                return
            self._logger.info("dsm.session.expired")
        self.login()

    def on_session_rejected(self) -> None:
        """Drop the rejected ``sid``; the next call re-issues it."""
        if self._sid is not None:
            self._logger.info("dsm.session.rejected")
        self._sid = None
        self._created_at = None

    # -- login / logout -----------------------------------------------------

    def _record_call(self, method: str, version: int) -> None:
        if self.on_call is not None:
            self.on_call(self._auth_spec.api_name, method, self._auth_spec.path, version)

    def login(self) -> None:
        """SYNO.API.Auth method=login; raises mapped DSMErrors on refusal.

        The password travels ONLY inside the POST form body of this request
        and is never logged or echoed back in exceptions.
        """
        if self._closed:
            raise DSMError("authentication_failed", "dsm session is closed", stage="auth")
        self._record_call(LOGIN_METHOD, self._auth_spec.version)
        params = {
            "api": self._auth_spec.api_name,
            "version": str(self._auth_spec.version),
            "method": LOGIN_METHOD,
            "account": self._credentials.username,
            "passwd": self._credentials.password,
            "session": SESSION_NAME,
            "format": FORMAT_SID,
        }
        path = self._endpoint_path()
        try:
            response = self._http.request(
                "POST",
                path,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=urlencode(params),
            )
        except httpx.TransportError as exc:
            raise classify_transport_error(exc) from exc
        if response.status_code >= 400:
            raise_http_error(
                response.status_code,
                context="auth",
                api_name=self._auth_spec.api_name,
                method=LOGIN_METHOD,
            )
        body = _decoded_body(response, api_name=self._auth_spec.api_name, method=LOGIN_METHOD)
        success, data, error_code = envelope_data(body)
        if not success:
            # A login error code is a LOGIN context answer (2FA row applies).
            raise_envelope_error(
                api_name=self._auth_spec.api_name,
                method=LOGIN_METHOD,
                code=error_code if error_code is not None else 100,
                stage="auth",
                context="login",
            )
        if not isinstance(data, dict):
            raise DSMError(
                "protocol_error",
                "dsm login succeeded without a data object",
                stage="auth",
                api_name=self._auth_spec.api_name,
                method=LOGIN_METHOD,
            )
        sid = data.get("sid")
        if not isinstance(sid, str) or not sid:
            raise DSMError(
                "protocol_error",
                "dsm login succeeded without a sid",
                stage="auth",
                api_name=self._auth_spec.api_name,
                method=LOGIN_METHOD,
            )
        self._sid = sid
        self._created_at = self._clock()
        self._logger.info("dsm.session.created", api=self._auth_spec.api_name, version=self._auth_spec.version)

    def logout(self) -> None:
        """Best-effort session end; failure is logged, never raised.

        ``logout`` carries the sid as proof of ownership (the only bearer we
        hold). After this the sid is dropped from memory regardless of the
        device answer.
        """
        if self._sid is None:
            return
        self._record_call(LOGOUT_METHOD, self._auth_spec.version)
        params = {
            "api": self._auth_spec.api_name,
            "version": str(self._auth_spec.version),
            "method": LOGOUT_METHOD,
            "session": SESSION_NAME,
            "_sid": self._sid,
        }
        path = self._endpoint_path()
        try:
            self._http.request(
                "POST",
                path,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=urlencode(params),
            )
        except httpx.TransportError:
            self._logger.info("dsm.session.logout_failed")
        self._sid = None
        self._created_at = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.logout()

    def _endpoint_path(self) -> str:
        return f"{self._base_path}/{self._auth_spec.path}"


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
