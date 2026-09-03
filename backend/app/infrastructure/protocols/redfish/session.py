"""Redfish authentication strategies (docs/SECURITY.md §6, DEVICE_ADAPTERS.md §10).

- ``AuthMode.SESSION`` (default): login via ``POST /SessionService/Sessions``
  with decrypted credentials, hold the ``X-Auth-Token`` for the session
  lifetime, and DELETE the session on close. If the manager has no session
  service (login yields 404/405/501) there is NO silent fallback: the caller
  must have declared ``auth_mode=basic`` in the connection config, otherwise
  ``authentication_failed`` is raised with a hint (operator action, never an
  automatic downgrade).
- ``AuthMode.BASIC``: HTTP Basic on every request; chosen ONLY by explicit
  connection-config declaration (older managers). No session is created.
- ``AuthMode.NONE``: anonymous device access (no credentials configured).

Tokens and passwords never appear in logs, repr or exception text; the
strategies take an explicit structlog-style logger so tests can capture it.
Plaintext credentials exist ONLY inside the adapter call boundary
(SECURITY.md §5) and never leave the strategy object.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog

from app.infrastructure.protocols.redfish.errors import RedfishError, map_http_error


class AuthMode(StrEnum):
    NONE = "none"
    BASIC = "basic"
    SESSION = "session"


@dataclass(frozen=True)
class RedfishCredentials:
    """Plaintext credentials valid only inside the adapter call boundary."""

    username: str
    password: str

    def __repr__(self) -> str:
        return f"RedfishCredentials(username={self.username!r}, password=<redacted>)"


class RedfishAuth(Protocol):
    """Auth strategy used by ``RedfishClient`` for every request."""

    can_reauth: bool

    def prepare(self) -> None:
        """Ensure a usable credential state (login on demand / nothing)."""
        ...

    def headers(self) -> dict[str, str]:
        """Auth headers to attach to the next request."""
        ...

    def on_unauthorized(self) -> None:
        """Drop the rejected credential state so the next prepare re-issues."""
        ...

    def close(self) -> None:
        """Release device-side state (delete the session when one exists)."""
        ...


def _credentials_valid(credentials: RedfishCredentials) -> bool:
    return bool(credentials.username) and bool(credentials.password)


class NoAuth:
    """Anonymous access: no credential headers at all."""

    can_reauth = False

    def prepare(self) -> None:
        return None

    def headers(self) -> dict[str, str]:
        return {}

    def on_unauthorized(self) -> None:
        return None

    def close(self) -> None:
        return None


class BasicAuth:
    """Explicit HTTP Basic authentication (only when config declared basic)."""

    can_reauth = False

    def __init__(self, *, credentials: RedfishCredentials, logger: structlog.BoundLogger) -> None:
        if not _credentials_valid(credentials):
            msg = "basic auth requires username and password credentials"
            raise ValueError(msg)
        self._credentials = credentials
        self._logger = logger

    def prepare(self) -> None:
        return None

    def headers(self) -> dict[str, str]:
        raw = f"{self._credentials.username}:{self._credentials.password}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

    def on_unauthorized(self) -> None:
        return None

    def close(self) -> None:
        return None


_SESSION_LOGIN_PATH = "SessionService/Sessions"
_SESSION_UNSUPPORTED_STATUSES = frozenset({404, 405, 501})


def _origin_of(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


class SessionAuth:
    """Redfish session authentication with bounded reuse and explicit close.

    ``clock`` returns seconds (default ``time.monotonic``); the session token
    is reused while ``now - created_at < session_lifetime`` and re-issued
    afterwards. ``http`` must be the SAME ``httpx.Client`` the protocol client
    uses (raw transport access for the anonymous login/logout calls).

    The device-supplied session URI (Location/@odata.id) is normalized to a
    same-origin absolute path at capture AND again before the DELETE on
    close: the X-Auth-Token must never leave the client origin (SECURITY.md
    §7 — a foreign Location is ignored, never contacted).
    """

    can_reauth = True

    def __init__(
        self,
        http: httpx.Client,
        *,
        base_path: str,
        credentials: RedfishCredentials,
        logger: structlog.BoundLogger,
        session_lifetime: float = 1800.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not _credentials_valid(credentials):
            msg = "session auth requires username and password credentials"
            raise ValueError(msg)
        self._http = http
        self._base_path = base_path
        self._credentials = credentials
        self._logger = logger
        self._session_lifetime = session_lifetime
        self._clock = clock if clock is not None else time.monotonic
        self._base_origin = _origin_of(str(self._http.base_url))
        self._token: str | None = None
        self._session_uri: str | None = None
        self._created_at: float | None = None
        self._closed = False

    def _same_origin_session_path(self, uri: str) -> str | None:
        """Normalize a device-supplied session URI to a same-origin path.

        Absolute URIs must share the http client origin; the returned form is
        path+query only so the DELETE always travels through the client's own
        base URL. Foreign/odd URIs yield None — the token is dropped without
        any off-origin request.
        """
        if uri.startswith("/"):
            return uri
        parts = urlsplit(uri)
        if parts.scheme in ("http", "https") and _origin_of(uri) == self._base_origin:
            return urlunsplit(("", "", parts.path, parts.query, ""))
        return None

    def _login_path(self) -> str:
        return f"{self._base_path}/{_SESSION_LOGIN_PATH}"

    def prepare(self) -> None:
        if self._closed:
            msg = "session auth is closed"
            raise RedfishError("authentication_failed", msg, stage="auth")
        now = self._clock()
        if self._token is not None and self._created_at is not None:
            if now - self._created_at < self._session_lifetime:
                return
            self._logger.info("redfish.session.expired")
        self._login()

    def _login(self) -> None:
        body = {
            "UserName": self._credentials.username,
            "Password": self._credentials.password,
        }
        response = self._http.request(
            "POST",
            self._login_path(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            content=json.dumps(body),
        )
        if response.status_code in _SESSION_UNSUPPORTED_STATUSES:
            # No silent downgrade (SECURITY.md §6): basic requires an explicit
            # connection-config declaration.
            raise map_http_error(response.status_code, _json_or_none(response), context="auth")
        if response.status_code in (401, 403):
            raise map_http_error(response.status_code, _json_or_none(response), context="auth")
        if response.status_code >= 400:
            raise map_http_error(response.status_code, _json_or_none(response), context="auth")
        token = response.headers.get("X-Auth-Token")
        if not token:
            raise RedfishError(
                "protocol_error",
                "session login succeeded without an X-Auth-Token",
                stage="auth",
            )
        self._token = token
        self._created_at = self._clock()
        raw_session_uri = response.headers.get("Location") or _body_odata_id(response)
        self._session_uri = self._same_origin_session_path(raw_session_uri) if raw_session_uri else None
        self._logger.info(
            "redfish.session.created",
            auth_mode="session",
            session_uri_prefix=self._session_uri.rsplit("/", 1)[0] if self._session_uri else None,
        )

    def headers(self) -> dict[str, str]:
        if self._token is None:
            return {}
        return {"X-Auth-Token": self._token}

    def on_unauthorized(self) -> None:
        if self._token is not None:
            self._logger.info("redfish.session.rejected")
        self._token = None
        self._created_at = None
        self._session_uri = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._token is not None and self._session_uri is not None:
            # Re-validate at delete time: only a same-origin path may carry
            # the token (SECURITY.md §7). A foreign/odd URI is never contacted.
            delete_uri = self._same_origin_session_path(self._session_uri)
            if delete_uri is not None:
                try:
                    self._http.request(
                        "DELETE",
                        delete_uri,
                        headers={"Accept": "application/json", "X-Auth-Token": self._token},
                    )
                except httpx.TransportError:
                    self._logger.info("redfish.session.delete_failed")
        self._token = None
        self._session_uri = None


def _json_or_none(response: httpx.Response) -> object | None:
    try:
        parsed: object = response.json()
    except ValueError:
        return None
    return parsed


def _body_odata_id(response: httpx.Response) -> str | None:
    body = _json_or_none(response)
    if isinstance(body, dict):
        odata_id = body.get("@odata.id")
        if isinstance(odata_id, str):
            return odata_id
    return None


def build_auth(
    http: httpx.Client,
    *,
    base_path: str,
    auth_mode: AuthMode | str,
    credentials: RedfishCredentials | None,
    logger: structlog.BoundLogger,
    session_lifetime: float = 1800.0,
    clock: Callable[[], float] | None = None,
) -> RedfishAuth:
    """Construct the strategy declared by the connection config."""
    mode = AuthMode(auth_mode)
    if mode is AuthMode.NONE:
        return NoAuth()
    if credentials is None:
        msg = f"auth_mode={mode.value} requires device credentials"
        raise ValueError(msg)
    if mode is AuthMode.BASIC:
        return BasicAuth(credentials=credentials, logger=logger)
    return SessionAuth(
        http,
        base_path=base_path,
        credentials=credentials,
        logger=logger,
        session_lifetime=session_lifetime,
        clock=clock,
    )
