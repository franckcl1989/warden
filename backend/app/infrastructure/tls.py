"""TLS verification for device management connections (docs/SECURITY.md §6).

- Management HTTPS verifies certificates by default (system CA store or the
  configured internal-CA bundle).
- Self-signed devices pin the admin-confirmed SHA-256 fingerprint of the leaf
  certificate (``tls_fingerprint_sha256`` in connection config); a changed
  certificate is a ``tls_validation_failed``, never silently accepted.
- There is NO permanent ``verify=false``: ``build_ssl_context`` refuses to
  create an unverified context for credentials, and ``verify_peer_connection``
  enforces the pin right after the handshake, before any data is exchanged.

Implementation note (environment): the deployed interpreter's ``ssl`` module
exposes no ``verify_callback``, so pinning cannot run inside OpenSSL's
handshake. Instead the pin is verified application-layer: the pinned context
accepts the peer certificate (the pin is the trust anchor for self-signed
devices), and ``verify_peer_connection`` compares the SHA-256 fingerprint of
the actual leaf certificate (``getpeercert(binary_form=True)``) with the
pinned value using a constant-time compare. The connection must not send data
before this check passes; ``open_pinned_connection`` combines handshake +
pin check and returns only a verified socket. httpx cannot interpose this
check, so ``build_managed_client`` only builds CA-validated clients; pinned
sessions are wired to ``open_pinned_connection`` by M1T3's adapters.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, Literal

import httpx

from app.infrastructure.network_policy import (
    DeviceEndpointPolicy,
    NetworkPolicyViolation,
    redirect_allowed,
)

_FINGERPRINT_RE = re.compile(r"[0-9a-fA-F]{64}")
CONNECT_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 30.0


class TlsPinMismatch(Exception):
    """Presented certificate does not match the pinned fingerprint.

    The boundary maps this to the stable ``tls_validation_failed`` error code
    (safe detail fields: ``stage``, ``fingerprint``).
    """

    def __init__(self, *, stage: str, fingerprint: str, reason: str) -> None:
        self.stage = stage
        self.fingerprint = fingerprint
        super().__init__(reason)


def tls_fingerprint(cert_der: bytes) -> str:
    """SHA-256 hex fingerprint of a DER certificate."""
    return hashlib.sha256(cert_der).hexdigest()


def validate_fingerprint(fingerprint: str) -> bool:
    """True when ``fingerprint`` is exactly 64 hex characters."""
    return _FINGERPRINT_RE.fullmatch(fingerprint) is not None


def verify_peer_fingerprint(cert_der: bytes, expected_fingerprint: str) -> bool:
    """Constant-time compare of the cert fingerprint against ``expected_fingerprint``."""
    if not validate_fingerprint(expected_fingerprint):
        msg = "fingerprint must be 64 hex characters"
        raise ValueError(msg)
    return hmac.compare_digest(tls_fingerprint(cert_der), expected_fingerprint.lower())


class TlsDecisionState(StrEnum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True)
class TlsVerification:
    """Result of the pinning decision layer (verified / mismatch / no pin configured)."""

    state: TlsDecisionState
    expected_fingerprint: str | None = None


def decide_verification(
    verify_tls: bool,
    pinned_fingerprint: str | None,
    actual_cert_der: bytes,
) -> TlsVerification:
    """Classify a presented certificate against the configured trust mode.

    ``verify_tls=False`` or no pin configured yields ``NOT_CONFIGURED``: the
    pinning layer did not run (CA validation or config are responsible).
    Credential code must not accept ``NOT_CONFIGURED`` with ``verify_tls``
    disabled.
    """
    if not verify_tls or pinned_fingerprint is None:
        return TlsVerification(TlsDecisionState.NOT_CONFIGURED)
    if not validate_fingerprint(pinned_fingerprint):
        msg = "fingerprint must be 64 hex characters"
        raise ValueError(msg)
    if verify_peer_fingerprint(actual_cert_der, pinned_fingerprint):
        return TlsVerification(TlsDecisionState.VERIFIED)
    return TlsVerification(TlsDecisionState.MISMATCH, expected_fingerprint=pinned_fingerprint)


def build_ssl_context(
    *,
    verify_tls: bool,
    pinned_fingerprint: str | None,
    ca_bundle_path: Path | None,
) -> ssl.SSLContext:
    """Build the TLS context for device connections.

    - ``verify_tls=False`` is rejected: unverified device connections are
      never permitted for credentials (SECURITY.md §6).
    - pin mode: the pin is the trust anchor, so the context accepts the peer
      certificate and the pin is enforced post-handshake by
      ``verify_peer_connection`` before any data flows.
    - CA mode: system store (or ``ca_bundle_path`` when given) + hostname
      verification, matching SECURITY.md's default certificate validation.
    """
    if not verify_tls:
        msg = "unverified TLS contexts are not allowed for device credentials (docs/SECURITY.md §6)"
        raise ValueError(msg)
    if pinned_fingerprint is not None:
        if not validate_fingerprint(pinned_fingerprint):
            msg = "fingerprint must be 64 hex characters"
            raise ValueError(msg)
        ctx = ssl.create_default_context()
        # The pin is the trust anchor for self-signed devices: chain
        # validation is off (CERT_NONE) so the handshake completes and the
        # certificate can be inspected; verify_peer_connection() MUST run
        # before any data is sent, otherwise this is an unverified connection.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=str(ca_bundle_path) if ca_bundle_path else None)


def verify_peer_connection(
    tls_socket: ssl.SSLSocket | ssl.SSLObject,
    expected_fingerprint: str,
) -> None:
    """Enforce the pin on a completed TLS handshake before any data is sent.

    Raises ``TlsPinMismatch`` when the peer presented no certificate or its
    fingerprint differs from ``expected_fingerprint``.
    """
    if not validate_fingerprint(expected_fingerprint):
        msg = "fingerprint must be 64 hex characters"
        raise ValueError(msg)
    cert_der = tls_socket.getpeercert(binary_form=True)
    if cert_der is None:
        msg = "peer presented no certificate"
        raise TlsPinMismatch(
            stage="tls_handshake",
            fingerprint=expected_fingerprint,
            reason=msg,
        )
    if not verify_peer_fingerprint(cert_der, expected_fingerprint):
        actual = tls_fingerprint(cert_der)
        msg = (
            "certificate fingerprint does not match the pinned value "
            f"(presented {actual}, pinned {expected_fingerprint})"
        )
        raise TlsPinMismatch(stage="tls_fingerprint", fingerprint=expected_fingerprint, reason=msg)


def open_pinned_connection(
    host: str,
    port: int,
    expected_fingerprint: str,
    *,
    timeout: float = CONNECT_TIMEOUT_SECONDS,
) -> ssl.SSLSocket:
    """Open a TLS connection to ``(host, port)`` and enforce the pin post-handshake.

    Returns a verified ``SSLSocket``; the caller may speak the protocol only
    after this returns. ``host`` must already be a validated resolved IP
    (see ``DeviceEndpointPolicy.resolve_endpoint``).
    """
    ctx = build_ssl_context(
        verify_tls=True,
        pinned_fingerprint=expected_fingerprint,
        ca_bundle_path=None,
    )
    raw = socket.create_connection((host, port), timeout=timeout)
    tls_socket = ctx.wrap_socket(raw, server_hostname=None)
    try:
        verify_peer_connection(tls_socket, expected_fingerprint)
    except Exception:
        tls_socket.close()
        raise
    return tls_socket


def build_managed_client(
    *,
    host_ip: IPv4Address | IPv6Address,
    port: int,
    scheme: Literal["http", "https"] = "https",
    verify_tls: bool = True,
    pinned_fingerprint: str | None = None,
    ca_bundle_path: Path | None = None,
    allowed_ports: frozenset[int] | set[int] | None = None,
    policy: DeviceEndpointPolicy | None = None,
    allow_redirects: bool = False,
) -> httpx.Client:
    """Build an httpx client for an already-resolved device endpoint.

    Applies the SSRF policy (allowed CIDRs, deny-list, port whitelist),
    DEVICE_ADAPTERS §8 timeouts (5 s connect / 30 s request) and the redirect
    policy (disabled by default; only same-IP allowed-port redirects when
    enabled). ``host_ip`` is the RESOLVED IP from the policy — never a
    hostname — so no rebinding can occur.

    Only CA-validated HTTPS clients can be built here: httpx cannot run the
    post-handshake pin check, so pinned sessions must use
    ``open_pinned_connection`` (M1T3 adapter wiring). Plain HTTP is refused:
    it cannot carry credentials.
    """
    if scheme != "https":
        msg = "plain http cannot carry credentials; only https device management is supported"
        raise ValueError(msg)
    if policy is None:
        msg = "a DeviceEndpointPolicy is required"
        raise ValueError(msg)
    allowed_ports = allowed_ports if allowed_ports is not None else frozenset({443, 8443})
    policy.validate_endpoint(host=None, ip=host_ip, port=port, allowed_ports=allowed_ports)
    if pinned_fingerprint is not None:
        msg = (
            "pinned TLS requires the post-handshake check; use open_pinned_connection "
            "(M1T3 session wiring)"
        )
        raise ValueError(msg)
    ctx = build_ssl_context(
        verify_tls=verify_tls,
        pinned_fingerprint=None,
        ca_bundle_path=ca_bundle_path,
    )
    host_str = f"[{host_ip}]" if isinstance(host_ip, IPv6Address) else str(host_ip)
    hooks: dict[str, list[Callable[..., Any]]] = {}
    if allow_redirects:
        src_ip = host_ip

        def on_redirect(request: httpx.Request, response: httpx.Response) -> None:
            location = response.headers.get("location")
            if location is None:
                return
            if not redirect_allowed(src_ip, location, allowed_ports):
                msg = f"redirect to {location} is not allowed by policy"
                raise NetworkPolicyViolation(stage="redirect", endpoint=location, reason=msg)

        hooks["redirect"] = [on_redirect]
    return httpx.Client(
        verify=ctx,
        base_url=f"https://{host_str}:{port}",
        timeout=httpx.Timeout(
            connect=CONNECT_TIMEOUT_SECONDS,
            read=REQUEST_TIMEOUT_SECONDS,
            write=REQUEST_TIMEOUT_SECONDS,
            pool=CONNECT_TIMEOUT_SECONDS,
        ),
        follow_redirects=allow_redirects,
        event_hooks=hooks,
    )
