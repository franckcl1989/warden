"""SSRF guard for outbound device connections (docs/SECURITY.md §7).

Every outbound device connection must pass ``DeviceEndpointPolicy``:

- resolve the management hostname first, then validate the RESOLVED IPs
  against the deployment-configured allowlist (``WARDEN_ALLOWED_DEVICE_CIDRS``)
  plus a hard deny-list (loopback, link-local incl. ``169.254.169.254``
  metadata, multicast, broadcast, IPv6 link-local, IPv6 ULA container range,
  all-zero/unspecified);
- connect using the resolved IP (no DNS rebinding);
- ports come from per-protocol whitelists, never from API parameters;
- redirects are disabled by default and only allowed to the same resolved IP
  on an allowed port.

Decisions: IPv6 ULA ``fc00::/7`` is denied as the container network range;
IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are evaluated as their IPv4
form so they cannot bypass the IPv4 rules.

``NetworkPolicyViolation`` carries ``stage``/``endpoint``/``reason``; the
boundary maps it to the stable ``network_unreachable`` error code (contracts/
error-codes.json: no dedicated SSRF code) with ``stage="endpoint_policy"``.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from urllib.parse import urlsplit

_DENY_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ip_network("0.0.0.0/8"),  # all-zero weirdness
    ip_network("127.0.0.0/8"),  # loopback
    ip_network("169.254.0.0/16"),  # link-local, includes 169.254.169.254 metadata
    ip_network("224.0.0.0/4"),  # multicast
    ip_network("255.255.255.255/32"),  # broadcast
    ip_network("::/128"),  # unspecified
    ip_network("::1/128"),  # loopback
    ip_network("fe80::/10"),  # IPv6 link-local
    ip_network("fc00::/7"),  # IPv6 ULA: container ranges
    ip_network("ff00::/8"),  # IPv6 multicast
)

# Per-protocol management port whitelists; adapters may narrow them via
# connection_config (``protocol_allowed_ports``), never widen beyond 1..65535.
DEFAULT_ALLOWED_PORTS: dict[str, frozenset[int]] = {
    "https": frozenset({443, 8443}),
    "http": frozenset({80, 8080, 8000}),
    "snmp": frozenset({161}),
    "ssh": frozenset({22, 2222}),
    "telnet": frozenset({23}),
}


def _normalize_ip(ip: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    """Evaluate IPv4-mapped IPv6 addresses as their embedded IPv4 address."""
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def protocol_allowed_ports(protocol: str, override: Iterable[int] | None = None) -> frozenset[int]:
    """Port whitelist for ``protocol``; ``override`` is strictly validated (no 0)."""
    if override is not None:
        ports = frozenset(override)
        if not ports or any(not 1 <= p <= 65535 for p in ports):
            msg = "ports must be within 1..65535"
            raise ValueError(msg)
        return ports
    try:
        return DEFAULT_ALLOWED_PORTS[protocol]
    except KeyError as exc:
        msg = f"unknown protocol {protocol!r}"
        raise ValueError(msg) from exc


class NetworkPolicyViolation(Exception):
    """SSRF guard rejection; the boundary maps it to ``network_unreachable``."""

    def __init__(self, *, stage: str, endpoint: str, reason: str) -> None:
        self.stage = stage
        self.endpoint = endpoint
        self.reason = reason
        super().__init__(f"network policy violation at {stage} for {endpoint}: {reason}")


class DeviceEndpointPolicy:
    """Allowlist + deny-list policy for outbound device endpoints."""

    def __init__(self, allowed_cidrs: Iterable[str] | None = None) -> None:
        cidrs = list(allowed_cidrs) if allowed_cidrs is not None else []
        try:
            self._allowed = tuple(ip_network(cidr, strict=False) for cidr in cidrs)
        except ValueError as exc:
            msg = f"invalid allowed_device_cidrs entry: {exc}"
            raise ValueError(msg) from exc

    def is_ip_allowed(self, ip: IPv4Address | IPv6Address) -> bool:
        ip = _normalize_ip(ip)
        if not self._allowed:
            # An empty allowlist means "no outbound device connections" —
            # fail closed rather than guess a network.
            return False
        if not any(ip in network for network in self._allowed):
            return False
        return not any(ip in network for network in _DENY_NETWORKS)

    def validate_endpoint(
        self,
        host: str | None,
        ip: IPv4Address | IPv6Address,
        port: int,
        allowed_ports: set[int] | frozenset[int],
    ) -> None:
        """Raise ``NetworkPolicyViolation`` unless ``(ip, port)`` is permitted."""
        endpoint = f"{host if host else ip}:{port}"
        if port not in allowed_ports:
            msg = (
                f"port {port} not in the adapter whitelist "
                f"(allowed: {sorted(allowed_ports)})"
            )
            raise NetworkPolicyViolation(stage="endpoint_policy", endpoint=endpoint, reason=msg)
        if not self.is_ip_allowed(ip):
            msg = f"resolved address {ip} is not inside the configured management CIDRs"
            raise NetworkPolicyViolation(stage="endpoint_policy", endpoint=endpoint, reason=msg)

    def resolve_endpoint(
        self,
        host: str,
        port: int,
        allowed_ports: set[int] | frozenset[int],
    ) -> tuple[IPv4Address | IPv6Address, int]:
        """Resolve ``host`` and return the first (IP, port) pair the policy permits.

        The connection must use the returned IP — never the hostname — so a
        second resolution cannot rebind to a different address.
        """
        if port not in allowed_ports:
            msg = f"port {port} not in the adapter whitelist (allowed: {sorted(allowed_ports)})"
            raise NetworkPolicyViolation(stage="endpoint_policy", endpoint=f"{host}:{port}", reason=msg)
        try:
            candidates = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except OSError as exc:
            msg = "management hostname could not be resolved"
            raise NetworkPolicyViolation(stage="endpoint_policy", endpoint=f"{host}:{port}", reason=msg) from exc
        for _family, _socktype, _proto, _canonname, sockaddr in candidates:
            candidate = ip_address(sockaddr[0])
            if self.is_ip_allowed(candidate):
                return candidate, port
        msg = "no allowed candidate among resolved addresses"
        raise NetworkPolicyViolation(stage="endpoint_policy", endpoint=f"{host}:{port}", reason=msg)


def redirect_allowed(
    src_ip: IPv4Address | IPv6Address,
    dst_url: str,
    allowed_ports: set[int] | frozenset[int],
) -> bool:
    """True only when the redirect target resolves to the same IP on an allowed port.

    Redirects are disabled by default; when a vendor requires them this helper
    compares the RESOLVED destination IP against the connection's source IP
    (never hostnames) and enforces the adapter port whitelist.
    """
    try:
        parts = urlsplit(dst_url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        port = parts.port
    except ValueError:
        return False
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if port not in allowed_ports:
        return False
    try:
        candidates = socket.getaddrinfo(
            parts.hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except OSError:
        return False
    src_ip = _normalize_ip(src_ip)
    return any(_normalize_ip(ip_address(sockaddr[0])) == src_ip for *_rest, sockaddr in candidates)
