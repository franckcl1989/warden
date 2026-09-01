"""SSRF guard tests (docs/SECURITY.md §7).

Resolve-then-validate against an admin-configured CIDR allowlist, deny
loopback/link-local/metadata/multicast/broadcast/container ranges, port
whitelists per protocol and same-IP redirect policy.
"""

from __future__ import annotations

from ipaddress import ip_address
from unittest.mock import patch

import pytest
from app.infrastructure.network_policy import (
    DEFAULT_ALLOWED_PORTS,
    DeviceEndpointPolicy,
    NetworkPolicyViolation,
    protocol_allowed_ports,
    redirect_allowed,
)


def policy(*cidrs: str) -> DeviceEndpointPolicy:
    return DeviceEndpointPolicy(list(cidrs))


def fake_addrinfo(host: str, port: int, ips: list[str]) -> list[tuple]:
    return [
        (2, 1, 6, "", (ip, port, 0, 0)) if ":" not in ip else (10, 1, 6, "", (ip, port, 0, 0))
        for ip in ips
    ]


@pytest.mark.unit
def test_loopback_denied() -> None:
    p = policy("127.0.0.0/8", "::1/128", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("127.0.0.1")) is False
    assert p.is_ip_allowed(ip_address("::1")) is False


@pytest.mark.unit
def test_link_local_denied() -> None:
    p = policy("169.254.0.0/16", "fe80::/10", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("169.254.0.1")) is False
    assert p.is_ip_allowed(ip_address("fe80::1")) is False


@pytest.mark.unit
def test_metadata_ip_denied() -> None:
    p = policy("169.254.0.0/16", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("169.254.169.254")) is False


@pytest.mark.unit
def test_multicast_and_broadcast_denied() -> None:
    p = policy("224.0.0.0/4", "255.255.255.255/32", "ff00::/8", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("224.0.0.1")) is False
    assert p.is_ip_allowed(ip_address("255.255.255.255")) is False
    assert p.is_ip_allowed(ip_address("ff02::1")) is False


@pytest.mark.unit
def test_all_zero_denied() -> None:
    p = policy("0.0.0.0/8", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("0.0.0.0")) is False  # noqa: S104


@pytest.mark.unit
def test_ipv6_ula_container_range_denied() -> None:
    p = policy("fc00::/7", "10.0.0.0/8")
    assert p.is_ip_allowed(ip_address("fd00::1")) is False
    assert p.is_ip_allowed(ip_address("fc00::1")) is False


@pytest.mark.unit
def test_ipv4_mapped_ipv6_evaluated_as_ipv4() -> None:
    p = policy("10.0.0.0/8", "127.0.0.0/8")
    assert p.is_ip_allowed(ip_address("::ffff:10.0.0.5")) is True
    assert p.is_ip_allowed(ip_address("::ffff:127.0.0.1")) is False


@pytest.mark.unit
def test_allowed_cidr_accepted() -> None:
    p = policy("192.168.10.0/24", "2001:db8::/64")
    assert p.is_ip_allowed(ip_address("192.168.10.5")) is True
    assert p.is_ip_allowed(ip_address("192.168.11.5")) is False
    assert p.is_ip_allowed(ip_address("2001:db8::42")) is True
    assert p.is_ip_allowed(ip_address("2001:db9::42")) is False


@pytest.mark.unit
def test_ula_denied_even_when_allowlisted() -> None:
    # The deny-list is a hard safety net: fd01::/64 sits inside the denied
    # container range fc00::/7, so allowlisting it must NOT enable it.
    p = policy("fd01::/64")
    assert p.is_ip_allowed(ip_address("fd01::42")) is False


@pytest.mark.unit
def test_empty_allowlist_denies_everything() -> None:
    p = policy()
    assert p.is_ip_allowed(ip_address("192.168.10.5")) is False


@pytest.mark.unit
def test_validate_endpoint_enforces_port_whitelist() -> None:
    p = policy("192.168.10.0/24")
    p.validate_endpoint("switch-1", ip_address("192.168.10.5"), 8443, {443, 8443})
    with pytest.raises(NetworkPolicyViolation, match="port"):
        p.validate_endpoint("switch-1", ip_address("192.168.10.5"), 8080, {443, 8443})


@pytest.mark.unit
def test_resolve_picks_only_allowed_candidates() -> None:
    p = policy("10.20.0.0/16")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("mgmt.example", 443, ["10.99.0.5", "10.20.1.1"]),
    ):
        ip, port = p.resolve_endpoint("mgmt.example", 443, {443, 8443})
    assert ip == ip_address("10.20.1.1")
    assert port == 443


@pytest.mark.unit
def test_resolve_raises_when_no_candidate_allowed() -> None:
    p = policy("10.20.0.0/16")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("mgmt.example", 443, ["10.99.0.5", "169.254.1.1"]),
    ), pytest.raises(NetworkPolicyViolation, match="no allowed"):
        p.resolve_endpoint("mgmt.example", 443, {443, 8443})


@pytest.mark.unit
def test_resolve_raises_when_port_not_allowed() -> None:
    p = policy("10.20.0.0/16")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("mgmt.example", 8080, ["10.20.1.1"]),
    ), pytest.raises(NetworkPolicyViolation, match="port"):
        p.resolve_endpoint("mgmt.example", 8080, {443, 8443})


@pytest.mark.unit
def test_redirect_to_different_ip_denied() -> None:
    src = ip_address("10.20.1.1")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("evil.example", 443, ["10.99.0.5"]),
    ):
        assert redirect_allowed(src, "https://evil.example/", {443, 8443}) is False


@pytest.mark.unit
def test_redirect_same_ip_allowed_port_allowed() -> None:
    src = ip_address("10.20.1.1")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("mgmt.example", 8443, ["10.20.1.1"]),
    ):
        assert redirect_allowed(src, "https://mgmt.example/redir", {443, 8443}) is True


@pytest.mark.unit
def test_redirect_same_ip_disallowed_port_denied() -> None:
    src = ip_address("10.20.1.1")
    with patch(
        "app.infrastructure.network_policy.socket.getaddrinfo",
        return_value=fake_addrinfo("mgmt.example", 8080, ["10.20.1.1"]),
    ):
        assert redirect_allowed(src, "http://mgmt.example/", {443, 8443}) is False


@pytest.mark.unit
def test_redirect_unknown_scheme_denied() -> None:
    src = ip_address("10.20.1.1")
    assert redirect_allowed(src, "ftp://mgmt.example/", {443, 8443}) is False
    assert redirect_allowed(src, "not a url", {443, 8443}) is False


@pytest.mark.unit
def test_default_port_whitelists() -> None:
    assert DEFAULT_ALLOWED_PORTS["https"] == frozenset({443, 8443})
    assert DEFAULT_ALLOWED_PORTS["http"] == frozenset({80, 8080, 8000})
    assert DEFAULT_ALLOWED_PORTS["snmp"] == frozenset({161})
    assert DEFAULT_ALLOWED_PORTS["ssh"] == frozenset({22, 2222})
    assert DEFAULT_ALLOWED_PORTS["telnet"] == frozenset({23})
    assert all(1 <= p <= 65535 for ports in DEFAULT_ALLOWED_PORTS.values() for p in ports)


@pytest.mark.unit
def test_port_override_validated_strictly() -> None:
    assert protocol_allowed_ports("https", [8443, 9443]) == frozenset({8443, 9443})
    with pytest.raises(ValueError, match="1.*65535"):
        protocol_allowed_ports("https", [0])
    with pytest.raises(ValueError, match="1.*65535"):
        protocol_allowed_ports("https", [65536])
    with pytest.raises(ValueError, match="1.*65535"):
        protocol_allowed_ports("https", [])
    with pytest.raises(ValueError, match="unknown protocol"):
        protocol_allowed_ports("gopher")


@pytest.mark.unit
def test_network_policy_violation_carries_stage_and_endpoint() -> None:
    p = policy("10.20.0.0/16")
    try:
        p.validate_endpoint("mgmt.example", ip_address("169.254.169.254"), 443, {443})
    except NetworkPolicyViolation as exc:
        assert exc.stage == "endpoint_policy"
        assert exc.endpoint == "mgmt.example:443"
        assert exc.reason
    else:
        raise AssertionError("expected NetworkPolicyViolation")
