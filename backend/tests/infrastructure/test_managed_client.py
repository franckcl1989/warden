"""Managed HTTP client factory tests.

The factory is policy-checked and configured for real sockets; no network
traffic happens in these tests. The decision/policy functions are tested in
``test_tls.py`` / ``test_network_policy.py``; the factory's network behavior
is exercised by M1T3 device sessions (documented in the module).
"""

from __future__ import annotations

from ipaddress import ip_address

import httpx
import pytest
from app.infrastructure.network_policy import DeviceEndpointPolicy, NetworkPolicyViolation
from app.infrastructure.tls import build_managed_client


@pytest.mark.unit
def test_client_rejects_port_outside_whitelist() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with pytest.raises(NetworkPolicyViolation):
        build_managed_client(
            host_ip=ip_address("192.168.10.5"),
            port=8080,
            verify_tls=True,
            pinned_fingerprint=None,
            ca_bundle_path=None,
            allowed_ports=frozenset({443, 8443}),
            policy=p,
        )


@pytest.mark.unit
def test_client_rejects_ip_outside_allowlist() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with pytest.raises(NetworkPolicyViolation):
        build_managed_client(
            host_ip=ip_address("10.0.0.9"),
            port=443,
            verify_tls=True,
            pinned_fingerprint=None,
            ca_bundle_path=None,
            allowed_ports=frozenset({443, 8443}),
            policy=p,
        )


@pytest.mark.unit
def test_client_builds_with_expected_timeouts_and_base_url() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with build_managed_client(
        host_ip=ip_address("192.168.10.5"),
        port=8443,
        verify_tls=True,
        pinned_fingerprint=None,
        ca_bundle_path=None,
        allowed_ports=frozenset({443, 8443}),
        policy=p,
    ) as client:
        assert isinstance(client, httpx.Client)
        assert client.base_url == httpx.URL("https://192.168.10.5:8443")
        assert client.timeout.connect == 5.0
        assert client.timeout.read == 30.0
        assert client.follow_redirects is False


@pytest.mark.unit
def test_client_ipv6_base_url_is_bracketed() -> None:
    p = DeviceEndpointPolicy(["2001:db8::/64"])
    with build_managed_client(
        host_ip=ip_address("2001:db8::42"),
        port=443,
        verify_tls=True,
        pinned_fingerprint=None,
        ca_bundle_path=None,
        allowed_ports=frozenset({443, 8443}),
        policy=p,
    ) as client:
        assert client.base_url == httpx.URL("https://[2001:db8::42]:443")


@pytest.mark.unit
def test_client_refuses_plain_http_scheme() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with pytest.raises(ValueError, match="https"):
        build_managed_client(
            host_ip=ip_address("192.168.10.5"),
            port=80,
            scheme="http",
            verify_tls=True,
            pinned_fingerprint=None,
            ca_bundle_path=None,
            allowed_ports=frozenset({80}),
            policy=p,
        )


@pytest.mark.unit
def test_client_refuses_unverified_tls() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with pytest.raises(ValueError, match="unverified"):
        build_managed_client(
            host_ip=ip_address("192.168.10.5"),
            port=443,
            verify_tls=False,
            pinned_fingerprint=None,
            ca_bundle_path=None,
            allowed_ports=frozenset({443, 8443}),
            policy=p,
        )


@pytest.mark.unit
def test_client_refuses_pinned_mode_until_transport_wiring() -> None:
    # The pin check happens post-handshake (no ssl verify_callback on the
    # deployed interpreter); an httpx client cannot enforce it, so the factory
    # refuses to silently build an unverified client. M1T3 wires sessions to
    # open_pinned_connection.
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with pytest.raises(ValueError, match="open_pinned_connection"):
        build_managed_client(
            host_ip=ip_address("192.168.10.5"),
            port=443,
            verify_tls=True,
            pinned_fingerprint="a" * 64,
            ca_bundle_path=None,
            allowed_ports=frozenset({443, 8443}),
            policy=p,
        )


@pytest.mark.unit
def test_client_redirect_enabled_only_explicitly() -> None:
    p = DeviceEndpointPolicy(["192.168.10.0/24"])
    with build_managed_client(
        host_ip=ip_address("192.168.10.5"),
        port=443,
        verify_tls=True,
        pinned_fingerprint=None,
        ca_bundle_path=None,
        allowed_ports=frozenset({443, 8443}),
        policy=p,
        allow_redirects=True,
    ) as client:
        assert client.follow_redirects is True
