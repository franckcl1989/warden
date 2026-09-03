"""Fake adapter launch descriptors (M3T4, DEVICE_ADAPTERS.md §2 ``create_launch``).

Unit tests over the fake's launch method: a supported console.kvm.open
yields a URL descriptor whose URL never carries credentials; the
``no_graphical_console`` knob (dev/test only, mirroring the Redfish
simulator knob) makes it fail honestly with ``not_configured`` — the adapter
never fabricates a console that is not there (AGENTS.md: 不得把设备不支持...
伪装成成功). Unknown capabilities are refused as ``unsupported_capability``.
"""

from __future__ import annotations

import uuid

import pytest
from app.adapters.fake import FakeSimpleAdapter
from app.domain.adapter import AdapterError, DeviceSession

FAKE = FakeSimpleAdapter()
DEVICE_ID = uuid.uuid4()

PASSWORD = "fake-device-password-1"


def _session(**config: object) -> DeviceSession:
    merged: dict[str, object] = {"protocol": "https"}
    merged.update(config)
    return DeviceSession(
        device_id=DEVICE_ID,
        management_endpoint="192.0.2.10",
        connection_config=merged,
        credentials={"username": "admin", "password": PASSWORD},
    )


class TestFakeLaunch:
    def test_kvm_launch_returns_url_descriptor_without_credentials(self) -> None:
        descriptor = FAKE.create_launch(_session(), "console.kvm.open")
        assert descriptor.kind == "url"
        assert descriptor.url == "https://192.0.2.10/console"
        # Descriptor URLs never carry credentials or platform tokens.
        assert PASSWORD not in descriptor.url
        assert "admin" not in descriptor.url
        assert descriptor.vendor_session_ref is None
        assert isinstance(descriptor.display_hint, str)

    def test_http_protocol_config_reflects_the_scheme(self) -> None:
        descriptor = FAKE.create_launch(
            _session(protocol="http", port=8080), "console.kvm.open"
        )
        assert descriptor.url == "http://192.0.2.10:8080/console"

    def test_no_graphical_console_knob_fails_honestly(self) -> None:
        with pytest.raises(AdapterError) as raised:
            FAKE.create_launch(_session(no_graphical_console=True), "console.kvm.open")
        assert raised.value.code == "not_configured"
        assert "no_graphical_console" in raised.value.message

    def test_unknown_capability_is_unsupported_capability(self) -> None:
        with pytest.raises(AdapterError) as raised:
            FAKE.create_launch(_session(), "power.on")
        assert raised.value.code == "unsupported_capability"
