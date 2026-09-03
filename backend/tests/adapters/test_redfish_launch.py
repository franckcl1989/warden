"""Common Redfish adapter launch descriptors (M3T4, DEVICE_ADAPTERS.md §2/§4.2).

The common adapter implements console.kvm.open per the generic Redfish
surface: the manager's GraphicalConsole block (ServiceEnabled + KVM among
ConnectTypesSupported when the array is present) is the ONLY standard
advertisement of a KVM-capable console, so a launch succeeds exactly when
that advertisement exists and returns the validated manager origin URL —
never credentials. The ``no_graphical_console`` simulator knob removes the
advertisement and the launch fails honestly with ``not_configured`` (no
fabricated console, AGENTS.md). Vendor HTML5 session-creation APIs are M3T5
overlay territory; nothing vendor-specific lives here.
"""

from __future__ import annotations

import uuid

import pytest
from app.adapters.redfish.common import RedfishCommonAdapter
from app.domain.adapter import AdapterError, DeviceSession

from tests.adapters.conftest import SIM_HOST, SIM_PASSWORD, SIM_USERNAME, SimAccess

ADAPTER = RedfishCommonAdapter()


def sim_session(sim: SimAccess, **config: object) -> DeviceSession:
    merged: dict[str, object] = {"protocol": "http", "port": sim.port}
    merged.update(config)
    return DeviceSession(
        device_id=uuid.uuid4(),
        management_endpoint=SIM_HOST,
        connection_config=merged,
        credentials={"username": SIM_USERNAME, "password": SIM_PASSWORD},
    )


class TestRedfishLaunch:
    def test_kvm_launch_returns_graphical_console_url_descriptor(self, sim: SimAccess) -> None:
        descriptor = ADAPTER.create_launch(sim_session(sim), "console.kvm.open")
        assert descriptor.kind == "url"
        assert descriptor.url == f"http://{SIM_HOST}:{sim.port}/"
        # No credentials or platform tokens ever enter the descriptor.
        assert SIM_PASSWORD not in descriptor.url
        assert SIM_USERNAME not in descriptor.url
        assert descriptor.vendor_session_ref is None

    def test_no_graphical_console_knob_fails_honestly(self, sim: SimAccess) -> None:
        sim.set(no_graphical_console=True)
        with pytest.raises(AdapterError) as raised:
            ADAPTER.create_launch(sim_session(sim), "console.kvm.open")
        assert raised.value.code == "not_configured"
        assert "no_graphical_console" in raised.value.message
        assert raised.value.stage == "launch"

    def test_task_capability_is_not_a_launch(self, sim: SimAccess) -> None:
        with pytest.raises(AdapterError) as raised:
            ADAPTER.create_launch(sim_session(sim), "power.on")
        assert raised.value.code == "unsupported_capability"

    def test_unreachable_device_maps_through_adapter_error_codes(self, sim: SimAccess) -> None:
        with pytest.raises(AdapterError) as raised:
            ADAPTER.create_launch(sim_session(sim, port=1), "console.kvm.open")
        assert raised.value.code in (
            "network_unreachable",
            "protocol_error",
            "authentication_failed",
        )
