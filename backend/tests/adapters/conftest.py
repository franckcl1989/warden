"""Shared fixtures for the Redfish common-adapter contract suite.

The suite talks to ONE uvicorn-booted test-device simulator
(tests/simulators/redfish) per session; tests reconfigure it through the
simulator's control endpoint (profile + SRV-MON surface knobs). The simulator
is a TEST DEVICE SIMULATOR — never hardware evidence (module READMEs).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import pytest

from tests.simulators.redfish.app import (
    FAILURE_KEYS,
    FLOAT_KNOB_DEFAULTS,
    INT_KNOB_KEYS,
    STRING_KNOB_DEFAULTS,
    SURFACE_KNOB_KEYS,
    SimulatorConfig,
)
from tests.simulators.redfish.serving import serve_simulator

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

SIM_USERNAME = "admin"
SIM_PASSWORD = "sim-pass-1"
SIM_HOST = "127.0.0.1"


@dataclass
class SimAccess:
    """Control access to the booted simulator."""

    base_url: str
    client: httpx.Client

    @property
    def port(self) -> int:
        parsed = urlsplit(self.base_url)
        assert parsed.port is not None
        return parsed.port

    def reset(self) -> None:
        """Back to the pristine healthy generic-profile with every knob off."""
        body: dict[str, object] = {"profile": "healthy", "vendor": "generic", "reset_state": True}
        body.update(dict.fromkeys(SURFACE_KNOB_KEYS, False))
        body.update(dict.fromkeys(INT_KNOB_KEYS, 0))
        body["reset_types_override"] = []
        body.update(FLOAT_KNOB_DEFAULTS)
        body.update(STRING_KNOB_DEFAULTS)
        body["failures"] = dict.fromkeys(FAILURE_KEYS, False)
        body["media_hosts_required"] = False
        body["media_hosts"] = []
        response = self.client.post("/warden-sim/control", json=body)
        assert response.status_code == 200, response.text

    def set(self, **knobs: object) -> None:
        response = self.client.post("/warden-sim/control", json=knobs)
        assert response.status_code == 200, response.text


@pytest.fixture(scope="session")
def sim_server() -> Iterator[SimAccess]:
    """One simulator boot per test session (profiles/knobs switched per test)."""
    with serve_simulator(SimulatorConfig(profile="healthy")) as url, httpx.Client(
        base_url=url, timeout=10.0
    ) as client:
        access = SimAccess(base_url=url, client=client)
        yield access


@pytest.fixture()
def sim(sim_server: SimAccess) -> Iterator[SimAccess]:
    """Per-test control handle: every test starts from the pristine profile."""
    sim_server.reset()
    yield sim_server
