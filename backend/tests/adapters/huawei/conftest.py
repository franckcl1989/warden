"""Shared fixtures for the Huawei VRP adapter contract suite (M5T2).

Each test boots ONE switch-simulator agent over real UDP on an
OS-assigned port (sync hosting helper); tests configure v3/v2c
credentials, model profile, counter steps and knobs per test via
``switch_agent(profile_key, ...)``. The simulator is a TEST DEVICE
SIMULATOR — never hardware evidence (tests/simulators/switch/README.md).
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from app.domain.adapter import CollectionRequest, ConnectionProfile, DeviceSession
from tests.simulators.switch.agent import AgentConfig, AgentCredential, SwitchAgent
from tests.simulators.switch.hosting import running_agent
from tests.simulators.switch.profiles import profile_by_key

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

SIM_HOST = "127.0.0.1"
V3_USERNAME = "monitor"
V3_AUTH_KEY = "sim-auth-key-1"
V3_PRIV_KEY = "sim-priv-key-1"
V2C_COMMUNITY = "public"
UTC = datetime.UTC

DEFAULT_V3_USER = AgentCredential(username=V3_USERNAME, auth_key=V3_AUTH_KEY, privacy_key=V3_PRIV_KEY)


@dataclass
class SwitchAgentHandle:
    """A booted agent + connection helpers for one adapter test."""

    agent: SwitchAgent
    profile_key: str
    port: int

    @property
    def v3_credentials(self) -> dict[str, object]:
        return {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY}

    def session(self, device_id: uuid.UUID | None = None) -> DeviceSession:
        return DeviceSession(
            device_id=device_id or uuid.uuid4(),
            management_endpoint=SIM_HOST,
            connection_config={"snmp_version": "v3", "port": self.port},
            credentials={"snmp": self.v3_credentials},
        )

    def session_v2c(self, device_id: uuid.UUID | None = None) -> DeviceSession:
        return DeviceSession(
            device_id=device_id or uuid.uuid4(),
            management_endpoint=SIM_HOST,
            connection_config={"snmp_version": "v2c", "port": self.port},
            credentials={"snmp": {"community": V2C_COMMUNITY}},
        )

    def profile(self, adapter_key: str = "switch.huawei_vrp_base") -> ConnectionProfile:
        return ConnectionProfile(
            adapter_key=adapter_key,
            management_endpoint=SIM_HOST,
            port=self.port,
            connection_config={"snmp_version": "v3"},
            credentials={"snmp": self.v3_credentials},
            verify_tls=False,
            tls_fingerprint_sha256=None,
        )

    def profile_v2c(self, adapter_key: str = "switch.huawei_vrp_base") -> ConnectionProfile:
        return ConnectionProfile(
            adapter_key=adapter_key,
            management_endpoint=SIM_HOST,
            port=self.port,
            connection_config={"snmp_version": "v2c"},
            credentials={"snmp": {"community": V2C_COMMUNITY}},
            verify_tls=False,
            tls_fingerprint_sha256=None,
        )

    def request(self, now: datetime.datetime | None = None) -> CollectionRequest:
        return CollectionRequest(
            device_id=uuid.uuid4(),
            collection_type="metrics",
            now=now if now is not None else datetime.datetime.now(UTC),
        )


@pytest.fixture()
def switch_agent() -> Iterator[object]:
    """Factory: ``with switch_agent(profile_key, **agent_overrides) as h:``
    boots one agent (real UDP) for the block and yields a handle."""

    @contextmanager
    def boot(profile_key: str, **agent_overrides: object) -> Iterator[SwitchAgentHandle]:
        if "v3_user" not in agent_overrides:
            agent_overrides["v3_user"] = DEFAULT_V3_USER
        config = AgentConfig(profile=profile_by_key(profile_key), **agent_overrides)
        agent = SwitchAgent(config)
        with running_agent(agent) as started:
            handle = SwitchAgentHandle(agent=agent, profile_key=profile_key, port=int(started.port or 0))
            assert handle.port > 0
            yield handle

    yield boot
