"""Switch simulator self-tests: agent + emitter mechanics over real UDP."""

from __future__ import annotations

import asyncio
import datetime

import pytest

from tests.simulators.switch.agent import AgentConfig, AgentCredential, SwitchAgent
from tests.simulators.switch.emitters import (
    TRAP_LINK_DOWN,
    TrapCredentials,
    TrapEmitter,
    generic_line,
    vrp_auth_failure_line,
    vrp_link_state_line,
    vrp_restart_line,
)
from tests.simulators.switch.profiles import MODEL_S5732_H48XUM2CC, profile_by_key

UTC = datetime.UTC

AUTH_KEY = "sim-auth-key-1"
PRIV_KEY = "sim-priv-key-1"


async def _started_agent(**overrides: object) -> SwitchAgent:
    agent = SwitchAgent(
        AgentConfig(
            profile=profile_by_key("core_s5732"),
            v3_user=AgentCredential(
                username="monitor",
                auth_key=AUTH_KEY,
                privacy_key=PRIV_KEY,
            ),
            **overrides,
        )
    )
    await agent.start()
    return agent


class TestProfiles:
    def test_profiles_carry_exact_model_strings(self) -> None:
        core = profile_by_key("core_s5732")
        assert core.model == MODEL_S5732_H48XUM2CC
        assert core.adapter_key == "switch.huawei_vrp_core"
        assert core.sys_descr.startswith(f"Huawei Technologies Co., Ltd. {MODEL_S5732_H48XUM2CC}")
        assert "VRP" in core.sys_descr
        access = profile_by_key("access_s5735")
        assert access.device_type == "access_switch"
        assert access.adapter_key == "switch.huawei_vrp_access"

    def test_unknown_profile_rejected(self) -> None:
        with pytest.raises(ValueError):
            profile_by_key("no-such-profile")


class TestSyslogLines:
    def test_link_state_line_classifies_as_flap_down(self) -> None:
        from app.infrastructure.ingest.dispatcher import classify_syslog
        from app.infrastructure.ingest.syslog_parse import parse_syslog_line

        line = vrp_link_state_line(
            hostname="sim-switch",
            interface="GigabitEthernet0/0/1",
            direction="down",
            when=datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC),
        )
        parsed = parse_syslog_line(line)
        assert parsed is not None
        event = classify_syslog(parsed)
        assert event.__class__.__name__ == "ClassifiedEvent"
        assert event.event_type == "event.port_flap"
        assert event.component_native_id == "GigabitEthernet0/0/1"

    def test_restart_and_auth_lines_classify(self) -> None:
        from app.infrastructure.ingest.dispatcher import classify_syslog
        from app.infrastructure.ingest.syslog_parse import parse_syslog_line

        parsed = parse_syslog_line(vrp_restart_line(hostname="sim-switch"))
        assert parsed is not None
        assert classify_syslog(parsed).event_type == "event.device_restart"
        parsed = parse_syslog_line(vrp_auth_failure_line(hostname="sim-switch"))
        assert parsed is not None
        assert classify_syslog(parsed).event_type == "event.auth_failure"
        parsed = parse_syslog_line(generic_line(hostname="sim-switch", content="display this"))
        assert parsed is not None
        assert classify_syslog(parsed).__class__.__name__ == "DropReason"


class TestSwitchAgentMechanics:
    """Real SNMP client (app SnmpClient) against the simulator over UDP."""

    async def test_v3_get_and_walk_ifdescr(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection
        from app.infrastructure.protocols.snmp.values import SnmpKind, SnmpValue

        agent = await _started_agent()
        try:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    username="monitor",
                    auth_key=AUTH_KEY,
                    privacy_key=PRIV_KEY,
                )
            )
            # The client facade is sync (asyncio.run per call): async tests
            # exercise it from a worker thread, like the real worker does.
            value = await asyncio.to_thread(client.get, "1.3.6.1.2.1.1.1.0")
            assert isinstance(value, SnmpValue)
            assert value.kind is SnmpKind.STRING
            assert "S5732-H48XUM2CC" in str(value.value)
            walked, truncated = await asyncio.to_thread(client.walk, "1.3.6.1.2.1.2.2.1.2")
            assert truncated is False
            assert len(walked) == 52  # 48 GE + 4 XGE ifDescr rows
            assert all(isinstance(item, SnmpValue) for item in walked)
            assert any(str(item.value) == "GigabitEthernet0/0/1" for item in walked)
            assert any(str(item.value) == "XGigabitEthernet0/0/1" for item in walked)
        finally:
            await agent.stop()

    async def test_wrong_v3_credentials_never_answer(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        import time

        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection
        from app.infrastructure.protocols.snmp.errors import SnmpError

        agent = await _started_agent()

        def _read_with_error() -> tuple[str | None, float]:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    username="monitor",
                    auth_key="WRONG-KEY",
                    privacy_key=PRIV_KEY,
                    timeout_seconds=0.5,
                    retries=0,
                )
            )
            start = time.monotonic()
            try:
                client.get("1.3.6.1.2.1.1.1.0")
                return None, time.monotonic() - start
            except SnmpError as exc:
                return exc.code, time.monotonic() - start

        try:
            code, elapsed = await asyncio.to_thread(_read_with_error)
            assert code == "authentication_failed"
            assert elapsed < 3
        finally:
            await agent.stop()

    async def test_counters_advance_between_reads(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent(counter_step_if_in_octets=125_000)

        def _read_three() -> tuple[int, int, int]:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    community="public",
                    version="v2c",
                )
            )
            first = client.get("1.3.6.1.2.1.2.2.1.10.1")
            second = client.get("1.3.6.1.2.1.2.2.1.10.1")
            third = client.get("1.3.6.1.2.1.2.2.1.10.1")
            return int(first.value), int(second.value), int(third.value)

        try:
            first, second, third = await asyncio.to_thread(_read_three)
            assert second - first == 125_000
            assert third - second == 125_000
        finally:
            await agent.stop()

    async def test_missing_leaf_is_not_present(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection
        from app.infrastructure.protocols.snmp.values import NOT_PRESENT

        agent = await _started_agent()

        def _read_missing() -> tuple[bool, int]:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    community="public",
                    version="v2c",
                )
            )
            missing = client.get("1.3.6.1.2.1.99.99.0")
            walked, truncated = client.walk("1.3.6.1.2.1.99.99")
            return missing is NOT_PRESENT, len(walked), truncated

        try:
            is_not_present, walked_count, truncated = await asyncio.to_thread(_read_missing)
            assert is_not_present is True
            assert walked_count == 0
            assert truncated is False
        finally:
            await agent.stop()

    async def test_walk_truncation_is_marked_not_silent(
        self, isolated_snmp_boots: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        del isolated_snmp_boots
        import app.infrastructure.protocols.snmp.client as snmp_client_module
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        monkeypatch.setattr(snmp_client_module, "WALK_MAX_ROWS", 2)
        agent = await _started_agent()

        def _walk_ifdescr() -> tuple[int, bool]:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    community="public",
                    version="v2c",
                )
            )
            rows, truncated = client.walk("1.3.6.1.2.1.2.2.1.2")
            return len(rows), truncated

        try:
            rows, truncated = await asyncio.to_thread(_walk_ifdescr)
            # 2 pages x 20 rows of the 52-row ifDescr tree: the guard fired
            # mid-subtree, so the result must SAY truncated (M5T2 asserts).
            assert truncated is True
            assert rows == 40
        finally:
            await agent.stop()


class TestTrapEmitter:
    async def test_v3_link_down_trap_is_decoded_by_platform_receiver(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        from app.infrastructure.ingest.trap_receiver import TrapReceiver, TrapUser

        profile = profile_by_key("core_s5732")
        received = []
        receiver = TrapReceiver(
            host="127.0.0.1",
            port=0,
            handler=lambda trap, peer: received.append((trap, peer)),
            engine_id_hex="77617264656e2d747261702d72656376",
        )
        receiver.set_users(
            [
                TrapUser(
                    username="monitor",
                    engine_id_hex=profile.engine_id_hex,
                    auth_key=AUTH_KEY,
                    privacy_key=PRIV_KEY,
                )
            ]
        )
        await receiver.start()
        emitter = TrapEmitter(
            profile_engine_id_hex=profile.engine_id_hex,
            port=receiver.port or 0,
            credentials=TrapCredentials(
                username="monitor",
                auth_key=AUTH_KEY,
                privacy_key=PRIV_KEY,
            ),
        )
        try:
            await emitter.send_v3(TRAP_LINK_DOWN, if_index=24)
            await asyncio.sleep(0.4)
            assert len(received) == 1
            trap, peer = received[0]
            assert trap.security_model == 3
            assert trap.security_name == "monitor"
            assert peer == "127.0.0.1"
            oid_vb = trap.varbind("1.3.6.1.6.3.1.1.4.1.0")
            assert oid_vb is not None
            assert str(oid_vb.value) == TRAP_LINK_DOWN
        finally:
            await emitter.close()
            await receiver.stop()
