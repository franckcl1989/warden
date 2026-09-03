"""Switch simulator self-tests: agent + emitter mechanics over real UDP."""

from __future__ import annotations

import asyncio
import datetime

import pytest
from app.adapters.huawei import oids as huawei_oids
from app.infrastructure.protocols.snmp.oid import parse_oid

from tests.simulators.switch.agent import (
    AgentConfig,
    AgentCredential,
    CounterState,
    SwitchAgent,
)
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

# pysnmp asyncio transports on the Windows proactor emit ResourceWarnings
# from __del__ at garbage collection (fd already closed); pytest turns them
# into PytestUnraisableExceptionWarning failures. With the M5T2 suites
# booting many agents in one process, the GC noise lands here — same
# environment noise the ingest/worker suites already ignore (M5T1 report).
pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]


async def _started_agent(profile_key: str = "core_s5732", **overrides: object) -> SwitchAgent:
    agent = SwitchAgent(
        AgentConfig(
            profile=profile_by_key(profile_key),
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
            # The USM refusal itself is fast; the bound is generous so GC /
            # thread churn after many agent boots in one pytest process
            # (M5T2 suites) cannot flake the assertion.
            assert elapsed < 10
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


class TestM5T2TreesAndKnobs:
    """M5T2 tree mechanics over real UDP: per-region walks, deterministic
    counter advances, HC rollover, per-profile entity/optics/PoE layouts and
    the honest-state knobs."""

    async def test_hc_counters_advance_once_per_walk(self, isolated_snmp_boots: None) -> None:
        """A column walk must advance every leaf of ITS OWN column exactly
        once (the GETBULK continuation is region-bounded — a foreign tail
        read would silently advance another table's counter)."""
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent()
        try:
            target = parse_oid("1.3.6.1.2.1.31.1.1.1.6.1")
            state = agent._tree[target]  # noqa: SLF001
            assert isinstance(state, CounterState)

            def _walk_and_count() -> tuple[int, int]:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                before = state.reads
                # Walking a DIFFERENT column (ifName) must not advance .6.1.
                client.walk("1.3.6.1.2.1.31.1.1.1.1")
                foreign_reads = state.reads - before
                before = state.reads
                rows, truncated = client.walk("1.3.6.1.2.1.31.1.1.1.6")
                own_reads = state.reads - before
                return foreign_reads, own_reads, len(rows), truncated  # type: ignore[return-value]

            foreign, own, rows, truncated = await asyncio.to_thread(_walk_and_count)  # type: ignore[misc]
            assert foreign == 0
            assert own == 1
            assert rows == 52 and truncated is False
        finally:
            await agent.stop()

    async def test_hc_counter_rollover_wraps_to_a_small_base(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        step = 125_000
        agent = await _started_agent(hc_wrap_at=3 * step)
        try:
            def _read_sequence() -> list[int]:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                values = []
                for _ in range(5):
                    raw = client.get("1.3.6.1.2.1.31.1.1.1.6.1")
                    values.append(int(raw.value))  # type: ignore[union-attr]
                return values

            values = await asyncio.to_thread(_read_sequence)
            # step, 2*step, 3*step, then the rollover to a small base, then
            # ascending again — the adapter's counter_reset partial path.
            assert values == [step, 2 * step, 3 * step, step, 2 * step]
        finally:
            await agent.stop()

    async def test_entity_rows_and_absent_psu_slot(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent(profile_key="core_s5731s")
        try:
            def _read_entities() -> tuple[list[str], list[int]]:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                names = []
                walked, _ = client.walk(huawei_oids.COL_ENTITY_NAME)
                names = [str(item.value) for item in walked]  # type: ignore[union-attr]
                present: dict[int, int] = {}
                walked, _ = client.walk(huawei_oids.COL_ENTITY_PRESENT)
                present = {int(item.oid.rsplit(".", 1)[1]): int(item.value) for item in walked}  # type: ignore[union-attr]
                return names, [present[arc] for arc in sorted(present)]

            names, present_values = await asyncio.to_thread(_read_entities)
            assert names == ["PSU1", "PSU2", "FAN1", "FAN2", "SystemTemp"]
            # PSU2 slot is installed-but-absent on the core_s5731s profile.
            assert present_values == [1, 2, 1, 1, 1]
        finally:
            await agent.stop()

    async def test_optics_rows_only_on_module_ports_and_knob_removal(
        self, isolated_snmp_boots: None
    ) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent()

        def _optics_rows(client: SnmpClient) -> list[int]:
            walked, _truncated = client.walk(huawei_oids.COL_OPTICS_RX)
            return sorted(int(item.oid.rsplit(".", 1)[1]) for item in walked)  # type: ignore[union-attr]

        try:
            client = SnmpClient(
                SnmpConnection(
                    host="127.0.0.1",
                    port=agent.port or 0,
                    community="public",
                    version="v2c",
                )
            )
            rows = await asyncio.to_thread(_optics_rows, client)
            assert rows == [49, 50, 51, 52]
            await asyncio.to_thread(agent.set_transceiver_present, 49, present=False)
            rows = await asyncio.to_thread(_optics_rows, client)
            assert rows == [50, 51, 52]
        finally:
            await agent.stop()

    async def test_poe_layout_and_knobs(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent(profile_key="access_s5735")
        try:
            def _read() -> dict[str, object]:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                states = {}
                walked, _ = client.walk(huawei_oids.COL_POE_STATE)
                states = {int(item.oid.rsplit(".", 1)[1]): int(item.value) for item in walked}  # type: ignore[union-attr]
                total = client.get(huawei_oids.OID_POE_TOTAL_MW)
                budget = client.get(huawei_oids.OID_POE_BUDGET_MW)
                alarm = client.get(huawei_oids.OID_POE_ALARM)
                return {
                    "count": len(states),
                    "state1": states.get(1),
                    "state17": states.get(17),
                    "state18": states.get(18),
                    "total": None if not hasattr(total, "value") else int(total.value),  # type: ignore[union-attr]
                    "budget": None if not hasattr(budget, "value") else int(budget.value),  # type: ignore[union-attr]
                    "alarm": None if not hasattr(alarm, "value") else int(alarm.value),  # type: ignore[union-attr]
                }

            snapshot = await asyncio.to_thread(_read)
            assert snapshot["count"] == 48
            assert snapshot["state1"] == 1 and snapshot["state17"] == 3 and snapshot["state18"] == 4
            assert snapshot["total"] == 80_000 and snapshot["budget"] == 400_000 and snapshot["alarm"] == 1
            await asyncio.to_thread(agent.set_poe_budget_present, False)
            await asyncio.to_thread(agent.set_poe_alarm_state, 3)
            snapshot = await asyncio.to_thread(_read)
            assert snapshot["budget"] is None and snapshot["alarm"] == 3
        finally:
            await agent.stop()

    async def test_layer2_and_stp_knobs(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection

        agent = await _started_agent()
        try:
            await asyncio.to_thread(agent.set_loop_detected, True)
            await asyncio.to_thread(agent.set_storm_detected, True)
            await asyncio.to_thread(agent.set_stp_state, 2, 2)
            await asyncio.to_thread(agent.set_fan_fault, 3, fault=True)

            def _read() -> dict[str, object]:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                loop = client.get(huawei_oids.OID_LOOP_STATUS)
                storm = client.get(huawei_oids.OID_STORM_STATUS)
                stp = {}
                walked, _ = client.walk(huawei_oids.COL_STP_STATE)
                stp = {int(item.oid.rsplit(".", 1)[1]): int(item.value) for item in walked}  # type: ignore[union-attr]
                fan_status = client.get(f"{huawei_oids.COL_ENTITY_STATUS}.3")
                return {
                    "loop": int(loop.value),  # type: ignore[union-attr]
                    "storm": int(storm.value),  # type: ignore[union-attr]
                    "stp2": stp.get(2),
                    "stp1": stp.get(1),
                    "fan_status": int(fan_status.value),  # type: ignore[union-attr]
                }

            snapshot = await asyncio.to_thread(_read)
            assert snapshot["loop"] == 2 and snapshot["storm"] == 2
            assert snapshot["stp2"] == 2 and snapshot["stp1"] == 4
            assert snapshot["fan_status"] == 2
        finally:
            await agent.stop()

    async def test_sys_descr_override_serves_custom_identity(self, isolated_snmp_boots: None) -> None:
        del isolated_snmp_boots
        from app.infrastructure.protocols.snmp.client import SnmpClient, SnmpConnection
        from app.infrastructure.protocols.snmp.values import SnmpValue

        sys_descr = (
            "Huawei Technologies Co., Ltd. S5700-28C-HI simulator, "
            "VRP (R) software, Version V200R003C00"
        )
        agent = await _started_agent(sys_descr_override=sys_descr)
        try:
            def _read() -> str:
                client = SnmpClient(
                    SnmpConnection(
                        host="127.0.0.1",
                        port=agent.port or 0,
                        community="public",
                        version="v2c",
                    )
                )
                raw = client.get(huawei_oids.OID_SYS_DESCR)
                assert isinstance(raw, SnmpValue)
                return str(raw.value)

            text = await asyncio.to_thread(_read)
            assert "S5700-28C-HI" in text and "S5732-H48XUM2CC" not in text
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
