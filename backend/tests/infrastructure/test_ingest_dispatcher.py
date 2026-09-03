"""Syslog/trap -> platform event classification tests (M5T1).

Mapping tables carry [basis] tags ([rfc-3418]/[rfc-2863]/[sim]); classification
never invents an event: unmatched messages become DropReasons and are counted
by the receiver, never stored.
"""

from __future__ import annotations

import datetime

from app.infrastructure.ingest.dispatcher import (
    ClassifiedEvent,
    DropReason,
    classify_syslog,
    classify_trap,
)
from app.infrastructure.ingest.syslog_parse import parse_syslog_line
from app.infrastructure.ingest.trap_types import ParsedTrap, TrapVarBind

UTC = datetime.UTC

PORT_FLAP = "event.port_flap"
DEVICE_RESTART = "event.device_restart"
AUTH_FAILURE = "event.auth_failure"


def _syslog(raw: str):
    parsed = parse_syslog_line(raw)
    assert parsed is not None
    return parsed


def test_port_down_syslog_is_port_flap_with_component() -> None:
    event = classify_syslog(
        _syslog("<190>Aug  4 2026 14:22:01 s5732-1 %%01IFNET/4/LINK_STATE(l): "
                "GigabitEthernet0/0/1: The protocol state of the link turned from UP to DOWN.")
    )
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == PORT_FLAP
    assert event.component_native_id == "GigabitEthernet0/0/1"
    assert event.severity == "warning"
    assert event.source == "syslog"
    assert event.occurred_at == datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC)
    assert event.detail["direction"] == "down"
    assert event.basis.startswith("[sim]")
    assert event.native_event_id is not None
    assert event.native_event_id.startswith("syslog|")


def test_port_up_syslog_is_info() -> None:
    event = classify_syslog(
        _syslog("<190>Aug  4 2026 14:22:05 s5732-1 %%01IFNET/4/LINK_STATE(l): "
                "GigabitEthernet0/0/1: The protocol state of the link turned from DOWN to UP.")
    )
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == PORT_FLAP
    assert event.severity == "info"
    assert event.detail["direction"] == "up"


def test_auth_failure_syslog_keywords() -> None:
    for line in (
        "<190>Aug  4 2026 14:23:00 sw %%01SECE/4/AUTH_FAIL(l): Authentication failed for user",
        "<190>Aug  4 2026 14:23:01 sw %%01SECE/4/AUTH_FAIL(l): login failure on VTY0",
        "<190>Aug  4 2026 14:23:02 sw %%01SECE/4/AUTH_FAIL(l): failed login attempt",
    ):
        event = classify_syslog(_syslog(line))
        assert isinstance(event, ClassifiedEvent)
        assert event.event_type == AUTH_FAILURE
        assert event.severity == "warning"
        assert event.component_native_id is None


def test_device_restart_syslog() -> None:
    event = classify_syslog(
        _syslog("<190>Aug  4 2026 14:22:01 sw %%01SHELL/5/CMD(l): System restarted")
    )
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == DEVICE_RESTART
    assert event.severity == "critical"


def test_unknown_syslog_message_is_drop_reason() -> None:
    result = classify_syslog(
        _syslog("<190>Aug  4 2026 14:25:00 sw %%01SHELL/5/CMD(l): user executed display this")
    )
    assert isinstance(result, DropReason)
    assert result.reason == "unclassifiable"


def test_flap_without_interface_is_drop_reason() -> None:
    result = classify_syslog(
        _syslog("<190>Aug  4 2026 14:25:00 sw %%01IFNET/4/LINK_STATE(l): "
                "The protocol state of the link turned from UP to DOWN.")
    )
    assert isinstance(result, DropReason)
    assert result.reason == "missing_component"


def test_empty_message_is_drop_reason() -> None:
    result = classify_syslog(_syslog("<14>"))
    assert isinstance(result, DropReason)
    assert result.reason == "empty_message"


# --- traps ------------------------------------------------------------------

def _trap(trap_oid: str, varbinds: list[tuple[str, object]]) -> ParsedTrap:
    return ParsedTrap(
        received_at=datetime.datetime(2026, 8, 4, 14, 30, 0, tzinfo=UTC),
        message_processing_model=1,
        security_model=2,
        security_name="public",
        security_level=1,
        community="public",
        varbinds=[TrapVarBind(name=name, value=value) for name, value in varbinds],
    )


def test_link_down_trap_is_port_flap_down() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.3",
        [
            ("1.3.6.1.2.1.1.3.0", 1400),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.3"),
            ("1.3.6.1.2.1.2.2.1.1.24", 24),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == PORT_FLAP
    assert event.component_native_id == "24"
    assert event.severity == "warning"
    assert event.source == "snmp_trap"
    assert event.detail["direction"] == "down"
    assert event.basis.startswith("[rfc-")
    assert event.detail["trap_oid"] == "1.3.6.1.6.3.1.1.5.3"
    assert event.native_event_id is not None
    assert event.native_event_id.startswith("trap|")
    assert "24" in event.native_event_id


def test_link_up_trap_is_port_flap_up_info() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.4",
        [
            ("1.3.6.1.2.1.1.3.0", 1500),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.4"),
            ("1.3.6.1.2.1.2.2.1.1.7", 7),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == PORT_FLAP
    assert event.component_native_id == "7"
    assert event.severity == "info"
    assert event.detail["direction"] == "up"


def test_cold_start_trap_is_device_restart() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.1",
        [
            ("1.3.6.1.2.1.1.3.0", 10),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.1"),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == DEVICE_RESTART
    assert event.severity == "critical"


def test_warm_start_trap_is_device_restart_warning() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.2",
        [
            ("1.3.6.1.2.1.1.3.0", 11),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.2"),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == DEVICE_RESTART
    assert event.severity == "warning"


def test_authentication_failure_trap() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.5",
        [
            ("1.3.6.1.2.1.1.3.0", 12),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.5"),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert event.event_type == AUTH_FAILURE
    assert event.severity == "warning"


def test_unknown_trap_oid_is_drop_reason() -> None:
    trap = _trap(
        "1.3.6.1.4.1.2011.5.25.99.1",
        [("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.4.1.2011.5.25.99.1")],
    )
    result = classify_trap(trap)
    assert isinstance(result, DropReason)
    assert result.reason == "unclassifiable"


def test_link_down_without_ifindex_is_drop_reason() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.3",
        [("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.3")],
    )
    result = classify_trap(trap)
    assert isinstance(result, DropReason)
    assert result.reason == "missing_component"


def test_trap_missing_trap_oid_varbind_is_drop_reason() -> None:
    trap = _trap("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.1.3.0", 1)])
    result = classify_trap(trap)
    assert isinstance(result, DropReason)
    assert result.reason == "unclassifiable"


def test_classified_event_messages_are_normalized() -> None:
    trap = _trap(
        "1.3.6.1.6.3.1.1.5.3",
        [
            ("1.3.6.1.2.1.1.3.0", 1400),
            ("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.6.3.1.1.5.3"),
            ("1.3.6.1.2.1.2.2.1.1.24", 24),
        ],
    )
    event = classify_trap(trap)
    assert isinstance(event, ClassifiedEvent)
    assert isinstance(event.message, str)
    assert "secret" not in event.message
    syslog_event = classify_syslog(
        _syslog("<190>Aug  4 2026 14:22:01 sw tag: GigabitEthernet0/0/2 changed state to down")
    )
    assert isinstance(syslog_event, ClassifiedEvent)
    assert "GigabitEthernet0/0/2" in syslog_event.message
