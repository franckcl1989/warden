"""Syslog/trap -> platform event classification (M5T1 event-ingest).

Classifies parsed syslog lines and parsed traps into the contracts/events.json
types the platform can store (event.port_flap / event.device_restart /
event.auth_failure). Everything that does NOT map cleanly becomes a
``DropReason`` — the receiver counts it and never stores a fabricated event
(M5T1 brief: unknown messages counted + dropped, NOT stored as fake events).

Every mapping row carries its [basis] tag:

- trap OIDs 1.3.6.1.6.3.1.1.5.x are SNMPv2-MIB/IF-MIB standard notifications
  ([rfc-3418] coldStart/warmStart/authenticationFailure, [rfc-2863]
  linkDown/linkUp; the v1 generic-trap conversion follows [rfc-1157]);
- syslog text patterns are [sim] — the fixture-DSL wording of the switch
  simulator. Real VRP log wording must be archived from the target model's
  event catalog during M5 hardware certification before any [huawei-doc-url]
  claim replaces a [sim] row (ADR-018; no guessed vendor patterns).

Severity is decided per mapping row (documented above the tables), NOT
guessed from the message: the platform needs a stable normalized severity for
each event type.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field

from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage
from app.infrastructure.ingest.trap_types import ParsedTrap, TrapVarBind
from app.infrastructure.protocols.snmp.values import SnmpKind, SnmpValue, normalize_value

PORT_FLAP = "event.port_flap"
DEVICE_RESTART = "event.device_restart"
AUTH_FAILURE = "event.auth_failure"

TRAP_OID_VARBIND = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UP_TIME_VARBIND = "1.3.6.1.2.1.1.3.0"
IF_INDEX_COLUMN = "1.3.6.1.2.1.2.2.1.1"

INTERFACE_RE = re.compile(
    r"(?:GigabitEthernet|XGigabitEthernet|Eth-Trunk|GE|10GE|25GE|100GE)\d+(?:/\d+){1,3}"
)

# --- syslog mapping tables (all [sim]: fixture DSL wording) ------------------
# Each row: (event_type, severity, [match regexes on the message text]).
# Port-flap rows additionally require an interface token in the message.
_SYSLOG_DOWN_KEYWORDS = (
    "turned from UP to DOWN",
    "changed state to down",
    "link state is DOWN",
)
_SYSLOG_UP_KEYWORDS = (
    "turned from DOWN to UP",
    "changed state to up",
    "link state is UP",
)
_SYSLOG_RESTART_KEYWORDS = ("system restarted", "system rebooted", "system reboot")
_SYSLOG_AUTH_KEYWORDS = (
    "authentication failed",
    "login failed",
    "login failure",
    "failed login",
)


@dataclass(frozen=True)
class ClassifiedEvent:
    """One syslog/trap message mapped onto a platform event (pre-attribution)."""

    event_type: str
    severity: str  # normalized: unknown/info/warning/critical
    message: str
    source: str  # syslog | snmp_trap
    occurred_at: datetime.datetime | None
    component_native_id: str | None
    native_event_id: str | None
    basis: str
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DropReason:
    """Why a parsed message was NOT stored (counted by the receiver)."""

    reason: str  # unparseable | empty_message | unclassifiable | missing_component


def _syslog_occurrence_id(parsed: ParsedSyslogMessage) -> str | None:
    """Occurrence id for syslog: device timestamp + content digest.

    A retransmitted identical datagram (same device timestamp + content)
    dedupes; a genuinely new occurrence (new timestamp or new content) is a
    new row. Without a device timestamp the event gets no native id and the
    platform's content-hash dedupe applies (M2T2 store semantics).
    """
    if parsed.timestamp is None:
        return None
    digest_source = f"{parsed.tag or ''}|{parsed.message}"
    digest = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:12]
    return f"syslog|{parsed.timestamp.isoformat()}|{digest}"


def classify_syslog(parsed: ParsedSyslogMessage) -> ClassifiedEvent | DropReason:
    """Map one parsed syslog line to a platform event or a drop reason."""
    if not parsed.message:
        return DropReason(reason="empty_message")
    text = parsed.message
    interface = INTERFACE_RE.search(text)
    lowered = text.lower()

    def match_any(keywords: tuple[str, ...]) -> bool:
        return any(keyword.lower() in lowered for keyword in keywords)

    if match_any(_SYSLOG_DOWN_KEYWORDS):
        if interface is None:
            return DropReason(reason="missing_component")
        return _flap(parsed, interface.group(0), "down", "warning")
    if match_any(_SYSLOG_UP_KEYWORDS):
        if interface is None:
            return DropReason(reason="missing_component")
        return _flap(parsed, interface.group(0), "up", "info")
    if match_any(_SYSLOG_RESTART_KEYWORDS):
        return ClassifiedEvent(
            event_type=DEVICE_RESTART,
            severity="critical",
            message="device restart reported by syslog",
            source="syslog",
            occurred_at=parsed.timestamp,
            component_native_id=None,
            native_event_id=_syslog_occurrence_id(parsed),
            basis="[sim] system restart syslog wording (fixture DSL)",
        )
    if match_any(_SYSLOG_AUTH_KEYWORDS):
        return ClassifiedEvent(
            event_type=AUTH_FAILURE,
            severity="warning",
            message="device login authentication failed",
            source="syslog",
            occurred_at=parsed.timestamp,
            component_native_id=None,
            native_event_id=_syslog_occurrence_id(parsed),
            basis="[sim] authentication-failure syslog wording (fixture DSL)",
        )
    return DropReason(reason="unclassifiable")


def _flap(
    parsed: ParsedSyslogMessage,
    interface: str,
    direction: str,
    severity: str,
) -> ClassifiedEvent:
    message = f"interface {interface} link {direction}"
    return ClassifiedEvent(
        event_type=PORT_FLAP,
        severity=severity,
        message=message,
        source="syslog",
        occurred_at=parsed.timestamp,
        component_native_id=interface,
        native_event_id=_syslog_occurrence_id(parsed),
        basis="[sim] VRP LINK_STATE-style flap wording (fixture DSL)",
        detail={"direction": direction},
    )


# --- trap mapping table ------------------------------------------------------
# Standard notification OIDs: SNMPv2-MIB RFC 3418 (coldStart/warmStart/
# authenticationFailure) and IF-MIB RFC 2863 (linkDown/linkUp); v1 generic
# traps convert onto the same OIDs per RFC 2576/1157 before classification.
_TRAP_OID_ROWS: dict[str, tuple[str, str, str]] = {
    # trap OID -> (event_type, severity, direction-or-None label)
    "1.3.6.1.6.3.1.1.5.1": (DEVICE_RESTART, "critical", "coldStart"),
    "1.3.6.1.6.3.1.1.5.2": (DEVICE_RESTART, "warning", "warmStart"),
    "1.3.6.1.6.3.1.1.5.3": (PORT_FLAP, "warning", "linkDown"),
    "1.3.6.1.6.3.1.1.5.4": (PORT_FLAP, "info", "linkUp"),
    "1.3.6.1.6.3.1.1.5.5": (AUTH_FAILURE, "warning", "authenticationFailure"),
}
_TRAP_OID_BASES: dict[str, str] = {
    "1.3.6.1.6.3.1.1.5.1": "[rfc-3418] coldStart",
    "1.3.6.1.6.3.1.1.5.2": "[rfc-3418] warmStart",
    "1.3.6.1.6.3.1.1.5.3": "[rfc-2863] linkDown",
    "1.3.6.1.6.3.1.1.5.4": "[rfc-2863] linkUp",
    "1.3.6.1.6.3.1.1.5.5": "[rfc-3418] authenticationFailure",
}


def _varbind_value(var_bind: TrapVarBind) -> int | str | None:
    """Typed python value of one varbind.

    Accepts python natives (unit tests / synthetic traps) and pysnmp ASN.1
    value objects (the wire receiver). Missing-value markers normalize to
    None — never 0.
    """
    raw = var_bind.value
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        return raw
    normalized = normalize_value(var_bind.name, raw)
    if not isinstance(normalized, SnmpValue):
        return None
    if normalized.kind in (SnmpKind.INTEGER, SnmpKind.UNSIGNED, SnmpKind.COUNTER, SnmpKind.TIMETICKS):
        return int(normalized.value)
    if normalized.kind in (SnmpKind.STRING, SnmpKind.IP, SnmpKind.HEX, SnmpKind.OID):
        return str(normalized.value)
    return None


def _trap_occurrence_id(trap_oid: str, if_index: int | None, sys_up_time: int | None) -> str:
    """Occurrence id for traps: trap OID + row + the agent's sysUpTime.

    A retransmitted trap (identical payload including sysUpTime) dedupes; a
    distinct flap has a different sysUpTime and becomes a new row.
    """
    if_index_part = if_index if if_index is not None else "-"
    uptime_part = sys_up_time if sys_up_time is not None else "-"
    return f"trap|{trap_oid}|{if_index_part}|{uptime_part}"


def classify_trap(parsed: ParsedTrap) -> ClassifiedEvent | DropReason:
    """Map one decoded trap to a platform event or a drop reason."""
    trap_oid_varbind = parsed.varbind(TRAP_OID_VARBIND)
    if trap_oid_varbind is None:
        return DropReason(reason="unclassifiable")
    trap_oid = _varbind_value(trap_oid_varbind)
    if not isinstance(trap_oid, str):
        return DropReason(reason="unclassifiable")
    row = _TRAP_OID_ROWS.get(trap_oid)
    if row is None:
        return DropReason(reason="unclassifiable")
    event_type, severity, label = row

    sys_up_time_varbind = parsed.varbind(SYS_UP_TIME_VARBIND)
    sys_up_time = _varbind_value(sys_up_time_varbind) if sys_up_time_varbind is not None else None
    uptime = int(sys_up_time) if isinstance(sys_up_time, int) else None

    if event_type == PORT_FLAP:
        if_index = None
        for var_bind in parsed.varbinds_under(IF_INDEX_COLUMN):
            value = _varbind_value(var_bind)
            if isinstance(value, int):
                if_index = value
                break
        if if_index is None:
            return DropReason(reason="missing_component")
        direction = "down" if label == "linkDown" else "up"
        return ClassifiedEvent(
            event_type=PORT_FLAP,
            severity=severity,
            message=f"ifIndex {if_index}: link {direction} ({label} trap)",
            source="snmp_trap",
            occurred_at=None,
            component_native_id=str(if_index),
            native_event_id=_trap_occurrence_id(trap_oid, if_index, uptime),
            basis=_TRAP_OID_BASES[trap_oid],
            detail={"direction": direction, "trap_oid": trap_oid},
        )
    return ClassifiedEvent(
        event_type=event_type,
        severity=severity,
        message=f"{label} trap received",
        source="snmp_trap",
        occurred_at=None,
        component_native_id=None,
        native_event_id=_trap_occurrence_id(trap_oid, None, uptime),
        basis=_TRAP_OID_BASES[trap_oid],
        detail={"trap_oid": trap_oid},
    )
