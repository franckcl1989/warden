"""Parsed trap / syslog message types shared by the ingest receivers (M5T1).

The receivers are transport layers: syslog parsing lives in
``syslog_parse.py``, traps are decoded by the pysnmp-engine receiver into
``ParsedTrap``, and ``app.infrastructure.ingest.dispatcher`` classifies both
into platform events. All three modules share this small type module.

``ParsedTrap.value`` keeps the pysnmp ASN.1 object so classification can read
typed values (integers for ifIndex/sysUpTime, OIDs as dotted strings) without
a lossy string round trip.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any

from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage

__all__ = ["ParsedSyslogMessage", "ParsedTrap", "TrapVarBind"]

SNMPV1 = "snmpv1"
SNMPV2C = "snmpv2c"
SNMPV3 = "snmpv3"


@dataclass(frozen=True)
class TrapVarBind:
    """One decoded trap varbind (name dotted; value stays ASN.1-typed)."""

    name: str
    value: Any


@dataclass(frozen=True)
class ParsedTrap:
    """One decoded SNMP trap, ready for classification.

    ``security_model``: 1=v1, 2=v2c, 3=v3 (RFC 3411). ``security_name`` is
    the USM user for v3 and the community for v1/v2c. The community is never
    stored into events; it is only used for receiver-side matching and audit
    markers (SECURITY.md §6/§10).
    """

    received_at: datetime.datetime
    message_processing_model: int
    security_model: int
    security_name: str
    security_level: int
    community: str | None
    varbinds: tuple[TrapVarBind, ...]

    def varbind(self, name: str) -> TrapVarBind | None:
        for var_bind in self.varbinds:
            if var_bind.name == name:
                return var_bind
        return None

    def varbinds_under(self, prefix: str) -> tuple[TrapVarBind, ...]:
        return tuple(
            var_bind
            for var_bind in self.varbinds
            if var_bind.name == prefix or var_bind.name.startswith(prefix + ".")
        )
