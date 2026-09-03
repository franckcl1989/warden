"""SNMP OID registry mechanics + the M5T1 documented seed set.

The adapter's MIB table (M5T2) owns the Huawei OIDs; this module ships the
registry MECHANICS and a small SEED set the simulator serves and M5T2 extends:

- SNMPv2-MIB system group leaves — RFC 3418 (sysDescr/sysName/sysUpTime;
  sysUpTime.0 is timeticks, never converted to seconds by the client);
- IF-MIB interface table columns — RFC 2863 (ifIndex/ifDescr/
  ifAdminStatus/ifOperStatus and the 32-bit octet/error counters).

Every OID carries a ``basis`` tag (a document reference); OIDs without a
citable source are NEVER added here (M5T1 brief: never guessed OIDs —
[huawei-doc-url] or [sim] are the only admissible bases, and the seed set
is entirely RFC-standard).

``OidRegistry`` maps dotted OIDs to definitions:

- ``lookup(oid)`` returns the exact leaf definition, or — for a column
  prefix registered as a table column — the column definition plus the
  instance arc (the row index). Unregistered OIDs return None.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.infrastructure.protocols.snmp.values import SnmpKind

# --- basis tags -------------------------------------------------------------
RFC_1213 = "[rfc-1213]"  # RFC 1213 MIB-II (the system group's origin)
RFC_2863 = "[rfc-2863]"  # RFC 2863 IF-MIB
RFC_3418 = "[rfc-3418]"  # RFC 3418 SNMPv2-MIB

# --- seed set ---------------------------------------------------------------
# Standard MIB objects only — the basis tag is the citable RFC, and the
# simulator serves exactly this tree (tests/simulators/switch).
SEED_SYSTEM: tuple[dict[str, object], ...] = (
    {
        "oid": "1.3.6.1.2.1.1.1.0",
        "label": "sysDescr",
        "kind": "string",
        "basis": RFC_3418,
    },
    {
        "oid": "1.3.6.1.2.1.1.2.0",
        "label": "sysObjectID",
        "kind": "oid",
        "basis": RFC_3418,
    },
    {
        "oid": "1.3.6.1.2.1.1.3.0",
        "label": "sysUpTime",
        "kind": "timeticks",
        "basis": RFC_3418,
    },
    {
        "oid": "1.3.6.1.2.1.1.5.0",
        "label": "sysName",
        "kind": "string",
        "basis": RFC_3418,
    },
    {
        "oid": "1.3.6.1.2.1.2.1.0",
        "label": "ifNumber",
        "kind": "integer",
        "basis": RFC_2863,
    },
)

# IF-MIB ifTable columns (RFC 2863). Instances are appended by the walk
# (ifIndex rows); M5T2 will extend this table with the Huawei trees.
_IFTABLE_COLUMN_ROWS: tuple[dict[str, object], ...] = (
    {"oid": "1.3.6.1.2.1.2.2.1.1", "label": "ifIndex", "kind": "integer", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.2", "label": "ifDescr", "kind": "string", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.3", "label": "ifType", "kind": "integer", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.7", "label": "ifAdminStatus", "kind": "integer", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.8", "label": "ifOperStatus", "kind": "integer", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.10", "label": "ifInOctets", "kind": "counter", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.14", "label": "ifInErrors", "kind": "counter", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.16", "label": "ifOutOctets", "kind": "counter", "basis": RFC_2863},
    {"oid": "1.3.6.1.2.1.2.2.1.20", "label": "ifOutErrors", "kind": "counter", "basis": RFC_2863},
)
SEED_IFTABLE_COLUMNS: tuple[dict[str, object], ...] = tuple(
    {**row, "is_column": True} for row in _IFTABLE_COLUMN_ROWS
)


@dataclass(frozen=True)
class OidDef:
    """One registered OID definition (basis tag mandatory)."""

    oid: str
    label: str
    kind: SnmpKind
    basis: str
    is_column: bool = False

    def __post_init__(self) -> None:
        if not self.basis.startswith("["):
            msg = f"OID {self.oid} ({self.label}) lacks a [basis] tag"
            raise ValueError(msg)
        if self.is_column and self.oid.endswith(".0"):
            msg = f"column OID {self.oid} must not end in .0 (scalar shape)"
            raise ValueError(msg)


@dataclass(frozen=True)
class ResolvedOid:
    """A matched definition and — for column matches — the row instance arc."""

    definition: OidDef
    instance: tuple[int, ...] | None = None

    @property
    def instance_dotted(self) -> str | None:
        return ".".join(str(part) for part in self.instance) if self.instance else None


def parse_oid(oid: str) -> tuple[int, ...]:
    """Dotted string -> integer tuple; malformed input raises ValueError."""
    parts = oid.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        msg = f"malformed OID {oid!r}"
        raise ValueError(msg)
    return tuple(int(part) for part in parts)


class OidRegistry:
    """Exact-leaf + table-column registry with longest-prefix resolution."""

    def __init__(self, definitions: tuple[dict[str, object], ...] = ()) -> None:
        self._leaves: dict[tuple[int, ...], OidDef] = {}
        self._columns: dict[tuple[int, ...], OidDef] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: dict[str, object]) -> None:
        kind = SnmpKind(str(definition["kind"]))
        is_column = bool(definition.get("is_column", False))
        parsed = parse_oid(str(definition["oid"]))
        oid_def = OidDef(
            oid=str(definition["oid"]),
            label=str(definition["label"]),
            kind=kind,
            basis=str(definition["basis"]),
            is_column=is_column,
        )
        target = self._columns if is_column else self._leaves
        if parsed in target:
            msg = f"duplicate OID registration {definition['oid']!r}"
            raise ValueError(msg)
        target[parsed] = oid_def

    def lookup(self, oid: str) -> ResolvedOid | None:
        parsed = parse_oid(oid)
        leaf = self._leaves.get(parsed)
        if leaf is not None:
            return ResolvedOid(definition=leaf)
        for width in range(len(parsed) - 1, 0, -1):
            column = self._columns.get(parsed[:width])
            if column is not None:
                return ResolvedOid(definition=column, instance=parsed[width:])
        return None

    def resolve_walk_start(self, prefix: str) -> tuple[str, ...]:
        """Sorted leaf/column OIDs at or below ``prefix`` (walk planning)."""
        parsed = parse_oid(prefix)
        matches: list[str] = []
        for target in (self._leaves, self._columns):
            for oid_tuple in target:
                if len(oid_tuple) >= len(parsed) and oid_tuple[: len(parsed)] == parsed:
                    matches.append(".".join(str(part) for part in oid_tuple))
        return tuple(sorted(matches))
