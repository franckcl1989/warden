"""SNMP value normalization: pysnmp ASN.1 values -> typed platform values.

The SNMP client must hand adapters TYPED values (int/str/ip/hex per the ASN.1
type of the varbind) and a typed NOT_PRESENT sentinel for missing leaves
(noSuchInstance/noSuchObject/endOfMibView) — a missing value is NEVER turned
into 0 or an empty string (DEVICE_ADAPTERS.md §2.3, M5T1 brief).

Kinds:

- ``INTEGER``/``UNSIGNED`` — signed/unsigned integers;
- ``COUNTER`` — Counter32/Counter64 (monotonic counters; M5T2 rate math must
  treat these as counters, never as gauges);
- ``TIMETICKS`` — hundredths of a second since the agent booted;
- ``STRING`` — OctetString decoded as text (UTF-8 first, latin-1 fallback);
- ``HEX`` — OctetString carrying non-text binary payload;
- ``IP`` — IpAddress as dotted quad;
- ``OID`` — an ObjectIdentifier value (e.g. trap OIDs) as dotted string.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pyasn1.type import univ
from pysnmp.proto import rfc1155, rfc1902
from pysnmp.smi import exval

from app.infrastructure.protocols.snmp.errors import SnmpError


class SnmpKind(StrEnum):
    INTEGER = "integer"
    UNSIGNED = "unsigned"
    COUNTER = "counter"
    TIMETICKS = "timeticks"
    STRING = "string"
    HEX = "hex"
    IP = "ip"
    OID = "oid"


@dataclass(frozen=True)
class SnmpValue:
    oid: str
    kind: SnmpKind
    value: int | str


#: Typed not-present sentinel (singleton). ``normalize_value`` returns this
#: object for noSuchInstance / noSuchObject / endOfMibView markers; the
#: client aligns returned values by input order and tests with ``is``.
NOT_PRESENT = object()

_MISSING_TYPES = (exval.noSuchInstance.__class__, exval.noSuchObject.__class__, exval.endOfMib.__class__)


def _decode_octet_string(raw: bytes) -> tuple[SnmpKind, str]:
    """One OctetString payload -> STRING (readable text) or HEX (binary).

    UTF-8 is tried first; single-byte vendor encodings fall back to latin-1.
    Payloads that still contain control bytes are binary: they become HEX
    so the bytes stay recoverable and are never misread as text.
    """
    for encoding in ("utf-8", "latin-1"):
        try:
            candidate = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if any(ord(char) < 32 and char not in "\t\r\n" for char in candidate):
            continue
        return SnmpKind.STRING, candidate
    return SnmpKind.HEX, raw.hex()


def normalize_value(oid: str, raw: Any) -> SnmpValue | object:
    """Normalize one varbind value into a typed ``SnmpValue``.

    Missing-value markers (noSuchInstance / noSuchObject / endOfMibView)
    normalize to the ``NOT_PRESENT`` sentinel — never 0. Unrecognized value
    objects raise ``SnmpError(protocol_error)``: guessing a type would hand
    the adapter a fabricated value.
    """
    if isinstance(raw, _MISSING_TYPES):
        return NOT_PRESENT
    if isinstance(raw, (rfc1902.Counter64, rfc1902.Counter32)):
        return SnmpValue(oid=oid, kind=SnmpKind.COUNTER, value=int(raw))
    if isinstance(raw, (rfc1902.TimeTicks, rfc1155.TimeTicks)):
        # rfc1155.TimeTicks is the SMIv1 twin of rfc1902.TimeTicks (identical
        # tag): the trap receiver's RFC 2576 v1->v2 conversion synthesizes
        # sysUpTime.0 with the v1 class (pysnmp keeps the rfc1155 value for
        # the leaves it fabricates), so both normalize as TIMETICKS.
        return SnmpValue(oid=oid, kind=SnmpKind.TIMETICKS, value=int(raw))
    if isinstance(raw, (rfc1902.Integer32, rfc1902.Integer)):
        return SnmpValue(oid=oid, kind=SnmpKind.INTEGER, value=int(raw))
    if isinstance(raw, (rfc1902.Unsigned32, rfc1902.Gauge32)):
        return SnmpValue(oid=oid, kind=SnmpKind.UNSIGNED, value=int(raw))
    if isinstance(raw, (rfc1902.IpAddress, rfc1155.IpAddress)):
        # rfc1155.IpAddress likewise reaches the platform from the v1 trap
        # path (RFC 2576 synthesizes snmpTrapAddress.0 with the v1 class).
        octets = raw.asOctets()
        if not isinstance(octets, bytes):  # pragma: no cover - py3 bytes path
            octets = octets.encode("latin-1")
        try:
            formatted = str(ipaddress.ip_address(octets))
        except ValueError as exc:
            raise SnmpError(
                "protocol_error",
                "snmp IpAddress payload is not a valid address",
                stage="parse",
            ) from exc
        return SnmpValue(oid=oid, kind=SnmpKind.IP, value=formatted)
    if isinstance(raw, (rfc1902.ObjectIdentifier, univ.ObjectIdentifier)):
        return SnmpValue(oid=oid, kind=SnmpKind.OID, value=str(raw))
    if isinstance(raw, rfc1902.OctetString):
        octets = raw.asOctets()
        kind, value = _decode_octet_string(octets if isinstance(octets, bytes) else bytes(octets))
        return SnmpValue(oid=oid, kind=kind, value=value)
    raise SnmpError(
        "protocol_error",
        "unrecognized snmp varbind value type",
        stage="parse",
    )
