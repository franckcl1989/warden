"""SNMP typed-value normalization unit tests.

The client must return typed values (int/str/ip per ASN.1 type) and a typed
not-present sentinel for noSuchInstance/noSuchObject — NEVER a fabricated 0
(DEVICE_ADAPTERS.md §2.3, M5T1 brief: typed sentinel not-present).
"""

from __future__ import annotations

import pytest
from app.infrastructure.protocols.snmp.errors import SnmpError
from app.infrastructure.protocols.snmp.values import (
    NOT_PRESENT,
    SnmpKind,
    SnmpValue,
    normalize_value,
)
from pysnmp.proto import rfc1155, rfc1902
from pysnmp.smi import exval

MODULE = "app.infrastructure.protocols.snmp.values"


def test_integer_kind_and_value() -> None:
    value = normalize_value("1.3.6.1.2.1.2.1.0", rfc1902.Integer32(48))
    assert value.oid == "1.3.6.1.2.1.2.1.0"
    assert value.kind is SnmpKind.INTEGER
    assert value.value == 48


@pytest.mark.parametrize(
    ("cls", "payload", "kind"),
    [
        (rfc1902.Counter32, 42, SnmpKind.COUNTER),
        (rfc1902.Counter64, 2**40, SnmpKind.COUNTER),
        (rfc1902.Unsigned32, 7, SnmpKind.UNSIGNED),
        (rfc1902.TimeTicks, 123456, SnmpKind.TIMETICKS),
        (rfc1902.Gauge32, 9, SnmpKind.UNSIGNED),
    ],
)
def test_numeric_kinds(cls: type, payload: int, kind: SnmpKind) -> None:
    value = normalize_value("1.3.6.1.2.1.1.3.0", cls(payload))
    assert value.kind is kind
    assert value.value == payload


def test_text_octet_string_decodes_utf8() -> None:
    value = normalize_value("1.3.6.1.2.1.1.1.0", rfc1902.OctetString("S5732 模拟".encode()))
    assert value.kind is SnmpKind.STRING
    assert value.value == "S5732 模拟"


def test_octet_string_falls_back_to_latin1_on_invalid_utf8() -> None:
    raw = "port\xe9".encode("latin-1")  # not valid utf-8
    value = normalize_value("1.3.6.1.2.1.2.2.1.2.1", rfc1902.OctetString(raw))
    assert value.kind is SnmpKind.STRING
    assert value.value == "port\u00e9"


def test_binary_octet_string_becomes_hex() -> None:
    value = normalize_value("1.3.6.1.2.1.99.1.1.0", rfc1902.OctetString(b"\x00\x0c\x29\xab"))
    assert value.kind is SnmpKind.HEX
    assert value.value == "000c29ab"


def test_ip_address_becomes_dotted_string() -> None:
    value = normalize_value("1.3.6.1.2.1.4.20.1.1.1", rfc1902.IpAddress("192.0.2.1"))
    assert value.kind is SnmpKind.IP
    assert value.value == "192.0.2.1"


@pytest.mark.parametrize(
    ("cls", "payload", "kind", "expected"),
    [
        (rfc1155.TimeTicks, 123456, SnmpKind.TIMETICKS, 123456),
        (rfc1155.IpAddress, "192.0.2.9", SnmpKind.IP, "192.0.2.9"),
    ],
)
def test_smi_v1_trap_artifacts_normalize_like_their_smi_v2_twins(
    cls: type, payload: int | str, kind: SnmpKind, expected: int | str
) -> None:
    # RFC 2576 v1->v2 trap conversion keeps the rfc1155 value class for the
    # leaves pysnmp synthesizes (sysUpTime.0, snmpTrapAddress.0): they must
    # normalize to the same kinds as their rfc1902 twins, never raise.
    value = normalize_value("1.3.6.1.2.1.1.3.0", cls(payload))
    assert value.kind is kind
    assert value.value == expected


def test_oid_value_becomes_dotted_string() -> None:
    value = normalize_value("1.3.6.1.6.3.1.1.4.1.0", rfc1902.ObjectIdentifier("1.3.6.1.6.3.1.1.5.3"))
    assert value.kind is SnmpKind.OID
    assert value.value == "1.3.6.1.6.3.1.1.5.3"


def test_no_such_instance_is_typed_not_present() -> None:
    value = normalize_value("1.3.6.1.2.1.2.1.0", exval.noSuchInstance)
    assert value is NOT_PRESENT


def test_no_such_object_is_typed_not_present() -> None:
    value = normalize_value("1.3.6.1.2.1.2.1.0", exval.noSuchObject)
    assert value is NOT_PRESENT


def test_end_of_mib_is_typed_not_present() -> None:
    value = normalize_value("1.3.6.1.2.1.2.1.0", exval.endOfMib)
    assert value is NOT_PRESENT


def test_unknown_value_type_raises_protocol_error() -> None:
    with pytest.raises(SnmpError) as raised:
        normalize_value("1.3.6.1.2.1.2.1.0", object())  # type: ignore[arg-type]
    assert raised.value.code == "protocol_error"


def test_not_present_sentinel_is_a_singleton() -> None:
    assert normalize_value("1.3.6.1.9.9.1.0", exval.noSuchInstance) is NOT_PRESENT


def test_snmp_value_repr_carries_no_secret_material() -> None:
    value = SnmpValue(oid="1.3.6.1.2.1.1.1.0", kind=SnmpKind.STRING, value="secret-ish text")
    assert "secret-ish text" in repr(value)
