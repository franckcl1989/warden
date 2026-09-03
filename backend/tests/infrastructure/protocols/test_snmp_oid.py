"""SNMP OID registry unit tests (M5T1 mechanics + seed set integrity)."""

from __future__ import annotations

import pytest
from app.infrastructure.protocols.snmp.oid import (
    RFC_2863,
    RFC_3418,
    OidDef,
    OidRegistry,
    parse_oid,
)
from app.infrastructure.protocols.snmp.values import SnmpKind


def _seed_registry() -> OidRegistry:
    from app.infrastructure.protocols.snmp.oid import SEED_IFTABLE_COLUMNS, SEED_SYSTEM

    registry = OidRegistry(SEED_SYSTEM + SEED_IFTABLE_COLUMNS)
    return registry


def test_parse_oid_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_oid("1.3.6.1.2.not-an-oid.1")
    with pytest.raises(ValueError):
        parse_oid("")


def test_exact_leaf_lookup() -> None:
    resolved = _seed_registry().lookup("1.3.6.1.2.1.1.1.0")
    assert resolved is not None
    assert resolved.definition.label == "sysDescr"
    assert resolved.definition.kind is SnmpKind.STRING
    assert resolved.definition.basis == RFC_3418
    assert resolved.instance is None


def test_table_column_resolves_instance_arc() -> None:
    resolved = _seed_registry().lookup("1.3.6.1.2.1.2.2.1.10.3")
    assert resolved is not None
    assert resolved.definition.label == "ifInOctets"
    assert resolved.definition.kind is SnmpKind.COUNTER
    assert resolved.definition.basis == RFC_2863
    assert resolved.definition.is_column is True
    assert resolved.instance == (3,)
    assert resolved.instance_dotted == "3"


def test_multiple_instance_arc_kept_whole() -> None:
    resolved = _seed_registry().lookup("1.3.6.1.2.1.2.2.1.2.1.27")
    assert resolved is not None
    assert resolved.instance == (1, 27)
    assert resolved.instance_dotted == "1.27"


def test_unknown_oid_is_none() -> None:
    assert _seed_registry().lookup("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.1") is None
    assert _seed_registry().lookup("1.3.6.1.2.1.99.1") is None


def test_scalar_without_zero_suffix_does_not_match_leaf() -> None:
    # sysDescr is registered at ...1.1.0; ...1.1 (the column of the scalar) is
    # not itself servable.
    assert _seed_registry().lookup("1.3.6.1.2.1.1.1") is None


def test_duplicate_registration_rejected() -> None:
    registry = OidRegistry()
    registry.register({"oid": "1.3.6.1.2.1.1.1.0", "label": "sysDescr", "kind": "string", "basis": RFC_3418})
    with pytest.raises(ValueError):
        registry.register({"oid": "1.3.6.1.2.1.1.1.0", "label": "dup", "kind": "string", "basis": RFC_3418})


def test_definition_requires_basis_tag() -> None:
    with pytest.raises(ValueError):
        OidDef(oid="1.3.6.1.2.1.1.1.0", label="sysDescr", kind=SnmpKind.STRING, basis="guessed")


def test_every_seed_has_rfc_basis_and_valid_kind() -> None:
    from app.infrastructure.protocols.snmp.oid import SEED_IFTABLE_COLUMNS, SEED_SYSTEM

    for definition in SEED_SYSTEM + SEED_IFTABLE_COLUMNS:
        SnmpKind(str(definition["kind"]))  # invalid kind raises
        assert str(definition["basis"]).startswith("[rfc-")
        parse_oid(str(definition["oid"]))
        OidDef(
            oid=str(definition["oid"]),
            label=str(definition["label"]),
            kind=SnmpKind(str(definition["kind"])),
            basis=str(definition["basis"]),
            is_column=bool(definition.get("is_column", False)),
        )


def test_walk_start_returns_registered_roots_in_order() -> None:
    roots = _seed_registry().resolve_walk_start("1.3.6.1.2.1.1")
    assert "1.3.6.1.2.1.1.1.0" in roots
    assert "1.3.6.1.2.1.1.5.0" in roots
    columns = _seed_registry().resolve_walk_start("1.3.6.1.2.1.2.2.1")
    assert columns[0] == "1.3.6.1.2.1.2.2.1.1"
    assert "1.3.6.1.2.1.2.2.1.20" in columns
