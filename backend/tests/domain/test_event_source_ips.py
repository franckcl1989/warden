"""event_source_ips strict schema validation tests (RISK R-14, M5T1).

Every event-capable adapter declares the same strict item pattern
(domain/adapter.py); the ingest layer re-parses values defensively with
``ipaddress``. The pattern must accept exactly what ``ipaddress`` accepts and
reject hostnames/whitespace/garbage.
"""

from __future__ import annotations

import ipaddress
import re

import pytest
from app.domain.adapter import (
    EVENT_SOURCE_IPS_CONFIG_KEY,
    EVENT_SOURCE_IPS_ITEM_PATTERN,
    EVENT_SOURCE_IPS_SCHEMA,
    validate_json_schema,
)

_PATTERN = re.compile(EVENT_SOURCE_IPS_ITEM_PATTERN)

_ACCEPT = (
    "192.168.1.10",
    "10.0.0.0/8",
    "192.168.10.50/32",
    "2001:db8::1",
    "::1",
    "fe80::/10",
    "2001:db8:85a3:0:0:8a2e:370:7334",
    "0.0.0.0/0",
)

_REJECT = (
    "switch-1.internal",
    "192.168.1.999",
    "10.0.0.0/33",
    " 192.168.1.1",
    "192.168.1.1 ",
    "192.168.1.1/24/24",
    "2001:db8::1/129",
    "1.2.3.4:5678",
    "",
    "not-an-ip",
)


@pytest.mark.parametrize("raw", _ACCEPT)
def test_pattern_accepts_valid_ip_or_cidr(raw: str) -> None:
    assert _PATTERN.fullmatch(raw) is not None
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        ipaddress.ip_network(raw, strict=False)


@pytest.mark.parametrize("raw", _REJECT)
def test_pattern_rejects_invalid_entries(raw: str) -> None:
    assert _PATTERN.fullmatch(raw) is None


def test_dsm_connection_schema_validates_event_source_ips() -> None:
    from app.adapters.dsm import SynologyDsmAdapter

    schema = SynologyDsmAdapter.connection_schema
    assert validate_json_schema(
        {EVENT_SOURCE_IPS_CONFIG_KEY: ["192.168.1.10", "10.0.0.0/8", "2001:db8::1"]}, schema
    ) == []
    errors = validate_json_schema(
        {EVENT_SOURCE_IPS_CONFIG_KEY: ["192.168.1.999"]}, schema
    )
    assert len(errors) == 1
    errors = validate_json_schema(
        {EVENT_SOURCE_IPS_CONFIG_KEY: ["switch-1.internal"]}, schema
    )
    assert len(errors) == 1


def test_schema_fragment_is_the_strict_array() -> None:
    assert EVENT_SOURCE_IPS_SCHEMA["type"] == "array"
    assert "pattern" in EVENT_SOURCE_IPS_SCHEMA["items"]  # type: ignore[operator]
