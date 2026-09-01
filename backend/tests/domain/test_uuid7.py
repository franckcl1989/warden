"""Unit tests for RFC 9562 UUIDv7 generation (docs/DATA_MODEL.md §1)."""

from __future__ import annotations

import time
import uuid
from itertools import pairwise

import pytest
from app.domain.uuid7 import uuid7


@pytest.mark.unit
def test_uuid7_version_and_variant_bits() -> None:
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122
    assert str(value)[14] == "7"
    assert str(value)[19] in "89ab"


@pytest.mark.unit
def test_uuid7_embeds_millisecond_timestamp() -> None:
    before = time.time_ns() // 1_000_000
    value = uuid7()
    after = time.time_ns() // 1_000_000
    embedded = value.int >> 80
    assert before <= embedded <= after


@pytest.mark.unit
def test_uuid7_values_are_strictly_ordered() -> None:
    values = [uuid7() for _ in range(2000)]
    assert all(previous < current for previous, current in pairwise(values))


@pytest.mark.unit
def test_uuid7_bulk_generation_is_unique() -> None:
    values = {uuid7() for _ in range(5000)}
    assert len(values) == 5000
