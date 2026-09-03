"""Fixture drift check (tests/fixtures/redfish, M3T1 provenance policy).

Each fixture JSON is a FROZEN contract snapshot captured from the TEST
DEVICE SIMULATOR (simulator origin only — never 真机). This module verifies
every M3T2 snapshot still equals what the simulator emits for its documented
profile: a drift means the snapshot must be re-taken AND its provenance row
updated in the README — never silently regenerated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.simulators.redfish.payloads import (
    SimulatorConfig,
    _View,
    drive,
    memory_dimm,
    power,
    thermal,
    volume,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "redfish"
DEFAULT_VIEW = _View(SimulatorConfig())


def _load(name: str) -> dict[str, object]:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    assert isinstance(payload, dict)
    return payload


@pytest.mark.unit
@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("memory-dimm0-healthy.json", memory_dimm(DEFAULT_VIEW, "DIMM0")),
        ("memory-dimm4-empty-slot.json", memory_dimm(DEFAULT_VIEW, "DIMM4")),
        ("thermal-healthy.json", thermal(DEFAULT_VIEW)),
        ("power-healthy.json", power(DEFAULT_VIEW)),
        ("drive-sda-healthy.json", drive(DEFAULT_VIEW, "sda")),
        ("volume-raid6-healthy.json", volume(DEFAULT_VIEW)),
    ],
)
def test_m3t2_fixture_matches_simulator_payload(filename: str, expected: dict[str, object]) -> None:
    assert _load(filename) == expected
