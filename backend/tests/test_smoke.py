"""Scaffold smoke test: contract loader + validation round-trip.

Verifies the contract pipeline the whole platform is built on: JSON sources
load into frozen domain types and pass the same closure rules the design
baseline enforces. Key counts mirror scripts/check-design.ps1 output.
"""

from __future__ import annotations

import pytest
from app.contracts.loader import load_contracts
from app.contracts.validation import validate_contracts


@pytest.mark.unit
def test_contract_round_trip() -> None:
    contracts = load_contracts()
    validate_contracts(contracts)

    assert len(contracts.requirements) == 51
    assert len(contracts.metric_definitions) == 52
    assert len(contracts.event_definitions) == 5
    assert len(contracts.operation_profiles) == 39
    assert len(contracts.stable_errors) == 27
    assert len(contracts.http_endpoints) == 50
    assert len(contracts.hardware_targets) == 10
