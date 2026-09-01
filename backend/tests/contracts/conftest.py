"""Shared fixtures for the contract-layer unit tests."""

from __future__ import annotations

import pytest
from app.contracts.loader import load_contracts
from app.domain.contracts import ContractSet


@pytest.fixture(scope="session")
def contracts() -> ContractSet:
    return load_contracts()
