"""Shared fixtures for the API shell tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client
