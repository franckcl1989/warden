"""Shared fixtures for the API shell tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from app.config import WardenSettings
from app.main import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def device_settings(fresh_test_db_dsn: str, tmp_path) -> WardenSettings:
    """Device API settings: allowed management CIDR + secret files.

    The fake adapter endpoint (192.0.2.x) lives inside the TEST-NET-1 range
    configured here; loopback stays denied so the SSRF tests are meaningful.
    """
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs="192.0.2.0/24",
        credential_master_key_file=key_file,
        session_secret_file=session_file,
    )


@pytest.fixture
def device_app(device_settings: WardenSettings) -> Iterator[FastAPI]:
    app = create_app(device_settings)
    try:
        yield app
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.fixture
def device_client(device_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(device_app) as test_client:
        yield test_client
