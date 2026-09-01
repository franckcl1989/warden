"""Shared integration fixtures: real PostgreSQL 18 + alembic-upgraded schema.

docs/TEST_STRATEGY.md §2.2: database tests run on the real PostgreSQL, never
SQLite. Each test that asks for a fixture gets a freshly recreated
``warden_test`` database with all migrations applied via the same alembic
subprocess path the deployment uses (DSN from ``WARDEN_TEST_POSTGRES_DSN`` or
the default local instance).
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from app.config import WardenSettings
from app.infrastructure.db import create_db_engine, create_session_factory
from app.main import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

BACKEND_DIR = Path(__file__).resolve().parents[1]
MAINTENANCE_DB = "postgres"
DEFAULT_TEST_DSN = "postgresql://warden@127.0.0.1:55433/warden_test"


def warden_test_dsn() -> str:
    """Test database DSN: CI overrides it via WARDEN_TEST_POSTGRES_DSN."""
    return os.environ.get("WARDEN_TEST_POSTGRES_DSN") or DEFAULT_TEST_DSN


def recreate_test_database(dsn: str) -> None:
    """Drop and recreate the test database (the test owns its lifecycle)."""
    database = make_url(dsn).database
    assert database is not None, "test DSN must name a database"
    maintenance = make_url(dsn).set(database=MAINTENANCE_DB).render_as_string(hide_password=False)
    with psycopg.connect(maintenance, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        connection.execute(f'CREATE DATABASE "{database}"')


def upgrade_test_database(dsn: str) -> None:
    env = os.environ.copy()
    env["WARDEN_POSTGRES_DSN"] = dsn
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        env=env,
        shell=False,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"alembic upgrade head failed (exit {result.returncode})\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )


@pytest.fixture
def fresh_test_db_dsn() -> str:
    dsn = warden_test_dsn()
    recreate_test_database(dsn)
    upgrade_test_database(dsn)
    return dsn


@pytest.fixture
def db_settings(fresh_test_db_dsn: str) -> WardenSettings:
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
    )


@pytest.fixture
def db_app(db_settings: WardenSettings) -> Iterator[FastAPI]:
    app = create_app(db_settings)
    try:
        yield app
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.fixture
def db_client(db_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(db_app) as test_client:
        yield test_client


@pytest.fixture
def db_session(fresh_test_db_dsn: str) -> Iterator[Session]:
    engine = create_db_engine(fresh_test_db_dsn)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            yield session
    finally:
        engine.dispose()
