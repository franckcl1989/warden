"""Unit tests for the database layer (no database required).

The happy-path connectivity behaviour of ``ping``/``DatabaseProbe`` is
covered by integration tests against the real PostgreSQL 18 instance; the
failure path here only needs a closed port on loopback.
"""

from __future__ import annotations

import os

import pytest
from app.infrastructure.db import (
    DatabaseProbe,
    create_db_engine,
    create_session_factory,
    dsn_with_psycopg_dialect,
    ping,
)
from app.infrastructure.readiness import ProbeResult
from sqlalchemy import create_engine

REFUSED_DSN = "postgresql+psycopg://warden@127.0.0.1:1/warden"


@pytest.mark.unit
def test_dsn_rewrites_plain_postgresql_scheme() -> None:
    assert (
        dsn_with_psycopg_dialect("postgresql://warden@127.0.0.1:55433/warden")
        == "postgresql+psycopg://warden@127.0.0.1:55433/warden"
    )


@pytest.mark.unit
def test_dsn_rewrites_postgres_scheme() -> None:
    assert (
        dsn_with_psycopg_dialect("postgres://warden@127.0.0.1:55433/warden")
        == "postgresql+psycopg://warden@127.0.0.1:55433/warden"
    )


@pytest.mark.unit
def test_dsn_passes_through_qualified_scheme() -> None:
    dsn = "postgresql+psycopg://warden@127.0.0.1:55433/warden"
    assert dsn_with_psycopg_dialect(dsn) == dsn


@pytest.mark.unit
def test_dsn_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError):
        dsn_with_psycopg_dialect("sqlite:///warden.db")


@pytest.mark.unit
def test_create_engine_uses_psycopg_driver() -> None:
    engine = create_db_engine("postgresql://warden@127.0.0.1:55433/warden")
    try:
        assert engine.url.drivername == "postgresql+psycopg"
        factory = create_session_factory(engine)
        assert factory.kw["bind"] is engine
        assert factory.kw["expire_on_commit"] is False
    finally:
        engine.dispose()


@pytest.mark.unit
def test_ping_returns_false_when_database_unreachable() -> None:
    engine = create_engine(REFUSED_DSN, connect_args={"connect_timeout": 1})
    try:
        assert ping(engine) is False
    finally:
        engine.dispose()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_database_probe_reports_unreachable_as_failed() -> None:
    engine = create_engine(REFUSED_DSN, connect_args={"connect_timeout": 1})
    try:
        result = await DatabaseProbe(engine=engine).check()
    finally:
        engine.dispose()
    assert isinstance(result, ProbeResult)
    assert result.name == "postgres"
    assert result.ok is False
    assert result.detail != ""


@pytest.mark.integration
def test_ping_connects_to_real_postgresql() -> None:
    dsn = os.environ.get("WARDEN_TEST_POSTGRES_DSN") or "postgresql://warden@127.0.0.1:55433/warden_test"
    engine = create_db_engine(dsn)
    try:
        assert ping(engine) is True
    finally:
        engine.dispose()
