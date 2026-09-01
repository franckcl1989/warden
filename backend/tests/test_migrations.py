"""Integration tests for the Alembic harness on the REAL PostgreSQL 18.

docs/TEST_STRATEGY.md §2.2: database/migration tests run on real PostgreSQL,
never SQLite. The test owns the ``warden_test`` database lifecycle: it
connects to the ``postgres`` maintenance database, drops and recreates
``warden_test``, then drives ``alembic upgrade head`` / ``downgrade base`` in
subprocesses that read the DSN from the app settings (WARDEN_POSTGRES_DSN env
var, exactly like the deployment migrate container). The DSN is never printed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parents[1]
MAINTENANCE_DB = "postgres"
DEFAULT_TEST_DSN = "postgresql://warden@127.0.0.1:55433/warden_test"


def _test_dsn() -> str:
    """Test database DSN: CI overrides it via WARDEN_TEST_POSTGRES_DSN."""
    return os.environ.get("WARDEN_TEST_POSTGRES_DSN") or DEFAULT_TEST_DSN


def _head_revision() -> str:
    config = AlembicConfig(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None, "migration tree has no head revision"
    return head


def _maintenance_dsn(dsn: str) -> str:
    url = make_url(dsn)
    return url.set(database=MAINTENANCE_DB).render_as_string(hide_password=False)


def _recreate_database(dsn: str) -> None:
    """Drop and recreate the test database (the test owns its lifecycle)."""
    database = make_url(dsn).database
    assert database is not None, "test DSN must name a database"
    with psycopg.connect(_maintenance_dsn(dsn), autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        connection.execute(f'CREATE DATABASE "{database}"')


def _run_alembic(dsn: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["WARDEN_POSTGRES_DSN"] = dsn
    # Fixed argv (interpreter + module + alembic subcommand): no shell, no
    # untrusted input; ruff's seen_shell_false only silences later calls.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        env=env,
        shell=False,
        check=False,
    )


def _assert_alembic_ok(result: subprocess.CompletedProcess[str], action: str) -> None:
    if result.returncode != 0:
        raise AssertionError(
            f"alembic {action} failed (exit {result.returncode})\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )


def _alembic_version_num(dsn: str) -> str | None:
    """Current applied revision, or None when no revision is applied."""
    with psycopg.connect(dsn) as connection:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    return None if row is None else str(row[0])


def _has_alembic_version_table(dsn: str) -> bool:
    with psycopg.connect(dsn) as connection:
        row = connection.execute("SELECT to_regclass('public.alembic_version')").fetchone()
    return row is not None and row[0] is not None


@pytest.fixture
def fresh_test_database() -> str:
    dsn = _test_dsn()
    _recreate_database(dsn)
    return dsn


@pytest.mark.integration
def test_upgrade_head_applies_baseline_and_records_head(fresh_test_database: str) -> None:
    _assert_alembic_ok(_run_alembic(fresh_test_database, "upgrade", "head"), "upgrade head")
    assert _alembic_version_num(fresh_test_database) == _head_revision()


@pytest.mark.integration
def test_downgrade_base_removes_applied_revision(fresh_test_database: str) -> None:
    _assert_alembic_ok(_run_alembic(fresh_test_database, "upgrade", "head"), "upgrade head")
    _assert_alembic_ok(_run_alembic(fresh_test_database, "downgrade", "base"), "downgrade base")
    # alembic deletes the version row on downgrade past the first revision but
    # leaves the (empty) version table in place; "gone" therefore means no
    # applied revision, verified via a fresh connection.
    assert _alembic_version_num(fresh_test_database) is None
    assert _has_alembic_version_table(fresh_test_database) is True


@pytest.mark.integration
def test_full_upgrade_downgrade_upgrade_cycle(fresh_test_database: str) -> None:
    _assert_alembic_ok(_run_alembic(fresh_test_database, "upgrade", "head"), "upgrade head")
    _assert_alembic_ok(_run_alembic(fresh_test_database, "downgrade", "base"), "downgrade base")
    assert _alembic_version_num(fresh_test_database) is None
    _assert_alembic_ok(_run_alembic(fresh_test_database, "upgrade", "head"), "upgrade head again")
    assert _alembic_version_num(fresh_test_database) == _head_revision()
