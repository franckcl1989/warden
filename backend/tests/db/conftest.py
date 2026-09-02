"""Shared database-privilege fixtures for tests/db (real PostgreSQL).

``warden_app_dsn`` drives the real production privilege model: the role is
created BEFORE the migrations run (0004's ``IF NOT EXISTS`` keeps it and
applies grants/REVOKEs; 0008 transfers ownership of the purgeable tables to
it), so the tests connect exactly as the production application account does
— including the 0008 ownership model.

Password policy: migration 0004 must not hardcode passwords, so the fixture
creates the role with a test-known password and drops it in teardown. The
production path is different: deployment compose (``postgres-init/
01-accounts.sh``) creates the role with a secret password before the migrate
container runs (documented in the M1T4 report and migration 0004 docstring).

Teardown after 0008: warden_app OWNS the purgeable tables in the test
database, so REVOKE alone no longer releases the role (PG15+: DROP ROLE fails
while objects depend on it). Teardown therefore REASSIGNs the owned objects
back to the migration user, DROPs the remaining privileges (DROP OWNED) and
only then drops the role.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import psycopg
import pytest
from sqlalchemy.engine import make_url

from tests.conftest import recreate_test_database, upgrade_test_database

DEFAULT_TEST_DSN = "postgresql://warden@127.0.0.1:55433/warden_test"
MAINTENANCE_DB = "postgres"

WARDEN_APP_ROLE = "warden_app"
WARDEN_APP_PASSWORD = "warden_app_test_password"


def base_test_dsn() -> str:
    return os.environ.get("WARDEN_TEST_POSTGRES_DSN") or DEFAULT_TEST_DSN


def _maintenance_dsn(base_dsn: str) -> str:
    return (
        make_url(base_dsn).set(database=MAINTENANCE_DB).render_as_string(hide_password=False)
    )


def _drop_app_role(base_dsn: str) -> None:
    """Release warden_app's objects/privileges in the test DB, then drop the role.

    The role OWNS the purgeable tables after 0008, so the test database must
    first REASSIGN them (to the DSN user) and DROP the remaining privileges
    (DROP OWNED also revokes schema/sequence grants). If the database is gone
    (failed setup), the in-database steps are skipped and the role drop alone
    decides. The database itself stays (other fixtures recreate it as needed);
    only the role lifecycle belongs to this fixture.
    """
    url = make_url(base_dsn)
    assert url.username is not None, "test DSN must name a user for REASSIGN OWNED"
    database = url.database
    try:
        if database is not None:
            with psycopg.connect(base_dsn, autocommit=True) as connection:
                connection.execute(
                    f"REASSIGN OWNED BY {WARDEN_APP_ROLE} TO {url.username}"
                )
                connection.execute(f"DROP OWNED BY {WARDEN_APP_ROLE}")
    except psycopg.Error:
        pass
    with psycopg.connect(_maintenance_dsn(base_dsn), autocommit=True) as connection:
        connection.execute(f"DROP ROLE IF EXISTS {WARDEN_APP_ROLE}")


@pytest.fixture
def warden_app_dsn() -> Iterator[str]:
    """Create warden_app, migrate with the role present, yield its DSN."""
    base_dsn = base_test_dsn()
    maintenance = _maintenance_dsn(base_dsn)
    database = make_url(base_dsn).database
    assert database is not None
    # Reset: drop the database (removes in-database objects/grants) then
    # recreate the role.
    with psycopg.connect(maintenance, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        connection.execute(f"DROP ROLE IF EXISTS {WARDEN_APP_ROLE}")
        connection.execute(
            f"CREATE ROLE {WARDEN_APP_ROLE} LOGIN PASSWORD '{WARDEN_APP_PASSWORD}'"
        )
    recreate_test_database(base_dsn)
    upgrade_test_database(base_dsn)
    app_dsn = (
        make_url(base_dsn)
        .set(username=WARDEN_APP_ROLE, password=WARDEN_APP_PASSWORD)
        .render_as_string(hide_password=False)
    )
    try:
        yield app_dsn
    finally:
        _drop_app_role(base_dsn)
