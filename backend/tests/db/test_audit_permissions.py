"""Database-level audit permission hardening (SECURITY.md §12, migration 0004).

The application account ``warden_app`` must be able to INSERT audit rows but
must NOT be able to UPDATE or DELETE them — the DATABASE PERMISSION layer,
independent of the append-only trigger (which rejects even privileged roles
and would mask a missing REVOKE).

Password policy: migration 0004 must not hardcode passwords, so the test
creates the role with a test-known password BEFORE the migrations run (0004's
``IF NOT EXISTS`` keeps it and applies grants + the REVOKE), and drops it in
teardown. The production path is different: deployment compose
(``postgres-init/01-accounts.sh``) creates the role with a secret password
before the migrate container runs. This split is documented in the M1T4
report.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import psycopg
import psycopg.types.json
import pytest
from sqlalchemy.engine import make_url

from tests.conftest import recreate_test_database, upgrade_test_database

DEFAULT_TEST_DSN = "postgresql://warden@127.0.0.1:55433/warden_test"
MAINTENANCE_DB = "postgres"

WARDEN_APP_ROLE = "warden_app"
WARDEN_APP_PASSWORD = "warden_app_test_password"


def _base_test_dsn() -> str:
    return os.environ.get("WARDEN_TEST_POSTGRES_DSN") or DEFAULT_TEST_DSN


def _maintenance_dsn(base_dsn: str) -> str:
    return (
        make_url(base_dsn).set(database=MAINTENANCE_DB).render_as_string(hide_password=False)
    )


def _drop_app_role(base_dsn: str) -> None:
    """Revoke in-database grants then drop the role (grants block DROP ROLE on PG15+).

    The database itself stays (other tests' fixtures recreate it as needed);
    only the role lifecycle belongs to this fixture. If the database is gone
    (failed setup), the revokes are skipped and the role drop alone decides.
    """
    maintenance = _maintenance_dsn(base_dsn)
    try:
        with psycopg.connect(base_dsn, autocommit=True) as connection:
            connection.execute(
                "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM warden_app"
            )
            connection.execute(
                "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM warden_app"
            )
            connection.execute("REVOKE USAGE ON SCHEMA public FROM warden_app")
    except psycopg.Error:
        pass
    with psycopg.connect(maintenance, autocommit=True) as connection:
        connection.execute(f"DROP ROLE IF EXISTS {WARDEN_APP_ROLE}")


@pytest.fixture
def warden_app_dsn() -> Iterator[str]:
    """Create warden_app, migrate with the role present, yield its DSN."""
    base_dsn = _base_test_dsn()
    maintenance = _maintenance_dsn(base_dsn)
    database = make_url(base_dsn).database
    assert database is not None
    # Reset: drop the database (removes in-database grants) then recreate the role.
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


def _insert_as_app(dsn: str, action: str) -> None:
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "INSERT INTO audit_logs (id, action, result, detail_jsonb) "
            "VALUES (gen_random_uuid(), %s, 'success', %s)",
            (action, psycopg.types.json.Jsonb({})),
        )
        connection.commit()


def _privileges_for_app(base_dsn: str, table: str) -> set[str]:
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = %s AND grantee = %s",
            (table, WARDEN_APP_ROLE),
        ).fetchall()
    return {row[0] for row in rows}


@pytest.mark.integration
def test_warden_app_can_insert_into_audit_logs(warden_app_dsn: str) -> None:
    _insert_as_app(warden_app_dsn, "role.permission.insert")
    with psycopg.connect(warden_app_dsn) as connection:
        count = connection.execute(
            "SELECT count(*) FROM audit_logs WHERE action = 'role.permission.insert'"
        ).fetchone()[0]
    assert count == 1


@pytest.mark.integration
def test_warden_app_update_rejected_by_permission_layer(warden_app_dsn: str) -> None:
    _insert_as_app(warden_app_dsn, "role.permission.update")
    with psycopg.connect(warden_app_dsn) as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
        connection.execute(
            "UPDATE audit_logs SET result = 'tampered' WHERE action = 'role.permission.update'"
        )
        connection.commit()


@pytest.mark.integration
def test_warden_app_delete_rejected_by_permission_layer(warden_app_dsn: str) -> None:
    _insert_as_app(warden_app_dsn, "role.permission.delete")
    with psycopg.connect(warden_app_dsn) as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
        connection.execute("DELETE FROM audit_logs WHERE action = 'role.permission.delete'")
        connection.commit()


@pytest.mark.integration
def test_warden_app_has_no_update_or_delete_grant_on_audit_logs(warden_app_dsn: str) -> None:
    """The information_schema view (the manual psql check) must show no
    UPDATE/DELETE for warden_app on audit_logs."""
    base_dsn = _base_test_dsn()
    privileges = _privileges_for_app(base_dsn, "audit_logs")
    assert "UPDATE" not in privileges
    assert "DELETE" not in privileges
    assert "INSERT" in privileges
    assert "SELECT" in privileges


@pytest.mark.integration
def test_warden_app_still_has_select_insert_update_on_other_tables(warden_app_dsn: str) -> None:
    """Least privilege must not break normal application writes elsewhere."""
    base_dsn = _base_test_dsn()
    privileges = _privileges_for_app(base_dsn, "users")
    assert {"SELECT", "INSERT", "UPDATE"} <= privileges
    assert "DELETE" not in privileges


@pytest.mark.integration
def test_warden_app_privilege_state_as_migration_verification_expects(warden_app_dsn: str) -> None:
    """The has_*_privilege queries migration 0004's verification block runs
    must report the expected state for warden_app: USAGE on schema public and
    INSERT on audit_logs true, UPDATE on audit_logs false. If these queries
    ever flip, the migration's RAISE WARNING fires and the broken account
    becomes visible instead of failing silently at runtime."""
    with psycopg.connect(warden_app_dsn) as connection:
        schema_usage, audit_insert, audit_update = connection.execute(
            "SELECT has_schema_privilege('warden_app', 'public', 'USAGE'), "
            "has_table_privilege('warden_app', 'audit_logs', 'INSERT'), "
            "has_table_privilege('warden_app', 'audit_logs', 'UPDATE')"
        ).fetchone()
    assert schema_usage is True
    assert audit_insert is True
    assert audit_update is False
