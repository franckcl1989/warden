"""Database-level audit permission hardening (SECURITY.md §12, migration 0004).

The application account ``warden_app`` must be able to INSERT audit rows but
must NOT be able to UPDATE or DELETE them — the DATABASE PERMISSION layer,
independent of the append-only trigger (which rejects even privileged roles
and would mask a missing REVOKE). The ``warden_app_dsn`` fixture (this
package's conftest) drives the real production role lifecycle; migration 0008
additionally made warden_app the owner of the purgeable tables — audit_logs
is deliberately NOT among them, and these tests pin that state.

Password policy: migration 0004 must not hardcode passwords, so the fixture
creates the role with a test-known password BEFORE the migrations run (0004's
``IF NOT EXISTS`` keeps it and applies grants + the REVOKE), and drops it in
teardown. The production path is different: deployment compose
(``postgres-init/01-accounts.sh``) creates the role with a secret password
before the migrate container runs. This split is documented in the M1T4
report.
"""

from __future__ import annotations

import psycopg
import psycopg.types.json
import pytest

from tests.db.conftest import WARDEN_APP_ROLE, base_test_dsn

_INSERT_AUDIT_ACTION = "role.permission.insert"
_UPDATE_AUDIT_ACTION = "role.permission.update"
_DELETE_AUDIT_ACTION = "role.permission.delete"


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
    _insert_as_app(warden_app_dsn, _INSERT_AUDIT_ACTION)
    with psycopg.connect(warden_app_dsn) as connection:
        count = connection.execute(
            "SELECT count(*) FROM audit_logs WHERE action = %s",
            (_INSERT_AUDIT_ACTION,),
        ).fetchone()[0]
    assert count == 1


@pytest.mark.integration
def test_warden_app_update_rejected_by_permission_layer(warden_app_dsn: str) -> None:
    _insert_as_app(warden_app_dsn, _UPDATE_AUDIT_ACTION)
    with psycopg.connect(warden_app_dsn) as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
        connection.execute(
            "UPDATE audit_logs SET result = 'tampered' WHERE action = %s",
            (_UPDATE_AUDIT_ACTION,),
        )
        connection.commit()


@pytest.mark.integration
def test_warden_app_delete_rejected_by_permission_layer(warden_app_dsn: str) -> None:
    _insert_as_app(warden_app_dsn, _DELETE_AUDIT_ACTION)
    with psycopg.connect(warden_app_dsn) as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
        connection.execute(
            "DELETE FROM audit_logs WHERE action = %s", (_DELETE_AUDIT_ACTION,)
        )
        connection.commit()


@pytest.mark.integration
def test_warden_app_has_no_update_or_delete_grant_on_audit_logs(warden_app_dsn: str) -> None:
    """The information_schema view (the manual psql check) must show no
    UPDATE/DELETE for warden_app on audit_logs."""
    base_dsn = base_test_dsn()
    privileges = _privileges_for_app(base_dsn, "audit_logs")
    assert "UPDATE" not in privileges
    assert "DELETE" not in privileges
    assert "INSERT" in privileges
    assert "SELECT" in privileges


@pytest.mark.integration
def test_warden_app_still_has_select_insert_update_on_other_tables(warden_app_dsn: str) -> None:
    """Least privilege must not break normal application writes elsewhere."""
    base_dsn = base_test_dsn()
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
