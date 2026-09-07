"""Migration 0015 tables: shape, single-row CHECKs, warden_app privileges.

Support: PLT-08（私有部署与必要运行状态，DEPLOYMENT.md §8）.

Unlike the 0013/0014 tables, system_state and ingest_heartbeat are NOT owned
by warden_app and grant no DELETE: ownership exists to enable the retention
sweep (0008 model), and neither table is a retention target — warden_app only
ever SELECTs/INSERTs/UPDATEs the single rows (upserts; nothing deletes).
These tests pin that effective matrix so the 0009 invariant (DELETE only on
the purgeable ownership set) stays intact for the new tables.
"""

from __future__ import annotations

import psycopg
import pytest

from tests.db.conftest import WARDEN_APP_ROLE, base_test_dsn

NEW_TABLES = ("system_state", "ingest_heartbeat")


@pytest.mark.integration
def test_0015_tables_exist_and_are_not_owned_by_warden_app(warden_app_dsn: str) -> None:
    del warden_app_dsn
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        for table in NEW_TABLES:
            owner = connection.execute(
                "SELECT pg_get_userbyid(c.relowner) FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relname = %s",
                (table,),
            ).fetchone()
            assert owner is not None, table
            assert owner[0] != WARDEN_APP_ROLE, (table, owner[0])


@pytest.mark.integration
def test_0015_single_row_checks_reject_second_row(warden_app_dsn: str) -> None:
    del warden_app_dsn
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        for statement in (
            "INSERT INTO system_state (id) VALUES (2)",
            "INSERT INTO ingest_heartbeat (id) VALUES (2)",
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(statement)
                connection.commit()
            connection.rollback()


@pytest.mark.integration
def test_0015_warden_app_has_select_insert_update_but_no_delete(
    warden_app_dsn: str,
) -> None:
    """The app account can run the single-row upserts and reads only.

    No DELETE: neither table is a retention target (module docstring).
    """
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        for table in NEW_TABLES:
            row = connection.execute(
                "SELECT has_table_privilege(%s, %s, 'SELECT'), "
                "has_table_privilege(%s, %s, 'INSERT'), "
                "has_table_privilege(%s, %s, 'UPDATE'), "
                "has_table_privilege(%s, %s, 'DELETE')",
                (WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table),
            ).fetchone()
            assert row == (True, True, True, False), (table, row)


@pytest.mark.integration
def test_0015_warden_app_functional_upsert_path(
    warden_app_dsn: str,
) -> None:
    """As warden_app: the ON CONFLICT single-row upsert really works."""
    with psycopg.connect(warden_app_dsn) as connection:
        connection.execute(
            "INSERT INTO system_state (id, maintenance_mode) VALUES (1, true) "
            "ON CONFLICT (id) DO UPDATE SET maintenance_mode = excluded.maintenance_mode"
        )
        connection.execute(
            "INSERT INTO ingest_heartbeat (id, events_received_total) VALUES (1, 7) "
            "ON CONFLICT (id) DO UPDATE SET events_received_total = "
            "ingest_heartbeat.events_received_total + excluded.events_received_total"
        )
        connection.commit()
        state_mode = connection.execute("SELECT maintenance_mode FROM system_state WHERE id = 1").fetchone()
        assert state_mode == (True,)
        events = connection.execute("SELECT events_received_total FROM ingest_heartbeat WHERE id = 1").fetchone()
        assert events == (7,)
