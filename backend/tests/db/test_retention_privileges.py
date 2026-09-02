"""Production privilege model for retention (migration 0008_retention_grants).

Controller ruling on the M2T3 concern: in production the maintenance worker
runs as ``warden_app``, which must REALLY be able to purge — so 0008
transferred the purgeable tables to warden_app ownership while leaving the
append-only streams (audit_logs, operation_task_events) with the migration
owner and their REVOKE + no-update/no-delete triggers intact (ADR-030).

These tests connect AS warden_app (the ``warden_app_dsn`` fixture migrates
with the role present) and assert the deployable model end to end:

- (a) the worker can DELETE from a purgeable table;
- (b) it CANNOT UPDATE/DELETE audit_logs or operation_task_events
  (permission denied — the permission layer, not only the triggers);
- (c) it can create and DROP a metric_points partition (ownership + schema
  CREATE), and information_schema shows metric_points owned by warden_app
  while audit_logs/operation_task_events are NOT.
"""

from __future__ import annotations

import psycopg
import psycopg.types.json
import pytest
from app.infrastructure.db import create_db_engine, create_session_factory

from tests.db.conftest import WARDEN_APP_ROLE, base_test_dsn
from tests.observation_factories import make_collection_device
from tests.task_factories import make_task, make_user

PURGEABLE_TABLES = (
    "metric_points",
    "metric_rollups_5m",
    "metric_rollups_1h",
    "device_events",
    "alerts",
    "operation_tasks",
    "ui_events",
    "sessions",
)
APPEND_ONLY_TABLES = ("audit_logs", "operation_task_events")

FUTURE_PARTITION_DAY = "2099-01-01"
FUTURE_PARTITION_NAME = "metric_points_2099_01_01"


def _owners(base_dsn: str, tables: tuple[str, ...]) -> dict[str, str]:
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT c.relname, pg_get_userbyid(c.relowner) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname = ANY(%s)",
            (list(tables),),
        ).fetchall()
    return {row[0]: row[1] for row in rows}


def _partition_owners(base_dsn: str) -> dict[str, str]:
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT child.relname, pg_get_userbyid(child.relowner) "
            "FROM pg_inherits "
            "JOIN pg_class child ON child.oid = pg_inherits.inhrelid "
            "JOIN pg_class parent ON parent.oid = pg_inherits.inhparent "
            "WHERE parent.relname = 'metric_points'"
        ).fetchall()
    return {row[0]: row[1] for row in rows}


@pytest.fixture
def superuser_session_factory():
    """ORM factory bound to the superuser test DSN (seeding FK targets).

    The warden_app_dsn fixture owns the database lifecycle (migrated with the
    role present); this engine only seeds rows the warden_app assertions need
    (devices/users/tasks), never the role lifecycle.
    """
    engine = create_db_engine(base_test_dsn())
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


# ------------------------------------------------------------- (c) ownership

@pytest.mark.integration
def test_0008_ownership_transfer_lands_on_purgeable_tables_and_partitions(
    warden_app_dsn: str,
) -> None:
    base_dsn = base_test_dsn()
    owners = _owners(base_dsn, PURGEABLE_TABLES)
    for table in PURGEABLE_TABLES:
        assert owners.get(table) == WARDEN_APP_ROLE, table
    # Every existing metric_points day partition was transferred too (ALTER
    # OWNER does not recurse into partitions on PG18).
    partition_owners = _partition_owners(base_dsn)
    assert partition_owners, "expected the 0006 pre-created partitions to exist"
    assert set(partition_owners.values()) == {WARDEN_APP_ROLE}, partition_owners


@pytest.mark.integration
def test_0008_append_only_tables_stay_with_the_migration_owner(
    warden_app_dsn: str,
) -> None:
    """audit_logs / operation_task_events are NOT owned by warden_app: the
    REVOKE + triggers stay effective at the database level."""
    base_dsn = base_test_dsn()
    owners = _owners(base_dsn, APPEND_ONLY_TABLES)
    for table in APPEND_ONLY_TABLES:
        assert owners.get(table) not in (None, WARDEN_APP_ROLE), table
        with psycopg.connect(base_dsn) as connection:
            owner_acl = connection.execute(
                "SELECT has_table_privilege(%s, %s, 'UPDATE'), "
                "has_table_privilege(%s, %s, 'DELETE')",
                (WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table),
            ).fetchone()
        assert owner_acl == (False, False), table


# ----------------------------------------------------- (a) purgeable DELETE

@pytest.mark.integration
def test_warden_app_can_delete_from_purgeable_tables(
    warden_app_dsn: str, superuser_session_factory
) -> None:
    """The maintenance sweep's deletes run as warden_app in production: the
    role must be able to DELETE purgeable rows (rollups seeded here)."""
    with superuser_session_factory() as session:
        device = make_collection_device(session, index=1)
        device_id = device.id

    with psycopg.connect(warden_app_dsn) as connection:
        # warden_app OWNS metric_rollups_5m: INSERT + DELETE are its own.
        connection.execute(
            "INSERT INTO metric_rollups_5m (id, device_id, metric_key, "
            "window_start, min_value, max_value, avg_value, last_value, "
            "count, quality) "
            "VALUES (gen_random_uuid(), %s, 'system.cpu_percent', "
            "TIMESTAMPTZ '2026-01-01 00:00:00+00', 1, 1, 1, 1, 1, 'good')",
            (device_id,),
        )
        connection.commit()
        deleted = connection.execute(
            "DELETE FROM metric_rollups_5m WHERE device_id = %s", (device_id,)
        )
        connection.commit()
        assert deleted.rowcount == 1
        remaining = connection.execute(
            "SELECT count(*) FROM metric_rollups_5m WHERE device_id = %s",
            (device_id,),
        ).fetchone()[0]
        assert remaining == 0


@pytest.mark.integration
def test_warden_app_has_delete_privilege_on_every_purgeable_table(
    warden_app_dsn: str,
) -> None:
    with psycopg.connect(warden_app_dsn) as connection:
        for table in PURGEABLE_TABLES:
            if table == "metric_points":
                # The parent itself carries no rows; DELETE matters on its
                # partitions, which are owned (asserted above). Ownership is
                # what enables DROP — exercised by the partition test below.
                continue
            has_delete = connection.execute(
                "SELECT has_table_privilege(%s, %s, 'DELETE')",
                (WARDEN_APP_ROLE, table),
            ).fetchone()[0]
            assert has_delete is True, table


# ------------------------------------------------- (c) partition lifecycle

@pytest.mark.integration
def test_warden_app_can_create_and_drop_metric_points_partitions(
    warden_app_dsn: str,
) -> None:
    """The daily maintenance loop (ensure_partitions + retention) runs as
    warden_app: it must be able to CREATE a partition (ownership of
    metric_points + CREATE on schema public) and DROP one (ownership of the
    partition itself — the retention sweep drops whole old partitions)."""
    with psycopg.connect(warden_app_dsn) as connection:
        created = connection.execute(
            "SELECT create_metric_partition(%s::date)", (FUTURE_PARTITION_DAY,)
        ).fetchone()[0]
        connection.commit()
        assert created is True
        exists = connection.execute(
            "SELECT to_regclass(%s)",
            (f"public.{FUTURE_PARTITION_NAME}",),
        ).fetchone()[0]
        assert exists is not None
        connection.execute(f'DROP TABLE IF EXISTS "{FUTURE_PARTITION_NAME}"')
        connection.commit()
        gone = connection.execute(
            "SELECT to_regclass(%s)",
            (f"public.{FUTURE_PARTITION_NAME}",),
        ).fetchone()[0]
        assert gone is None


# ------------------------------------------------ (b) append-only streams

@pytest.mark.integration
def test_warden_app_cannot_update_or_delete_append_only_streams(
    warden_app_dsn: str, superuser_session_factory
) -> None:
    """The worker CAN append to both streams (INSERT), but UPDATE/DELETE are
    denied at the permission layer — independent of the 0002/0005 triggers.

    Fixture seeding note: the FK targets (user/device/task) are seeded via a
    superuser session because warden_app is not the owner of those tables;
    the assertions themselves all run as warden_app.
    """
    with superuser_session_factory() as session:
        user = make_user(session, index=1)
        device = make_collection_device(session, index=1)
        task = make_task(
            session,
            device_id=device.id,
            requested_by=user.id,
            index=1,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="succeeded",
            idempotency_key="priv-model-task",
        )
        task_id = task.id

    with psycopg.connect(warden_app_dsn) as connection:
        # Append is the legitimate worker path (0008 grants SELECT, INSERT).
        connection.execute(
            "INSERT INTO operation_task_events (id, task_id, state, message) "
            "VALUES (gen_random_uuid(), %s, 'succeeded', 'appended-by-app')",
            (task_id,),
        )
        connection.commit()
        appended = connection.execute(
            "SELECT count(*) FROM operation_task_events WHERE task_id = %s AND "
            "message = 'appended-by-app'",
            (task_id,),
        ).fetchone()[0]
        assert appended == 1

        def _denied(statement: str, params: tuple[object, ...] = ()) -> None:
            # Each denied statement aborts its transaction: roll back so the
            # next assertion runs in a fresh one.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement, params)
                connection.commit()
            connection.rollback()

        # operation_task_events: UPDATE/DELETE denied at the permission layer
        # (independent of the 0005 trigger).
        _denied(
            "UPDATE operation_task_events SET message = 'tampered' WHERE task_id = %s",
            (task_id,),
        )
        _denied("DELETE FROM operation_task_events WHERE task_id = %s", (task_id,))
        # audit_logs: INSERT is granted (0004), UPDATE/DELETE are not.
        connection.execute(
            "INSERT INTO audit_logs (id, action, result, detail_jsonb) "
            "VALUES (gen_random_uuid(), 'priv.model', 'success', %s)",
            (psycopg.types.json.Jsonb({}),),
        )
        connection.commit()
        _denied("UPDATE audit_logs SET result = 'tampered' WHERE action = 'priv.model'")
        _denied("DELETE FROM audit_logs WHERE action = 'priv.model'")


@pytest.mark.integration
def test_warden_app_has_select_insert_but_no_update_or_delete_on_task_events(
    warden_app_dsn: str,
) -> None:
    """information_schema state for operation_task_events (0008 grants)."""
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'operation_task_events' AND grantee = %s",
            (WARDEN_APP_ROLE,),
        ).fetchall()
    privileges = {row[0] for row in rows}
    assert {"SELECT", "INSERT"} <= privileges
    assert "UPDATE" not in privileges
    assert "DELETE" not in privileges
