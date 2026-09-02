"""Schema-wide warden_app grants (migration 0009_schema_wide_grants).

Migration 0004's ``GRANT ... ON ALL TABLES`` was point-in-time: tables created
by 0005-0007 had no warden_app privileges in production, so the app/worker
account could not read/write them (dev/test never surfaced it — everything
runs as the superuser warden). 0009 grants SELECT/INSERT/UPDATE on EVERY table
existing at head (0008's ownership transfers make the purgeable tables work by
ownership; 0009 covers the rest), grants USAGE/SELECT on all sequences, and
re-asserts the append-only REVOKE so it wins over the blanket grant.

These tests assert the EFFECTIVE matrix (has_table_privilege counts
ownership, which is what deployability actually means) plus the
information_schema grant rows, and one functional pass as warden_app:

- every base table in schema public is SELECT/INSERT/UPDATE-able by
  warden_app, except audit_logs / operation_task_events which are
  SELECT/INSERT only (no UPDATE/DELETE — the REVOKE wins);
- DELETE exists ONLY on the purgeable tables (0008 ownership — the retention
  sweep's set) and never on the non-purgeable tables;
- every sequence grants USAGE/SELECT (ui_events_id_seq came after 0004);
- functional: INSERT into alerts + SELECT from metric_points + INSERT into
  collection_runs/metric_latest/collection_observation_errors/ui_events
  succeed as warden_app; UPDATE audit_logs is denied.
"""

from __future__ import annotations

import psycopg
import psycopg.types.json
import pytest

from tests.db.conftest import WARDEN_APP_ROLE, base_test_dsn
from tests.db.test_retention_privileges import (
    APPEND_ONLY_TABLES,
    PURGEABLE_TABLES,
)
from tests.observation_factories import make_collection_device

# Tables that exist at head (the effective-matrix loops cover every base
# table via pg_class; this list only pins the EXPECTED set for the subset
# assertions below and must be extended by tests when a migration adds a
# table — 0010 added preview_token_uses).
NON_PURGEABLE_TABLES = (
    "alembic_version",
    "users",
    "sessions",
    "audit_logs",
    "devices",
    "device_credentials",
    "device_capabilities",
    "components",
    "operation_tasks",
    "operation_task_events",
    "collection_runs",
    "metric_points",
    "metric_latest",
    "device_events",
    "collection_observation_errors",
    "alerts",
    "ui_events",
    "metric_rollups_5m",
    "metric_rollups_1h",
    "preview_token_uses",
    "files",
    "file_links",
    "device_file_tickets",
)


def _public_base_tables(base_dsn: str) -> list[str]:
    """Every base table in schema public (partition children included)."""
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')"
        ).fetchall()
    return [row[0] for row in rows]


@pytest.fixture
def superuser_session_factory():
    """ORM factory bound to the superuser test DSN (seeding FK targets).

    The warden_app_dsn fixture owns the database lifecycle (migrated with the
    role present); this engine only seeds rows the warden_app assertions need
    (devices), never the role lifecycle.
    """
    from app.infrastructure.db import create_db_engine, create_session_factory

    engine = create_db_engine(base_test_dsn())
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


@pytest.mark.integration
def test_0009_grants_select_insert_update_on_every_table(
    warden_app_dsn: str,
) -> None:
    """Effective matrix: warden_app can SELECT/INSERT/UPDATE every base table.

    has_table_privilege counts ownership, so the 0008-purgeable tables pass
    through ownership and the rest through the 0009 grant — exactly the
    production shape.
    """
    base_dsn = base_test_dsn()
    tables = _public_base_tables(base_dsn)
    assert set(NON_PURGEABLE_TABLES) <= set(tables), tables
    with psycopg.connect(base_dsn) as connection:
        for table in tables:
            if table in APPEND_ONLY_TABLES:
                continue
            row = connection.execute(
                "SELECT has_table_privilege(%s, %s, 'SELECT'), "
                "has_table_privilege(%s, %s, 'INSERT'), "
                "has_table_privilege(%s, %s, 'UPDATE')",
                (WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table, WARDEN_APP_ROLE, table),
            ).fetchone()
            assert row == (True, True, True), table
    # Every base table at head is covered by the assertions above: the
    # migration's own verification block would have warned otherwise.
    assert len(tables) >= len(NON_PURGEABLE_TABLES)


@pytest.mark.integration
def test_0009_append_only_pair_keeps_select_insert_only(
    warden_app_dsn: str,
) -> None:
    """The REVOKE wins over the blanket grant: no UPDATE/DELETE on the pair.

    Both at the effective level (has_table_privilege) and in
    information_schema.role_table_grants (no UPDATE/DELETE rows exist for
    warden_app on audit_logs / operation_task_events after 0009).
    """
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        for table in APPEND_ONLY_TABLES:
            row = connection.execute(
                "SELECT has_table_privilege(%s, %s, 'SELECT'), "
                "has_table_privilege(%s, %s, 'INSERT'), "
                "has_table_privilege(%s, %s, 'UPDATE'), "
                "has_table_privilege(%s, %s, 'DELETE')",
                (
                    WARDEN_APP_ROLE,
                    table,
                    WARDEN_APP_ROLE,
                    table,
                    WARDEN_APP_ROLE,
                    table,
                    WARDEN_APP_ROLE,
                    table,
                ),
            ).fetchone()
            assert row == (True, True, False, False), (table, row)
        grant_rows = connection.execute(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = %s AND table_schema = 'public' "
            "AND table_name = ANY(%s) AND privilege_type IN ('UPDATE', 'DELETE')",
            (WARDEN_APP_ROLE, list(APPEND_ONLY_TABLES)),
        ).fetchall()
    assert grant_rows == [], grant_rows


@pytest.mark.integration
def test_0009_delete_only_on_purgeable_tables(
    warden_app_dsn: str,
) -> None:
    """DELETE stays an ownership-only privilege (the 0008 sweep set).

    No blanket DELETE grant exists: the three post-0004 non-purgeable tables
    (collection_runs, metric_latest, collection_observation_errors) have no
    DELETE — DATA_MODEL §10 defines no retention for them in 0.1.0 — and no
    0004-era table gained one either.
    """
    base_dsn = base_test_dsn()
    purgeable_with_parent = {*PURGEABLE_TABLES}
    with psycopg.connect(base_dsn) as connection:
        for table in _public_base_tables(base_dsn):
            is_partition = table.startswith("metric_points_")
            effective = (
                "SELECT has_table_privilege(%s, %s, 'DELETE')",
                (WARDEN_APP_ROLE, table),
            )
            row = connection.execute(*effective).fetchone()
            expected = table in purgeable_with_parent or is_partition
            assert bool(row[0]) is expected, (table, row)
        # And information_schema shows no DELETE grant rows on tables that
        # warden_app does NOT own (ownership never appears as a grant). Note:
        # when the migration runs as superuser (dev/tests), a GRANT on a table
        # warden_app ALREADY owns materializes the implicit owner ACL (full
        # privileges, DELETE included) as explicit rows — an artifact of the
        # superuser grant, not an over-grant; the ownership filter below is
        # the honest invariant. Production's migrate account cannot grant on
        # warden_app-owned tables at all, so nothing materializes there.
        grant_rows = connection.execute(
            "SELECT g.table_name FROM information_schema.role_table_grants g "
            "WHERE g.grantee = %s AND g.privilege_type = 'DELETE' "
            "AND NOT EXISTS (SELECT 1 FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = g.table_schema AND c.relname = g.table_name "
            "AND pg_get_userbyid(c.relowner) = %s)",
            (WARDEN_APP_ROLE, WARDEN_APP_ROLE),
        ).fetchall()
    assert grant_rows == [], grant_rows


@pytest.mark.integration
def test_0009_sequences_grant_usage_and_select(
    warden_app_dsn: str,
) -> None:
    """Every sequence in schema public grants USAGE/SELECT to warden_app.

    ui_events_id_seq is the BIGSERIAL created by 0006 — after 0004's
    point-in-time sequence grant, so 0009 is what makes ui_events INSERT
    (nextval as the app account) work in production.
    """
    base_dsn = base_test_dsn()
    with psycopg.connect(base_dsn) as connection:
        rows = connection.execute(
            "SELECT c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'S'"
        ).fetchall()
        assert rows, "expected at least ui_events_id_seq"
        for (sequence,) in rows:
            usage, select = connection.execute(
                "SELECT has_sequence_privilege(%s, %s, 'USAGE'), "
                "has_sequence_privilege(%s, %s, 'SELECT')",
                (WARDEN_APP_ROLE, sequence, WARDEN_APP_ROLE, sequence),
            ).fetchone()
            assert usage is True, sequence
            assert select is True, sequence


@pytest.mark.integration
def test_warden_app_functional_paths_after_0009(
    warden_app_dsn: str, superuser_session_factory
) -> None:
    """As warden_app: worker writes land, audit UPDATE stays denied.

    Exercises the tables the collection worker and alert engine touch that
    0004's point-in-time grant never covered: alerts INSERT, metric_points
    SELECT, collection_runs INSERT, metric_latest INSERT (upsert path),
    collection_observation_errors INSERT and ui_events INSERT (nextval on
    ui_events_id_seq as warden_app — the 0009 sequence grant).
    """
    with superuser_session_factory() as session:
        device = make_collection_device(session, index=1)
        device_id = device.id

    with psycopg.connect(warden_app_dsn) as connection:
        # The brief's functional check: INSERT into alerts + SELECT from
        # metric_points (0006 tables, post-0004).
        connection.execute(
            "INSERT INTO alerts (id, device_id, rule_key, severity, status, "
            "title, evidence, first_occurred_at, last_occurred_at, dedupe_key) "
            "VALUES (gen_random_uuid(), %s, 'reachability.offline', 'critical', "
            "'active', 'device offline', %s, now(), now(), '0009-alert-1')",
            (device_id, psycopg.types.json.Jsonb({})),
        )
        connection.commit()
        count = connection.execute(
            "SELECT count(*) FROM metric_points WHERE device_id = %s", (device_id,)
        ).fetchone()[0]
        assert count == 0  # readable as warden_app; no rows seeded

        # Worker write paths on the previously-ungranted tables.
        connection.execute(
            "INSERT INTO collection_runs (id, device_id, collection_type, "
            "scheduled_at, state) VALUES (gen_random_uuid(), %s, 'metrics', "
            "now(), 'scheduled')",
            (device_id,),
        )
        connection.execute(
            "INSERT INTO metric_latest (id, device_id, metric_key, value_double, "
            "unit, quality, source, observed_at) VALUES (gen_random_uuid(), %s, "
            "'system.cpu_percent', 12.5, %s, 'good', 'poll', now())",
            (device_id, "%"),
        )
        connection.execute(
            "INSERT INTO collection_observation_errors (id, device_id, "
            "error_code, stage) VALUES (gen_random_uuid(), %s, "
            "'read_failed', 'collect')",
            (device_id,),
        )
        connection.execute(
            "INSERT INTO ui_events (entity_type, entity_id, version, event_type) "
            "VALUES ('device', %s, 1, 'updated')",
            (device_id,),
        )
        connection.commit()

        def _denied(statement: str, params: tuple[object, ...] = ()) -> None:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement, params)
                connection.commit()
            connection.rollback()

        _denied("UPDATE audit_logs SET result = 'tampered' WHERE action = '0009-gate'")
        # No DELETE over-grant: the non-purgeable post-0004 tables are not
        # sweep targets in 0.1.0 (DATA_MODEL §10 has no retention rule).
        _denied(
            "DELETE FROM collection_runs WHERE device_id = %s", (device_id,)
        )
