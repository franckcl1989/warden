"""Retention ownership model: warden_app owns the purgeable tables (M2T3 fix).

Controller ruling on the M2T3 concern (production retention privileges): the
maintenance worker runs as ``warden_app``, which per 0004 has SELECT/INSERT/
UPDATE but NO DELETE and no ownership — so the retention sweep could purge
nothing and partition DROP/CREATE was impossible. This migration makes the
sweep's behavior real and deployable WITHOUT weakening the append-only
streams:

- The purgeable tables (metric_points and its day partitions,
  metric_rollups_5m, metric_rollups_1h, device_events, alerts,
  operation_tasks, ui_events, sessions) are transferred to OWNER
  ``warden_app``. Ownership is the only PostgreSQL mechanism that grants the
  worker DELETE plus the partition lifecycle (CREATE TABLE ... PARTITION OF,
  DROP of old partitions): GRANTs cannot express it (there is no
  CREATE/DROP-ON-TABLE privilege, and 0004's ``ALL TABLES`` grant is
  point-in-time — it never covered 0005+ tables).
- ``audit_logs`` and ``operation_task_events`` STAY with the migration owner
  (``warden_migrate`` in production): warden_app is granted SELECT, INSERT on
  ``operation_task_events`` (the task engine must append events) and
  explicitly NO UPDATE/DELETE there; 0004's audit REVOKE and both
  no-update/no-delete triggers (0002/0005) stay fully intact. The append-only
  streams are exempt from automatic retention purge (ADR-030); physical
  cleanup is an out-of-band DBA operation in 0.1.0.

PostgreSQL 18 mechanics (empirically verified on 18.6 while implementing):

- ``ALTER TABLE ... OWNER TO`` on a partitioned table does NOT recurse into
  existing partitions; grants on the parent do not reach existing partitions
  and are not inherited by new ones either — so the transfer below enumerates
  the current children via pg_inherits. Partitions the maintenance loop
  creates later are owned by its creator (warden_app) and need no transfer.
- Creating a partition requires CREATE on the containing schema even when the
  role owns the partitioned table (the worker therefore needs
  ``CREATE ON SCHEMA public`` in production).
- A non-superuser owner can ``ALTER ... OWNER TO`` only when (a) it owns the
  object, (b) it is a member of the new owner role, and (c) the new owner has
  CREATE on the containing schema.

Deployment consequence (deployment/postgres-init/01-accounts.sh +
deployment/scripts/README.md, updated with this migration): the init script
must ``GRANT CREATE ON SCHEMA public TO warden_app`` (the partition lifecycle
and check (c) above) and ``GRANT warden_app TO warden_migrate`` (check (b):
the migrate account runs 0008 and must be able to transfer ownership). In
dev/test the migrations run as a superuser and bypass (b)/(c); in production
the init script runs before the migrate container, so 0008 lands
deterministically — a missing provisioning step makes the migration FAIL
loudly at the ALTER OWNER, which is the point: the alternative (0004-style
best-effort grants) would silently leave the sweep broken. The verification
block at the end warns — never fails — if the resulting state is wrong.

Rollback plan: downgrade restores ownership of the purgeable tables and their
partitions to ``warden_migrate`` (fallback: current_user when the role does
not exist — dev/test role lifecycle) and revokes what 0008 granted (schema
CREATE for warden_app, SELECT/INSERT on operation_task_events). Roles are
cluster-level resources and are never dropped (0004 rule). Data validation:
ownership and grants only — no data is touched. Space estimate: none.
"""

from __future__ import annotations

from alembic import op

revision = "0008_retention_grants"
down_revision = "0007_rollups"
branch_labels = None
depends_on = None

WARDEN_APP_ROLE = "warden_app"
WARDEN_MIGRATE_ROLE = "warden_migrate"

# DATA_MODEL.md §10 purgeable tables (the sweep deletes rows or DROPs whole
# metric_points partitions). audit_logs / operation_task_events are
# deliberately NOT in this list: they stay with the migration owner and keep
# their REVOKE + append-only triggers (ADR-030).
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

_PARTITION_TRANSFER_SQL = (
    f"""
    DO $$
    DECLARE
        child_name text;
    BEGIN
        FOR child_name IN
            SELECT child.relname
            FROM pg_inherits
            JOIN pg_class child ON child.oid = pg_inherits.inhrelid
            JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
            WHERE parent.relname = 'metric_points'
        LOOP
            EXECUTE format('ALTER TABLE %I OWNER TO {WARDEN_APP_ROLE}', child_name);
        END LOOP;
    END
    $$;
    """
)


def _ensure_role(role: str) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
                CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    # Partition lifecycle + the PG18 new-owner check need warden_app to hold
    # CREATE on schema public. Best-effort like 0004; the authoritative
    # production grant lives in deployment/postgres-init/01-accounts.sh
    # (runs before the migrate container).
    op.execute(f"GRANT CREATE ON SCHEMA public TO {WARDEN_APP_ROLE};")
    for table in PURGEABLE_TABLES:
        op.execute(f"ALTER TABLE {table} OWNER TO {WARDEN_APP_ROLE};")
    # ALTER OWNER does not recurse into existing partitions (PG18): transfer
    # today's metric_points children explicitly.
    op.execute(_PARTITION_TRANSFER_SQL)

    # Append-only streams stay with the migration owner. The task engine must
    # still append events as warden_app (SELECT, INSERT — no more; the REVOKE
    # is explicit belt for the defense-in-depth posture of 0002/0005);
    # 0004's audit REVOKE is re-asserted so a later blanket GRANT can never
    # silently widen it.
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT ON operation_task_events TO {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")

    # Verification (warn, never fail — 0004 posture): a broken state must be
    # visible in the migrate log; the fix is re-running provisioning +
    # migration, not silently shipping a sweep that cannot purge.
    op.execute(
        f"""
        DO $$
        DECLARE
            points_owner text;
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{WARDEN_APP_ROLE}')
               OR NOT COALESCE(has_schema_privilege('{WARDEN_APP_ROLE}', 'public', 'CREATE'), FALSE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app missing or without CREATE on schema public: partition '
                    'lifecycle and the 0008 ownership transfer need it (grant in '
                    'deployment/postgres-init/01-accounts.sh)';
            END IF;
            SELECT pg_get_userbyid(relowner) INTO points_owner
            FROM pg_class WHERE oid = 'metric_points'::regclass;
            IF points_owner IS DISTINCT FROM '{WARDEN_APP_ROLE}' THEN
                RAISE WARNING USING MESSAGE =
                    'metric_points is not owned by warden_app (owner: ' ||
                    COALESCE(points_owner, '<missing>') || '): the retention sweep '
                    'cannot DROP partitions — re-run the migration after provisioning';
            END IF;
            IF NOT COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'INSERT'), FALSE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app append-only privileges are wrong (want INSERT and no '
                    'UPDATE/DELETE on operation_task_events, no UPDATE/DELETE on '
                    'audit_logs): the append-only protections are compromised';
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute(f"REVOKE CREATE ON SCHEMA public FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE SELECT, INSERT ON operation_task_events FROM {WARDEN_APP_ROLE};")
    # Restore ownership to warden_migrate (production shape) or the executing
    # role (dev/test), partitions included.
    op.execute(
        f"""
        DO $$
        DECLARE
            restore_to name;
            child_name text;
            _table text;
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{WARDEN_MIGRATE_ROLE}') THEN
                restore_to := '{WARDEN_MIGRATE_ROLE}';
            ELSE
                restore_to := current_user;
            END IF;
            FOREACH _table IN ARRAY ARRAY['metric_points', 'metric_rollups_5m',
                'metric_rollups_1h', 'device_events', 'alerts', 'operation_tasks',
                'ui_events', 'sessions']::text[]
            LOOP
                EXECUTE format('ALTER TABLE %I OWNER TO %I', _table, restore_to);
            END LOOP;
            FOR child_name IN
                SELECT child.relname
                FROM pg_inherits
                JOIN pg_class child ON child.oid = pg_inherits.inhrelid
                JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
                WHERE parent.relname = 'metric_points'
            LOOP
                EXECUTE format('ALTER TABLE %I OWNER TO %I', child_name, restore_to);
            END LOOP;
        END
        $$;
        """
    )
