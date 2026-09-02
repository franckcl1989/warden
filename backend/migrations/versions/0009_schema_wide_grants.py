"""Schema-wide warden_app grants: close the post-0004 grant gap (M2T3 fix 2).

Migration 0004's ``GRANT ... ON ALL TABLES IN SCHEMA public`` is
point-in-time: PostgreSQL only grants on objects that exist when the statement
runs. Every table created afterwards — operation_tasks (0005),
operation_task_events (0005), collection_runs (0006), metric_points (0006),
metric_latest (0006), device_events (0006), collection_observation_errors
(0006), alerts (0006), ui_events (0006), metric_rollups_5m/1h (0007) — had NO
warden_app privileges in a fresh production install, so the app/worker account
could not read or write them. Dev/tests never surfaced it because the dev
database runs migrations as the superuser ``warden`` (the 0004 ``DO`` block
only warned; test sessions connected as ``warden``, not ``warden_app``).

0008 already solved the purgeable half via ownership (the maintenance worker
OWNS metric_points + partitions, rollups, device_events, alerts,
operation_tasks, ui_events, sessions, which is what enables the retention
sweep's DELETE + partition lifecycle). This migration grants what ownership
does not cover — SELECT/INSERT/UPDATE on EVERY table in schema public,
sequences included, minus the append-only pair — and fixes the footgun for
the rest of the project:

- ``GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public`` executed
  by the migration owner covers every relation that exists at head. 0008's
  ownership transfers made warden_app the owner of the purgeable tables, and
  an owner needs no grant (and a non-owner GRANT silently skips tables the
  grantor cannot grant on — 0004's documented posture) — so in production
  this statement's effective scope is exactly the warden_migrate-owned
  tables: users, devices, device_credentials, device_capabilities,
  components, operation_task_events, collection_runs, metric_latest,
  collection_observation_errors, audit_logs, plus alembic_version (sessions
  and the other purgeable tables are warden_app-owned after 0008). In dev
  (superuser) it lands everywhere; the effective matrix is identical.
- The append-only pair (audit_logs, operation_task_events) is REVOKEd
  UPDATE/DELETE AFTER the blanket grant, so the REVOKE definitively wins over
  the grant this migration itself adds (PostgreSQL ACLs are exact sets; the
  last statement decides). 0004's audit REVOKE and 0005's trigger both stay
  intact; 0008's SELECT/INSERT grant on operation_task_events is unchanged in
  effect. Verified: the migration's verification block asserts no UPDATE or
  DELETE privilege remains for warden_app on either table.
- ``GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public`` covers
  ``ui_events_id_seq`` (0006's BIGSERIAL — created after 0004, so its
  sequence grant was vacuous for it) and any future sequence.

DELETE is deliberately NOT granted here. The purgeable-DELETE set is
exclusively the 0008-owned tables (the retention sweep purges exactly those:
metric_points by partition DROP, rollups/device_events/resolved-alerts/
eventless-terminal-tasks/ui_events/sessions by DELETE). Verified FK
semantics for the two candidates the controller asked about:

- ``operation_tasks``: ``audit_logs.task_id`` is a plain UUID column, NOT a
  foreign key (0002 — the constraint list references only actor_user_id and
  session_id). No RESTRICT conflict exists between task purge and the
  immortal audit rows; the only guard on task deletion is the
  ``operation_task_events`` FK CASCADE + the 0005 append-only trigger, which
  is already handled (0008 ownership + the sweep's NOT EXISTS guard deletes
  only eventless terminal tasks). DELETE on operation_tasks stays as 0008
  granted it (ownership).
- ``collection_runs``: referenced by metric_points/metric_latest/
  metric_rollups_5m/metric_rollups_1h with ON DELETE SET NULL and by
  collection_observation_errors with ON DELETE CASCADE. DATA_MODEL §10
  defines NO retention for collection_runs, so the sweep never purges runs in
  0.1.0 and warden_app gets NO DELETE grant here. (If a future migration adds
  run retention: points leave first by partition DROP, and run deletion SET
  NULLs provenance on surviving rows and CASCADEs the error rows away — but
  that future migration must re-grant per the convention below.)
- ``collection_observation_errors``, ``metric_latest``: current-state /
  failure-detail stores with no DATA_MODEL §10 retention — SELECT/INSERT/
  UPDATE only.

Convention for the remainder of the project (this fixes the 0004 footgun
FORWARD, not only for the tables that exist today): EVERY future migration
that creates tables or sequences in schema public MUST end with the same
grant block — ``GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public
TO warden_app`` plus ``REVOKE UPDATE, DELETE ON audit_logs /
operation_task_events FROM warden_app`` (when the append-only pair is
affected) plus ``GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO
warden_app``. ``GRANT ON ALL TABLES`` is point-in-time and never reaches
later objects; re-granting at the end of each creating migration is the
only way a fresh production install stays deployable. Same note in
deployment/scripts/README.md.

Downgrade plan: revokes exactly what this migration granted on tables that
had no prior warden_app grant (collection_runs, metric_latest,
collection_observation_errors) and the sequence grant (0004-era grants on
0004-era objects are left untouched — the revoke list is precise, not a
blanket). Restoring the 0008 state means those three tables fall back to
their pre-0009 no-grant state, exactly as 0008 left them. Data validation:
grants only, no data touched. Space estimate: none.
"""

from __future__ import annotations

from alembic import op

revision = "0009_schema_wide_grants"
down_revision = "0008_retention_grants"
branch_labels = None
depends_on = None

WARDEN_APP_ROLE = "warden_app"
WARDEN_MIGRATE_ROLE = "warden_migrate"

# Tables created after 0004 that had NO warden_app grant before this
# migration. The downgrade revokes exactly these (the blanket GRANT of 0009
# also touched 0004-era tables and the 0008-owned purgeables, but there it was
# a no-op — grants cannot widen ownership, and an owner needs no grant — so
# nothing must be revoked there to restore the prior state).
_UNGRANTED_BEFORE_0009 = (
    "collection_runs",
    "metric_latest",
    "collection_observation_errors",
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
    # The schema-wide grant (point-in-time: covers every relation existing at
    # head). In production the purgeable tables are warden_app-owned by 0008
    # and are silently skipped — ownership already covers them; everything
    # warden_migrate owns gets the grant.
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    # The append-only pair: the REVOKE runs AFTER the blanket grant and wins
    # (PostgreSQL ACLs are exact sets). Belt for the 0004/0008 posture: a
    # later blanket grant can never silently widen these two streams.
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    # ui_events_id_seq (0006 BIGSERIAL) and any sequence created after 0004
    # need USAGE for the app account to INSERT (nextval runs as the caller).
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};")

    # Verification (warn, never fail — 0004 posture). Checks the EFFECTIVE
    # privileges (has_table_privilege counts ownership): every base table in
    # schema public must be readable/writable by warden_app, the append-only
    # pair must have no UPDATE/DELETE, and every sequence must grant USAGE.
    op.execute(
        f"""
        DO $$
        DECLARE
            rel record;
            problem_count integer := 0;
        BEGIN
            FOR rel IN
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
            LOOP
                IF NOT COALESCE(has_table_privilege('{WARDEN_APP_ROLE}',
                        'public.' || rel.relname, 'SELECT'), FALSE)
                   OR NOT COALESCE(has_table_privilege('{WARDEN_APP_ROLE}',
                        'public.' || rel.relname, 'INSERT'), FALSE)
                   OR NOT COALESCE(has_table_privilege('{WARDEN_APP_ROLE}',
                        'public.' || rel.relname, 'UPDATE'), FALSE)
                THEN
                    problem_count := problem_count + 1;
                END IF;
            END LOOP;
            IF problem_count > 0 THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app is missing SELECT/INSERT/UPDATE on ' ||
                    problem_count || ' relation(s) in schema public: the 0009 '
                    'grants did not land (grantor must own the objects or hold '
                    'GRANT OPTION) — re-run the migration after provisioning';
            END IF;
            IF COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app still has UPDATE or DELETE on the append-only '
                    'streams (audit_logs / operation_task_events): the REVOKE '
                    'did not win over the blanket grant — re-run the migration';
            END IF;
            FOR rel IN
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind = 'S'
            LOOP
                IF NOT COALESCE(has_sequence_privilege('{WARDEN_APP_ROLE}',
                        'public.' || rel.relname, 'USAGE'), FALSE)
                THEN
                    RAISE WARNING USING MESSAGE =
                        'warden_app is missing USAGE on sequence ' || rel.relname ||
                        ': 0009 sequence grants did not land';
                END IF;
            END LOOP;
        END
        $$;
        """  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; no user input
    )


def downgrade() -> None:
    # Precise reversal: only the tables that had NO warden_app grant before
    # 0009 lose theirs again (0004-era tables keep their 0004 grants; the
    # 0008-owned purgeables keep their ownership). Sequences: the only
    # sequence at head is ui_events_id_seq (0006), which had no grant before
    # 0009 — a blanket sequence revoke is exact here.
    for table in _UNGRANTED_BEFORE_0009:
        op.execute(f"REVOKE SELECT, INSERT, UPDATE ON {table} FROM {WARDEN_APP_ROLE};")
    op.execute(
        f"REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM {WARDEN_APP_ROLE};"  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; no user input
    )
