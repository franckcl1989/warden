"""System state (maintenance mode) + ingest heartbeat rows (M6T3b, PLT-08).

Closes the PLT-08 gap (docs/ARCHITECTURE.md §9 / API_CONTRACT.md §9 /
DEPLOYMENT.md §8/§9.2): the ``warden maintenance on|off`` host CLI
(deployment/scripts/warden, M0T7) flips a persistent maintenance flag that
was never migrated, and the event-ingest service records a durable heartbeat
that ``GET /system/status`` uses to report the receiver component honestly.

Design notes:

- ``system_state`` is a SINGLE-ROW table (CHECK id = 1) holding the
  maintenance flag + since/reason; a row appears on first use (app-level
  upsert or the host CLI). Absence reads as maintenance OFF.
- ``ingest_heartbeat`` is a SINGLE-ROW table (CHECK id = 1) advanced by the
  ingest service (app/workers/ingest.py): ``updated_at`` IS the process-alive
  stamp (written at startup and every heartbeat interval, events or not),
  ``events_received_total`` accumulates the durable received-message counter
  and ``last_received_at`` the newest event timestamp. In-process receivers'
  counters remain the hot-path source (M5T1); this row is the PLT-08 surface.
- Grants follow the 0013/0014 convention block (blanket S/I/U + the
  append-only pair REVOKE + sequence grant). Ownership is NOT transferred to
  warden_app: ownership exists to let the retention sweep DELETE/UPDATE as
  warden_app (0008 model, PURGEABLE_TABLES in tests/db), and neither table is
  a retention target — warden_app only ever SELECTs/INSERTs/UPDATEs them
  (single-row upserts; nothing deletes a row). Effective DELETE therefore
  stays absent, keeping the 0009 invariant (DELETE only on the purgeable
  ownership set) intact.

Rollback plan: downgrade drops both tables (grants disappear with the
objects). Data validation: the single-row CHECK constraints mirror
``app/models/system.py``. Space estimate: exactly one row per table — no
capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_system_state"
down_revision = "0014_terminal_sessions"
branch_labels = None
depends_on = None

WARDEN_APP_ROLE = "warden_app"
WARDEN_MIGRATE_ROLE = "warden_migrate"


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
    op.create_table(
        "system_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "maintenance_mode",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("maintenance_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("maintenance_reason", sa.Text(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_system_state_single_row"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ingest_heartbeat",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "events_received_total",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_ingest_heartbeat_single_row"),
        sa.PrimaryKeyConstraint("id"),
    )

    # 0013/0014 convention: the blanket S/I/U grant covers the tables created
    # above; the append-only pair REVOKE is re-asserted so it keeps winning
    # over the blanket grant. Ownership stays with the migration account —
    # these rows are never retention-purged (see the module docstring).
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};"
    )
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};"
    )


def downgrade() -> None:
    op.drop_table("ingest_heartbeat")
    op.drop_table("system_state")
