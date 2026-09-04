"""Browser terminal sessions + launch-ticket device-version binding (M5T4).

docs/API_CONTRACT.md §7/§11 (远程连接), SECURITY.md §8, ARCHITECTURE.md §5.4,
ADR-007: ``WS /terminal/sessions/{ticket}`` consumes one 60-second launch
ticket (protocol ssh/telnet) and opens ONE ``terminal_sessions`` row that
lives while the interactive browser terminal is open:

- bounded: at most 2 hours total and 15 minutes idle (enforced live by the
  API process AND by the retention sweep — a crashed API cannot leave a
  session row open forever, which would permanently block the per-device 1
  session cap);
- concurrency caps (每用户最多 3、每设备最多 1) count OPEN rows plus
  issued-unexpired launch tickets (API_CONTRACT.md §11);
- ``status`` starts ``open`` at ticket claim and moves to ``closed`` exactly
  once with ``close_reason`` + ``closed_at``; the CHECK ties the fields;
- terminal CONTENT is never stored: the row holds only who/which device/
  which protocol/opened/closed/reason — audit rows carry the same metadata
  (terminal.handshake_ok / terminal.handshake_failed / terminal.closed) and
  never content either (SECURITY.md §8/§12).

``launch_sessions.device_version`` (ALTER below) binds each ticket to the
device configuration version at issue time (API_CONTRACT.md §7: 票据绑定…
设备版本): the WebSocket connect refuses (uniform close) when the device was
re-configured after issue — config/credential changes must go through a new
probe + new launch.

Purgeability: rows leave after a 30-day lifetime like launch_sessions/login
sessions; the audit stream is the permanent record. Ownership transfers to
warden_app (0008 model) + the 0009 convention grant block runs point-in-time
plus the append-only pair REVOKEs, exactly like migration 0013.

Rollback plan: downgrade drops terminal_sessions and the added column
(grants/ownership disappear with the objects). Data validation: CHECK
constraints mirror ``app/models/terminal.py`` + the 0013 ORM change.
Space estimate: one bounded row per terminal session, 30-day lifetime — no
capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_terminal_sessions"
down_revision = "0013_launch_sessions"
branch_labels = None
depends_on = None

WARDEN_APP_ROLE = "warden_app"
WARDEN_MIGRATE_ROLE = "warden_migrate"

#: Machine close-reason vocabulary (mirrors app/models/terminal.py).
CLOSE_REASONS = (
    "user_closed",
    "idle_timeout",
    "max_duration",
    "handshake_failed",
    "device_connection_lost",
    "client_disconnected",
    "server_restart",
    "internal_error",
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
    # API_CONTRACT.md §7: 票据绑定用户、设备、能力、协议、来源会话和设备版本 —
    # M3T4 (0013) did not persist the device version; terminal tickets need it
    # at connect time. Nullable: 0013 rows (all historical) simply carry none.
    op.add_column(
        "launch_sessions",
        sa.Column("device_version", sa.Integer(), nullable=True),
    )
    op.create_table(
        "terminal_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        # The consumed one-time launch ticket (1:1 — a ticket is single-use;
        # UNIQUE prevents any race from creating two sessions per ticket).
        sa.Column("launch_session_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("capability_key", sa.String(length=64), nullable=False),
        sa.Column("requirement_id", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="open",
        ),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("close_reason", sa.String(length=32), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "protocol IN ('ssh', 'telnet')", name="ck_terminal_sessions_protocol"
        ),
        sa.CheckConstraint(
            "status IN ('open', 'closed')", name="ck_terminal_sessions_status"
        ),
        sa.CheckConstraint(
            "(status = 'closed') = (closed_at IS NOT NULL)",
            name="ck_terminal_sessions_closed",
        ),
        sa.CheckConstraint(
            "status <> 'closed' OR close_reason IS NOT NULL",
            name="ck_terminal_sessions_close_reason",
        ),
        sa.CheckConstraint(
            f"close_reason IS NULL OR close_reason IN {CLOSE_REASONS!r}",
            name="ck_terminal_sessions_reason_values",
        ),
        sa.ForeignKeyConstraint(
            ["launch_session_id"], ["launch_sessions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "launch_session_id", name="uq_terminal_sessions_launch_session"
        ),
    )
    op.create_index(
        "ix_terminal_sessions_user_opened", "terminal_sessions", ["user_id", "opened_at"]
    )
    op.create_index(
        "ix_terminal_sessions_device_opened",
        "terminal_sessions",
        ["device_id", "opened_at"],
    )
    op.create_index(
        "ix_terminal_sessions_open_activity",
        "terminal_sessions",
        ["status", "last_activity_at"],
    )
    op.create_index(
        "ix_terminal_sessions_opened_at", "terminal_sessions", ["opened_at"]
    )

    # 0013 convention: warden_app OWNS the purgeable table (the retention
    # sweep closes stale sessions and purges 30-day history as warden_app).
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    op.execute(f"ALTER TABLE terminal_sessions OWNER TO {WARDEN_APP_ROLE};")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};"
    )
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};"
    )

    # Verification (warn, never fail — 0004 posture): terminal_sessions must
    # be owned by warden_app and the append-only pair must keep protection.
    op.execute(
        f"""
        DO $$
        DECLARE
            table_owner text;
        BEGIN
            SELECT pg_get_userbyid(relowner) INTO table_owner
            FROM pg_class WHERE oid = 'terminal_sessions'::regclass;
            IF table_owner IS DISTINCT FROM '{WARDEN_APP_ROLE}' THEN
                RAISE WARNING USING MESSAGE =
                    'terminal_sessions is not owned by warden_app (owner: ' ||
                    COALESCE(table_owner, '<missing>') || '): the retention '
                    'sweep cannot close/purge terminal sessions — re-run the '
                    'migration after provisioning';
            END IF;
            IF COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app still has UPDATE or DELETE on the append-only '
                    'streams (audit_logs / operation_task_events): the 0014 '
                    'REVOKE did not win over the blanket grant';
            END IF;
        END
        $$;
        """  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; no user input
    )


def downgrade() -> None:
    op.drop_index("ix_terminal_sessions_opened_at", table_name="terminal_sessions")
    op.drop_index(
        "ix_terminal_sessions_open_activity", table_name="terminal_sessions"
    )
    op.drop_index(
        "ix_terminal_sessions_device_opened", table_name="terminal_sessions"
    )
    op.drop_index(
        "ix_terminal_sessions_user_opened", table_name="terminal_sessions"
    )
    op.drop_table("terminal_sessions")
    op.drop_column("launch_sessions", "device_version")
