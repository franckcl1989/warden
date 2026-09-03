"""Launch-session one-time tickets (M3T4, PLT-09 launch 部分).

docs/API_CONTRACT.md §7 (远程连接): ``POST /devices/{id}/launches`` issues a
launch row bound to user/device/capability/protocol/source web session, with
a 60-second ``expires_at``; ``GET /launches/{id}`` CONSUMES the row (single
GET — the second read is a uniform 404). The row itself is NOT a task: no
operation_tasks row, no dispatch fence, no idempotency key (API_CONTRACT.md
§6.1: 连接类能力不进入副作用任务队列).

``launch_sessions`` is purgeable exactly like the DATA_MODEL.md §10 set:

- issued rows past their 60-second window are marked ``expired`` by the
  retention sweep (bookkeeping; the single-use claim already checks
  ``expires_at`` at read time, so an expired row can never be consumed);
- rows leave after a 30-day lifetime (``expires_at < now - 30d``), like
  login sessions — the permanent audit trail (launch.create /
  launch.consume in audit_logs) is what forensics needs, never this row.

To let the sweep UPDATE/DELETE as ``warden_app``, 0013 transfers OWNERSHIP
to warden_app (the 0008 model) and re-runs the 0009 convention grant block
point-in-time plus the append-only pair REVOKEs AFTER the blanket grant —
exactly the 0010/0011 pattern (point-in-time GRANTs never reach tables
created afterwards).

Rollback plan: downgrade drops the table (grants and ownership disappear
with the object). Data validation: CHECK constraints below mirror the ORM
model in ``app/models/launch.py``. Space estimate: one bounded row per
launch, 30-day lifetime — no capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013_launch_sessions"
down_revision = "0012_operation_attempts"
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
        "launch_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("capability_key", sa.String(length=64), nullable=False),
        sa.Column("requirement_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        # The issuing web session (API_CONTRACT.md §7: 票据绑定来源会话).
        # ON DELETE CASCADE: the login-session retention sweep (30 days)
        # must never be blocked by stale ticket rows — a cascaded row is
        # always long-expired history (its audit trail is permanent).
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("descriptor_url", sa.Text(), nullable=True),
        sa.Column(
            "descriptor_data",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="issued",
        ),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "status IN ('issued', 'consumed', 'expired', 'revoked', 'failed')",
            name="ck_launch_sessions_status",
        ),
        sa.CheckConstraint(
            "protocol IN ('kvm', 'ssh', 'telnet', 'web')", name="ck_launch_sessions_protocol"
        ),
        sa.CheckConstraint(
            "(status = 'consumed') = (consumed_at IS NOT NULL)",
            name="ck_launch_sessions_consumed",
        ),
        sa.CheckConstraint(
            "status <> 'revoked' OR revoked_at IS NOT NULL", name="ck_launch_sessions_revoked"
        ),
        sa.CheckConstraint("version >= 1", name="ck_launch_sessions_version"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_launch_sessions_user_created", "launch_sessions", ["user_id", "created_at"])
    op.create_index(
        "ix_launch_sessions_device_created", "launch_sessions", ["device_id", "created_at"]
    )
    op.create_index("ix_launch_sessions_expires_at", "launch_sessions", ["expires_at"])

    # 0010/0011 convention: warden_app OWNS the purgeable table (the
    # retention sweep runs as warden_app — UPDATE for the issued->expired
    # marking and DELETE for the 30-day cleanup are ownership privileges,
    # 0008 model). The 0009 convention block re-grants S/I/U point-in-time
    # and re-asserts the append-only REVOKEs AFTER the blanket grant.
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    op.execute(f"ALTER TABLE launch_sessions OWNER TO {WARDEN_APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};")

    # Verification (warn, never fail — 0004 posture): launch_sessions must be
    # owned by warden_app (sweep UPDATE/DELETE) and the append-only pair must
    # keep its protection.
    op.execute(
        f"""
        DO $$
        DECLARE
            table_owner text;
        BEGIN
            SELECT pg_get_userbyid(relowner) INTO table_owner
            FROM pg_class WHERE oid = 'launch_sessions'::regclass;
            IF table_owner IS DISTINCT FROM '{WARDEN_APP_ROLE}' THEN
                RAISE WARNING USING MESSAGE =
                    'launch_sessions is not owned by warden_app (owner: ' ||
                    COALESCE(table_owner, '<missing>') || '): the retention '
                    'sweep cannot expire/purge launch sessions — re-run the '
                    'migration after provisioning';
            END IF;
            IF COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app still has UPDATE or DELETE on the append-only '
                    'streams (audit_logs / operation_task_events): the 0013 '
                    'REVOKE did not win over the blanket grant';
            END IF;
        END
        $$;
        """  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; no user input
    )


def downgrade() -> None:
    op.drop_index("ix_launch_sessions_expires_at", table_name="launch_sessions")
    op.drop_index("ix_launch_sessions_device_created", table_name="launch_sessions")
    op.drop_index("ix_launch_sessions_user_created", table_name="launch_sessions")
    op.drop_table("launch_sessions")
