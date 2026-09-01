"""Users, sessions and the append-only audit log (docs/DATA_MODEL.md §3/§9).

``users``: case-insensitive unique usernames via a functional unique index on
``lower(username)`` (plain text column — the ``citext`` extension is not used,
keeping the schema portable and the comparison semantics explicit).

``audit_logs`` is append-only: a PL/pgSQL trigger rejects UPDATE and DELETE
and the ORM model raises in ``before_update``/``before_delete`` listeners
(TEST_STRATEGY §2.2: 审计只追加). Downgrade drops the trigger and function
before dropping the tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_users_sessions_audit"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

APPEND_ONLY_TRIGGER_FUNCTION = "reject_audit_logs_modification"


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("role IN ('admin', 'operator', 'viewer')", name="ck_users_role"),
        sa.CheckConstraint("status IN ('active', 'disabled', 'locked')", name="ck_users_status"),
        sa.CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
        sa.CheckConstraint("version >= 1", name="ck_users_version"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_users_username_lower",
        "users",
        [sa.text("lower(username)")],
        unique=True,
        postgresql_using="btree",
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("csrf_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("client_summary", sa.String(length=255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version >= 1", name="ck_sessions_version"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sessions_session_id_hash", "sessions", ["session_id_hash"], unique=True)
    op.create_index("ix_sessions_user_id_revoked_at", "sessions", ["user_id", "revoked_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("requirement_id", sa.String(length=32), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("result", sa.String(length=16), nullable=False, server_default="success"),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent_summary", sa.String(length=255), nullable=True),
        sa.Column("detail_jsonb", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"])
    op.create_index("ix_audit_logs_actor_occurred_at", "audit_logs", ["actor_user_id", "occurred_at"])

    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION {APPEND_ONLY_TRIGGER_FUNCTION}()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs")
    op.execute(f"DROP FUNCTION IF EXISTS {APPEND_ONLY_TRIGGER_FUNCTION}()")
    op.drop_index("ix_audit_logs_actor_occurred_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_occurred_at", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_sessions_user_id_revoked_at", table_name="sessions")
    op.drop_index("ix_sessions_session_id_hash", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_users_username_lower", table_name="users")
    op.drop_table("users")
