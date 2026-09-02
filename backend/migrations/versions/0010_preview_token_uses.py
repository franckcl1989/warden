"""Single-use preview-token consumption ledger + warden_app ownership (M2T4 fix).

SECURITY.md §4 item 7 (确认令牌一次性) and §13 (重放确认令牌不能产生第二次
执行): the preview token's HMAC signature + 60 s TTL alone do not make it
single-use — within the validity window a replayed token with a FRESH
Idempotency-Key would create a second task whenever the profile's conflict
scope is non-mutex (device_read / device_read_heavy, e.g.
logs.support_bundle.collect -> two queued read tasks).

``preview_token_uses`` is the server-side consumption ledger:

- every issued preview token hash is INSERTed at issue time
  (``created_at``/``expires_at`` = now / now + 60 s);
- confirm atomically CLAIMS the row with a conditional UPDATE
  (``consumed_at IS NULL``) inside the SAME transaction that creates the
  task — a replay after a successful confirm matches zero rows and is
  rejected (409 preview_stale, reason=already used); a rolled-back confirm
  un-consumes automatically because the claim is in the task's transaction;
- the CHECK constraint ties ``consumed_at`` to ``consumed_by_task_id`` so a
  consumed row always names the task that consumed it.

The table is purgeable exactly like the DATA_MODEL.md §10 set: its rows only
cover the token window (60 s) plus a short retention margin, so the
maintenance sweep removes them after a 1-hour lifetime. To let that sweep run
as ``warden_app`` (the 0008 ownership model — DELETE is an ownership
privilege), 0010 transfers OWNERSHIP to warden_app and re-runs the 0009
convention grant block (point-in-time GRANTs never reach tables created
afterwards, so every creating migration must end with it; the append-only
pair audit_logs / operation_task_events is untouched — the REVOKEs below
re-assert their protection AFTER the blanket grant, per 0009).

Deployment consequence: identical to 0008 — the production init script
already grants warden_app CREATE on schema public and ``GRANT warden_app TO
warden_migrate`` for 0008, which is also what the ALTER OWNER here needs;
dev/test run as superuser and bypass both checks.

Rollback plan: downgrade drops the table (its grants and the ownership
transfer disappear with the object). Data validation: the CHECK constraint
plus the FK to operation_tasks (ON DELETE CASCADE — consumed rows name only
evented tasks, which the retention sweep never deletes; CASCADE keeps a task
purge from ever blocking on a stale ledger row). Space estimate: one bounded
row per preview token, 1-hour lifetime — no capacity promises (ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_preview_token_uses"
down_revision = "0009_schema_wide_grants"
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
        "preview_token_uses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by_task_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "(consumed_at IS NULL AND consumed_by_task_id IS NULL) OR "
            "(consumed_at IS NOT NULL AND consumed_by_task_id IS NOT NULL)",
            name="ck_preview_token_uses_consumed",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["consumed_by_task_id"], ["operation_tasks.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_preview_token_uses_token_hash"),
    )
    op.create_index("ix_preview_token_uses_expires_at", "preview_token_uses", ["expires_at"])

    # 0008/0009 privilege model: warden_app OWNS the purgeable table so the
    # retention sweep (runs as warden_app) can DELETE expired ledger rows;
    # the 0009 convention block re-grants S/I/U point-in-time and re-asserts
    # the append-only REVOKE AFTER the blanket grant (0009 posture).
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    op.execute(f"ALTER TABLE preview_token_uses OWNER TO {WARDEN_APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};")

    # Verification (warn, never fail — 0004 posture): the ledger must be
    # owned by warden_app (sweep purge) and the append-only pair must keep
    # its protection.
    op.execute(
        f"""
        DO $$
        DECLARE
            ledger_owner text;
        BEGIN
            SELECT pg_get_userbyid(relowner) INTO ledger_owner
            FROM pg_class WHERE oid = 'preview_token_uses'::regclass;
            IF ledger_owner IS DISTINCT FROM '{WARDEN_APP_ROLE}' THEN
                RAISE WARNING USING MESSAGE =
                    'preview_token_uses is not owned by warden_app (owner: ' ||
                    COALESCE(ledger_owner, '<missing>') || '): the retention '
                    'sweep cannot purge expired preview tokens — re-run the '
                    'migration after provisioning';
            END IF;
            IF COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app still has UPDATE or DELETE on the append-only '
                    'streams (audit_logs / operation_task_events): the 0010 '
                    'REVOKE did not win over the blanket grant';
            END IF;
        END
        $$;
        """  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; no user input
    )


def downgrade() -> None:
    op.drop_index("ix_preview_token_uses_expires_at", table_name="preview_token_uses")
    op.drop_table("preview_token_uses")
