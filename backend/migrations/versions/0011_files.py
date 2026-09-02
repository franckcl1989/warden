"""Controlled file layer: files / file_links / device_file_tickets (M2T5).

PLT-06 受控文件 (docs/API_CONTRACT.md §8, DATA_MODEL.md §8, SECURITY.md §9,
ARCHITECTURE.md §3.6): uploads (session -> streamed content -> complete with
hash verification), sensitive types encrypted at rest with AES-GCM per-file
keys wrapped by the file master key, permissioned downloads, DB-backed
device-pull tickets and file_links binding files to tasks/devices.

Ownership/grants follow the 0010 convention exactly:

- ``files`` is PURGEABLE: the retention sweep runs as ``warden_app`` and
  must UPDATE rows (30-day logical delete of support bundles/operation logs,
  config-backup keep-10/90 prune, abandoned-upload close-out) — UPDATE comes
  from the 0009-style blanket S/I/U grant; the sweep never row-deletes
  ``files`` (rows are the audit-visible lifecycle; only the physical bytes
  leave via the delayed cleanup, SECURITY.md §9: 物理清理前检查任务引用并写审
  计).
- ``file_links`` rows are history (never purged by 0.1.0 retention) but sit
  in the same grant posture.
- ``device_file_tickets`` is purgeable: expired tickets are row-deleted by
  the sweep, which needs DELETE — that comes from OWNERSHIP (0008 model), so
  the table is transferred to ``warden_app`` like 0010's ledger.
- The migration ends with the 0009 convention grant block (point-in-time
  GRANTs never reach tables created afterwards) and RE-ASSERTS the
  append-only pair REVOKEs AFTER the blanket grant, exactly like 0010.

Rollback plan: downgrade drops the three tables (grants and ownership
disappear with the objects). Data validation: CHECK constraints below mirror
the model in ``app/models/files.py``; FKs: files.uploaded_by RESTRICT (users
are never deleted), file_links.device_id RESTRICT, file_links.task_id and
tickets.created_by_task_id CASCADE (a purged eventless terminal task must
never be blocked by stale links — 0010 pattern). Space estimate: one row per
file/link/ticket — bounded by actual file volume; no capacity promises
(ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_files"
down_revision = "0010_preview_token_uses"
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
        "files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_type", sa.String(length=32), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        # Content SHA-256, set atomically with sha256 at upload complete —
        # uploading sessions carry no hash yet (NULL allowed until ready).
        sa.Column("storage_name", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=128), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "storage_backend",
            sa.String(length=32),
            nullable=False,
            server_default="local-volume",
        ),
        sa.Column("encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("key_version", sa.Integer(), nullable=True),
        sa.Column("uploaded_by", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="uploading",
        ),
        sa.Column(
            "metadata",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "file_type IN ('firmware', 'virtual_media', 'support_bundle', "
            "'config_backup', 'operation_log')",
            name="ck_files_file_type",
        ),
        sa.CheckConstraint(
            "status IN ('uploading', 'ready', 'quarantined', 'deleted')",
            name="ck_files_status",
        ),
        sa.CheckConstraint("size_bytes > 0", name="ck_files_size_bytes"),
        sa.CheckConstraint(
            "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'", name="ck_files_sha256"
        ),
        sa.CheckConstraint(
            "storage_name IS NULL OR storage_name ~ '^[0-9a-f]{64}$'",
            name="ck_files_storage_name",
        ),
        sa.CheckConstraint(
            "(encrypted = false AND key_version IS NULL) OR "
            "(encrypted = true AND key_version IS NOT NULL)",
            name="ck_files_encryption",
        ),
        sa.CheckConstraint("version >= 1", name="ck_files_version"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_files_status_created", "files", ["status", "created_at"])
    op.create_index("ix_files_type_status", "files", ["file_type", "status"])
    op.create_index("ix_files_uploaded_by_created", "files", ["uploaded_by", "created_at"])
    op.create_index("ix_files_storage_name", "files", ["storage_name"])

    op.create_table(
        "file_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "purpose IN ('input_firmware', 'input_virtual_media', 'output_support_bundle', "
            "'output_config_backup', 'output_operation_log')",
            name="ck_file_links_purpose",
        ),
        sa.CheckConstraint(
            "device_id IS NOT NULL OR task_id IS NOT NULL",
            name="ck_file_links_target",
        ),
        sa.ForeignKeyConstraint(["file_id"], ["files.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["task_id"], ["operation_tasks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_file_links_file_id", "file_links", ["file_id"])
    op.create_index("ix_file_links_device_id", "file_links", ["device_id"])
    op.create_index("ix_file_links_task_id", "file_links", ["task_id"])

    op.create_table(
        "device_file_tickets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expected_ip", sa.String(length=64), nullable=False),
        sa.Column("created_by_task_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "purpose IN ('firmware', 'virtual_media')", name="ck_device_file_tickets_purpose"
        ),
        sa.CheckConstraint(
            "char_length(expected_ip) BETWEEN 7 AND 64",
            name="ck_device_file_tickets_expected_ip",
        ),
        sa.ForeignKeyConstraint(["file_id"], ["files.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["created_by_task_id"], ["operation_tasks.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_device_file_tickets_expires_at", "device_file_tickets", ["expires_at"])

    # 0010 convention: warden_app OWNS the purgeable tables (files rows get
    # retention UPDATEs; expired tickets get row-deleted by the sweep — DELETE
    # is an ownership privilege, 0008 model). The 0009 convention block
    # re-grants S/I/U point-in-time and re-asserts the append-only REVOKEs
    # AFTER the blanket grant (0009 posture).
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    op.execute(f"ALTER TABLE files OWNER TO {WARDEN_APP_ROLE};")
    op.execute(f"ALTER TABLE file_links OWNER TO {WARDEN_APP_ROLE};")
    op.execute(f"ALTER TABLE device_file_tickets OWNER TO {WARDEN_APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON operation_task_events FROM {WARDEN_APP_ROLE};")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};")

    # Verification (warn, never fail — 0004 posture): the purgeable file
    # tables must be owned by warden_app (retention UPDATE/DELETE) and the
    # append-only pair must keep its protection.
    op.execute(
        f"""
        DO $$
        DECLARE
            table_owner text;
            _table text;
        BEGIN
            FOREACH _table IN ARRAY ARRAY['files', 'file_links',
                'device_file_tickets']::text[]
            LOOP
                EXECUTE format('SELECT pg_get_userbyid(relowner) FROM pg_class '
                    'WHERE oid = %L::regclass', _table) INTO table_owner;
                IF table_owner IS DISTINCT FROM '{WARDEN_APP_ROLE}' THEN
                    RAISE WARNING USING MESSAGE =
                        _table || ' is not owned by warden_app (owner: ' ||
                        COALESCE(table_owner, '<missing>') || '): the file '
                        'retention sweep cannot update/delete — re-run the '
                        'migration after provisioning';
                END IF;
            END LOOP;
            IF COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'DELETE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'UPDATE'), TRUE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'operation_task_events', 'DELETE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app still has UPDATE or DELETE on the append-only '
                    'streams (audit_logs / operation_task_events): the 0011 '
                    'REVOKE did not win over the blanket grant';
            END IF;
        END
        $$;
        """  # noqa: S608 - interpolates only the WARDEN_APP_ROLE constant; identifiers go through format('%L')
    )


def downgrade() -> None:
    op.drop_index("ix_device_file_tickets_expires_at", table_name="device_file_tickets")
    op.drop_table("device_file_tickets")
    op.drop_index("ix_file_links_file_id", table_name="file_links")
    op.drop_index("ix_file_links_device_id", table_name="file_links")
    op.drop_index("ix_file_links_task_id", table_name="file_links")
    op.drop_table("file_links")
    op.drop_index("ix_files_status_created", table_name="files")
    op.drop_index("ix_files_type_status", table_name="files")
    op.drop_index("ix_files_uploaded_by_created", table_name="files")
    op.drop_index("ix_files_storage_name", table_name="files")
    op.drop_table("files")
