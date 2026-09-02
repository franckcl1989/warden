"""Database account least privilege and audit_logs permission hardening.

docs/SECURITY.md §11/§12, DATA_MODEL.md §9.1, DEPLOYMENT.md §5, M1T4.

Production creates the two roles BEFORE this migration runs: the deployment
postgres-init script (``deployment/postgres-init/01-accounts.sh``) reads the
app/migrate DSN secrets and creates ``warden_app`` / ``warden_migrate`` with
real passwords. The migration therefore does NOT hardcode passwords — the
``DO $$`` blocks only create the roles when they are missing (dev/test, where
the test fixture creates ``warden_app`` itself), and ``ALTER ROLE`` is guarded
so it only runs when the executing user has CREATEROLE (superuser in
dev/test; the production migrate account is already created least-privilege
by the init script).

Grants (idempotent):

- ``warden_app`` (the application DSN account): USAGE on schema public,
  SELECT/INSERT/UPDATE on all tables, USAGE on all sequences — and an
  explicit ``REVOKE UPDATE, DELETE ON audit_logs`` (SECURITY.md §12: 审计在
  应用权限层只追加，并限制数据库应用账号的更新/删除权限). The append-only
  trigger from 0002 stays as belt-and-braces: it rejects even privileged
  roles; the permission layer protects the app account itself.
- ``warden_migrate`` (the migration account): CREATE/USAGE on schema public
  (it owns the schema/migrations), never the application DSN.

The GRANTs above are best-effort: PostgreSQL silently grants nothing when the
executing account is not the object owner and lacks GRANT OPTION — the state
when the migrate account runs without the deployment init script (manual
restore, changed install path). The migration therefore ends with a privilege
verification (``has_schema_privilege`` / ``has_table_privilege``) that
``RAISE WARNING`` when ``warden_app`` lacks schema USAGE or ``audit_logs``
INSERT, or still has UPDATE on ``audit_logs``. It never fails the migration:
the authoritative provisioning path is the deployment init script
(``deployment/postgres-init/01-accounts.sh``), which must run before the
migrate container.

``audit_logs.result`` is widened 16→32 so security events can record the
stable error code ``permission_denied`` without truncation; varchar widening
is metadata-only on PostgreSQL (no table rewrite, fully additive).

Rollback plan: downgrade revokes the grants and reverts the width; the roles
are cluster-level resources whose lifecycle belongs to the deployment, so
they are NOT dropped. Data validation: no data is touched. Space estimate:
none.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_audit_db_permissions"
down_revision = "0003_devices_creds_caps"
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
    _ensure_role(WARDEN_APP_ROLE)
    _ensure_role(WARDEN_MIGRATE_ROLE)
    # Enforce least privilege on warden_app whenever the current user may
    # (dev/test superuser); production already creates it least-privilege and
    # the migrate account cannot ALTER ROLE.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolcreaterole AND rolname = current_user) THEN
                ALTER ROLE {WARDEN_APP_ROLE} NOSUPERUSER NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {WARDEN_APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    # DEFINITIVE: the app account must never update or delete audit rows.
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {WARDEN_APP_ROLE};")
    op.execute(f"GRANT CREATE, USAGE ON SCHEMA public TO {WARDEN_MIGRATE_ROLE};")
    # Verification (best-effort grants may silently grant nothing): when the
    # migrate account lacks GRANT OPTION (production unless the deployment
    # init script provisioned privileges first), the GRANTs above are silent
    # no-ops. Warn — never fail — so a broken app account cannot pass
    # unnoticed; the init script is the production source of truth.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{WARDEN_APP_ROLE}')
               OR NOT COALESCE(has_schema_privilege('{WARDEN_APP_ROLE}', 'public', 'USAGE'), FALSE)
               OR NOT COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'INSERT'), FALSE)
               OR COALESCE(has_table_privilege('{WARDEN_APP_ROLE}', 'audit_logs', 'UPDATE'), TRUE)
            THEN
                RAISE WARNING USING MESSAGE =
                    'warden_app privilege state is missing (want USAGE on schema public, '
                    'INSERT on audit_logs, no UPDATE on audit_logs): provision the app account '
                    'via deployment/postgres-init/01-accounts.sh, then re-run the migration; '
                    'the app account will fail at runtime without these privileges';
            END IF;
        END
        $$;
        """
    )

    op.alter_column(
        "audit_logs",
        "result",
        existing_type=sa.String(length=16),
        type_=sa.String(length=32),
        existing_server_default="success",
        existing_nullable=False,
        nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "audit_logs",
        "result",
        existing_type=sa.String(length=32),
        type_=sa.String(length=16),
        existing_server_default="success",
        existing_nullable=False,
        nullable=False,
    )
    op.execute(f"REVOKE CREATE, USAGE ON SCHEMA public FROM {WARDEN_MIGRATE_ROLE};")
    op.execute(f"REVOKE USAGE ON ALL SEQUENCES IN SCHEMA public FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public FROM {WARDEN_APP_ROLE};")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {WARDEN_APP_ROLE};")
