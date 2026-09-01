"""Devices, encrypted credentials, discovered capabilities and components.

docs/DATA_MODEL.md §4.1-§4.4, M1T3 (PLT-02/PLT-03). The four tables land
together so device + credentials + capabilities + components are always
created/updated in one transaction (DATA_MODEL.md §11).

Design notes:

- ``devices.connection_config`` is a JSONB of non-sensitive protocol settings
  (port, TLS verification, SNMP version); credentials never live here.
- ``device_credentials.ciphertext`` is AES-256-GCM application-layer
  encryption (SECURITY.md §5); the row only stores ciphertext/nonce/
  key_version/secret_schema_version — the plaintext never touches the schema.
- ``components.status`` uses the ``component_status`` enum set from
  contracts/metrics.json (unknown/ok/warning/critical/absent); components are
  soft-retired (``retired_at``), never deleted.
- ``components`` is created now because discovery (probe) writes into it.

Rollback plan: ``downgrade`` drops components, then device_capabilities, then
device_credentials, then devices (reverse dependency order). Data validation:
the CHECK constraints (device_type/readiness/reachability/health/support_state/
status) reject out-of-contract values at the database, and unique constraints
prevent duplicate names and duplicate (device_type, management_endpoint,
adapter_key) onboarding (DATA_MODEL.md §4.1). Space estimate: four tables with
bounded text columns and two JSONB columns; per-device footprint is dominated
by connection_config + capability rows, well within the single-node baseline
(no capacity promises are made here — ADR-027).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_devices_creds_caps"
down_revision = "0002_users_sessions_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("device_type", sa.String(length=32), nullable=False),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("management_endpoint", sa.String(length=255), nullable=False),
        sa.Column("adapter_key", sa.String(length=64), nullable=False),
        sa.Column("connection_config", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("readiness", sa.String(length=16), nullable=False),
        sa.Column("reachability", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("health", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("last_known_health", sa.String(length=16), nullable=True),
        sa.Column("serial_number", sa.String(length=128), nullable=True),
        sa.Column("firmware_version", sa.String(length=64), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("device_type IN ('server', 'synology_nas', 'core_switch', 'access_switch')", name="ck_devices_device_type"),
        sa.CheckConstraint("readiness IN ('not_ready', 'ready', 'misconfigured')", name="ck_devices_readiness"),
        sa.CheckConstraint("reachability IN ('unknown', 'online', 'offline')", name="ck_devices_reachability"),
        sa.CheckConstraint("health IN ('unknown', 'healthy', 'warning', 'critical')", name="ck_devices_health"),
        sa.CheckConstraint("consecutive_failures >= 0", name="ck_devices_consecutive_failures"),
        sa.CheckConstraint("consecutive_successes >= 0", name="ck_devices_consecutive_successes"),
        sa.CheckConstraint("version >= 1", name="ck_devices_version"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_devices_name"),
        sa.UniqueConstraint("device_type", "management_endpoint", "adapter_key", name="uq_devices_type_endpoint_adapter"),
    )

    op.create_table(
        "device_credentials",
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("secret_schema_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("key_version >= 1", name="ck_device_credentials_key_version"),
        sa.CheckConstraint("secret_schema_version >= 1", name="ck_device_credentials_secret_schema_version"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("device_id"),
    )

    op.create_table(
        "device_capabilities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("capability_key", sa.String(length=64), nullable=False),
        sa.Column("support_state", sa.String(length=16), nullable=False),
        sa.Column("requirement_id", sa.String(length=32), nullable=False),
        sa.Column("discovery_method", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=32), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("adapter_version", sa.String(length=32), nullable=False),
        sa.CheckConstraint("support_state IN ('supported', 'unsupported', 'not_configured')", name="ck_device_capabilities_support_state"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "capability_key", name="uq_device_capabilities_device_key"),
    )

    op.create_table(
        "components",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("native_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("properties", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('unknown', 'ok', 'warning', 'critical', 'absent')",
            name="ck_components_status",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "kind", "native_id", name="uq_components_device_kind_native"),
    )


def downgrade() -> None:
    op.drop_table("components")
    op.drop_table("device_capabilities")
    op.drop_table("device_credentials")
    op.drop_table("devices")
