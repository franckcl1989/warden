"""Alembic environment wired to the Warden application settings.

The database URL always comes from ``WardenSettings.database_url``
(WARDEN_POSTGRES_DSN env var / WARDEN_POSTGRES_DSN_FILE secret file / the
repo-root .env) and is rewritten to the psycopg3 dialect, exactly like the
application engine in ``app.infrastructure.db``. Migrations run forward-only
in production (docs/DATA_MODEL.md §12); downgrades are exercised by tests.
"""

from __future__ import annotations

from logging.config import fileConfig

import app.models  # noqa: F401  (registers ORM models for autogenerate parity)
from alembic import context
from app.config import get_settings
from app.infrastructure.db import dsn_with_psycopg_dialect
from app.models.base import Base
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# configparser interpolation would eat percent signs in passwords; escape them
# so engine_from_config reads back the exact DSN.
config.set_main_option(
    "sqlalchemy.url", dsn_with_psycopg_dialect(get_settings().database_url).replace("%", "%%")
)

# Models registered in app.models (imported above via app.models.auth through
# app.models.__init__) supply the metadata for autogenerate parity checks.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (against the live database)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
