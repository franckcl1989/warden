"""SQLAlchemy engine/session factory and database readiness probe.

The codebase uses a synchronous engine over the psycopg (v3) driver against
PostgreSQL 18 (docs/TEST_STRATEGY.md §2.2: real PostgreSQL only, no SQLite).
DSNs arrive from ``WardenSettings.database_url``; they are never logged and
never rendered with their password visible. Every connection in the API,
worker and migration harness goes through this module so driver/URL handling
stays in one place.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.readiness import ProbeResult

POSTGRES_DRIVER_SCHEME = "postgresql+psycopg"

# Deployment DSNs are plain postgresql:// URLs; SQLAlchemy needs an explicit
# driver. A short connect timeout keeps /health/ready honest instead of
# hanging on an unreachable database host.
_CONNECT_TIMEOUT_SECONDS = 5


def dsn_with_psycopg_dialect(dsn: str) -> str:
    """Return ``dsn`` rewritten to the psycopg3 dialect.

    ``postgresql://`` / ``postgres://`` map to ``postgresql+psycopg://``;
    already-qualified DSNs pass through unchanged; anything else is rejected.
    """
    parts = urlsplit(dsn)
    if parts.scheme.lower() in ("postgresql", "postgres"):
        return urlunsplit(
            (POSTGRES_DRIVER_SCHEME, parts.netloc, parts.path, parts.query, parts.fragment)
        )
    if parts.scheme.lower() == POSTGRES_DRIVER_SCHEME:
        return dsn
    msg = f"Unsupported database scheme: {parts.scheme}"
    raise ValueError(msg)


def create_db_engine(dsn: str) -> Engine:
    """Create the application engine for ``dsn`` (lazy: no connection yet)."""
    return create_engine(
        dsn_with_psycopg_dialect(dsn),
        pool_pre_ping=True,
        connect_args={"connect_timeout": _CONNECT_TIMEOUT_SECONDS},
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create the ORM session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False)


def ping(engine: Engine) -> bool:
    """Return True when ``SELECT 1`` succeeds on a fresh connection."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False
    return True


@dataclass(frozen=True)
class DatabaseProbe:
    """Readiness probe reporting whether PostgreSQL is connectable.

    The synchronous ``ping`` runs in a worker thread so the async health
    endpoint never blocks the event loop.
    """

    engine: Engine
    name: str = "postgres"

    async def check(self) -> ProbeResult:
        ok = await asyncio.to_thread(ping, self.engine)
        return ProbeResult(name=self.name, ok=ok, detail="" if ok else "database unreachable")
