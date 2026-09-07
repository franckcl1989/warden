"""Maintenance-mode state and ingest heartbeat (M6T3b, PLT-08).

docs/DEPLOYMENT.md §8: maintenance mode is a HOST-CLI state persisted in the
single-row ``system_state`` table — the Web API/UI only read it (ADR-026;
SECURITY.md: the CLI runs only on the deployment host). This module is the
application-layer implementation of the transition semantics (used by tests
and in-container tooling); the ``warden maintenance on|off`` host CLI
(deployment/scripts/warden) applies the SAME semantics with plain SQL against
the same table shape — including the audit row and the
``system.status_changed`` ui_event so SSE clients refresh immediately
(API_CONTRACT.md §10).

Semantics (documented decisions):

- ``get_system_state`` reads the single row; an absent row (table never
  written — fresh install before first use) reads as maintenance OFF.
- ``enter_maintenance``/``exit_maintenance`` upsert the single row (id = 1),
  append an audit row (action ``maintenance.on``/``maintenance.off``,
  resource_type ``system_state``, resource_id ``maintenance_mode``, NO actor
  — the transition is host-CLI driven so ``actor_user_id`` stays NULL and
  ``detail`` carries ``{"source": "deployment_cli", ...}``) and write one
  ``system.status_changed`` ui_event — all in the CALLER's transaction
  (DATA_MODEL.md §11: state + audit + ui_event commit together).
- ``record_ingest_heartbeat`` advances the single-row ingest_heartbeat:
  ``events_received_total += delta`` (durable across ingest restarts),
  ``last_received_at`` advances only when the flush carries events (a site
  with no configured events keeps it NULL and is NOT reported degraded —
  documented idle semantics), and ``updated_at`` is stamped on every call as
  the process-alive signal for GET /system/status (ARCHITECTURE.md §9).
  Single-row atomic upsert: safe from any thread/process.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.infrastructure.time import utcnow
from app.models.auth import AuditLog
from app.models.observation import UiEvent
from app.models.system import (
    INGEST_HEARTBEAT_ROW_ID,
    SYSTEM_STATE_ROW_ID,
    IngestHeartbeat,
    SystemState,
)

# Support id for platform-state rows (docs/TRACEABILITY.md PLT-08:
# 私有部署与必要运行状态).
PLT_08 = "PLT-08"

MAINTENANCE_ON_ACTION = "maintenance.on"
MAINTENANCE_OFF_ACTION = "maintenance.off"

SYSTEM_UI_EVENT = "system.status_changed"
SYSTEM_UI_ENTITY = "system"

# The source marker the transition audit rows carry: maintenance toggles are
# host-CLI driven (ADR-026 — no Web API/UI switch exists), so the audit
# ``actor_user_id`` stays NULL and the caller source is recorded in detail.
HOST_CLI_SOURCE = "deployment_cli"


@dataclass(frozen=True)
class SystemStateView:
    """Read model of the maintenance state (absent row = OFF)."""

    maintenance_mode: bool = False
    maintenance_since: datetime.datetime | None = None
    maintenance_reason: str | None = None
    updated_at: datetime.datetime | None = None


def get_system_state(db: Session) -> SystemStateView:
    """Read the single-row system state (absent row reads as OFF).

    Reads with populate_existing: the row is written by bulk upserts (and by
    the host CLI's own connection) that bypass the ORM unit of work, so the
    identity map can hold a stale copy — the database row is the truth.
    """
    row = db.scalar(
        select(SystemState).where(SystemState.id == SYSTEM_STATE_ROW_ID).execution_options(populate_existing=True)
    )
    if row is None:
        return SystemStateView()
    return SystemStateView(
        maintenance_mode=bool(row.maintenance_mode),
        maintenance_since=row.maintenance_since,
        maintenance_reason=row.maintenance_reason,
        updated_at=row.updated_at,
    )


def maintenance_active(db: Session) -> bool:
    """True while maintenance mode is on (used by the API request gate)."""
    return get_system_state(db).maintenance_mode


def _upsert_state(
    db: Session,
    *,
    maintenance_mode: bool,
    reason: str | None,
    since: datetime.datetime | None,
    now: datetime.datetime,
) -> None:
    db.execute(
        pg_insert(SystemState)
        .values(
            id=SYSTEM_STATE_ROW_ID,
            maintenance_mode=maintenance_mode,
            maintenance_since=since,
            maintenance_reason=reason,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[SystemState.id],
            set_={
                "maintenance_mode": pg_insert(SystemState).excluded.maintenance_mode,
                "maintenance_since": pg_insert(SystemState).excluded.maintenance_since,
                "maintenance_reason": pg_insert(SystemState).excluded.maintenance_reason,
                "updated_at": pg_insert(SystemState).excluded.updated_at,
            },
        )
    )


def _append_transition_audit(
    db: Session,
    *,
    action: str,
    enabled: bool,
    since: datetime.datetime | None,
    reason: str | None,
    source: str,
) -> None:
    """Append the host-CLI transition audit row (append-only, no actor)."""
    detail: dict[str, object] = {"source": source, "maintenance_enabled": enabled}
    if since is not None:
        detail["maintenance_since"] = since.isoformat()
    if reason:
        detail["maintenance_reason"] = reason
    db.add(
        AuditLog(
            action=action,
            resource_type="system_state",
            resource_id="maintenance_mode",
            requirement_id=PLT_08,
            result="success",
            detail_jsonb=detail,
        )
    )


def _append_status_changed_ui_event(db: Session) -> None:
    """One system.status_changed SSE payload in the caller's transaction."""
    db.add(
        UiEvent(
            entity_type=SYSTEM_UI_ENTITY,
            entity_id=None,
            version=1,
            event_type=SYSTEM_UI_EVENT,
            payload={},
        )
    )


def enter_maintenance(
    db: Session,
    *,
    reason: str | None = None,
    now: datetime.datetime | None = None,
    source: str = HOST_CLI_SOURCE,
) -> None:
    """Turn maintenance mode on (the caller commits).

    ``maintenance_since`` is stamped at the transition; each CLI
    ``maintenance on`` starts a maintenance window (re-entry refreshes the
    stamp).
    """
    timestamp = now if now is not None else utcnow()
    _upsert_state(
        db,
        maintenance_mode=True,
        reason=reason,
        since=timestamp,
        now=timestamp,
    )
    _append_transition_audit(
        db,
        action=MAINTENANCE_ON_ACTION,
        enabled=True,
        since=timestamp,
        reason=reason,
        source=source,
    )
    _append_status_changed_ui_event(db)


def exit_maintenance(
    db: Session,
    *,
    now: datetime.datetime | None = None,
    source: str = HOST_CLI_SOURCE,
) -> None:
    """Turn maintenance mode off (the caller commits); clears since/reason."""
    timestamp = now if now is not None else utcnow()
    _upsert_state(
        db,
        maintenance_mode=False,
        reason=None,
        since=None,
        now=timestamp,
    )
    _append_transition_audit(
        db,
        action=MAINTENANCE_OFF_ACTION,
        enabled=False,
        since=None,
        reason=None,
        source=source,
    )
    _append_status_changed_ui_event(db)


def record_ingest_heartbeat(
    db: Session,
    *,
    events_received_delta: int = 0,
    received_at: datetime.datetime | None = None,
    now: datetime.datetime | None = None,
) -> None:
    """Advance the single-row ingest heartbeat (the caller commits)."""
    timestamp = now if now is not None else utcnow()
    db.execute(
        pg_insert(IngestHeartbeat)
        .values(
            id=INGEST_HEARTBEAT_ROW_ID,
            events_received_total=events_received_delta,
            last_received_at=received_at,
            updated_at=timestamp,
        )
        .on_conflict_do_update(
            index_elements=[IngestHeartbeat.id],
            set_={
                "events_received_total": IngestHeartbeat.events_received_total
                + pg_insert(IngestHeartbeat).excluded.events_received_total,
                "last_received_at": func.coalesce(
                    pg_insert(IngestHeartbeat).excluded.last_received_at,
                    IngestHeartbeat.last_received_at,
                ),
                "updated_at": pg_insert(IngestHeartbeat).excluded.updated_at,
            },
        )
    )


def get_ingest_heartbeat(
    db: Session,
) -> tuple[int, datetime.datetime | None, datetime.datetime | None]:
    """(events_received_total, last_received_at, updated_at); absent row -> zeros.

    Fresh read (populate_existing): the row is advanced by bulk upserts from
    another process/thread (the ingest consumer), never by ORM instances.
    """
    row = db.scalar(
        select(IngestHeartbeat)
        .where(IngestHeartbeat.id == INGEST_HEARTBEAT_ROW_ID)
        .execution_options(populate_existing=True)
    )
    if row is None:
        return 0, None, None
    return int(row.events_received_total), row.last_received_at, row.updated_at
