"""Maintenance-mode state + ingest heartbeat (M6T3b, PLT-08).

Application-layer semantics of migration 0015 on the real PostgreSQL:
single-row system_state transitions with audit + system.status_changed
ui_event in the caller's transaction, and the single-row ingest heartbeat
upsert (durable counter, last_received only on events, updated_at = process
stamp). Support: PLT-08（私有部署与必要运行状态）.
"""

from __future__ import annotations

import datetime

import pytest
from app.application.system_state import (
    MAINTENANCE_OFF_ACTION,
    MAINTENANCE_ON_ACTION,
    SYSTEM_UI_EVENT,
    enter_maintenance,
    exit_maintenance,
    get_ingest_heartbeat,
    get_system_state,
    maintenance_active,
    record_ingest_heartbeat,
)
from app.models.auth import AuditLog
from app.models.observation import UiEvent
from app.models.system import IngestHeartbeat, SystemState
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

UTC = datetime.UTC

PLT_08 = "PLT-08"


@pytest.mark.integration
def test_absent_state_row_reads_as_off(db_session: Session) -> None:
    state = get_system_state(db_session)
    assert state.maintenance_mode is False
    assert state.maintenance_since is None
    assert state.maintenance_reason is None
    assert maintenance_active(db_session) is False


@pytest.mark.integration
def test_enter_and_exit_maintenance_round_trip(db_session: Session) -> None:
    now = datetime.datetime(2026, 9, 7, 8, 0, 0, tzinfo=UTC)
    enter_maintenance(db_session, reason="升级维护窗口", now=now)
    db_session.commit()

    rows = db_session.scalars(select(SystemState)).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.id == 1
    assert row.maintenance_mode is True
    assert row.maintenance_since == now
    assert row.maintenance_reason == "升级维护窗口"

    state = get_system_state(db_session)
    assert state.maintenance_mode is True
    assert maintenance_active(db_session) is True

    exit_maintenance(db_session, now=now + datetime.timedelta(minutes=30))
    db_session.commit()
    refreshed = get_system_state(db_session)
    assert refreshed.maintenance_mode is False
    assert refreshed.maintenance_since is None
    assert refreshed.maintenance_reason is None
    assert len(db_session.scalars(select(SystemState)).all()) == 1


@pytest.mark.integration
def test_single_row_constraint_rejects_second_row(db_session: Session) -> None:
    db_session.add(SystemState(id=1, maintenance_mode=False))
    db_session.commit()
    db_session.add(SystemState(id=2, maintenance_mode=False))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.integration
def test_transitions_write_audit_and_sse_ui_event(db_session: Session) -> None:
    now = datetime.datetime(2026, 9, 7, 9, 0, 0, tzinfo=UTC)
    enter_maintenance(db_session, reason="升级", now=now)
    exit_maintenance(db_session, now=now + datetime.timedelta(minutes=10))
    db_session.commit()

    audit_rows = db_session.scalars(
        select(AuditLog)
        .where(AuditLog.action.in_((MAINTENANCE_ON_ACTION, MAINTENANCE_OFF_ACTION)))
        .order_by(AuditLog.occurred_at)
    ).all()
    assert [row.action for row in audit_rows] == [MAINTENANCE_ON_ACTION, MAINTENANCE_OFF_ACTION]
    for audit in audit_rows:
        assert audit.actor_user_id is None
        assert audit.session_id is None
        assert audit.resource_type == "system_state"
        assert audit.resource_id == "maintenance_mode"
        assert audit.requirement_id == PLT_08
        assert audit.result == "success"
        assert audit.detail_jsonb.get("source") == "deployment_cli"
    assert audit_rows[0].detail_jsonb.get("maintenance_enabled") is True
    assert audit_rows[0].detail_jsonb.get("maintenance_since") == "2026-09-07T09:00:00+00:00"
    assert audit_rows[0].detail_jsonb.get("maintenance_reason") == "升级"
    assert audit_rows[1].detail_jsonb.get("maintenance_enabled") is False
    assert "maintenance_since" not in audit_rows[1].detail_jsonb

    ui_events = db_session.scalars(select(UiEvent).where(UiEvent.event_type == SYSTEM_UI_EVENT)).all()
    assert len(ui_events) == 2
    assert all(event.entity_type == "system" for event in ui_events)
    assert all(event.entity_id is None for event in ui_events)


@pytest.mark.integration
def test_heartbeat_idle_stamp_and_event_accumulation(db_session: Session) -> None:
    t0 = datetime.datetime(2026, 9, 7, 10, 0, 0, tzinfo=UTC)

    # Idle stamp (no events): row exists, last_received_at stays NULL.
    record_ingest_heartbeat(db_session, now=t0)
    db_session.commit()
    total, last_received, updated = get_ingest_heartbeat(db_session)
    assert total == 0
    assert last_received is None
    assert updated == t0

    # Event flush: counter accumulates durably, last_received advances.
    record_ingest_heartbeat(
        db_session,
        events_received_delta=3,
        received_at=t0 + datetime.timedelta(seconds=5),
        now=t0 + datetime.timedelta(seconds=5),
    )
    record_ingest_heartbeat(
        db_session,
        events_received_delta=2,
        received_at=t0 + datetime.timedelta(seconds=9),
        now=t0 + datetime.timedelta(seconds=9),
    )
    db_session.commit()
    total, last_received, updated = get_ingest_heartbeat(db_session)
    assert total == 5
    assert last_received == t0 + datetime.timedelta(seconds=9)
    assert updated == t0 + datetime.timedelta(seconds=9)

    # Idle stamp after events keeps the counter and last_received.
    record_ingest_heartbeat(db_session, now=t0 + datetime.timedelta(minutes=1))
    db_session.commit()
    total, last_received, updated = get_ingest_heartbeat(db_session)
    assert total == 5
    assert last_received == t0 + datetime.timedelta(seconds=9)

    # Exactly one row ever exists.
    row_count = db_session.scalar(select(func.count()).select_from(IngestHeartbeat))
    assert row_count == 1


@pytest.mark.integration
def test_heartbeat_rejects_second_row(db_session: Session) -> None:
    record_ingest_heartbeat(db_session)
    db_session.commit()
    db_session.add(IngestHeartbeat(id=2, events_received_total=0))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
