"""Append-only audit enforcement on the real PostgreSQL (TEST_STRATEGY §2.2).

The table must accept inserts but reject updates and deletes both through the
database trigger and through the ORM model listeners.
"""

from __future__ import annotations

import pytest
from app.models.auth import AuditAppendOnlyError, AuditLog
from sqlalchemy import delete, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


def _insert_audit_row(db: Session, *, action: str = "test.action") -> AuditLog:
    row = AuditLog(action=action, result="success", detail_jsonb={"note": "x"})
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@pytest.mark.integration
def test_audit_insert_works(db_session: Session) -> None:
    row = _insert_audit_row(db_session)
    assert row.id is not None
    assert row.action == "test.action"


@pytest.mark.integration
def test_audit_update_rejected_by_database_trigger(db_session: Session) -> None:
    _insert_audit_row(db_session)
    with pytest.raises(SQLAlchemyError):
        db_session.execute(update(AuditLog).where(AuditLog.action == "test.action").values(result="hacked"))
        db_session.commit()


@pytest.mark.integration
def test_audit_delete_rejected_by_database_trigger(db_session: Session) -> None:
    _insert_audit_row(db_session)
    with pytest.raises(SQLAlchemyError):
        db_session.execute(delete(AuditLog).where(AuditLog.action == "test.action"))
        db_session.commit()


@pytest.mark.integration
def test_audit_orm_update_rejected_by_model(db_session: Session) -> None:
    row = _insert_audit_row(db_session)
    row.action = "tampered"
    with pytest.raises(AuditAppendOnlyError):
        db_session.commit()
    db_session.rollback()
    # The row is untouched.
    fresh = db_session.get(AuditLog, row.id)
    assert fresh is not None and fresh.action == "test.action"


@pytest.mark.integration
def test_audit_orm_delete_rejected_by_model(db_session: Session) -> None:
    row = _insert_audit_row(db_session)
    db_session.delete(row)
    with pytest.raises(AuditAppendOnlyError):
        db_session.commit()
    db_session.rollback()
    assert db_session.get(AuditLog, row.id) is not None


@pytest.mark.integration
def test_audit_raw_sql_update_rejected(db_session: Session) -> None:
    _insert_audit_row(db_session)
    with pytest.raises(SQLAlchemyError):
        db_session.execute(text("UPDATE audit_logs SET result = 'hacked' WHERE action = 'test.action'"))
        db_session.commit()


@pytest.mark.integration
def test_audit_rows_survive_until_365_days_retention_is_out_of_scope(db_session: Session) -> None:
    # Smoke: the append-only contract keeps history; retention (365 days) is a
    # cleanup job concern, not part of this milestone.
    row = _insert_audit_row(db_session, action="keep.me")
    assert db_session.scalar(text("SELECT count(*) FROM audit_logs WHERE action = 'keep.me'")) == 1
    assert row.occurred_at is not None
