"""Partition maintenance integration tests (real PostgreSQL).

docs/DEPLOYMENT.md §9.2 (PostgreSQL 日分区未来至少预创建 14 天) + M2T3 brief:
``ensure_partitions`` keeps the future 14-day partition window; it is
idempotent (existing partitions are never recreated). Tests anchor on the
real current date because migration 0006 pre-creates today..today+13 at test
database creation.
"""

from __future__ import annotations

import datetime

from app.application.maintenance import ensure_partitions
from app.infrastructure.time import utcnow
from sqlalchemy import text
from sqlalchemy.orm import Session

UTC = datetime.UTC


def _partition_names(db_session: Session) -> set[str]:
    rows = db_session.execute(
        text(
            """
            SELECT child.relname
            FROM pg_inherits
            JOIN pg_class child ON child.oid = pg_inherits.inhrelid
            JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
            WHERE parent.relname = 'metric_points'
            """
        )
    ).all()
    return {row[0] for row in rows}


def test_ensure_partitions_creates_the_next_14_days(db_session: Session) -> None:
    # A window fully before the migration-created one (today..today+13).
    anchor = utcnow() - datetime.timedelta(days=40)
    created = ensure_partitions(db_session, now=anchor)

    assert created == 14
    names = _partition_names(db_session)
    for offset in range(14):
        day = anchor.date() + datetime.timedelta(days=offset)
        assert day.strftime("metric_points_%Y_%m_%d") in names
    assert (anchor.date() - datetime.timedelta(days=1)).strftime(
        "metric_points_%Y_%m_%d"
    ) not in names


def test_ensure_partitions_is_idempotent(db_session: Session) -> None:
    anchor = utcnow() - datetime.timedelta(days=40)
    first = ensure_partitions(db_session, now=anchor)
    second = ensure_partitions(db_session, now=anchor)

    assert first == 14
    assert second == 0


def test_ensure_partitions_extends_an_existing_window(db_session: Session) -> None:
    ensure_partitions(db_session, now=utcnow())  # migration window already there
    later = utcnow() + datetime.timedelta(days=30)
    created = ensure_partitions(db_session, now=later)

    assert created == 14
    names = _partition_names(db_session)
    assert (later.date() + datetime.timedelta(days=13)).strftime(
        "metric_points_%Y_%m_%d"
    ) in names
