"""Partition-window helpers for tests that persist metric_points rows.

A freshly recreated warden_test database pre-creates daily metric_points
partitions ONLY for the migration-time window (migration 0006:
[current_date .. current_date + 13] in the DB session time zone). Tests that
insert metric_points at fixed or clock-relative timestamps must therefore
create the partitions their own rows need — or the suite depends on the wall
clock: rows whose session-local day has already rolled past the pre-created
window fail with ``no partition of relation "metric_points" found for row``
(the UTC+8 post-midnight suite flake, M2T8). The helpers compute the needed
day range in the DB session time zone — the SAME frame PostgreSQL uses to
route a row to its day partition — so tests stay window-agnostic under any
session time zone, not just the dev Asia/Shanghai one.
"""

from __future__ import annotations

import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session


def ensure_partitions_around(
    session: Session,
    instants: list[datetime.datetime],
    *,
    margin_days: int = 1,
) -> int:
    """Create metric_points day partitions for the session-local days of each
    instant, plus ``margin_days`` on both sides.

    Uses ``create_metric_partition`` (the same idempotent helper migration
    0006 and the daily maintenance share), so existing partitions are never
    recreated. Commits, so a later test rollback never undoes the window.
    Returns how many partitions were created.
    """
    created = 0
    for instant in instants:
        rows = session.execute(
            text(
                """
                SELECT create_metric_partition(day::date)
                FROM generate_series(
                    (:ts AT TIME ZONE current_setting('TimeZone'))::date - :margin,
                    (:ts AT TIME ZONE current_setting('TimeZone'))::date + :margin,
                    '1 day'::interval
                ) AS day
                """
            ),
            {"ts": instant, "margin": margin_days},
        ).all()
        created += sum(1 for row in rows if row[0] is True)
    session.commit()
    return created


def partition_name_for(session: Session, instant: datetime.datetime) -> str:
    """The metric_points partition name a row observed at ``instant`` routes
    to — its day in the DB session time zone (the partition-bound semantics of
    ``create_metric_partition``)."""
    name = session.execute(
        text(
            "SELECT 'metric_points_' || to_char("
            "(:ts AT TIME ZONE current_setting('TimeZone')), 'YYYY_MM_DD')"
        ),
        {"ts": instant},
    ).scalar()
    return str(name)
