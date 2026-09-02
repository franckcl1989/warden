"""M2T8 regression: metric_points daily-partition boundary at local midnight.

Background (the UTC+8 post-midnight suite flake): a fresh warden_test
database pre-creates day partitions only for the migration-time window
(0006: ``[current_date .. current_date + 13]`` in the DB session time zone).
Tests that inserted metric_points at fixed dates (or at ``now - hours`` that
crossed the session-local day rollover) failed with ``no partition of
relation "metric_points" found for row`` as soon as the wall clock advanced
past the local day those rows belonged to — which is exactly what happens
between 00:00 and 08:00 Asia/Shanghai, when the UTC date still lags the
local date. The suite must be window-agnostic: every test creates the
partitions its own rows need, and rows outside any ensured window fail
loudly (never fabricate storage).

These tests simulate the boundary by FREEZING the clock at the two instants
that straddle a session-local midnight — local 23:59:59.9 and 00:00:00.1 of
the next local day — derived from the DB session time zone (Asia/Shanghai in
this deployment), and run the partition-sensitive flows through them:

- the maintenance window step (``ensure_partitions``) plus the real
  collection pipeline, on both sides of the midnight rollover;
- the honest no-partition failure for out-of-window rows (the old flake
  signature, now an explicit semantic);
- the retention sweep run exactly at the local-midnight instant.

The windowing contract only holds for UTC or east-of-UTC session time zones
(the deployment sets Asia/Shanghai): for a west-of-UTC session the UTC-day
window cannot cover the previous local day, so those sessions are skipped
with a message instead of asserting a property the app never promised.
"""

from __future__ import annotations

import datetime
import uuid
from types import SimpleNamespace

import pytest
from app.application.collection import run_collection
from app.application.maintenance import enforce_retention, ensure_partitions
from app.config import WardenSettings
from app.domain.adapter import Observation, ObservationBatch
from app.infrastructure.observation_store import (
    claim_collection_run,
    ensure_metric_partitions,
    persist_observation_batch,
)
from app.models.observation import MetricPoint
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from tests.observation_factories import make_collection_device, make_collection_run, make_keyring
from tests.partition_helpers import partition_name_for

# The boundary pair sits far in the past of any real wall clock, so the
# migration's future pre-created window (current_date .. +13) can never
# overlap the partitions these tests create and drop — the runs stay
# deterministic at any wall-clock time.
BACK_DAYS = 60


def _session_instant(db: Session, local_day: datetime.date, clock: str) -> datetime.datetime:
    """``local_day`` at ``clock`` as an aware instant in the DB session zone."""
    return db.execute(
        text(
            "SELECT (CAST(:d AS date) + CAST(:t AS time)) "
            "AT TIME ZONE current_setting('TimeZone')"
        ),
        {"d": local_day, "t": clock},
    ).scalar()


def _utc_day_start(instant: datetime.datetime) -> datetime.datetime:
    instant = instant.astimezone(datetime.UTC)
    return instant.replace(hour=0, minute=0, second=0, microsecond=0)


def _point_batch(now: datetime.datetime) -> ObservationBatch:
    return ObservationBatch(
        observations=(Observation("health.overall", "healthy", now, source="redfish"),),
        events=(),
        components=(),
    )


def _claim_and_run(
    db: Session, *, settings: object, now: datetime.datetime, device_id: uuid.UUID
) -> None:
    run = make_collection_run(
        db, device_id=device_id, scheduled_at=now - datetime.timedelta(seconds=1)
    )
    claimed = claim_collection_run(db, lease_owner="boundary-worker", lease_seconds=300)
    assert claimed is not None and claimed.id == run.id
    db.commit()
    run_collection(db, run.id, settings=settings, keyring=make_keyring(), now=now)
    db.commit()


def _row_partition(db: Session, device_id: uuid.UUID) -> str:
    return str(
        db.execute(
            text(
                "SELECT c.relname FROM metric_points p "
                "JOIN pg_class c ON c.oid = p.tableoid "
                "WHERE p.device_id = :did LIMIT 1"
            ),
            {"did": device_id},
        ).scalar()
    )


@pytest.fixture
def boundary(db_session: Session) -> SimpleNamespace:
    """The session-local-day boundary pair frozen at a date far in the past.

    ``before`` is local 23:59:59.9 of day X and ``after`` is local
    00:00:00.1 of day X+1 (== 23:59:59.9 / 00:00:00.1 Asia/Shanghai in this
    deployment). Both share one UTC day for UTC/east-of-UTC sessions — the
    property that lets the UTC-day-based maintenance window cover both sides
    of the local-midnight rollover.
    """
    offset_seconds = int(
        db_session.execute(text("SELECT EXTRACT(TIMEZONE FROM now())")).scalar()
    )
    if offset_seconds < 0:
        pytest.skip(
            "metric_points day-partition windows are defined for UTC/east-of-UTC "
            "sessions (deployment: Asia/Shanghai); this DB session is west of UTC"
        )
    today = db_session.execute(text("SELECT current_date")).scalar()
    day_before = today - datetime.timedelta(days=BACK_DAYS)
    day_after = day_before + datetime.timedelta(days=1)
    return SimpleNamespace(
        today=today,
        before=_session_instant(db_session, day_before, "23:59:59.9"),
        after=_session_instant(db_session, day_after, "00:00:00.1"),
    )


class TestLocalMidnightBoundary:
    def test_pipeline_rows_on_both_sides_of_local_midnight_land_in_their_day_partitions(
        self,
        db_session: Session,
        db_settings: object,
        boundary: SimpleNamespace,
    ) -> None:
        # The daily maintenance rolls the future window from the UTC date of
        # its clock read (ensure_partitions: start_date = now.date()). The two
        # boundary instants share one UTC day (UTC/east-of-UTC sessions), so
        # the windows ensured at that day's UTC midnight must cover rows
        # observed on BOTH sides of the local-midnight rollover.
        utc_days = {_utc_day_start(boundary.before), _utc_day_start(boundary.after)}
        created = 0
        for day_start in utc_days:
            created += ensure_partitions(db_session, now=day_start)
        db_session.commit()
        assert created == 14 * len(utc_days)  # fully in the past: nothing pre-created

        device_before = make_collection_device(db_session, index=75, next_poll_at=None)
        device_after = make_collection_device(db_session, index=76, next_poll_at=None)
        _claim_and_run(db_session, settings=db_settings, now=boundary.before, device_id=device_before.id)
        _claim_and_run(db_session, settings=db_settings, now=boundary.after, device_id=device_after.id)

        before_partition = _row_partition(db_session, device_before.id)
        after_partition = _row_partition(db_session, device_after.id)
        assert before_partition == partition_name_for(db_session, boundary.before)
        assert after_partition == partition_name_for(db_session, boundary.after)
        assert before_partition != after_partition  # the rollover moved the day
        assert before_partition.startswith("metric_points_")

    def test_out_of_window_rows_fail_honestly_on_both_sides_of_midnight(
        self,
        db_session: Session,
        boundary: SimpleNamespace,
    ) -> None:
        # A freshly migrated DB pre-creates only [current_date .. +13]. Rows
        # observed in earlier session-local days — the exact signature of the
        # old post-midnight flake — must fail loudly, never fabricate
        # storage; a test that needs such rows creates their partitions
        # explicitly (see the module autouse windows of test_collection,
        # test_observation_store and test_metrics_api).
        for index, instant in enumerate((boundary.before, boundary.after)):
            device = make_collection_device(db_session, index=80 + index, next_poll_at=None)
            run = make_collection_run(db_session, device_id=device.id)
            with pytest.raises(SQLAlchemyError):
                persist_observation_batch(
                    db_session,
                    device_id=device.id,
                    batch=_point_batch(instant),
                    run_id=run.id,
                    now=instant,
                )
                db_session.commit()
            db_session.rollback()

    def test_retention_at_local_midnight_drops_only_fully_old_partitions(
        self,
        db_session: Session,
        boundary: SimpleNamespace,
    ) -> None:
        # raw_retention_days = 7, sweep at local 00:00:00.1: a partition is
        # dropped when its range END (the next local midnight) is at/before
        # the cutoff. The partition whose day straddles the cutoff is kept
        # whole (DATA_MODEL.md §10: day granularity is the documented
        # precision) even though part of its local day precedes the cutoff.
        settings = WardenSettings(_env_file=None)
        today = boundary.today
        span_start = today - datetime.timedelta(days=10)
        created = ensure_metric_partitions(db_session, start_date=span_start, days=10)
        db_session.commit()
        assert created == 10  # all before the migration window: none existed

        device = make_collection_device(db_session, index=77, next_poll_at=None)

        def _seed_point(observed_at: datetime.datetime, value: float) -> None:
            db_session.add(
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device.id,
                    component_id=None,
                    metric_key="system.cpu_percent",
                    observed_at=observed_at,
                    value_double=value,
                    unit="%",
                    quality="good",
                    source="redfish",
                )
            )

        kept_instant = _session_instant(db_session, today - datetime.timedelta(days=7), "23:59:59.9")
        dropped_instant = _session_instant(db_session, today - datetime.timedelta(days=8), "23:59:59.9")
        _seed_point(kept_instant, 1.0)
        _seed_point(dropped_instant, 2.0)
        db_session.commit()

        boundary_now = _session_instant(db_session, today, "00:00:00.1")
        report = enforce_retention(db_session, now=boundary_now, settings=settings)
        db_session.commit()

        expected_dropped = {
            f"metric_points_{(today - datetime.timedelta(days=days)).strftime('%Y_%m_%d')}"
            for days in (8, 9, 10)
        }
        assert set(report.partitions_dropped) == expected_dropped
        # The kept row (day today-7, whose partition straddles the cutoff) is
        # still readable; the older row left with its whole partition.
        remaining = db_session.scalars(
            select(MetricPoint.value_double)
            .where(MetricPoint.device_id == device.id)
            .order_by(MetricPoint.value_double)
        ).all()
        assert remaining == [1.0]
