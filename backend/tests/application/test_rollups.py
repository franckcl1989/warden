"""Rollup generation integration tests (real PostgreSQL).

docs/DATA_MODEL.md §5.4 + M2T3 brief: ``metric_rollups_5m`` aggregates the
closed 5-minute window from raw metric_points (numeric gauge keys only, no
state/counter averaging); ``metric_rollups_1h`` aggregates the closed hour
from the twelve closed 5-minute rows (min of mins, max of maxes, simple mean
of avgs with count sum — documented choice). Regeneration is idempotent
(ON CONFLICT DO UPDATE), window boundaries are half-open
[window_start, window_start + interval).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.application.maintenance import generate_rollups
from app.config import WardenSettings
from app.infrastructure.observation_store import ensure_metric_partitions
from app.models.devices import Component, Device
from app.models.observation import MetricPoint, MetricRollup1h, MetricRollup5m
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tests.observation_factories import make_collection_device

UTC = datetime.UTC
NOW = datetime.datetime(2026, 9, 1, 12, 3, 30, tzinfo=UTC)  # floor5 -> 12:00
# The closed 5-minute window [11:55, 12:00): the window generate_rollups
# targets at ``now=NOW``.
WINDOW5 = datetime.datetime(2026, 9, 1, 11, 55, tzinfo=UTC)
ZERO_UUID = "00000000-0000-0000-0000-000000000000"

SETTINGS = WardenSettings(_env_file=None)

GAUGE_KEY = "temperature.cpu"  # series=gauge, scope=component, unit Cel
COUNTER_KEY = "memory.ecc_errors"  # monotonic_counter — no numeric rollups
STATE_KEY = "memory.status"  # state — no numeric rollups
DEVICE_KEY = "system.cpu_percent"  # series=gauge, scope=device


def _point(
    db: Session,
    *,
    device_id: uuid.UUID,
    component_id: uuid.UUID | None,
    metric_key: str,
    observed_at: datetime.datetime,
    value_double: float | None = None,
    value_text: str | None = None,
    quality: str = "good",
) -> None:
    assert (value_double is None) != (value_text is None)
    db.add(
        MetricPoint(
            id=uuid.uuid4(),
            device_id=device_id,
            component_id=component_id,
            metric_key=metric_key,
            observed_at=observed_at,
            value_double=value_double,
            value_text=value_text,
            unit="Cel" if metric_key == GAUGE_KEY else None,
            quality=quality,
            source="redfish",
        )
    )


def _seeded_environment(db: Session) -> tuple[Device, Component]:
    device = make_collection_device(db, index=1)
    component = Component(
        device_id=device.id,
        kind="processor",
        native_id="CPU0",
        name="CPU 0",
        status="ok",
        properties={},
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    db.add(component)
    db.commit()
    db.refresh(component)
    ensure_metric_partitions(db, start_date=(NOW.date() - datetime.timedelta(days=1)), days=3)
    db.commit()
    return device, component


def _rollup_rows(db: Session, model: type[MetricRollup5m] | type[MetricRollup1h]) -> list:
    # generate_rollups upserts through the same session: expire the identity
    # map so re-selected rows reflect the regenerated database values.
    db.expire_all()
    return list(db.scalars(select(model)).all())


class TestFiveMinuteRollups:
    def test_closed_gauge_window_produces_correct_rollup(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5  # [11:55, 12:00)
        values = [10.0, 12.0, 14.0, 18.0, 26.0]
        for offset, value in enumerate(values):
            _point(
                db_session,
                device_id=device.id,
                component_id=component.id,
                metric_key=GAUGE_KEY,
                observed_at=window + datetime.timedelta(seconds=10 * offset),
                value_double=value,
            )
        db_session.commit()

        report = generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        row = rows[0]
        assert row.window_start == window
        assert row.device_id == device.id
        assert row.component_id == component.id
        assert row.metric_key == GAUGE_KEY
        assert row.min_value == 10.0
        assert row.max_value == 26.0
        assert row.avg_value == pytest.approx(16.0)
        assert row.last_value == 26.0
        assert row.count == 5
        assert row.quality == "good"
        assert row.collection_run_id is None
        assert report.rows_5m == 1

    def test_window_edges_belong_to_their_half_open_window(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5  # [11:55, 12:00)
        # exact window start -> IN the window; exact window end -> NEXT window
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=DEVICE_KEY,
            observed_at=window,
            value_double=1.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=None,
            metric_key=DEVICE_KEY,
            observed_at=window + datetime.timedelta(minutes=5),
            value_double=99.0,
        )
        db_session.commit()

        generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].window_start == window
        assert rows[0].last_value == 1.0
        assert rows[0].count == 1

    def test_gauge_only_keys_are_rolled_up(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=1),
            value_double=42.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=COUNTER_KEY,
            observed_at=window + datetime.timedelta(seconds=2),
            value_double=100.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=STATE_KEY,
            observed_at=window + datetime.timedelta(seconds=3),
            value_text="ok",
        )
        db_session.commit()

        generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].metric_key == GAUGE_KEY

    def test_regeneration_is_idempotent_and_reflects_new_points(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=10),
            value_double=2.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=20),
            value_double=4.0,
        )
        db_session.commit()

        first = generate_rollups(db_session, now=NOW, settings=SETTINGS)
        second = generate_rollups(db_session, now=NOW, settings=SETTINGS)

        assert first.rows_5m == 1 and second.rows_5m == 1
        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].avg_value == pytest.approx(3.0)
        assert rows[0].count == 2

        # A late point in the same window folds in on regeneration.
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=30),
            value_double=6.0,
        )
        db_session.commit()
        generate_rollups(db_session, now=NOW, settings=SETTINGS)
        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].avg_value == pytest.approx(4.0)
        assert rows[0].last_value == 6.0
        assert rows[0].count == 3

    def test_partial_point_marks_window_quality_partial(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=5),
            value_double=1.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=15),
            value_double=2.0,
            quality="partial",
        )
        db_session.commit()

        generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].quality == "partial"
        assert rows[0].count == 2

    def test_device_scope_and_component_scope_keys_do_not_cross_contaminate(
        self, db_session: Session
    ) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5
        _point(
            db_session,
            device_id=device.id,
            component_id=None,
            metric_key=DEVICE_KEY,
            observed_at=window + datetime.timedelta(seconds=1),
            value_double=11.0,
        )
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=DEVICE_KEY,
            observed_at=window + datetime.timedelta(seconds=2),
            value_double=22.0,
        )
        db_session.commit()

        generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 2
        by_component = {row.component_id: row for row in rows}
        assert by_component[None].last_value == 11.0
        assert by_component[component.id].last_value == 22.0

    def test_catch_up_generates_windows_left_behind_by_downtime(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        window = WINDOW5  # 11:55-12:00, generated first
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=window + datetime.timedelta(seconds=1),
            value_double=1.0,
        )
        db_session.commit()
        generate_rollups(db_session, now=NOW, settings=SETTINGS)
        assert len(_rollup_rows(db_session, MetricRollup5m)) == 1

        # 25 minutes of downtime: windows 12:00/12:05/12:10 never ran; the
        # next pass must catch up from the marker instead of skipping them.
        later = NOW + datetime.timedelta(minutes=25)
        for observed, value in [
            (later - datetime.timedelta(minutes=15), 10.0),  # -> window 12:10
            (later - datetime.timedelta(minutes=20), 20.0),  # -> window 12:05
            (later - datetime.timedelta(minutes=25), 30.0),  # -> window 12:00
        ]:
            _point(
                db_session,
                device_id=device.id,
                component_id=component.id,
                metric_key=GAUGE_KEY,
                observed_at=observed,
                value_double=value,
            )
        db_session.commit()

        report = generate_rollups(db_session, now=later, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert report.rows_5m == 3  # three new windows rolled up
        assert len(rows) == 4
        starts = sorted({row.window_start for row in rows})
        assert starts == [
            datetime.datetime(2026, 9, 1, 11, 55, tzinfo=UTC),
            datetime.datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
            datetime.datetime(2026, 9, 1, 12, 5, tzinfo=UTC),
            datetime.datetime(2026, 9, 1, 12, 10, tzinfo=UTC),
        ]


class TestHourlyRollups:
    """The 1h row aggregates twelve closed 5m rows (DATA_MODEL.md §5.4).

    Generation mirrors the maintenance cadence: one pass per closed 5-minute
    window (DEPLOYMENT.md §9.3 每 5 分钟生成指标聚合); the hourly row appears
    only on the pass that closes the hour's last window.
    """

    HOUR = datetime.datetime(2026, 9, 1, 10, 0, tzinfo=UTC)  # hour [10:00, 11:00)

    def _seed_hour_points(
        self,
        db: Session,
        device_id: uuid.UUID,
        *,
        partial_window: int | None = None,
    ) -> None:
        for offset in range(12):
            win = self.HOUR + datetime.timedelta(minutes=5 * offset)
            _point(
                db,
                device_id=device_id,
                component_id=None,
                metric_key=DEVICE_KEY,
                observed_at=win + datetime.timedelta(seconds=30),
                value_double=float(offset) * 2.0,
                quality="partial" if offset == partial_window else "good",
            )

    def _run_hour_passes(self, db: Session) -> dict[str, int]:
        """Simulate the 5-minute maintenance cadence closing hour [10:00, 11:00).

        One pass per closed window (DEPLOYMENT.md §9.3), the same way the
        worker loop runs; returns the last pass's rollup report counters.
        """
        counts = {"rows_5m": 0, "rows_1h": 0}
        for k in range(1, 13):
            report = generate_rollups(
                db,
                now=self.HOUR + datetime.timedelta(minutes=5 * k, seconds=30),
                settings=SETTINGS,
            )
            counts["rows_5m"] = report.rows_5m
            counts["rows_1h"] = report.rows_1h
        return counts

    def test_hourly_rollup_aggregates_closed_5m_windows(self, db_session: Session) -> None:
        device, _component = _seeded_environment(db_session)
        self._seed_hour_points(db_session, device.id)
        db_session.commit()

        counts = self._run_hour_passes(db_session)

        rows_5m = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows_5m) == 12
        assert counts["rows_1h"] == 1
        rows = _rollup_rows(db_session, MetricRollup1h)
        assert len(rows) == 1
        row = rows[0]
        assert row.window_start == self.HOUR
        assert row.min_value == 0.0
        assert row.max_value == 22.0
        # avg of the 12 window avgs (each window has one point -> window avg is
        # the point value); documented choice: simple mean of avgs.
        assert row.avg_value == pytest.approx(11.0)
        assert row.last_value == 22.0  # last value of the latest window
        assert row.count == 12
        assert row.quality == "good"
        assert row.device_id == device.id
        assert row.metric_key == DEVICE_KEY

    def test_hourly_quality_propagates_worst_window_quality(self, db_session: Session) -> None:
        device, _component = _seeded_environment(db_session)
        self._seed_hour_points(db_session, device.id, partial_window=4)
        db_session.commit()

        self._run_hour_passes(db_session)

        rows = _rollup_rows(db_session, MetricRollup1h)
        assert len(rows) == 1
        assert rows[0].quality == "partial"
        assert rows[0].count == 12

    def test_hourly_regeneration_is_idempotent(self, db_session: Session) -> None:
        device, _component = _seeded_environment(db_session)
        self._seed_hour_points(db_session, device.id)
        db_session.commit()
        self._run_hour_passes(db_session)
        hourly_before = _rollup_rows(db_session, MetricRollup1h)
        assert len(hourly_before) == 1
        avg_before = hourly_before[0].avg_value

        # Extra maintenance passes (including catch-up passes that re-target
        # the same hour) must converge: one row, identical values, no dupes.
        for k in (1, 2, 3):
            generate_rollups(
                db_session,
                now=self.HOUR + datetime.timedelta(hours=1, minutes=5 * k, seconds=30),
                settings=SETTINGS,
            )

        hourly_after = _rollup_rows(db_session, MetricRollup1h)
        assert len(hourly_after) == 1
        assert hourly_after[0].avg_value == avg_before
        assert hourly_after[0].count == 12

    def test_hourly_rollup_not_generated_for_unclosed_windows(self, db_session: Session) -> None:
        device, _component = _seeded_environment(db_session)
        # Points in the CURRENT (unclosed) 5-minute window only: neither a 5m
        # nor a 1h row may exist for them yet.
        now = self.HOUR + datetime.timedelta(hours=2, minutes=3, seconds=30)
        _point(
            db_session,
            device_id=device.id,
            component_id=None,
            metric_key=DEVICE_KEY,
            observed_at=now - datetime.timedelta(seconds=30),
            value_double=5.0,
        )
        db_session.commit()

        generate_rollups(db_session, now=now, settings=SETTINGS)

        assert len(_rollup_rows(db_session, MetricRollup5m)) == 0
        assert len(_rollup_rows(db_session, MetricRollup1h)) == 0

    def test_hourly_rollup_reflects_only_windows_that_closed(self, db_session: Session) -> None:
        # A point that lands in the window [12:00, 12:05) must only add to
        # that window's rollup, never to the already-closed hour [10:00, 11:00)
        # whose hourly row exists.
        device, _component = _seeded_environment(db_session)
        self._seed_hour_points(db_session, device.id)
        db_session.commit()
        self._run_hour_passes(db_session)
        assert len(_rollup_rows(db_session, MetricRollup1h)) == 1

        late = self.HOUR + datetime.timedelta(hours=2, minutes=4, seconds=30)
        _point(
            db_session,
            device_id=device.id,
            component_id=None,
            metric_key=DEVICE_KEY,
            observed_at=late,
            value_double=99.0,
        )
        db_session.commit()
        generate_rollups(
            db_session,
            now=self.HOUR + datetime.timedelta(hours=2, minutes=5, seconds=30),
            settings=SETTINGS,
        )

        hourly = _rollup_rows(db_session, MetricRollup1h)
        assert len(hourly) == 1
        assert hourly[0].count == 12  # the late point is NOT folded into 10:00
        late_rows = [
            row
            for row in _rollup_rows(db_session, MetricRollup5m)
            if row.window_start == self.HOUR + datetime.timedelta(hours=2)
        ]
        assert len(late_rows) == 1
        assert late_rows[0].count == 1
        assert late_rows[0].last_value == 99.0


class TestWindowAlignment:
    def test_rollup_window_starts_are_utc_5m_aligned(self, db_session: Session) -> None:
        device, component = _seeded_environment(db_session)
        # observed at 11:57:41 -> window start 11:55:00
        _point(
            db_session,
            device_id=device.id,
            component_id=component.id,
            metric_key=GAUGE_KEY,
            observed_at=datetime.datetime(2026, 9, 1, 11, 57, 41, tzinfo=UTC),
            value_double=5.0,
        )
        db_session.commit()

        generate_rollups(db_session, now=NOW, settings=SETTINGS)

        rows = _rollup_rows(db_session, MetricRollup5m)
        assert len(rows) == 1
        assert rows[0].window_start == datetime.datetime(2026, 9, 1, 11, 55, 0, tzinfo=UTC)
        assert rows[0].window_start.minute % 5 == 0
        assert rows[0].window_start.second == 0

    def test_hourly_window_starts_are_utc_hour_aligned(self, db_session: Session) -> None:
        device, _component = _seeded_environment(db_session)
        for offset in range(12):
            win = datetime.datetime(2026, 9, 1, 10, 0, tzinfo=UTC) + datetime.timedelta(
                minutes=5 * offset
            )
            _point(
                db_session,
                device_id=device.id,
                component_id=None,
                metric_key=DEVICE_KEY,
                observed_at=win + datetime.timedelta(seconds=30),
                value_double=float(offset),
            )
        db_session.commit()
        for k in range(1, 13):
            generate_rollups(
                db_session,
                now=datetime.datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
                + datetime.timedelta(minutes=5 * k, seconds=30),
                settings=SETTINGS,
            )

        rows = _rollup_rows(db_session, MetricRollup1h)
        assert len(rows) == 1
        assert rows[0].window_start.minute == 0
        assert rows[0].window_start.second == 0

    def test_rows_do_not_exist_for_window_without_points(self, db_session: Session) -> None:
        _device, _component = _seeded_environment(db_session)
        report = generate_rollups(db_session, now=NOW, settings=SETTINGS)
        total = db_session.scalar(select(func.count()).select_from(MetricRollup5m))
        assert total == 0
        assert report.rows_5m == 0

