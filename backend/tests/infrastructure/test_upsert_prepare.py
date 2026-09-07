"""M6T4b regression: metric upserts must not depend on plan caching.

docs/TEST_STRATEGY.md §2.2: database tests run on the real PostgreSQL 18,
never SQLite. This module reproduces the reliability defect the M6T4 load
smoke exposed (LOAD_SMOKE.md "观察到的平台可靠性现象", M6T4b brief):

- ``metric_latest``/``metric_points``/rollup upserts targeted a COALESCE
  expression unique index with an arbiter containing a PARAMETER
  (``coalesce(component_id, $1::uuid)``). psycopg3 auto-prepares a statement
  after ``prepare_threshold`` (default 5) executions on the same connection;
  under the resulting generic plan the parameter cannot be folded into the
  index-inference comparison, so PostgreSQL intermittently raises
  "no unique or exclusion constraint matching the ON CONFLICT specification".
- The fix (migration 0016) replaces the expression indexes with partial
  unique index pairs whose predicates are constant (``component_id IS
  NULL`` / ``IS NOT NULL``), so the ON CONFLICT arbiters contain NO
  parameters and plan caching cannot change the outcome.

Each test pins a single pooled connection (``pool_size=1``) and repeats the
real store/maintenance statement 60+ times — far past the prepare threshold
— so a plan-caching regression fails here deterministically. The prepare
settings under test are the psycopg3 default (auto-PREPARE on) and
``prepare_threshold=None`` (auto-PREPARE off).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.application.maintenance import generate_rollups
from app.config import WardenSettings
from app.domain.adapter import ComponentObserved, Observation, ObservationBatch
from app.infrastructure.db import dsn_with_psycopg_dialect
from app.infrastructure.observation_store import persist_observation_batch
from app.models.devices import Component
from app.models.observation import MetricLatest, MetricPoint, MetricRollup1h, MetricRollup5m
from sqlalchemy import Engine, create_engine, func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from tests.observation_factories import make_collection_device, make_collection_run
from tests.partition_helpers import ensure_partitions_around

UTC = datetime.UTC
SETTINGS = WardenSettings(_env_file=None)

# Fixed instants for the rollup hour scenario (raw points only exist inside
# the regeneration lookback, so the repeated pass re-upserts them).
ROLLUP_HOUR = datetime.datetime(2026, 9, 1, 10, 0, tzinfo=UTC)  # hour [10:00, 11:00)
ROLLUP_PASS_NOW = datetime.datetime(2026, 9, 1, 11, 3, tzinfo=UTC)
ROLLUP_WINDOWS = [
    ROLLUP_HOUR + datetime.timedelta(minutes=5 * offset)
    for offset in range(9, 12)  # 10:45..10:55
]

GAUGE_KEY = "temperature.cpu"  # series=gauge, scope=component, unit Cel
DEVICE_KEY = "system.cpu_percent"  # series=gauge, scope=device
CELSIUS = "Cel"

REPEAT_LATEST = 60  # 12x the default prepare_threshold -> the flip is certain
REPEAT_ROLLUPS = 30


def _pinned_engine(dsn: str, *, disable_prepare: bool) -> Engine:
    """Engine whose pool holds exactly ONE connection.

    A single connection is required for psycopg3's per-connection auto-prepare
    counters to accumulate across the loop — a pool of N would spread the
    executions over N connections and mask the defect.
    """
    connect_args: dict[str, object] = {"connect_timeout": 5}
    if disable_prepare:
        connect_args["prepare_threshold"] = None
    return create_engine(
        dsn_with_psycopg_dialect(dsn),
        pool_size=1,
        max_overflow=0,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


def _pinned_session(dsn: str, *, disable_prepare: bool) -> tuple[Engine, Session]:
    engine = _pinned_engine(dsn, disable_prepare=disable_prepare)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, factory()


def _metric_batch(now: datetime.datetime, value: float) -> ObservationBatch:
    """One device-scope + two component-scope good observations.

    The device-scope row (component_id NULL) and the component-scope rows
    (component_id set) hit the two halves of the partial unique index pair —
    and, before migration 0016, the two conflict paths of the COALESCE
    expression index.
    """
    return ObservationBatch(
        observations=(
            Observation("health.overall", "healthy", now, source="redfish"),
            Observation(
                GAUGE_KEY,
                value,
                now,
                component_kind="processor",
                component_native_id="cpu-0",
                source="redfish",
            ),
            Observation(
                "drive.status",
                "ok",
                now,
                component_kind="drive",
                component_native_id="drive-0",
                source="redfish",
            ),
        ),
        components=(
            ComponentObserved(kind="processor", native_id="cpu-0", name="CPU", status="ok"),
            ComponentObserved(kind="drive", native_id="drive-0", name="Drive", status="ok"),
        ),
    )


class TestLatestUpsertPlanCachingIndependence:
    """metric_latest DO UPDATE / metric_points DO NOTHING at both prepare settings.

    Pre-fix evidence (expression-index arbiters, current schema): the default
    setting fails the bulk of the 60 repetitions once auto-PREPARE switches to
    a generic plan (flip point around the 5th-10th execution); with
    ``prepare_threshold=None`` all 60 succeed. Post-fix both are zero-failure.
    """

    NOW = datetime.datetime(2026, 9, 2, 10, 0, tzinfo=UTC)

    @pytest.fixture(params=[False, True], ids=["default-auto-prepare", "prepare-disabled"])
    def _pinned_env(self, fresh_test_db_dsn: str, request: pytest.FixtureRequest) -> tuple[Engine, Session]:
        engine, session = _pinned_session(fresh_test_db_dsn, disable_prepare=request.param)
        ensure_partitions_around(session, [self.NOW])
        yield engine, session
        session.close()
        engine.dispose()

    @pytest.mark.parametrize("changing_value", [False, True], ids=["constant-value", "changing-value"])
    def test_repeated_batch_persistence_never_fails(
        self, _pinned_env: tuple[Engine, Session], changing_value: bool
    ) -> None:
        _engine, session = _pinned_env
        device = make_collection_device(session, index=0)
        run = make_collection_run(session, device_id=device.id)
        failures: list[str] = []
        latest_values: list[float] = []
        for iteration in range(REPEAT_LATEST):
            value = float(iteration) if changing_value else 42.5
            batch = _metric_batch(self.NOW, value)
            try:
                outcome = persist_observation_batch(
                    session, device_id=device.id, batch=batch, run_id=run.id, now=self.NOW
                )
                session.commit()
            except SQLAlchemyError as exc:  # noqa: PERF203
                session.rollback()
                failures.append(type(exc).__name__ + ": " + str(exc).splitlines()[0][:160])
                continue
            latest_values.append(value)
            if iteration > 0:
                assert outcome.points_written == 0
                assert outcome.points_deduped == 3

        assert failures == [], f"{len(failures)}/{REPEAT_LATEST} upserts failed: {failures[:3]}"
        # Every repetition must have landed: exactly the 3 series exist and the
        # last DO UPDATE won (value refreshed by the upsert, not the first row).
        latest = session.scalars(select(MetricLatest).where(MetricLatest.device_id == device.id)).all()
        assert len(latest) == 3
        gauge = next(row for row in latest if row.metric_key == GAUGE_KEY)
        assert gauge.component_id is not None
        assert gauge.value_double == latest_values[-1]
        device_row = next(row for row in latest if row.metric_key == "health.overall")
        assert device_row.component_id is None
        assert device_row.value_text == "healthy"
        points = session.scalar(select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id))
        assert points == 3


class TestRollupUpsertPlanCachingIndependence:
    """Rollup regeneration (ON CONFLICT DO UPDATE) at both prepare settings.

    One pass closes the hour [10:00, 11:00) and upserts the three in-lookback
    5m windows (10:45/10:50/10:55, device- AND component-scoped series) plus
    the hourly row; repeating the identical pass regenerates the same rows, so
    the identical statement text crosses the auto-prepare threshold on a
    pinned connection (maintenance.py used the same COALESCE arbiter pattern —
    the same latent defect once a worker connection served enough passes).
    """

    @pytest.fixture(params=[False, True], ids=["default-auto-prepare", "prepare-disabled"])
    def _pinned_env(self, fresh_test_db_dsn: str, request: pytest.FixtureRequest) -> tuple[Engine, Session]:
        engine, session = _pinned_session(fresh_test_db_dsn, disable_prepare=request.param)
        ensure_partitions_around(session, ROLLUP_WINDOWS)
        yield engine, session
        session.close()
        engine.dispose()

    def _seed_points(self, session: Session, device_id: uuid.UUID, component_id: uuid.UUID) -> None:
        for offset, window in enumerate(ROLLUP_WINDOWS):
            session.add(
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device_id,
                    component_id=component_id,
                    metric_key=GAUGE_KEY,
                    observed_at=window + datetime.timedelta(seconds=10 + offset),
                    value_double=float(offset) + 1.0,
                    unit=CELSIUS,
                    quality="good",
                    source="redfish",
                )
            )
            session.add(
                MetricPoint(
                    id=uuid.uuid4(),
                    device_id=device_id,
                    component_id=None,
                    metric_key=DEVICE_KEY,
                    observed_at=window + datetime.timedelta(seconds=20 + offset),
                    value_double=float(offset) + 10.0,
                    unit=None,
                    quality="good",
                    source="redfish",
                )
            )
        session.commit()

    def test_repeated_regeneration_never_fails(self, _pinned_env: tuple[Engine, Session]) -> None:
        _engine, session = _pinned_env
        device = make_collection_device(session, index=1)
        component = Component(
            device_id=device.id,
            kind="processor",
            native_id="cpu-0",
            name="CPU 0",
            status="ok",
            properties={},
            first_seen_at=ROLLUP_WINDOWS[0],
            last_seen_at=ROLLUP_WINDOWS[0],
        )
        session.add(component)
        session.commit()
        session.refresh(component)
        self._seed_points(session, device.id, component.id)

        failures: list[str] = []
        counters: list[tuple[int, int]] = []
        for _ in range(REPEAT_ROLLUPS):
            try:
                report = generate_rollups(session, now=ROLLUP_PASS_NOW, settings=SETTINGS)
                session.commit()
            except SQLAlchemyError as exc:  # noqa: PERF203
                session.rollback()
                failures.append(type(exc).__name__ + ": " + str(exc).splitlines()[0][:160])
                continue
            counters.append((report.rows_5m, report.rows_1h))

        assert failures == [], f"{len(failures)}/{REPEAT_ROLLUPS} passes failed: {failures[:3]}"
        assert counters == [(6, 2)] * len(counters)
        rows_5m = session.scalars(select(MetricRollup5m)).all()
        rows_1h = session.scalars(select(MetricRollup1h)).all()
        assert len(rows_5m) == 6  # 3 windows x (component-scoped + device-scoped)
        assert len(rows_1h) == 2
        component_row = next(row for row in rows_1h if row.component_id == component.id)
        assert component_row.metric_key == GAUGE_KEY
        device_row = next(row for row in rows_1h if row.component_id is None)
        assert device_row.metric_key == DEVICE_KEY


class TestPartialUniqueIndexLayout:
    """Migration 0016 layout: partial pairs, no COALESCE expression indexes.

    Guards the schema contract the store upserts now rely on (constant
    predicates, no parameters) AND the coalesce semantics (a NULL
    component_id row is unique per device+key within its own partition; the
    two partitions do not share key space, exactly like COALESCE never made a
    NULL row collide with a real component's row).
    """

    PAIRS = {
        "metric_latest": ("uq_metric_latest_series_component", "uq_metric_latest_series_device"),
        "metric_points": ("uq_metric_points_dedup_component", "uq_metric_points_dedup_device"),
        "metric_rollups_5m": ("uq_metric_rollups_5m_component", "uq_metric_rollups_5m_device"),
        "metric_rollups_1h": ("uq_metric_rollups_1h_component", "uq_metric_rollups_1h_device"),
    }

    def _indexdefs(self, session: Session, table: str) -> dict[str, str]:
        rows = session.execute(
            text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = :table"),
            {"table": table},
        ).all()
        return {str(name): str(definition) for name, definition in rows}

    def test_expression_dedupe_indexes_replaced_by_partial_pairs(self, db_session: Session) -> None:
        for table, (component_index, device_index) in self.PAIRS.items():
            defs = self._indexdefs(db_session, table)
            assert not any("COALESCE(component_id" in definition for definition in defs.values()), table
            # pg_get_indexdef wraps predicates in parentheses: check the
            # predicate content, not the exact quoting.
            assert "component_id IS NOT NULL" in defs[component_index], table
            assert "component_id IS NULL" in defs[device_index], table

    def test_latest_null_and_component_rows_are_unique_per_partition(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=2)
        component = Component(
            device_id=device.id,
            kind="processor",
            native_id="cpu-0",
            name="CPU 0",
            status="ok",
            properties={},
            first_seen_at=datetime.datetime.now(datetime.UTC),
            last_seen_at=datetime.datetime.now(datetime.UTC),
        )
        db_session.add(component)
        db_session.commit()
        db_session.refresh(component)
        now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

        def _latest_row(component_id: uuid.UUID | None, value: float) -> MetricLatest:
            return MetricLatest(
                device_id=device.id,
                component_id=component_id,
                metric_key="layout.probe",
                value_double=value,
                value_text=None,
                unit=None,
                quality="good",
                source="poll",
                observed_at=now,
            )

        db_session.add(_latest_row(None, 1.0))
        db_session.commit()
        # Same device+key with a real component_id coexists: the partitions are
        # independent (the coalesce expression NEVER made these two collide
        # either — it only merged NULL with the zero-uuid placeholder).
        db_session.add(_latest_row(component.id, 2.0))
        db_session.commit()
        assert (
            db_session.scalar(select(func.count()).select_from(MetricLatest).where(MetricLatest.device_id == device.id))
            == 2
        )
        # Duplicate within the NULL partition is rejected at the database.
        with pytest.raises(IntegrityError):
            db_session.add(_latest_row(None, 3.0))
            db_session.commit()
        db_session.rollback()
