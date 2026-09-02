"""Collection orchestration on the REAL PostgreSQL 18 (TEST_STRATEGY §2.2).

Covers the M2T2 pipeline end-to-end (docs/ARCHITECTURE.md §5.1,
DATA_MODEL.md §11): scheduling due runs per collection type, claiming,
fake-adapter happy/partial/critical/no-data/failure modes, device
reachability hysteresis (3 failures offline / 2 successes online),
health aggregation, alert open/resolve with dedupe and counters, credential
backoff, and ui_events written in the same transaction.
"""

from __future__ import annotations

import datetime

import pytest
from app.adapters.fake import FAILURE_MODE_KEY
from app.application.collection import (
    AUTH_FAILURE_BACKOFF_MULTIPLIER,
    run_collection,
    schedule_due_collections,
)
from app.infrastructure.observation_store import claim_collection_run
from app.models.devices import Device
from app.models.observation import (
    Alert,
    CollectionObservationError,
    CollectionRun,
    DeviceEvent,
    MetricLatest,
    MetricPoint,
    UiEvent,
)
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from tests.observation_factories import make_collection_device, make_keyring

T0 = datetime.datetime(2026, 9, 2, 8, 0, 0, tzinfo=datetime.UTC)
TICK = datetime.timedelta(seconds=31)


@pytest.fixture(autouse=True)
def _metric_partition_window(request: pytest.FixtureRequest) -> None:
    """Create the day partitions this module's fixed-clock rows need.

    A fresh test DB pre-creates partitions only for the migration window
    (current_date .. +13 in the DB session zone), so rows at the module's
    fixed ``T0`` would otherwise depend on the wall clock (the UTC+8
    post-midnight flake, M2T8). The window is computed from ``T0`` in the DB
    session time zone — the same frame PostgreSQL routes rows by.
    """
    if "db_session" not in request.fixturenames:
        return
    from tests.partition_helpers import ensure_partitions_around

    ensure_partitions_around(request.getfixturevalue("db_session"), [T0])


def _claim_and_run(
    db: Session,
    *,
    settings: object,
    collection_type: str | None = None,
    now: datetime.datetime = T0,
) -> CollectionRun | None:
    """Claim the oldest claimable run and execute it with the fake adapter."""
    run = claim_collection_run(db, lease_owner="test-worker", lease_seconds=300)
    if run is None:
        return None
    db.commit()
    run_collection(db, run.id, settings=settings, keyring=make_keyring(), now=now)
    db.commit()
    db.refresh(run)
    return run


class TestCrossSessionRunTerminalState:
    """Regression: the production worker claims in session A and executes in
    session B (collection_pool._default_handler, run.py --once, the smoke
    script). The run row must reach its terminal state with correct counts —
    a detached ORM instance passed across sessions must never silently lose
    the terminal-state writes (M2T2 review finding 1).
    """

    @pytest.mark.parametrize(
        (
            "index",
            "connection_config",
            "expected_state",
            "expected_successes",
            "expected_failures",
            "expected_error_code",
        ),
        [
            (20, {}, "succeeded", 19, 0, None),
            (21, {"partial_mode": True}, "partial", 17, 2, None),
            (22, {FAILURE_MODE_KEY: "network_unreachable"}, "failed", 0, 1, "network_unreachable"),
        ],
    )
    def test_terminal_state_persists_across_claim_and_execute_sessions(
        self,
        db_session: Session,
        db_settings: object,
        index: int,
        connection_config: dict[str, object],
        expected_state: str,
        expected_successes: int,
        expected_failures: int,
        expected_error_code: str | None,
    ) -> None:
        make_collection_device(
            db_session,
            index=index,
            connection_config=connection_config,
            next_poll_at=T0 - TICK,
        )
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        factory = sessionmaker(bind=db_session.get_bind())
        with factory() as session_a:
            run = claim_collection_run(session_a, lease_owner="cross-session-worker", lease_seconds=300)
            assert run is not None
            session_a.commit()
            run_id = run.id
        with factory() as session_b:
            run_collection(session_b, run_id, settings=db_settings, keyring=make_keyring(), now=T0)
            session_b.commit()
        with factory() as session_c:
            row = session_c.get(CollectionRun, run_id)
            assert row is not None
            assert row.state == expected_state
            assert row.success_count == expected_successes
            assert row.failure_count == expected_failures
            assert row.finished_at is not None
            assert row.error_code == expected_error_code


class TestCollectionTypeMapping:
    """Capability key -> collection type (the freshness cadence source, one
    documented place, M2T2 review finding 4)."""

    @pytest.mark.parametrize(
        ("capability_key", "expected_type"),
        [
            # metrics.json keys (health and metric values) -> metrics collection
            ("health.overall", "metrics"),
            ("indicator.led", "metrics"),
            ("temperature.cpu", "metrics"),
            ("drive.status", "metrics"),
            # events.json keys -> logs collection
            ("event.sel", "logs"),
            ("event.system_log", "logs"),
            # operations / capability discovery -> discovery collection
            ("power.on", "discovery"),
            ("console.kvm.open", "discovery"),
            ("firmware.update", "discovery"),
        ],
    )
    def test_mapping(self, capability_key: str, expected_type: str) -> None:
        from app.application.collection import collection_type_for_capability_key

        assert collection_type_for_capability_key(capability_key) == expected_type


class TestScheduling:
    def test_schedules_all_due_types_for_new_device(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=None)
        scheduled = schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        assert scheduled == 5  # reachability, health, metrics, logs, discovery
        runs = db_session.scalars(
            select(CollectionRun).where(CollectionRun.device_id == device.id)
        ).all()
        assert {run.collection_type for run in runs} == {
            "reachability", "health", "metrics", "logs", "discovery",
        }
        assert all(run.state == "scheduled" for run in runs)
        db_session.refresh(device)
        assert device.next_poll_at is not None
        assert device.next_poll_at <= T0 + datetime.timedelta(seconds=30)

    def test_skips_types_with_pending_runs(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        again = schedule_due_collections(db_session, now=T0 + TICK, settings=db_settings)
        db_session.commit()
        assert again == 0  # all types still pending -> no duplicate scheduling
        count = db_session.scalar(
            select(func.count()).select_from(CollectionRun).where(
                CollectionRun.device_id == device.id
            )
        )
        assert count == 5

    def test_disabled_or_not_ready_devices_are_not_scheduled(self, db_session: Session, db_settings: object) -> None:
        make_collection_device(db_session, index=0, enabled=False, next_poll_at=T0 - TICK)
        make_collection_device(db_session, index=1, readiness="not_ready", next_poll_at=T0 - TICK)
        scheduled = schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        assert scheduled == 0

    def test_next_poll_at_stays_in_future_after_scheduling(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        db_session.refresh(device)
        assert device.next_poll_at is not None
        assert device.next_poll_at > T0


class TestRunPipeline:
    def test_happy_path_run_succeeded(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "succeeded"
        assert run.success_count > 0
        assert run.failure_count == 0
        assert run.finished_at is not None

        db_session.refresh(device)
        assert device.reachability == "online"
        assert device.consecutive_failures == 0
        assert device.consecutive_successes == 1
        assert device.health == "healthy"
        assert device.last_collected_at is not None
        assert device.last_seen_at is not None

        points = db_session.scalar(
            select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id)
        )
        assert points == 19
        latest = db_session.scalar(
            select(func.count()).select_from(MetricLatest).where(MetricLatest.device_id == device.id)
        )
        assert latest == 19
        events = db_session.scalar(
            select(func.count()).select_from(DeviceEvent).where(DeviceEvent.device_id == device.id)
        )
        assert events == 1
        ui_events = db_session.scalars(
            select(UiEvent).where(UiEvent.entity_id == device.id).order_by(UiEvent.id)
        ).all()
        assert any(event.event_type == "device.updated" for event in ui_events)

        # the alert engine ran and found nothing to open (all healthy)
        alerts = db_session.scalars(select(Alert).where(Alert.device_id == device.id)).all()
        assert alerts == []

    def test_partial_mode_run_partial_with_errors(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={"partial_mode": True}, next_poll_at=T0 - TICK
        )
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "partial"
        assert run.failure_count == 2
        errors = db_session.scalars(
            select(CollectionObservationError).where(CollectionObservationError.device_id == device.id)
        ).all()
        assert {row.metric_key_or_event_key for row in errors} == {"temperature.memory", "fan.status"}
        # successes persisted despite the errors
        points = db_session.scalar(
            select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id)
        )
        assert points == 17
        db_session.refresh(device)
        assert device.reachability == "online"

    def test_no_data_mode_run_failed(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={"no_data_mode": True}, next_poll_at=T0 - TICK
        )
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "failed"
        assert run.failure_count == 2
        assert run.success_count == 0
        # no fabricated points
        points = db_session.scalar(
            select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id)
        )
        assert points == 0

    def test_failure_mode_marks_run_failed_and_failure_streak(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={FAILURE_MODE_KEY: "network_unreachable"}, next_poll_at=T0 - TICK
        )
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "failed"
        assert run.error_code == "network_unreachable"
        db_session.refresh(device)
        assert device.reachability == "unknown"  # 1 failure: not offline yet
        assert device.consecutive_failures == 1
        assert device.last_known_health is None


class TestOfflineHysteresis:
    def _run_failures(self, db_session: Session, db_settings: object, device: Device, count: int) -> None:
        now = T0
        for _ in range(count):
            schedule_due_collections(db_session, now=now, settings=db_settings)
            db_session.commit()
            run = _claim_and_run(db_session, settings=db_settings, now=now)
            assert run is not None and run.state == "failed"
            now = now + TICK

    def test_three_failures_offline_and_alert_opened(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={FAILURE_MODE_KEY: "network_unreachable"}, next_poll_at=T0 - TICK
        )
        self._run_failures(db_session, db_settings, device, 3)
        db_session.refresh(device)
        assert device.reachability == "offline"
        assert device.consecutive_failures == 3
        alerts = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        offline = [alert for alert in alerts if alert.rule_key == "device.offline"]
        assert len(offline) == 1
        assert offline[0].severity == "critical"
        # the failure path also emitted alert ui_events (entity = the alert)
        ui_types = db_session.scalars(
            select(UiEvent.event_type).where(UiEvent.entity_type == "alert")
        ).all()
        assert "alert.opened" in ui_types

    def test_two_successes_after_offline_resolve_alert(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={FAILURE_MODE_KEY: "network_unreachable"}, next_poll_at=T0 - TICK
        )
        self._run_failures(db_session, db_settings, device, 3)
        db_session.refresh(device)
        assert device.reachability == "offline"

        # switch the device back to healthy and run twice: 1st success keeps
        # offline (hysteresis), 2nd goes online and resolves the alert
        device.connection_config = {}
        db_session.commit()
        now = T0 + 4 * TICK
        for _ in range(2):
            schedule_due_collections(db_session, now=now, settings=db_settings)
            db_session.commit()
            run = _claim_and_run(db_session, settings=db_settings, now=now)
            assert run is not None and run.state == "succeeded"
            now = now + TICK
        db_session.refresh(device)
        assert device.reachability == "online"
        assert device.consecutive_successes == 2
        alerts = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "resolved")
        ).all()
        offline = [alert for alert in alerts if alert.rule_key == "device.offline"]
        assert len(offline) == 1
        assert offline[0].resolved_at is not None
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert all(alert.rule_key != "device.offline" for alert in active)


class TestAlertsEndToEnd:
    def _run_once(self, db_session: Session, db_settings: object, now: datetime.datetime) -> CollectionRun:
        schedule_due_collections(db_session, now=now, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=now)
        assert run is not None
        return run

    def test_critical_mode_opens_health_and_status_alerts(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={"critical_mode": True}, next_poll_at=T0 - TICK
        )
        self._run_once(db_session, db_settings, T0)
        db_session.refresh(device)
        assert device.health == "critical"
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        by_rule: dict[str, list[Alert]] = {}
        for alert in active:
            by_rule.setdefault(alert.rule_key, []).append(alert)
        assert [alert.severity for alert in by_rule["device.health"]] == ["critical"]
        status = {alert.dedupe_key: alert for alert in by_rule["status.problem"]}
        assert any("drive.status" in key for key in status)
        assert any("drive.smart" in key for key in status)
        assert any("drive.predictive_failure" in key for key in status)
        assert any("raid.status" in key for key in status)
        assert any("indicator.led" in key for key in status)
        for alert in status.values():
            assert alert.severity == "critical"

    def test_repeated_critical_dedupes_single_active_alert(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={"critical_mode": True}, next_poll_at=T0 - TICK
        )
        self._run_once(db_session, db_settings, T0)
        self._run_once(db_session, db_settings, T0 + TICK)
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert len(active) == 6  # device.health + 5 status.problem dedupes
        assert len({alert.dedupe_key for alert in active}) == len(active)
        health_alerts = [alert for alert in active if alert.rule_key == "device.health"]
        assert len(health_alerts) == 1

    def test_health_alert_resolves_after_two_good_signals(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={"critical_mode": True}, next_poll_at=T0 - TICK
        )
        self._run_once(db_session, db_settings, T0)
        db_session.refresh(device)
        assert device.health == "critical"
        device.connection_config = {}
        db_session.commit()
        now = T0 + 2 * TICK
        # 1st healthy run: signal_count=1 (resolve_after=2) -> still active
        self._run_once(db_session, db_settings, now)
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        health = [alert for alert in active if alert.rule_key == "device.health"]
        assert len(health) == 1
        assert health[0].signal_count == 1
        # 2nd healthy run: resolves
        self._run_once(db_session, db_settings, now + TICK)
        resolved = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "resolved")
        ).all()
        health = [alert for alert in resolved if alert.rule_key == "device.health"]
        assert len(health) == 1
        assert health[0].resolved_at is not None

    def test_data_expired_opens_and_fresh_resolves(self, db_session: Session, db_settings: object) -> None:
        from app.application.collection import process_collection_events
        from app.models.observation import MetricLatest

        device = make_collection_device(db_session, next_poll_at=None)
        # seed stale latest rows for every supported metric of SRV-MON-02:
        # the group is only "fresh" when ALL its supported metrics are fresh.
        stale_at = T0 - datetime.timedelta(seconds=200)
        for metric_key in ("temperature.cpu", "temperature.memory", "temperature.inlet", "temperature.board"):
            db_session.add(
                MetricLatest(
                    device_id=device.id,
                    metric_key=metric_key,
                    value_double=42.5,
                    value_text=None,
                    unit="Cel",
                    quality="good",
                    source="redfish",
                    observed_at=stale_at,
                )
            )
        db_session.commit()
        process_collection_events(db_session, device=device, now=T0, settings=db_settings)
        db_session.commit()
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        expired = [alert for alert in active if alert.rule_key == "data.expired"]
        assert len(expired) == 1
        assert expired[0].severity == "warning"
        assert "SRV-MON-02" in expired[0].dedupe_key

        # fresh data resolves (resolve_after=1)
        for row in db_session.scalars(
            select(MetricLatest).where(MetricLatest.device_id == device.id)
        ).all():
            row.observed_at = T0
        db_session.commit()
        process_collection_events(db_session, device=device, now=T0, settings=db_settings)
        db_session.commit()
        resolved = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "resolved")
        ).all()
        expired = [alert for alert in resolved if alert.rule_key == "data.expired"]
        assert len(expired) == 1

    def test_data_expired_uses_configured_metrics_interval(self, db_session: Session, db_settings: object) -> None:
        # The freshness cadence comes from settings by collection type, not a
        # hardcoded 60s (M2T2 review finding 4): with a 90s metrics interval,
        # 200s-old data is stale (not expired) and only >270s opens.
        from app.application.collection import process_collection_events
        from app.config import WardenSettings
        from app.models.observation import MetricLatest

        assert isinstance(db_settings, WardenSettings)
        settings = db_settings.model_copy(update={"metrics_interval_seconds": 90})
        device = make_collection_device(db_session, next_poll_at=None)
        stale_at = T0 - datetime.timedelta(seconds=200)  # within 3x90=270s
        for metric_key in ("temperature.cpu", "temperature.memory", "temperature.inlet", "temperature.board"):
            db_session.add(
                MetricLatest(
                    device_id=device.id,
                    metric_key=metric_key,
                    value_double=42.5,
                    value_text=None,
                    unit="Cel",
                    quality="good",
                    source="redfish",
                    observed_at=stale_at,
                )
            )
        db_session.commit()
        process_collection_events(db_session, device=device, now=T0, settings=settings)
        db_session.commit()
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert all(alert.rule_key != "data.expired" for alert in active)

        # now older than 3x the 90s interval -> expired opens
        for row in db_session.scalars(
            select(MetricLatest).where(MetricLatest.device_id == device.id)
        ).all():
            row.observed_at = T0 - datetime.timedelta(seconds=280)
        db_session.commit()
        process_collection_events(db_session, device=device, now=T0, settings=settings)
        db_session.commit()
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        expired = [alert for alert in active if alert.rule_key == "data.expired"]
        assert len(expired) == 1
        assert "SRV-MON-02" in expired[0].dedupe_key


class TestCredentialBackoff:
    def test_authentication_failed_backs_off_next_poll(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(
            db_session, connection_config={FAILURE_MODE_KEY: "authentication_failed"}, next_poll_at=T0 - TICK
        )
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "failed"
        assert run.error_code == "authentication_failed"
        first_failed_type = run.collection_type
        db_session.refresh(device)
        # the failing type is backed off to 5x ITS interval (collection_type
        # decides the interval; reachability/health share the 30s setting)
        from app.application.collection import collection_intervals

        intervals = collection_intervals(db_settings)
        interval = intervals[run.collection_type]
        state = device.collection_state or {}
        backoff = state.get("_backoff")
        assert isinstance(backoff, dict)
        expected_until = T0 + datetime.timedelta(seconds=interval * AUTH_FAILURE_BACKOFF_MULTIPLIER)
        parsed = datetime.datetime.fromisoformat(str(backoff[run.collection_type]))
        assert parsed >= expected_until - datetime.timedelta(seconds=1)
        assert run.collection_type == first_failed_type

        # while the backoff is active the scheduler creates nothing new: the
        # failing type is backed off and the other types still have pending
        # runs from the first tick
        now = T0 + TICK
        scheduled = schedule_due_collections(db_session, now=now, settings=db_settings)
        db_session.commit()
        assert scheduled == 0

        # drain the pending runs (each fails with authentication_failed and
        # backs off its own type), then once the FIRST backoff expires the
        # scheduler creates exactly that type's run again (the others are
        # still backed off)
        while True:
            pending = db_session.scalars(
                select(CollectionRun).where(
                    CollectionRun.device_id == device.id,
                    CollectionRun.state.in_(("scheduled", "running")),
                )
            ).all()
            if not pending:
                break
            run = _claim_and_run(db_session, settings=db_settings, now=now)
            assert run is not None and run.state == "failed"
        first_backoff_expiry = now + datetime.timedelta(seconds=interval * AUTH_FAILURE_BACKOFF_MULTIPLIER + 1)
        created = schedule_due_collections(db_session, now=first_backoff_expiry, settings=db_settings)
        db_session.commit()
        assert created >= 1
        new_runs = db_session.scalars(
            select(CollectionRun).where(
                CollectionRun.device_id == device.id, CollectionRun.scheduled_at >= first_backoff_expiry
            )
        ).all()
        # the originally-failing type is rescheduled once its backoff expires
        assert first_failed_type in {item.collection_type for item in new_runs}


class TestOneTransactionPerBatch:
    def test_rollback_removes_everything(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = claim_collection_run(db_session, lease_owner="w", lease_seconds=300)
        db_session.commit()
        assert run is not None
        run_collection(db_session, run.id, settings=db_settings, keyring=make_keyring(), now=T0)
        db_session.rollback()  # abort the batch transaction
        counts = (
            db_session.scalar(
                select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id)
            ),
            db_session.scalar(
                select(func.count()).select_from(MetricLatest).where(MetricLatest.device_id == device.id)
            ),
            db_session.scalar(
                select(func.count()).select_from(UiEvent).where(UiEvent.entity_id == device.id)
            ),
        )
        assert counts == (0, 0, 0)
        db_session.refresh(run)
        assert run.state == "running"  # the terminal state was part of the batch


class TestPartitionRoutingEndToEnd:
    def test_points_land_in_daily_partition(self, db_session: Session, db_settings: object) -> None:
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        _claim_and_run(db_session, settings=db_settings, now=T0)
        # The point landed in the daily partition of ITS OWN session-local
        # day (the partition-bound semantics) — the expected name is derived
        # from the stored row, never a hard-coded date (M2T8 window fix).
        relname, expected = db_session.execute(
            text(
                "SELECT c.relname, "
                "'metric_points_' || to_char(p.observed_at AT TIME ZONE "
                "current_setting('TimeZone'), 'YYYY_MM_DD') "
                "FROM metric_points p JOIN pg_class c ON c.oid = p.tableoid "
                "WHERE p.device_id = :did LIMIT 1"
            ),
            {"did": device.id},
        ).one()
        assert str(relname) == str(expected)
        assert str(relname).startswith("metric_points_")


class TestQualitySemantics:
    def test_unsupported_metric_never_written_as_point(self, db_session: Session, db_settings: object) -> None:
        # The fake only returns contract metrics; a missing metric is an
        # ObservationError — verified in the store tests. Here we assert the
        # end-to-end run never fabricates zero values.
        device = make_collection_device(db_session, next_poll_at=T0 - TICK)
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        _claim_and_run(db_session, settings=db_settings, now=T0)
        zero_values = db_session.scalars(
            select(MetricPoint).where(MetricPoint.device_id == device.id, MetricPoint.value_double == 0)
        ).all()
        assert all(point.metric_key == "memory.ecc_errors" for point in zero_values)


class TestUnsupportedCapabilityEndToEnd:
    def test_unsupported_metric_is_error_and_never_drives_status_problem(
        self, db_session: Session, db_settings: object
    ) -> None:
        # critical_mode reports indicator.led=critical, but the device does
        # NOT support indicator.led: no point, an unsupported_capability
        # error, run=partial, and no status.problem signal for it — while the
        # supported metrics still alert normally (M2T2 review finding 2).
        from app.models.devices import DeviceCapability

        device = make_collection_device(
            db_session, connection_config={"critical_mode": True}, next_poll_at=T0 - TICK
        )
        row = db_session.scalar(
            select(DeviceCapability).where(
                DeviceCapability.device_id == device.id,
                DeviceCapability.capability_key == "indicator.led",
            )
        )
        assert row is not None
        db_session.delete(row)
        db_session.commit()
        schedule_due_collections(db_session, now=T0, settings=db_settings)
        db_session.commit()
        run = _claim_and_run(db_session, settings=db_settings, now=T0)
        assert run is not None
        assert run.state == "partial"  # 18 good + 1 unsupported error
        points = db_session.scalars(
            select(MetricPoint).where(
                MetricPoint.device_id == device.id, MetricPoint.metric_key == "indicator.led"
            )
        ).all()
        assert points == []
        latest = db_session.scalars(
            select(MetricLatest).where(
                MetricLatest.device_id == device.id, MetricLatest.metric_key == "indicator.led"
            )
        ).all()
        assert latest == []
        errors = db_session.scalars(
            select(CollectionObservationError).where(
                CollectionObservationError.device_id == device.id,
                CollectionObservationError.metric_key_or_event_key == "indicator.led",
            )
        ).all()
        assert [(row.error_code, row.stage) for row in errors] == [("unsupported_capability", "validate")]
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        status = [alert for alert in active if alert.rule_key == "status.problem"]
        assert all("indicator.led" not in alert.dedupe_key for alert in status)
        assert any("drive.status" in alert.dedupe_key for alert in status)
        assert any(alert.rule_key == "device.health" for alert in active)
