"""Observation persistence on the REAL PostgreSQL 18 (TEST_STRATEGY §2.2).

Covers DATA_MODEL.md §5/§6 semantics: batch persistence (points/latest/
components/events), at-least-once dedup via unique indexes, partial quality,
day-partition routing + the partition helper, observation errors, the
collection_run claim/lease/reclaim transitions, and the alert
open/resolve/count lifecycle with durable counters.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from app.domain.adapter import (
    ComponentObserved,
    EventObservation,
    Observation,
    ObservationBatch,
    ObservationError,
    Quality,
)
from app.domain.observation import AlertSignal
from app.generated.alerts import ALERT_RULES
from app.infrastructure.observation_store import (
    apply_alert_signals,
    claim_collection_run,
    ensure_metric_partitions,
    persist_observation_batch,
    release_collection_lease,
)
from app.models.observation import (
    Alert,
    CollectionObservationError,
    DeviceEvent,
    MetricLatest,
    MetricPoint,
)
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from tests.observation_factories import make_collection_device, make_collection_run

NOW = datetime.datetime(2026, 9, 2, 10, 0, 0, tzinfo=datetime.UTC)
PAST = NOW - datetime.timedelta(hours=1)
FUTURE = NOW + datetime.timedelta(hours=1)
ZERO = uuid.UUID("00000000-0000-0000-0000-000000000000")


def _normal_batch(now: datetime.datetime = NOW) -> ObservationBatch:
    return ObservationBatch(
        observations=(
            Observation("health.overall", "healthy", now, source="redfish"),
            Observation(
                "temperature.cpu", 42.5, now, component_kind="processor", component_native_id="cpu-0", source="redfish"
            ),
            Observation(
                "drive.status", "ok", now, component_kind="drive", component_native_id="drive-0", source="redfish"
            ),
        ),
        events=(
            EventObservation(
                event_type="event.sel",
                severity="info",
                message="SEL 测试事件",
                occurred_at=now,
                source="redfish_sel",
                native_event_id="NATIVE-1",
            ),
        ),
        components=(
            ComponentObserved(kind="processor", native_id="cpu-0", name="CPU", status="ok"),
            ComponentObserved(kind="drive", native_id="drive-0", name="Drive", status="ok"),
        ),
    )


class TestBatchPersistence:
    def test_persist_writes_points_latest_components_events(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        outcome = persist_observation_batch(
            db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW
        )
        db_session.commit()

        assert outcome.successes == 3
        assert outcome.errors == 0
        assert outcome.points_written == 3
        assert outcome.points_deduped == 0
        assert outcome.latest_written == 3
        assert outcome.events_written == 1

        points = db_session.scalars(select(MetricPoint).where(MetricPoint.device_id == device.id)).all()
        assert len(points) == 3
        cpu = next(p for p in points if p.metric_key == "temperature.cpu")
        assert cpu.value_double == 42.5
        assert cpu.unit == "Cel"
        assert cpu.quality == "good"
        assert cpu.collection_run_id == run.id
        health = next(p for p in points if p.metric_key == "health.overall")
        assert health.value_text == "healthy"
        assert health.value_double is None

        latest = db_session.scalars(select(MetricLatest).where(MetricLatest.device_id == device.id)).all()
        assert {row.metric_key for row in latest} == {"health.overall", "temperature.cpu", "drive.status"}

        from app.models.devices import Component

        rows = db_session.scalars(
            select(Component).where(Component.device_id == device.id).order_by(Component.kind)
        ).all()
        assert [(row.kind, row.native_id, row.status) for row in rows] == [
            ("drive", "drive-0", "ok"),
            ("processor", "cpu-0", "ok"),
        ]
        assert all(row.retired_at is None for row in rows)

        events = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert len(events) == 1
        assert events[0].native_event_id == "NATIVE-1"
        assert events[0].severity == "info"

    def test_native_event_id_dedupes(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = _normal_batch()
        persist_observation_batch(
            db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW
        )
        db_session.commit()
        second = persist_observation_batch(
            db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW
        )
        db_session.commit()
        assert second.events_written == 0
        assert second.events_deduped == 1
        count = db_session.scalar(
            select(func.count()).select_from(DeviceEvent).where(DeviceEvent.device_id == device.id)
        )
        assert count == 1

    def test_hash_dedup_for_events_without_native_id(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = ObservationBatch(
            events=(
                EventObservation(
                    event_type="event.sel", severity="warning", message="重复内容",
                    occurred_at=NOW, source="redfish_sel",
                ),
            )
        )
        first = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert first.events_written == 1
        second = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert second.events_written == 0
        assert second.events_deduped == 1
        count = db_session.scalar(
            select(func.count()).select_from(DeviceEvent).where(DeviceEvent.device_id == device.id)
        )
        assert count == 1

    def test_duplicate_point_is_deduped_not_overwritten(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = _normal_batch()
        first = persist_observation_batch(
            db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW
        )
        db_session.commit()
        second = persist_observation_batch(
            db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW
        )
        db_session.commit()
        assert first.points_written == 3
        assert second.points_written == 0
        assert second.points_deduped == 3
        count = db_session.scalar(
            select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device.id)
        )
        assert count == 3

    def test_partial_quality_point_written_but_latest_not_updated(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = ObservationBatch(
            observations=(
                Observation("temperature.cpu", 99.0, NOW, quality=Quality.PARTIAL, source="redfish"),
            )
        )
        outcome = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert outcome.successes == 1
        assert outcome.latest_written == 0
        points = db_session.scalars(select(MetricPoint).where(MetricPoint.device_id == device.id)).all()
        assert len(points) == 1
        assert points[0].quality == "partial"
        latest = db_session.scalars(select(MetricLatest).where(MetricLatest.device_id == device.id)).all()
        assert latest == []

    def test_error_quality_observation_becomes_error_row_not_point(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = ObservationBatch(
            observations=(
                Observation("temperature.cpu", 42.5, NOW, quality=Quality.ERROR, source="redfish"),
            )
        )
        outcome = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert outcome.successes == 0
        assert outcome.errors == 1
        points = db_session.scalars(select(MetricPoint).where(MetricPoint.device_id == device.id)).all()
        assert points == []
        errors = db_session.scalars(
            select(CollectionObservationError).where(CollectionObservationError.device_id == device.id)
        ).all()
        assert len(errors) == 1

    def test_invalid_metric_key_and_enum_value_become_errors(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = ObservationBatch(
            observations=(
                Observation("not.a.metric", 1, NOW, source="redfish"),
                Observation("drive.status", "bogus-status", NOW, source="redfish"),
                Observation("temperature.cpu", "hot", NOW, source="redfish"),
            ),
            errors=(ObservationError(key="fan.status", error_code="protocol_error", stage="parse", detail="x"),),
        )
        outcome = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert outcome.successes == 0
        assert outcome.errors == 4
        errors = db_session.scalars(
            select(CollectionObservationError).where(CollectionObservationError.device_id == device.id)
        ).all()
        assert {row.metric_key_or_event_key for row in errors} == {
            "not.a.metric",
            "drive.status",
            "temperature.cpu",
            "fan.status",
        }
        assert all(row.error_code == "protocol_error" for row in errors)

    def test_event_validation_errors(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        batch = ObservationBatch(
            events=(
                EventObservation(
                    event_type="event.sel", severity="loud", message="x", occurred_at=NOW, source="redfish_sel"
                ),
                EventObservation(
                    event_type="event.sel", severity="info", message="x", occurred_at=NOW, source="syslog"
                ),
                EventObservation(
                    event_type="event.unknown", severity="info", message="x", occurred_at=NOW, source="redfish_sel"
                ),
            )
        )
        outcome = persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        assert outcome.errors == 3
        assert outcome.events_written == 0

    def test_components_retired_when_missing_from_non_empty_batch(self, db_session: Session) -> None:
        from app.models.devices import Component

        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        first = _normal_batch()
        persist_observation_batch(db_session, device_id=device.id, batch=first, run_id=run.id, now=NOW)
        db_session.commit()
        second = ObservationBatch(
            observations=(Observation("health.overall", "healthy", NOW, source="redfish"),),
            components=(ComponentObserved(kind="processor", native_id="cpu-0", name="CPU", status="ok"),),
        )
        persist_observation_batch(db_session, device_id=device.id, batch=second, run_id=run.id, now=NOW)
        db_session.commit()
        rows = db_session.scalars(
            select(Component).where(Component.device_id == device.id).order_by(Component.kind)
        ).all()
        drive = next(row for row in rows if row.native_id == "drive-0")
        assert drive.retired_at is not None
        cpu = next(row for row in rows if row.native_id == "cpu-0")
        assert cpu.retired_at is None

    def test_empty_components_never_retire(self, db_session: Session) -> None:
        from app.models.devices import Component

        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        persist_observation_batch(db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW)
        db_session.commit()
        batch = ObservationBatch(
            observations=(Observation("health.overall", "healthy", NOW, source="redfish"),)
        )
        persist_observation_batch(db_session, device_id=device.id, batch=batch, run_id=run.id, now=NOW)
        db_session.commit()
        retired = db_session.scalar(
            select(func.count()).select_from(Component).where(
                Component.device_id == device.id, Component.retired_at.is_not(None)
            )
        )
        assert retired == 0

    def test_reobserved_component_clears_retired_at(self, db_session: Session) -> None:
        from app.models.devices import Component

        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        # batch 1: drive observed; batch 2: drive missing -> retired;
        # batch 3: drive re-observed -> retired_at must be cleared so the
        # component is visible again (M2T2 review finding 3).
        persist_observation_batch(db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW)
        db_session.commit()
        retire = ObservationBatch(
            observations=(Observation("health.overall", "healthy", NOW, source="redfish"),),
            components=(ComponentObserved(kind="processor", native_id="cpu-0", name="CPU", status="ok"),),
        )
        persist_observation_batch(db_session, device_id=device.id, batch=retire, run_id=run.id, now=NOW)
        db_session.commit()
        drive = db_session.scalar(
            select(Component).where(Component.device_id == device.id, Component.native_id == "drive-0")
        )
        assert drive is not None and drive.retired_at is not None
        back = _normal_batch()
        persist_observation_batch(db_session, device_id=device.id, batch=back, run_id=run.id, now=NOW)
        db_session.commit()
        drive = db_session.scalar(
            select(Component).where(Component.device_id == device.id, Component.native_id == "drive-0")
        )
        assert drive is not None
        assert drive.retired_at is None
        assert drive.last_seen_at == NOW

    def test_unsupported_metric_becomes_error_not_point(self, db_session: Session) -> None:
        from app.models.devices import DeviceCapability

        device = make_collection_device(db_session)
        # remove the drive.status capability: the device does not support it
        row = db_session.scalar(
            select(DeviceCapability).where(
                DeviceCapability.device_id == device.id,
                DeviceCapability.capability_key == "drive.status",
            )
        )
        assert row is not None
        db_session.delete(row)
        db_session.commit()
        run = make_collection_run(db_session, device_id=device.id)
        outcome = persist_observation_batch(
            db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW
        )
        db_session.commit()
        # drive.status -> unsupported_capability error; the rest persists
        assert outcome.successes == 2
        assert outcome.errors == 1
        points = db_session.scalars(
            select(MetricPoint).where(
                MetricPoint.device_id == device.id, MetricPoint.metric_key == "drive.status"
            )
        ).all()
        assert points == []
        latest = db_session.scalars(
            select(MetricLatest).where(
                MetricLatest.device_id == device.id, MetricLatest.metric_key == "drive.status"
            )
        ).all()
        assert latest == []
        errors = db_session.scalars(
            select(CollectionObservationError).where(CollectionObservationError.device_id == device.id)
        ).all()
        assert [(row.metric_key_or_event_key, row.error_code) for row in errors] == [
            ("drive.status", "unsupported_capability")
        ]
        events = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert len(events) == 1  # event.sel is still supported

    def test_unsupported_event_becomes_error_not_row(self, db_session: Session) -> None:
        from app.models.devices import DeviceCapability

        device = make_collection_device(db_session)
        row = db_session.scalar(
            select(DeviceCapability).where(
                DeviceCapability.device_id == device.id,
                DeviceCapability.capability_key == "event.sel",
            )
        )
        assert row is not None
        db_session.delete(row)
        db_session.commit()
        run = make_collection_run(db_session, device_id=device.id)
        outcome = persist_observation_batch(
            db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW
        )
        db_session.commit()
        assert outcome.successes == 3
        assert outcome.errors == 1
        events = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert events == []
        errors = db_session.scalars(
            select(CollectionObservationError).where(CollectionObservationError.device_id == device.id)
        ).all()
        assert errors[0].metric_key_or_event_key == "event.sel"
        assert errors[0].error_code == "unsupported_capability"


class TestPartitions:
    def test_rows_land_in_today_partition(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        persist_observation_batch(db_session, device_id=device.id, batch=_normal_batch(), run_id=run.id, now=NOW)
        db_session.commit()
        row = db_session.execute(
            text(
                "SELECT c.relname FROM metric_points p "
                "JOIN pg_class c ON c.oid = p.tableoid WHERE p.metric_key = 'temperature.cpu'"
            )
        ).scalar()
        assert row is not None
        assert str(row).startswith("metric_points_")

    def test_insert_outside_partition_window_fails_honestly(self, db_session: Session) -> None:
        # No partition exists for this old date: PostgreSQL must reject the
        # insert instead of fabricating storage semantics.
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id)
        old = NOW - datetime.timedelta(days=400)
        with pytest.raises(SQLAlchemyError):
            persist_observation_batch(
                db_session, device_id=device.id, batch=_normal_batch(now=old), run_id=run.id, now=old
            )
            db_session.commit()
        db_session.rollback()

    def test_create_metric_partition_is_idempotent(self, db_session: Session) -> None:
        start = datetime.date(2026, 10, 1)  # outside the migration's pre-created window
        assert ensure_metric_partitions(db_session, start_date=start, days=1) == 1
        assert ensure_metric_partitions(db_session, start_date=start, days=1) == 0
        name = db_session.execute(
            text("SELECT to_regclass('public.metric_points_2026_10_01')")
        ).scalar()
        assert name is not None


class TestCollectionRunClaim:
    def test_claim_transitions_scheduled_to_running_with_lease(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id, scheduled_at=PAST)
        claimed = claim_collection_run(db_session, lease_owner="w1", lease_seconds=300)
        db_session.commit()
        assert claimed is not None
        assert claimed.id == run.id
        assert claimed.state == "running"
        assert claimed.lease_owner == "w1"
        assert claimed.attempt_count == 1
        assert claimed.started_at is not None

    def test_claim_skips_running_with_valid_lease(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        make_collection_run(
            db_session, device_id=device.id, state="running", lease_owner="w1", lease_expires_at=FUTURE
        )
        assert claim_collection_run(db_session, lease_owner="w2", lease_seconds=300) is None

    def test_claim_reclaims_expired_lease_running_run(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        expired = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
        run = make_collection_run(
            db_session, device_id=device.id, state="running", lease_owner="dead", lease_expires_at=expired
        )
        claimed = claim_collection_run(db_session, lease_owner="w2", lease_seconds=300)
        db_session.commit()
        assert claimed is not None and claimed.id == run.id
        assert claimed.lease_owner == "w2"
        assert claimed.attempt_count == 2

    def test_release_lease_expires_immediately_for_reclaim(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id, scheduled_at=PAST)
        claim_collection_run(db_session, lease_owner="w1", lease_seconds=300)
        db_session.commit()
        assert release_collection_lease(db_session, run_id=run.id, owner="w1") is True
        db_session.commit()
        claimed = claim_collection_run(db_session, lease_owner="w2", lease_seconds=300)
        db_session.commit()
        assert claimed is not None and claimed.id == run.id
        assert claimed.attempt_count == 2

    def test_release_lease_wrong_owner_fails(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        run = make_collection_run(db_session, device_id=device.id, scheduled_at=PAST)
        claim_collection_run(db_session, lease_owner="w1", lease_seconds=300)
        db_session.commit()
        assert release_collection_lease(db_session, run_id=run.id, owner="intruder") is False


def _rules_by_key() -> dict[str, object]:
    return {rule.rule_key: rule for rule in ALERT_RULES}


class TestAlertLifecycle:
    def test_open_refresh_resolve_with_counters(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        rules = _rules_by_key()
        opened: list[tuple[str, uuid.UUID]] = []

        opened += apply_alert_signals(
            db_session,
            device_id=device.id,
            signals=(
                AlertSignal(
                    rule_key="device.health",
                    dedupe_key=f"device.health:{device.id}",
                    title="设备健康异常",
                    evidence={"value": "critical"},
                    severity="critical",
                ),
            ),
            rules_by_key=rules,
            now=NOW,
        )
        db_session.commit()
        assert [event for event, _ in opened] == ["alert.opened"]
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert len(active) == 1
        assert active[0].severity == "critical"
        assert active[0].signal_count == 0

        # a second open-worthy signal refreshes, never duplicates
        opened += apply_alert_signals(
            db_session,
            device_id=device.id,
            signals=(
                AlertSignal(
                    rule_key="device.health",
                    dedupe_key=f"device.health:{device.id}",
                    title="设备健康异常",
                    evidence={"value": "warning"},
                    severity="warning",
                ),
            ),
            rules_by_key=rules,
            now=NOW + datetime.timedelta(minutes=1),
        )
        db_session.commit()
        assert [event for event, _ in opened] == ["alert.opened", "alert.updated"]
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert len(active) == 1
        assert active[0].severity == "warning"

        # first good signal counts (resolve_after=2), second resolves
        good = AlertSignal(
            rule_key="device.health",
            dedupe_key=f"device.health:{device.id}",
            title="设备健康异常",
            evidence={"value": "healthy"},
            resolve=True,
        )
        ui1 = apply_alert_signals(db_session, device_id=device.id, signals=(good,), rules_by_key=rules, now=NOW)
        db_session.commit()
        assert ui1 == []
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert len(active) == 1
        assert active[0].signal_count == 1
        ui2 = apply_alert_signals(db_session, device_id=device.id, signals=(good,), rules_by_key=rules, now=NOW)
        db_session.commit()
        assert [event for event, _ in ui2] == ["alert.resolved"]
        resolved = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "resolved")
        ).all()
        assert len(resolved) == 1
        assert resolved[0].resolved_at is not None

    def test_no_decision_resets_counter_but_keeps_alert_active(self, db_session: Session) -> None:
        device = make_collection_device(db_session)
        rules = _rules_by_key()
        apply_alert_signals(
            db_session,
            device_id=device.id,
            signals=(
                AlertSignal(
                    rule_key="device.health",
                    dedupe_key=f"device.health:{device.id}",
                    title="设备健康异常",
                    evidence={"value": "critical"},
                    severity="critical",
                ),
            ),
            rules_by_key=rules,
            now=NOW,
        )
        db_session.commit()
        good = AlertSignal(
            rule_key="device.health",
            dedupe_key=f"device.health:{device.id}",
            title="设备健康异常",
            evidence={"value": "healthy"},
            resolve=True,
        )
        apply_alert_signals(db_session, device_id=device.id, signals=(good,), rules_by_key=rules, now=NOW)
        db_session.commit()
        unknown = AlertSignal(
            rule_key="device.health",
            dedupe_key=f"device.health:{device.id}",
            title="设备健康异常",
            evidence={"value": "unknown"},
            no_decision=True,
        )
        apply_alert_signals(db_session, device_id=device.id, signals=(unknown,), rules_by_key=rules, now=NOW)
        db_session.commit()
        active = db_session.scalars(
            select(Alert).where(Alert.device_id == device.id, Alert.status == "active")
        ).all()
        assert len(active) == 1
        assert active[0].signal_count == 0

    def test_db_prevents_two_active_alerts_for_same_dedupe(self, db_session: Session) -> None:
        # The partial unique index uq_alerts_active_dedupe is the hard guard:
        # a second OPEN (not refresh — e.g. a race) violates it at the DB.
        device = make_collection_device(db_session)
        from sqlalchemy.exc import IntegrityError

        db_session.add(
            Alert(
                device_id=device.id,
                rule_key="device.health",
                severity="critical",
                status="active",
                title="t",
                evidence={},
                first_occurred_at=NOW,
                last_occurred_at=NOW,
                dedupe_key=f"device.health:{device.id}",
                signal_count=0,
            )
        )
        db_session.commit()
        with pytest.raises(IntegrityError):
            db_session.add(
                Alert(
                    device_id=device.id,
                    rule_key="device.health",
                    severity="critical",
                    status="active",
                    title="t",
                    evidence={},
                    first_occurred_at=NOW,
                    last_occurred_at=NOW,
                    dedupe_key=f"device.health:{device.id}",
                    signal_count=0,
                )
            )
            db_session.commit()
        db_session.rollback()
