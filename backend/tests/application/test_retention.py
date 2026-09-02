"""Retention enforcement integration tests (real PostgreSQL).

docs/DATA_MODEL.md 搂10 + M2T3 brief: raw metric_points leave via DROP of old
daily partitions (never row deletes), rollups/events/resolved alerts/terminal
operation tasks/sessions/ui_events via batch deletes, audit_logs stay
append-only (0002 trigger + 0004 REVOKE 鈥?the function reports the skip).
Every delete is counted; deletes never touch active/queued/verification_required
tasks and never delete audit history.
"""

from __future__ import annotations

import datetime
import uuid

from app.application.maintenance import enforce_retention
from app.config import WardenSettings
from app.infrastructure.observation_store import ensure_metric_partitions
from app.models.auth import AuditLog, User
from app.models.auth import Session as DBSession
from app.models.observation import (
    Alert,
    DeviceEvent,
    MetricPoint,
    MetricRollup1h,
    MetricRollup5m,
    UiEvent,
)
from app.models.operation import OperationTask, OperationTaskEvent
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from tests.observation_factories import make_collection_device
from tests.task_factories import make_task, make_user

UTC = datetime.UTC
NOW = datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
SETTINGS = WardenSettings(_env_file=None)


def _seed_partitions(db: Session) -> None:
    ensure_metric_partitions(
        db, start_date=(NOW.date() - datetime.timedelta(days=12)), days=15
    )
    db.commit()


def _seed_raw_point(
    db: Session,
    *,
    device_id: uuid.UUID,
    observed_at: datetime.datetime,
    value: float,
) -> None:
    db.add(
        MetricPoint(
            id=uuid.uuid4(),
            device_id=device_id,
            component_id=None,
            metric_key="system.cpu_percent",
            observed_at=observed_at,
            value_double=value,
            unit="%",
            quality="good",
            source="redfish",
        )
    )


def _point_count(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(MetricPoint)) or 0)


def _partition_names(db: Session) -> set[str]:
    rows = db.execute(
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


def _user(db: Session) -> User:
    return make_user(db, index=0)


def _session_row(
    db: Session,
    user: User,
    *,
    revoked_at: datetime.datetime | None,
    absolute_expires_at: datetime.datetime | None = None,
) -> DBSession:
    row = DBSession(
        session_id_hash=uuid.uuid4().hex,
        user_id=user.id,
        expires_at=NOW + datetime.timedelta(hours=1),
        absolute_expires_at=absolute_expires_at or (NOW + datetime.timedelta(hours=12)),
        revoked_at=revoked_at,
        csrf_secret_hash=uuid.uuid4().hex,
    )
    db.add(row)
    return row


def _ui_event(db: Session, *, occurred_at: datetime.datetime) -> None:
    db.add(
        UiEvent(
            entity_type="device",
            entity_id=uuid.uuid4(),
            version=1,
            event_type="device.updated",
            payload={},
            occurred_at=occurred_at,
        )
    )


class TestPartitionDrop:
    def test_old_partitions_are_dropped_recent_kept(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=1)
        _seed_partitions(db_session)
        old_day = NOW - datetime.timedelta(days=8)  # partition fully below cutoff
        kept_day = NOW - datetime.timedelta(days=2)
        for observed_at, value in [(old_day + datetime.timedelta(hours=2), 1.0), (kept_day, 2.0)]:
            _seed_raw_point(db_session, device_id=device.id, observed_at=observed_at, value=value)
        db_session.commit()
        assert "metric_points_2026_08_24" in _partition_names(db_session)
        assert _point_count(db_session) == 2

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert old_day.date().strftime("metric_points_%Y_%m_%d") in report.partitions_dropped
        names = _partition_names(db_session)
        assert old_day.date().strftime("metric_points_%Y_%m_%d") not in names
        assert kept_day.date().strftime("metric_points_%Y_%m_%d") in names
        assert _point_count(db_session) == 1
        remaining = db_session.scalar(
            select(MetricPoint.value_double).where(MetricPoint.metric_key == "system.cpu_percent")
        )
        assert remaining == 2.0

    def test_partial_partition_touching_cutoff_is_kept(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=2)
        _seed_partitions(db_session)
        # raw_retention_days=7 -> cutoff = Aug 25 12:00; the partition
        # [Aug 25 00:00, Aug 26 00:00) still holds retained data -> kept even
        # though empty partitions before it are dropped.
        observed_at = NOW - datetime.timedelta(days=7) - datetime.timedelta(hours=6)
        _seed_raw_point(db_session, device_id=device.id, observed_at=observed_at, value=7.5)
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        names = _partition_names(db_session)
        partition = observed_at.date().strftime("metric_points_%Y_%m_%d")
        assert partition in names
        assert partition not in report.partitions_dropped
        assert _point_count(db_session) == 1


class TestRollupAndEventRetention:
    def _seed_rollups(self, db: Session, device_id: uuid.UUID) -> None:
        db.add_all(
            [
                MetricRollup5m(
                    device_id=device_id,
                    component_id=None,
                    metric_key="system.cpu_percent",
                    window_start=NOW - datetime.timedelta(days=35),
                    min_value=1.0, max_value=1.0, avg_value=1.0, last_value=1.0,
                    count=1, quality="good",
                ),
                MetricRollup5m(
                    device_id=device_id,
                    component_id=None,
                    metric_key="system.cpu_percent",
                    window_start=NOW - datetime.timedelta(days=5),
                    min_value=2.0, max_value=2.0, avg_value=2.0, last_value=2.0,
                    count=1, quality="good",
                ),
                MetricRollup1h(
                    device_id=device_id,
                    component_id=None,
                    metric_key="system.cpu_percent",
                    window_start=NOW - datetime.timedelta(days=200),
                    min_value=1.0, max_value=1.0, avg_value=1.0, last_value=1.0,
                    count=1, quality="good",
                ),
                MetricRollup1h(
                    device_id=device_id,
                    component_id=None,
                    metric_key="system.cpu_percent",
                    window_start=NOW - datetime.timedelta(days=100),
                    min_value=2.0, max_value=2.0, avg_value=2.0, last_value=2.0,
                    count=1, quality="good",
                ),
            ]
        )

    def test_rollups_older_than_retention_are_deleted(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=3)
        self._seed_rollups(db_session, device.id)
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.rollup_5m_deleted == 1
        assert report.rollup_1h_deleted == 1
        assert db_session.scalar(select(func.count()).select_from(MetricRollup5m)) == 1
        assert db_session.scalar(select(func.count()).select_from(MetricRollup1h)) == 1

    def test_device_events_older_than_retention_are_deleted(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=4)
        db_session.add_all(
            [
                DeviceEvent(
                    device_id=device.id,
                    event_type="event.sel",
                    severity="info",
                    message="old",
                    occurred_at=NOW - datetime.timedelta(days=200),
                    source="redfish_sel",
                    native_event_id="OLD-1",
                ),
                DeviceEvent(
                    device_id=device.id,
                    event_type="event.sel",
                    severity="critical",
                    message="fresh",
                    occurred_at=NOW - datetime.timedelta(days=5),
                    source="redfish_sel",
                    native_event_id="NEW-1",
                ),
            ]
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.device_events_deleted == 1
        remaining = db_session.scalar(select(DeviceEvent.message).where(DeviceEvent.device_id == device.id))
        assert remaining == "fresh"


class TestAlertRetention:
    def test_resolved_alerts_older_than_retention_are_deleted(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=5)

        def _alert(*, status: str, resolved_at: datetime.datetime | None, title: str) -> Alert:
            return Alert(
                device_id=device.id,
                rule_key="device.health",
                severity="critical",
                status=status,
                title=title,
                evidence={},
                first_occurred_at=NOW - datetime.timedelta(days=200),
                last_occurred_at=NOW - datetime.timedelta(days=200),
                resolved_at=resolved_at,
                dedupe_key=f"device.health:{device.id}:{title}",
                signal_count=0,
            )

        db_session.add_all(
            [
                _alert(status="resolved", resolved_at=NOW - datetime.timedelta(days=200), title="old-resolved"),
                _alert(status="resolved", resolved_at=NOW - datetime.timedelta(days=5), title="fresh-resolved"),
                _alert(status="active", resolved_at=None, title="active-forever"),
            ]
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.resolved_alerts_deleted == 1
        titles = set(db_session.scalars(select(Alert.title)).all())
        assert titles == {"fresh-resolved", "active-forever"}

    def test_no_active_alert_is_ever_deleted_by_retention(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=6)
        db_session.add(
            Alert(
                device_id=device.id,
                rule_key="device.offline",
                severity="critical",
                status="active",
                title="offline",
                evidence={},
                first_occurred_at=NOW - datetime.timedelta(days=300),
                last_occurred_at=NOW - datetime.timedelta(days=300),
                resolved_at=None,
                dedupe_key=f"device.offline:{device.id}",
                signal_count=0,
            )
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.resolved_alerts_deleted == 0
        assert db_session.scalar(select(func.count()).select_from(Alert)) == 1


class TestOperationTaskRetention:
    def test_terminal_tasks_survive_append_only_event_stream(self, db_session: Session) -> None:
        # DATA_MODEL.md §7.3/0005 keep operation_task_events append-only at the
        # database: a task cannot be removed while its event stream exists, so
        # the sweep reports the skip instead of failing the whole pass.
        device = make_collection_device(db_session, index=7)
        user = _user(db_session)
        old = make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=7,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="succeeded",
            idempotency_key="retention-old-7",
        )
        old.finished_at = NOW - datetime.timedelta(days=400)
        db_session.add(OperationTaskEvent(task_id=old.id, state="succeeded", message="done"))
        fresh = make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=8,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="succeeded",
            idempotency_key="retention-fresh-8",
        )
        fresh.finished_at = NOW - datetime.timedelta(days=5)
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.operation_tasks_deleted == 0
        assert report.operation_tasks_skipped_append_only is True
        assert db_session.scalar(select(func.count()).select_from(OperationTask)) == 2
        events = db_session.scalar(
            select(func.count()).select_from(OperationTaskEvent).where(OperationTaskEvent.task_id == old.id)
        )
        assert events == 1  # the event stream is untouched

    def test_non_terminal_tasks_survive_retention(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=9)
        user = _user(db_session)
        make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=9,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="verification_required",
            idempotency_key="retention-verify-9",
        )
        make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=10,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="queued",
            idempotency_key="retention-queued-10",
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.operation_tasks_deleted == 0
        assert report.operation_tasks_skipped_append_only is True
        assert db_session.scalar(select(func.count()).select_from(OperationTask)) == 2


class TestUiEventAndSessionRetention:
    def test_ui_events_older_than_10_minutes_are_deleted(self, db_session: Session) -> None:
        make_collection_device(db_session, index=11)
        _ui_event(db_session, occurred_at=NOW - datetime.timedelta(minutes=20))
        _ui_event(db_session, occurred_at=NOW - datetime.timedelta(seconds=30))
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.ui_events_deleted == 1
        assert db_session.scalar(select(func.count()).select_from(UiEvent)) == 1

    def test_sessions_cleaned_thirty_days_after_expiry_or_revocation(
        self, db_session: Session
    ) -> None:
        user = _user(db_session)
        _session_row(db_session, user, revoked_at=NOW - datetime.timedelta(days=40))
        _session_row(
            db_session,
            user,
            revoked_at=None,
            absolute_expires_at=NOW - datetime.timedelta(days=40),
        )
        _session_row(db_session, user, revoked_at=None)
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.sessions_deleted == 2
        assert db_session.scalar(select(func.count()).select_from(DBSession)) == 1


class TestAuditStaysAppendOnly:
    def test_audit_rows_are_never_deleted_by_the_maintenance_loop(
        self, db_session: Session
    ) -> None:
        user = _user(db_session)
        db_session.add(
            AuditLog(
                actor_user_id=user.id,
                action="test.old_action",
                occurred_at=NOW - datetime.timedelta(days=400),
                result="success",
            )
        )
        db_session.add(
            AuditLog(
                actor_user_id=user.id,
                action="test.linked_action",
                occurred_at=NOW - datetime.timedelta(days=400),
                result="success",
            )
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        # 0002 trigger + 0004 REVOKE keep the table append-only: the sweep
        # records the skip instead of crashing or weakening the protection.
        assert report.audit_deleted == 0
        assert report.audit_skipped_append_only is True
        assert db_session.scalar(select(func.count()).select_from(AuditLog)) == 2

    def test_audit_never_removed_when_linked_task_is_cleaned(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=12)
        user = _user(db_session)
        old = make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=12,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="succeeded",
            idempotency_key="retention-linked-12",
        )
        old.finished_at = NOW - datetime.timedelta(days=400)
        db_session.add(
            AuditLog(
                actor_user_id=user.id,
                action="operation.accepted",
                occurred_at=NOW - datetime.timedelta(days=400),
                result="success",
                task_id=old.id,
                device_id=device.id,
            )
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.operation_tasks_deleted == 0
        assert report.operation_tasks_skipped_append_only is True
        assert report.audit_deleted == 0
        assert report.audit_skipped_append_only is True
        remaining = db_session.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.task_id == old.id)
        )
        assert remaining == 1


class TestFunctionSafety:
    def test_retention_is_idempotent(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=13)
        _seed_partitions(db_session)
        _seed_raw_point(
            db_session,
            device_id=device.id,
            observed_at=NOW - datetime.timedelta(days=8),
            value=1.0,
        )
        db_session.commit()

        first = enforce_retention(db_session, now=NOW, settings=SETTINGS)
        second = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert len(first.partitions_dropped) >= 1  # every partition below cutoff
        assert (NOW.date() - datetime.timedelta(days=8)).strftime(
            "metric_points_%Y_%m_%d"
        ) in first.partitions_dropped
        assert second.partitions_dropped == []
        assert second.rollup_5m_deleted == 0

    def test_retention_counts_returned_for_tests(self, db_session: Session) -> None:
        make_collection_device(db_session, index=14)
        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)
        assert report.rollup_5m_deleted == 0
        assert report.rollup_1h_deleted == 0
        assert report.device_events_deleted == 0
        assert report.resolved_alerts_deleted == 0
        assert report.operation_tasks_deleted == 0
        assert report.ui_events_deleted == 0
        assert report.sessions_deleted == 0
        assert report.as_dict()["audit_deleted"] == 0  # report shape is stable
        assert report.as_dict()["operation_tasks_skipped_append_only"] is True

    def test_retention_uses_settings_retention_days(self, db_session: Session) -> None:
        # A deployment that lowers raw retention to 1 day must drop partitions
        # sooner than the 7-day default would.
        device = make_collection_device(db_session, index=15)
        _seed_partitions(db_session)
        _seed_raw_point(
            db_session,
            device_id=device.id,
            observed_at=NOW - datetime.timedelta(days=2),
            value=1.0,
        )
        db_session.commit()
        tight = WardenSettings(raw_retention_days=1, _env_file=None)

        report = enforce_retention(db_session, now=NOW, settings=tight)

        assert len(report.partitions_dropped) >= 1
        assert (NOW.date() - datetime.timedelta(days=2)).strftime(
            "metric_points_%Y_%m_%d"
        ) in report.partitions_dropped
