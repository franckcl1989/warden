"""Retention enforcement integration tests (real PostgreSQL).

docs/DATA_MODEL.md §10 + M2T3 fix rulings: raw metric_points leave via DROP
of old daily partitions (never row deletes), rollups/events/resolved alerts/
terminal operation tasks/sessions/ui_events via batch deletes — with the
append-only exemptions of ADR-030:

- a terminal task is purged only when it has NO operation_task_events rows
  (the 0005 trigger + FK cascade make evented tasks unremovable);
- sessions referenced by audit_logs.session_id survive (the 0002 audit
  trigger rejects the FK SET NULL);
- audit_logs and operation_task_events themselves are never deleted: the
  sweep records ``*_skipped_append_only`` instead of crashing or weakening
  the append-only protections.

Every delete is counted; deletes never touch active/queued/verification_
required tasks and never delete audit or task-event history.
"""

from __future__ import annotations

import datetime
import uuid

from app.application.maintenance import enforce_retention
from app.config import WardenSettings
from app.infrastructure.observation_store import ensure_metric_partitions
from app.models.auth import AuditLog, User
from app.models.auth import Session as DBSession
from app.models.launch import LaunchSession
from app.models.observation import (
    Alert,
    DeviceEvent,
    MetricPoint,
    MetricRollup1h,
    MetricRollup5m,
    UiEvent,
)
from app.models.operation import OperationTask, OperationTaskEvent, PreviewTokenUse
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
    def test_eventless_terminal_tasks_are_purged(self, db_session: Session) -> None:
        # A terminal task with NO event rows can be removed at the application
        # layer (no append-only stream to violate — ADR-030 keeps the streams
        # intact, not the task rows themselves).
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

        assert report.operation_tasks_deleted == 1
        remaining = db_session.scalars(select(OperationTask.id)).all()
        assert len(remaining) == 1
        assert remaining[0] == fresh.id

    def test_evented_terminal_tasks_survive_with_their_append_only_stream(
        self, db_session: Session
    ) -> None:
        # DATA_MODEL.md §7.3/0005 keep operation_task_events append-only at
        # the database: the FK cascade would fire the no-delete trigger, so a
        # task cannot be removed while its event stream exists. The sweep
        # reports the append-only skip (ADR-030) instead of failing the pass.
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
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.operation_tasks_deleted == 0
        assert report.operation_task_events_skipped_append_only is True
        assert db_session.scalar(select(func.count()).select_from(OperationTask)) == 1
        events = db_session.scalar(
            select(func.count())
            .select_from(OperationTaskEvent)
            .where(OperationTaskEvent.task_id == old.id)
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
        assert db_session.scalar(select(func.count()).select_from(OperationTask)) == 2


class TestPreviewTokenUseRetention:
    """Single-use preview-token ledger sweep (migration 0010).

    Ledger rows only cover the 60-second token window: consumed AND
    expired-unconsumed rows older than the 1-hour retention carry no value
    (the operation.create audit row and the task itself are the permanent
    record) and are purged; live (unexpired) rows — unconsumed tokens the
    user may still confirm, and just-consumed ones whose confirm is still
    within the window — survive.
    """

    def test_consumed_and_expired_preview_token_rows_are_swept(
        self, db_session: Session
    ) -> None:
        device = make_collection_device(db_session, index=16)
        user = _user(db_session)
        # A QUEUED task (never purged by retention) anchors the consumed rows:
        # the ledger's consumed_by_task_id FK stays valid for the whole pass.
        holder_task = make_task(
            db_session,
            device_id=device.id,
            requested_by=user.id,
            index=16,
            requirement_id="SRV-ACT-02",
            capability_key="power.on",
            state="queued",
            idempotency_key="ledger-holder-16",
        )
        db_session.commit()

        def _row(
            *,
            expires_at: datetime.datetime,
            consumed_at: datetime.datetime | None,
            consumed_by_task_id: object = None,
        ) -> PreviewTokenUse:
            return PreviewTokenUse(
                token_hash=uuid.uuid4().hex,
                user_id=user.id,
                device_id=device.id,
                created_at=expires_at,
                expires_at=expires_at,
                consumed_at=consumed_at,
                consumed_by_task_id=consumed_by_task_id,
            )

        db_session.add_all(
            [
                # Old and fully expired: swept (both states).
                _row(expires_at=NOW - datetime.timedelta(hours=2), consumed_at=None),
                _row(
                    expires_at=NOW - datetime.timedelta(hours=2),
                    consumed_at=NOW - datetime.timedelta(hours=2),
                    consumed_by_task_id=holder_task.id,
                ),
                # Still live: kept (unconsumed token may still confirm; the
                # just-consumed confirm is still inside its window).
                _row(
                    expires_at=NOW + datetime.timedelta(minutes=30),
                    consumed_at=None,
                ),
                _row(
                    expires_at=NOW + datetime.timedelta(minutes=30),
                    consumed_at=NOW - datetime.timedelta(seconds=10),
                    consumed_by_task_id=holder_task.id,
                ),
            ]
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.preview_token_uses_deleted == 2
        remaining = db_session.scalars(select(PreviewTokenUse.token_hash)).all()
        assert len(remaining) == 2
        # The queued anchor task and its ledger references are untouched.
        assert report.operation_tasks_deleted == 0


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

    def test_sessions_referenced_by_audit_rows_survive_cleanup(self, db_session: Session) -> None:
        # audit_logs.session_id is FK ON DELETE SET NULL; the 0002 audit
        # trigger rejects the internal UPDATE of the FK action (PostgreSQL
        # fires child row triggers on FK actions), so an audit-linked session
        # cannot be deleted while its audit row lives (ADR-030). The sweep
        # must skip it and purge only the unreferenced one.
        user = _user(db_session)
        audit_linked = _session_row(
            db_session, user, revoked_at=NOW - datetime.timedelta(days=40)
        )
        db_session.flush()  # populate audit_linked.id (uuid7 client-side default)
        db_session.add(
            AuditLog(
                actor_user_id=user.id,
                session_id=audit_linked.id,
                action="test.session_linked",
                occurred_at=NOW - datetime.timedelta(days=40),
                result="success",
            )
        )
        _session_row(db_session, user, revoked_at=NOW - datetime.timedelta(days=40))
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.sessions_deleted == 1
        remaining_ids = set(db_session.scalars(select(DBSession.id)).all())
        assert remaining_ids == {audit_linked.id}
        audit_rows = db_session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.session_id == audit_linked.id)
        )
        assert audit_rows == 1


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

        # 0002 trigger + 0004 REVOKE keep the table append-only; ADR-030
        # exempts it from automatic retention purge: the sweep records the
        # protection state instead of crashing or weakening the protection.
        assert report.audit_skipped_append_only is True
        assert db_session.scalar(select(func.count()).select_from(AuditLog)) == 2

    def test_audit_never_removed_when_linked_task_is_cleaned(self, db_session: Session) -> None:
        # audit_logs.task_id is NOT a foreign key: purging an eventless
        # terminal task leaves its audit rows fully intact.
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

        assert report.operation_tasks_deleted == 1
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
        assert report.preview_token_uses_deleted == 0
        assert report.as_dict()["audit_skipped_append_only"] is True  # report shape is stable
        assert report.as_dict()["operation_task_events_skipped_append_only"] is True

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


class TestLaunchSessionRetention:
    """One-time launch tickets (migration 0013, API_CONTRACT.md §7).

    Issued rows past their 60-second window are marked ``expired`` by the
    sweep (bookkeeping — the single-use claim checks ``expires_at`` itself,
    so an expired row can never be consumed); rows leave after the 30-day
    lifetime (DATA_MODEL.md §10 set), like login sessions. Consumed rows
    keep their status/time until the 30-day purge (forensics), then leave —
    the permanent audit trail (launch.create / launch.consume) is what
    survives.
    """

    def _launch_row(
        self,
        db_session: Session,
        device_id: uuid.UUID,
        user_id: uuid.UUID,
        web_session_id: uuid.UUID,
        *,
        status: str,
        consumed_at: datetime.datetime | None,
        expires_at: datetime.datetime,
        revoked_at: datetime.datetime | None = None,
    ) -> None:
        db_session.add(
            LaunchSession(
                device_id=device_id,
                capability_key="console.kvm.open",
                requirement_id="SRV-ACT-03",
                user_id=user_id,
                session_id=web_session_id,
                protocol="kvm",
                descriptor_url=f"https://192.0.2.10/console/{uuid.uuid4().hex}",
                status=status,
                consumed_at=consumed_at,
                expires_at=expires_at,
                revoked_at=revoked_at,
                created_at=expires_at - datetime.timedelta(seconds=60),
            )
        )

    def test_issued_rows_past_expiry_are_marked_expired(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=20)
        user = _user(db_session)
        web_session = _session_row(db_session, user, revoked_at=None)
        db_session.flush()
        # Expired 5 minutes ago: the sweep must mark it expired.
        self._launch_row(
            db_session,
            device.id,
            user.id,
            web_session.id,
            status="issued",
            consumed_at=None,
            expires_at=NOW - datetime.timedelta(minutes=5),
        )
        # Still inside the 60-second window: stays issued.
        self._launch_row(
            db_session,
            device.id,
            user.id,
            web_session.id,
            status="issued",
            consumed_at=None,
            expires_at=NOW + datetime.timedelta(seconds=30),
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.launch_sessions_expired == 1
        rows = db_session.scalars(select(LaunchSession).order_by(LaunchSession.expires_at)).all()
        assert {row.status for row in rows} == {"expired", "issued"}
        # Neither row is old enough for the 30-day purge.
        assert report.launch_sessions_deleted == 0

    def test_rows_older_than_thirty_days_are_purged_in_every_status(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=21)
        user = _user(db_session)
        web_session = _session_row(db_session, user, revoked_at=None)
        db_session.flush()
        for index, status in enumerate(("issued", "consumed", "expired", "revoked")):
            self._launch_row(
                db_session,
                device.id,
                user.id,
                web_session.id,
                status=status,
                consumed_at=NOW - datetime.timedelta(days=40)
                if status == "consumed"
                else None,
                expires_at=NOW - datetime.timedelta(days=40 + index),
                revoked_at=NOW - datetime.timedelta(days=40 + index)
                if status == "revoked"
                else None,
            )
        # A fresh consumed row stays (forensics window not reached).
        self._launch_row(
            db_session,
            device.id,
            user.id,
            web_session.id,
            status="consumed",
            consumed_at=NOW - datetime.timedelta(minutes=1),
            expires_at=NOW - datetime.timedelta(seconds=10),
        )
        db_session.commit()

        report = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert report.launch_sessions_deleted == 4
        remaining = db_session.scalars(select(LaunchSession.status)).all()
        assert remaining == ["consumed"]
        # Issued rows past expiry are marked even when they stay for the
        # forensics window; the expired/revoked rows above were already gone
        # before the marking pass ran? The sweep marks BEFORE it purges, so a
        # 40-day-old issued row counts in both counters.
        assert report.launch_sessions_expired == 1

    def test_launch_retention_is_idempotent(self, db_session: Session) -> None:
        device = make_collection_device(db_session, index=22)
        user = _user(db_session)
        web_session = _session_row(db_session, user, revoked_at=None)
        db_session.flush()
        self._launch_row(
            db_session,
            device.id,
            user.id,
            web_session.id,
            status="issued",
            consumed_at=None,
            expires_at=NOW - datetime.timedelta(days=31),
        )
        db_session.commit()

        first = enforce_retention(db_session, now=NOW, settings=SETTINGS)
        second = enforce_retention(db_session, now=NOW, settings=SETTINGS)

        assert first.launch_sessions_expired == 1
        assert first.launch_sessions_deleted == 1
        assert second.launch_sessions_expired == 0
        assert second.launch_sessions_deleted == 0
        assert db_session.scalar(select(func.count()).select_from(LaunchSession)) == 0

