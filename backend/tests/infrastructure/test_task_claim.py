"""Operation task persistence on the REAL PostgreSQL 18 (TEST_STRATEGY §2.2).

Covers: FIFO claim, FOR UPDATE SKIP LOCKED concurrency (no double
assignment), the device mutex partial unique index, lease renewal/expiry,
recovery and timeout scans, conditional transitions with same-transaction
events, and the append-only event trigger.
"""

from __future__ import annotations

import datetime
import threading
import uuid
from collections import Counter

import pytest
from app.domain.operation import TaskState
from app.domain.uuid7 import uuid7
from app.infrastructure.db import create_session_factory
from app.infrastructure.tasks import (
    claim_task,
    clear_lease,
    mark_timeout,
    mark_verification_required,
    recovery_scan,
    release_lease,
    renew_lease,
    requeue_task,
    timeout_scan,
)
from app.models.operation import OperationTask, OperationTaskAppendOnlyError, OperationTaskEvent
from sqlalchemy import delete, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from tests.task_factories import make_device, make_task, make_user

NOW = datetime.datetime.now(datetime.UTC)
PAST = NOW - datetime.timedelta(seconds=3600)
FUTURE = NOW + datetime.timedelta(seconds=3600)


def _claim(session: Session, owner: str = "w1", lease_seconds: int = 300) -> OperationTask | None:
    return claim_task(session, lease_owner=owner, lease_seconds=lease_seconds)


@pytest.fixture
def ctx(db_session: Session) -> dict[str, object]:
    return {"user": make_user(db_session), "device": make_device(db_session)}


class TestClaim:
    def test_claim_returns_oldest_queued_task(self, db_session: Session, ctx: dict[str, object]) -> None:
        base = NOW - datetime.timedelta(minutes=30)
        device2 = make_device(db_session, index=1)
        device3 = make_device(db_session, index=2)
        oldest = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=11,
            created_at=base,
        )
        make_task(
            db_session,
            device_id=device2.id,
            requested_by=ctx["user"].id,
            index=12,
            created_at=base + datetime.timedelta(seconds=1),
        )
        make_task(
            db_session,
            device_id=device3.id,
            requested_by=ctx["user"].id,
            index=13,
            created_at=base + datetime.timedelta(seconds=2),
        )
        claimed = _claim(db_session)
        assert claimed is not None
        assert claimed.id == oldest.id
        assert claimed.state == "running"
        assert claimed.lease_owner == "w1"
        assert claimed.lease_expires_at is not None
        assert claimed.started_at is not None
        assert claimed.version == 2

    def test_claim_appends_running_event_in_same_transaction(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session)
        db_session.commit()
        events = (
            db_session.query(OperationTaskEvent)
            .filter(OperationTaskEvent.task_id == task.id)
            .order_by(OperationTaskEvent.occurred_at)
            .all()
        )
        assert [event.state for event in events] == ["running"]
        assert events[0].message == "claimed"

    def test_claim_skips_non_queued_and_returns_none(self, db_session: Session, ctx: dict[str, object]) -> None:
        assert _claim(db_session) is None

    def test_claim_does_not_reclaim_already_running_task(self, db_session: Session, ctx: dict[str, object]) -> None:
        make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            state="running",
            lease_owner="other",
            lease_expires_at=FUTURE,
        )
        assert _claim(db_session) is None

    def test_claim_is_fifo_across_devices(self, db_session: Session, ctx: dict[str, object]) -> None:
        base = NOW - datetime.timedelta(minutes=10)
        device2 = make_device(db_session, index=1)
        device3 = make_device(db_session, index=2)
        first = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=21,
            created_at=base,
        )
        make_task(
            db_session,
            device_id=device2.id,
            requested_by=ctx["user"].id,
            index=22,
            created_at=base + datetime.timedelta(seconds=5),
        )
        make_task(
            db_session,
            device_id=device3.id,
            requested_by=ctx["user"].id,
            index=23,
            created_at=base + datetime.timedelta(seconds=10),
        )
        assert _claim(db_session).id == first.id


class TestDeviceMutex:
    def test_second_mutex_scope_task_is_rejected_at_insert(self, db_session: Session, ctx: dict[str, object]) -> None:
        make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id, index=1)
        with pytest.raises(IntegrityError):
            make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id, index=2)
        db_session.rollback()

    def test_mutex_scope_task_rejected_even_when_first_is_running(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=1,
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
        )
        with pytest.raises(IntegrityError):
            make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id, index=2)
        db_session.rollback()

    def test_component_disk_tasks_conflict_per_device_conservatively(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        # 0.1.0 conservative mapping (documented in migration 0005): two
        # component:disk tasks on one device never run concurrently.
        make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=1,
            conflict_scope="component:disk",
            capability_key="disk.smart_test.quick",
            requirement_id="NAS-ACT-04",
        )
        with pytest.raises(IntegrityError):
            make_task(
                db_session,
                device_id=ctx["device"].id,
                requested_by=ctx["user"].id,
                index=2,
                conflict_scope="component:disk",
                capability_key="disk.smart_test.full",
                requirement_id="NAS-ACT-04",
            )
        db_session.rollback()

    def test_different_scopes_coexist_and_both_claim(self, db_session: Session, ctx: dict[str, object]) -> None:
        change = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=1,
            conflict_scope="device",
            capability_key="power.on",
            requirement_id="SRV-ACT-02",
        )
        read = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=2,
            conflict_scope="device_read",
            capability_key="firmware.query",
            requirement_id="SRV-ACT-06",
            idempotency_key="read-key-001",
        )
        first = _claim(db_session)
        assert first.id == change.id
        second = _claim(db_session)
        assert second.id == read.id

    def test_two_read_tasks_on_same_device_both_run_concurrently(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        a = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=1,
            conflict_scope="device_read",
            capability_key="firmware.query",
            requirement_id="SRV-ACT-06",
            idempotency_key="read-key-a",
        )
        b = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            index=2,
            conflict_scope="device_read",
            capability_key="asset.refresh",
            requirement_id="SRV-ACT-07",
            idempotency_key="read-key-b",
        )
        claimed = {_claim(db_session).id for _ in range(2)}
        assert claimed == {a.id, b.id}


class TestConcurrentClaims:
    def test_concurrent_claims_never_double_assign(self, fresh_test_db_dsn: str) -> None:
        """20 threads x 50 tasks: every task is claimed exactly once.

        The dev PostgreSQL runs with max_connections=8 (about two application
        slots), so the 20 threads share a deliberately small connection pool
        (pool_size=1 + overflow=1). Claiming is still genuinely concurrent at
        the row level: two claim transactions race on FOR UPDATE SKIP LOCKED
        and the assertion is that no task is ever assigned twice.
        """
        from app.infrastructure.db import dsn_with_psycopg_dialect
        from sqlalchemy import create_engine

        engine = create_engine(
            dsn_with_psycopg_dialect(fresh_test_db_dsn),
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5},
            pool_size=1,
            max_overflow=1,
        )
        factory = create_session_factory(engine)
        try:
            with factory() as session:
                user = make_user(session)
                devices = [make_device(session, index=i) for i in range(50)]
                tasks = [
                    make_task(
                        session,
                        device_id=device.id,
                        requested_by=user.id,
                        index=i,
                        idempotency_key=f"stress-key-{i:03d}",
                    )
                    for i, device in enumerate(devices)
                ]
                task_ids = [task.id for task in tasks]
            claimed: list[uuid.UUID] = []
            lock = threading.Lock()
            threads = []

            def worker() -> None:
                while True:
                    with factory() as session:
                        task = claim_task(session, lease_owner="stress", lease_seconds=300)
                        session.commit()
                    if task is None:
                        break
                    with lock:
                        claimed.append(task.id)

            for _ in range(20):
                thread = threading.Thread(target=worker)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join(timeout=120)
                assert not thread.is_alive(), "claim worker thread hung"

            counts = Counter(claimed)
            assert set(counts) == set(task_ids), "some tasks were never claimed"
            assert all(count == 1 for count in counts.values()), "a task was claimed twice"
            assert len(claimed) == 50
        finally:
            engine.dispose()


class TestLease:
    def test_renewal_by_owner(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1", lease_seconds=300)
        assert renew_lease(db_session, task_id=task.id, owner="w1", lease_seconds=600) is True
        db_session.commit()
        db_session.refresh(task)
        assert task.lease_expires_at is not None
        assert task.lease_expires_at > NOW + datetime.timedelta(seconds=500)

    def test_renewal_by_wrong_owner_fails(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert renew_lease(db_session, task_id=task.id, owner="intruder", lease_seconds=600) is False

    def test_renewal_after_expiry_fails(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1", lease_seconds=300)
        task.lease_expires_at = PAST
        db_session.commit()
        assert renew_lease(db_session, task_id=task.id, owner="w1", lease_seconds=600) is False

    def test_release_lease_expires_immediately(self, db_session: Session, ctx: dict[str, object]) -> None:
        from app.infrastructure.time import utcnow

        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert release_lease(db_session, task_id=task.id, owner="w1") is True
        db_session.commit()
        db_session.refresh(task)
        assert task.state == "running"
        assert task.lease_owner is None
        found = recovery_scan(db_session, now=utcnow())
        assert [item.id for item in found] == [task.id]

    def test_release_lease_wrong_owner_fails(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert release_lease(db_session, task_id=task.id, owner="other") is False

    def test_clear_lease_parked_task_is_not_a_recovery_candidate(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert clear_lease(db_session, task_id=task.id) is True
        db_session.commit()
        db_session.refresh(task)
        assert task.lease_owner is None and task.lease_expires_at is None
        assert recovery_scan(db_session, now=NOW) == []

    def test_clear_lease_is_a_noop_when_lease_already_cleared(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        # A second maintenance pass processing the same fenced candidate (both
        # passes scanned before either processed) must not re-park or re-count
        # it: clear_lease requires an existing lease (lease_expires_at NOT
        # NULL), so the parked task no longer matches.
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert clear_lease(db_session, task_id=task.id) is True
        db_session.commit()
        db_session.refresh(task)
        assert clear_lease(db_session, task_id=task.id) is False
        db_session.refresh(task)
        assert task.lease_owner is None and task.lease_expires_at is None


class TestScans:
    def test_recovery_scan_finds_only_expired_running_leases(self, db_session: Session, ctx: dict[str, object]) -> None:
        devices = [make_device(db_session, index=i) for i in range(1, 5)]
        expired = make_task(
            db_session,
            device_id=devices[0].id,
            requested_by=ctx["user"].id,
            index=1,
            state="running",
            lease_owner="dead",
            lease_expires_at=PAST,
        )
        active = make_task(
            db_session,
            device_id=devices[1].id,
            requested_by=ctx["user"].id,
            index=2,
            state="running",
            lease_owner="alive",
            lease_expires_at=FUTURE,
            idempotency_key="scan-key-2",
        )
        parked = make_task(
            db_session,
            device_id=devices[2].id,
            requested_by=ctx["user"].id,
            index=3,
            state="running",
            lease_owner=None,
            lease_expires_at=None,
            idempotency_key="scan-key-3",
        )
        queued = make_task(
            db_session,
            device_id=devices[3].id,
            requested_by=ctx["user"].id,
            index=4,
            state="queued",
            idempotency_key="scan-key-4",
        )
        found = {task.id for task in recovery_scan(db_session, now=NOW)}
        assert found == {expired.id}
        assert active.id not in found and parked.id not in found and queued.id not in found

    def test_timeout_scan_finds_overdue_running_and_waiting_device(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        devices = [make_device(db_session, index=i) for i in range(1, 6)]
        overdue_running = make_task(
            db_session,
            device_id=devices[0].id,
            requested_by=ctx["user"].id,
            index=1,
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            timeout_at=PAST,
        )
        overdue_waiting = make_task(
            db_session,
            device_id=devices[1].id,
            requested_by=ctx["user"].id,
            index=2,
            state="waiting_device",
            timeout_at=PAST,
            idempotency_key="timeout-key-2",
        )
        not_due = make_task(
            db_session,
            device_id=devices[2].id,
            requested_by=ctx["user"].id,
            index=3,
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            timeout_at=FUTURE,
            idempotency_key="timeout-key-3",
        )
        no_timeout = make_task(
            db_session,
            device_id=devices[3].id,
            requested_by=ctx["user"].id,
            index=4,
            state="running",
            lease_owner="w",
            lease_expires_at=FUTURE,
            idempotency_key="timeout-key-4",
        )
        queued_overdue = make_task(
            db_session,
            device_id=devices[4].id,
            requested_by=ctx["user"].id,
            index=5,
            state="queued",
            timeout_at=PAST,
            idempotency_key="timeout-key-5",
        )
        found = {task.id for task in timeout_scan(db_session, now=NOW)}
        assert found == {overdue_running.id, overdue_waiting.id}
        assert not_due.id not in found and no_timeout.id not in found and queued_overdue.id not in found


class TestConditionalTransitions:
    def test_requeue_returns_task_to_queued_with_event(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert requeue_task(db_session, task_id=task.id, message="recovery_requeued") is True
        db_session.commit()
        db_session.refresh(task)
        assert task.state == "queued"
        assert task.lease_owner is None and task.lease_expires_at is None
        assert task.version == 3
        events = db_session.query(OperationTaskEvent).filter(OperationTaskEvent.task_id == task.id).all()
        assert [event.state for event in events] == ["running", "queued"]

    def test_requeue_is_a_noop_on_non_running_task(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        assert requeue_task(db_session, task_id=task.id, message="x") is False

    def test_mark_timeout_timed_out_sets_finished_at(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            state="running",
            lease_owner="w",
            lease_expires_at=PAST,
            timeout_at=PAST,
        )
        assert (
            mark_timeout(
                db_session,
                task_id=task.id,
                to_state=TaskState.TIMED_OUT,
                message="timeout",
                error_code=None,
            )
            is True
        )
        db_session.commit()
        db_session.refresh(task)
        assert task.state == "timed_out"
        assert task.finished_at is not None
        assert task.error_code is None
        assert task.lease_owner is None

    def test_mark_timeout_verification_required_keeps_task_open(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        task = make_task(
            db_session,
            device_id=ctx["device"].id,
            requested_by=ctx["user"].id,
            state="running",
            lease_owner="w",
            lease_expires_at=PAST,
            timeout_at=PAST,
        )
        assert (
            mark_timeout(
                db_session,
                task_id=task.id,
                to_state=TaskState.VERIFICATION_REQUIRED,
                message="ambiguous timeout",
                error_code="ambiguous_result",
            )
            is True
        )
        db_session.commit()
        db_session.refresh(task)
        assert task.state == "verification_required"
        assert task.finished_at is None
        assert task.error_code == "ambiguous_result"

    def test_mark_verification_required_records_ambiguous_result(
        self, db_session: Session, ctx: dict[str, object]
    ) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        assert mark_verification_required(db_session, task_id=task.id, message="ambiguous") is True
        db_session.commit()
        db_session.refresh(task)
        assert task.state == "verification_required"
        assert task.error_code == "ambiguous_result"

    def test_transition_event_is_in_same_transaction(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        _claim(db_session, owner="w1")
        db_session.commit()  # the claim (running + event) is now durable
        requeue_task(db_session, task_id=task.id, message="recovery_requeued")
        db_session.rollback()  # abort the requeue transaction: event must vanish too
        db_session.refresh(task)
        assert task.state == "running"  # requeue rolled back
        events = db_session.query(OperationTaskEvent).filter(OperationTaskEvent.task_id == task.id).all()
        assert [event.state for event in events] == ["running"]


class TestAppendOnlyEvents:
    def _insert_event(self, db_session: Session, task_id: uuid.UUID) -> OperationTaskEvent:
        event = OperationTaskEvent(task_id=task_id, state="queued", message="seed")
        db_session.add(event)
        db_session.commit()
        db_session.refresh(event)
        return event

    def test_event_insert_works(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        event = self._insert_event(db_session, task.id)
        assert event.id is not None

    def test_event_update_rejected_by_database_trigger(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        self._insert_event(db_session, task.id)
        with pytest.raises(SQLAlchemyError):
            db_session.execute(
                update(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id).values(message="tampered")
            )
            db_session.commit()
        db_session.rollback()

    def test_event_delete_rejected_by_database_trigger(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        self._insert_event(db_session, task.id)
        with pytest.raises(SQLAlchemyError):
            db_session.execute(delete(OperationTaskEvent).where(OperationTaskEvent.task_id == task.id))
            db_session.commit()
        db_session.rollback()

    def test_event_raw_sql_update_rejected(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        self._insert_event(db_session, task.id)
        with pytest.raises(SQLAlchemyError):
            db_session.execute(
                text("UPDATE operation_task_events SET message = 'hacked' WHERE task_id = :tid"),
                {"tid": task.id},
            )
            db_session.commit()
        db_session.rollback()

    def test_event_orm_update_rejected_by_model(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        event = self._insert_event(db_session, task.id)
        event.message = "tampered"
        with pytest.raises(OperationTaskAppendOnlyError):
            db_session.commit()
        db_session.rollback()
        fresh = db_session.get(OperationTaskEvent, event.id)
        assert fresh is not None and fresh.message == "seed"

    def test_event_orm_delete_rejected_by_model(self, db_session: Session, ctx: dict[str, object]) -> None:
        task = make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id)
        event = self._insert_event(db_session, task.id)
        db_session.delete(event)
        with pytest.raises(OperationTaskAppendOnlyError):
            db_session.commit()
        db_session.rollback()
        assert db_session.get(OperationTaskEvent, event.id) is not None


class TestContractConstraints:
    def test_short_idempotency_key_rejected(self, db_session: Session, ctx: dict[str, object]) -> None:
        with pytest.raises(IntegrityError):
            task = OperationTask(
                requirement_id="SRV-ACT-02",
                capability_key="power.on",
                device_id=ctx["device"].id,
                requested_by=ctx["user"].id,
                risk_level="high",
                parameters={},
                idempotency_key="short",
                conflict_scope="device",
                state="queued",
            )
            db_session.add(task)
            db_session.commit()
        db_session.rollback()

    def test_bad_idempotency_key_chars_rejected(self, db_session: Session, ctx: dict[str, object]) -> None:
        with pytest.raises(IntegrityError):
            db_session.add(
                OperationTask(
                    requirement_id="SRV-ACT-02",
                    capability_key="power.on",
                    device_id=ctx["device"].id,
                    requested_by=ctx["user"].id,
                    risk_level="high",
                    parameters={},
                    idempotency_key="bad key with spaces",
                    conflict_scope="device",
                    state="queued",
                )
            )
            db_session.commit()
        db_session.rollback()

    def test_duplicate_requested_by_idempotency_key_rejected(self, db_session: Session, ctx: dict[str, object]) -> None:
        make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id, index=1)
        with pytest.raises(IntegrityError):
            make_task(db_session, device_id=ctx["device"].id, requested_by=ctx["user"].id, index=1)
        db_session.rollback()

    def test_uuid7_primary_key_is_timestamp_ordered(self) -> None:
        a, b = uuid7(), uuid7()
        assert a < b
