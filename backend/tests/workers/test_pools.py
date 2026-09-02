"""ConcurrencyPool tests on the real PostgreSQL (TEST_STRATEGY §2.2).

The pool claims real operation_tasks: distinct devices per task so the device
mutex never interferes. Handler exceptions must never fabricate a result —
the task stays running and the lease is released for the fence-aware
recovery sweep.
"""

from __future__ import annotations

import threading
import time
import uuid

from app.infrastructure.db import create_db_engine, create_session_factory, dsn_with_psycopg_dialect
from app.infrastructure.tasks import recovery_scan
from app.infrastructure.time import utcnow
from app.models.operation import OperationTask, OperationTaskEvent
from app.workers.concurrency import ConcurrencyPool
from app.workers.maintenance import MaintenanceLoop
from sqlalchemy import create_engine, select

from tests.task_factories import make_device, make_task, make_user


def _pool_engine(dsn: str):
    """Engine for pool tests: the dev server allows ~two app connections
    (max_connections=8), so worker threads share a deliberately small pool."""
    return create_engine(
        dsn_with_psycopg_dialect(dsn),
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
        pool_size=1,
        max_overflow=1,
    )


def _seed_tasks(dsn: str, count: int) -> list[uuid.UUID]:
    engine = create_db_engine(dsn)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            user = make_user(session)
            task_ids = []
            for index in range(count):
                device = make_device(session, index=index + 100)
                task = make_task(
                    session,
                    device_id=device.id,
                    requested_by=user.id,
                    index=index,
                    idempotency_key=f"pool-key-{index:03d}",
                )
                task_ids.append(task.id)
        return task_ids
    finally:
        engine.dispose()


class TestPoolProcessing:
    def test_pool_claims_and_processes_all_tasks(self, fresh_test_db_dsn: str) -> None:
        task_ids = _seed_tasks(fresh_test_db_dsn, count=6)
        processed: list[uuid.UUID] = []
        lock = threading.Lock()
        done = threading.Event()

        def handler(task: OperationTask) -> None:
            with lock:
                processed.append(task.id)
            if len(processed) >= 6:
                done.set()

        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        pool = ConcurrencyPool(
            name="test-pool",
            max_workers=3,
            session_factory=factory,
            handler=handler,
            lease_seconds=300,
            lease_owner="test-worker",
            poll_interval=0.05,
        )
        try:
            pool.start()
            assert done.wait(timeout=30), "pool did not process all tasks"
            time.sleep(0.2)  # let remaining claims land
            pool.stop()
        finally:
            pool.stop()
            engine.dispose()
        assert sorted(processed) == sorted(task_ids)

    def test_handler_exception_releases_task_for_recovery(self, fresh_test_db_dsn: str) -> None:
        task_ids = _seed_tasks(fresh_test_db_dsn, count=2)

        def failing_handler(task: OperationTask) -> None:
            del task
            raise RuntimeError("adapter exploded")

        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        pool = ConcurrencyPool(
            name="test-pool",
            max_workers=2,
            session_factory=factory,
            handler=failing_handler,
            lease_seconds=300,
            lease_owner="test-worker",
            poll_interval=0.05,
        )
        try:
            pool.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                with factory() as session:
                    expired = recovery_scan(session, now=utcnow())
                if len(expired) >= 2:
                    break
                time.sleep(0.05)
            pool.stop()
            # Tasks stay running with an expired lease: recovery candidates.
            with factory() as session:
                running = session.scalars(select(OperationTask).where(OperationTask.state == "running")).all()
                assert len(running) == 2
                for task in running:
                    assert task.lease_owner is None
                    assert task.lease_expires_at is not None
            # fence-less tasks get requeued by the maintenance sweep
            report = MaintenanceLoop(factory).run_once()
            assert report.requeued == 2
            with factory() as session:  # fresh session: no stale identity map
                refreshed = {task.id: task for task in session.scalars(select(OperationTask)).all()}
                for task_id in task_ids:
                    assert refreshed[task_id].state == "queued"
        finally:
            pool.stop()
            engine.dispose()

    def test_no_handler_appends_not_configured_and_releases(self, fresh_test_db_dsn: str) -> None:
        task_ids = _seed_tasks(fresh_test_db_dsn, count=1)
        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        pool = ConcurrencyPool(
            name="test-pool",
            max_workers=1,
            session_factory=factory,
            handler=None,
            lease_seconds=300,
            lease_owner="test-worker",
            poll_interval=0.05,
        )
        try:
            pool.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                with factory() as session:
                    events = session.scalars(
                        select(OperationTaskEvent).where(OperationTaskEvent.message.like("handler_not_configured%"))
                    ).all()
                if len(events) >= 1:
                    break
                time.sleep(0.05)
            pool.stop()
            with factory() as session:
                task = session.get(OperationTask, task_ids[0])
                assert task.state == "running"
                assert task.lease_owner is None
        finally:
            pool.stop()
            engine.dispose()

    def test_graceful_shutdown_drains_inflight_handler(self, fresh_test_db_dsn: str) -> None:
        task_ids = _seed_tasks(fresh_test_db_dsn, count=4)
        processed: list[uuid.UUID] = []
        lock = threading.Lock()

        def slow_handler(task: OperationTask) -> None:
            time.sleep(0.3)
            with lock:
                processed.append(task.id)

        engine = _pool_engine(fresh_test_db_dsn)
        factory = create_session_factory(engine)
        pool = ConcurrencyPool(
            name="test-pool",
            max_workers=2,
            session_factory=factory,
            handler=slow_handler,
            lease_seconds=300,
            lease_owner="test-worker",
            poll_interval=0.02,
        )
        try:
            pool.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                with lock:
                    done = len(processed)
                if done >= 4:
                    break
                time.sleep(0.05)
            pool.stop()  # must wait for in-flight handlers
        finally:
            pool.stop()
            engine.dispose()
        assert sorted(processed) == sorted(task_ids)
