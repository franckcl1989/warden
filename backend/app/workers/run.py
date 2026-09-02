"""Worker service entry point: ``python -m app.workers.run [--once]``.

Builds the engine and session factory from WardenSettings (WARDEN_POSTGRES_DSN
or WARDEN_POSTGRES_DSN_FILE), starts the four components of ARCHITECTURE.md
§3.3 — scheduler loop, operation pool, collection pool, maintenance loop —
and shuts them down gracefully on SIGTERM/SIGINT.

``--once`` runs a single scheduler tick and a single maintenance pass against
the configured database and exits; it is used by deployments, smoke tests and
CI to prove the worker can connect, lock and sweep without churning tasks.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import threading
import time
from collections.abc import Sequence

import structlog

from app.config import get_settings
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.logging import configure_logging
from app.workers.collection_pool import CollectionPool
from app.workers.maintenance import MaintenanceLoop
from app.workers.operation_pool import OperationPool
from app.workers.scheduler import Scheduler


def worker_owner() -> str:
    """Stable lease-owner identity for this worker process."""
    return f"worker-{socket.gethostname()}-{os.getpid()}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.workers.run",
        description="Warden worker service: scheduler, operation pool, "
        "collection pool and maintenance loop (M2T1 skeleton).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one scheduler tick and one maintenance pass, then exit",
    )
    args = parser.parse_args(argv)

    configure_logging()
    log = structlog.get_logger()
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    owner = worker_owner()

    if args.once:
        try:
            scheduler_ran = Scheduler(session_factory).run_once()
            report = MaintenanceLoop(session_factory).run_once()
            log.info(
                "worker_once_done",
                lease_owner=owner,
                scheduler_lock_acquired=scheduler_ran,
                maintenance_lock_acquired=report.lock_acquired,
                requeued=report.requeued,
                verify_only=report.verify_only,
                verification_required=report.verification_required,
                timed_out=report.timed_out,
            )
            return 0
        finally:
            engine.dispose()

    stop_event = threading.Event()

    def _request_stop(_signum: int, _frame: object) -> None:
        log.info("worker_shutdown_requested", signal=_signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    operation_pool = OperationPool(
        session_factory=session_factory,
        max_workers=settings.operation_workers,
        lease_seconds=settings.task_lease_seconds,
        lease_owner=owner,
    )
    collection_pool = CollectionPool(
        session_factory=session_factory,
        max_workers=settings.collection_workers,
        lease_seconds=settings.task_lease_seconds,
        lease_owner=owner,
    )
    loop_threads = [
        threading.Thread(
            target=Scheduler(session_factory).run_forever,
            args=(stop_event,),
            name="scheduler",
            daemon=True,
        ),
        threading.Thread(
            target=MaintenanceLoop(session_factory).run_forever,
            args=(stop_event,),
            name="maintenance",
            daemon=True,
        ),
    ]
    pools = [operation_pool, collection_pool]
    try:
        for pool in pools:
            pool.start()
        for thread in loop_threads:
            thread.start()
        log.info("worker_started", lease_owner=owner, components=2 + len(pools))
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        for pool in pools:
            pool.stop()
        for thread in loop_threads:
            thread.join(timeout=15.0)
        engine.dispose()
    log.info("worker_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
