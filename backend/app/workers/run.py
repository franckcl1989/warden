"""Worker service entry point: ``python -m app.workers.run [--once]``.

Builds the engine and session factory from WardenSettings (WARDEN_POSTGRES_DSN
or WARDEN_POSTGRES_DSN_FILE), starts the four components of ARCHITECTURE.md
§3.3 — scheduler loop, operation pool (M2T6: OperationExecutor wiring),
collection pool, maintenance loop — and shuts them down gracefully on
SIGTERM/SIGINT.

``--once`` runs a single scheduler tick, drains the claimable collection
runs once, and runs a single maintenance pass against the configured database
and exits; it is used by deployments, smoke tests and CI to prove the worker
can connect, lock, schedule, collect and sweep without churning tasks.
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
from sqlalchemy.orm import Session, sessionmaker

from app.application.collection import run_collection
from app.config import WardenSettings, get_settings
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.files import FileStorage
from app.infrastructure.logging import configure_logging
from app.infrastructure.observation_store import claim_collection_run
from app.workers.collection_pool import CollectionPool
from app.workers.maintenance import MaintenanceLoop
from app.workers.operation_executor import OperationExecutor
from app.workers.operation_pool import OperationPool
from app.workers.scheduler import Scheduler

# --once drains at most this many collection runs (bounded smoke, never a
# hidden backlog drain).
ONCE_MAX_COLLECTION_RUNS = 100


def worker_owner() -> str:
    """Stable lease-owner identity for this worker process."""
    return f"worker-{socket.gethostname()}-{os.getpid()}"


def _process_due_collections_once(
    session_factory: sessionmaker[Session],
    *,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    owner: str,
) -> int:
    """Claim and execute claimable collection runs once (--once smoke path)."""
    processed = 0
    for _ in range(ONCE_MAX_COLLECTION_RUNS):
        with session_factory() as session:
            run = claim_collection_run(
                session, lease_owner=owner, lease_seconds=settings.task_lease_seconds
            )
            session.commit()
        if run is None:
            break
        with session_factory() as session:
            # run.id, not the detached instance: run_collection re-loads the
            # row in this session (terminal-state writes must not be lost).
            run_collection(session, run.id, settings=settings, keyring=keyring)
            session.commit()
        processed += 1
    return processed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.workers.run",
        description=(
            "Warden worker service: scheduler, operation pool (M2T6 executor), "
            "collection pool and maintenance loop."
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one scheduler tick, drain claimable collection runs once, "
        "run one maintenance pass, then exit",
    )
    args = parser.parse_args(argv)

    configure_logging()
    log = structlog.get_logger()
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    owner = worker_owner()
    # The worker needs the credential master key to decrypt device credentials
    # for collection (SECURITY.md §5); unset secrets fail fast at startup.
    keyring = CredentialKeyring.from_current(
        CredentialCipher(settings.credential_master_key.get_secret_value().encode("utf-8"))
    )
    # M2T5: the file-volume + audit logger for the maintenance loop's file
    # retention (physical cleanup / aging / ticket purge, SECURITY.md §9).
    file_storage = FileStorage(settings.resolved_file_store_root)
    audit_logger = AuditLogger(session_factory)

    if args.once:
        try:
            scheduler_ran = Scheduler(session_factory, settings=settings).run_once()
            collection_processed = _process_due_collections_once(
                session_factory, settings=settings, keyring=keyring, owner=owner
            )
            report = MaintenanceLoop(
                session_factory,
                file_storage=file_storage,
                audit_logger=audit_logger,
            ).run_once()
            log.info(
                "worker_once_done",
                lease_owner=owner,
                scheduler_lock_acquired=scheduler_ran,
                collection_runs_processed=collection_processed,
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

    operation_executor = OperationExecutor(
        session_factory=session_factory,
        lease_owner=owner,
        lease_seconds=settings.task_lease_seconds,
        settings=settings,
        keyring=keyring,
        audit_logger=audit_logger,
    )
    operation_pool = OperationPool(
        session_factory=session_factory,
        max_workers=settings.operation_workers,
        lease_seconds=settings.task_lease_seconds,
        lease_owner=owner,
        handler=operation_executor,
    )
    collection_pool = CollectionPool(
        session_factory=session_factory,
        max_workers=settings.collection_workers,
        lease_seconds=settings.task_lease_seconds,
        lease_owner=owner,
        settings=settings,
        keyring=keyring,
    )
    loop_threads = [
        threading.Thread(
            target=Scheduler(session_factory).run_forever,
            args=(stop_event,),
            name="scheduler",
            daemon=True,
        ),
        threading.Thread(
            target=MaintenanceLoop(
                session_factory,
                file_storage=file_storage,
                audit_logger=audit_logger,
            ).run_forever,
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
