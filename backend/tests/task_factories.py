"""Factories for operation-task tests (integration, real PostgreSQL).

Creates the FK chain users -> devices -> operation_tasks with minimal,
contract-valid rows. The ``warden_test`` database is recreated by the
``fresh_test_db_dsn``/``db_session`` fixtures before each test.
"""

from __future__ import annotations

import datetime
import uuid

from app.models.auth import User
from app.models.devices import Device
from app.models.operation import OperationTask
from sqlalchemy.orm import Session

IDEMPOTENCY_KEY = "test-idem-0001"


def make_user(db: Session, *, index: int = 0) -> User:
    user = User(
        username=f"op-user-{index}",
        display_name=f"操作员 {index}",
        role="operator",
        status="active",
        password_hash="x",
        must_change_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def make_device(db: Session, *, index: int = 0) -> Device:
    device = Device(
        name=f"test-device-{index}",
        device_type="synology_nas",
        management_endpoint=f"192.168.10.{index % 250 + 1}",
        adapter_key="nas.synology_dsm",
        connection_config={},
        readiness="ready",
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def make_task(
    db: Session,
    *,
    device_id: uuid.UUID,
    requested_by: uuid.UUID,
    index: int = 0,
    requirement_id: str = "SRV-ACT-02",
    capability_key: str = "power.on",
    conflict_scope: str = "device",
    state: str = "queued",
    idempotency_key: str = IDEMPOTENCY_KEY,
    risk_level: str = "high",
    lease_owner: str | None = None,
    lease_expires_at: datetime.datetime | None = None,
    dispatch_started_at: datetime.datetime | None = None,
    device_job_id: str | None = None,
    timeout_at: datetime.datetime | None = None,
    verification_state: str | None = None,
    created_at: datetime.datetime | None = None,
) -> OperationTask:
    task = OperationTask(
        requirement_id=requirement_id,
        capability_key=capability_key,
        device_id=device_id,
        requested_by=requested_by,
        risk_level=risk_level,
        parameters={},
        idempotency_key=f"{idempotency_key}-{index}",
        conflict_scope=conflict_scope,
        state=state,
        lease_owner=lease_owner,
        lease_expires_at=lease_expires_at,
        dispatch_started_at=dispatch_started_at,
        device_job_id=device_job_id,
        timeout_at=timeout_at,
        verification_state=verification_state,
    )
    if created_at is not None:
        task.created_at = created_at
    db.add(task)
    db.commit()
    db.refresh(task)
    return task
