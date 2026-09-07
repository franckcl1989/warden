"""GET /system/status + maintenance-mode API enforcement (M6T3b, PLT-08).

Covers docs/API_CONTRACT.md §2 (503 maintenance_mode with since/reason) + §9
(GET /system/status protected component status), DEPLOYMENT.md §8 (维护模式
开启后 API 拒绝新任务和 launch；previews/探针/上传/读取保持可用) and
SECURITY.md §3.1 (system.read 仅管理员). Component derivations are tested
per the documented semantics of app/application/system_status.py: worker
stopped (activity stale / pending work without activity), worker degraded
(collection lag > 2 intervals), ingest idle-is-ok vs stopped, database ok,
file_storage ok/unavailable.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Iterator

import pytest
from app.application.system_state import enter_maintenance, exit_maintenance
from app.config import WardenSettings
from app.main import create_app
from app.models.system import IngestHeartbeat
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login_csrf,
)
from tests.observation_factories import make_collection_device, make_collection_run
from tests.task_factories import make_device, make_task, make_user

API = "/api/v1"
SYSTEM_STATUS_PATH = f"{API}/system/status"
UTC = datetime.UTC
NONEXISTENT_DEVICE = str(uuid.uuid4())


@pytest.fixture
def system_settings(fresh_test_db_dsn: str, tmp_path) -> WardenSettings:
    """Status-API settings: tiny worker/ingest timers + a tmp file volume.

    The derivations read thresholds from settings (2×task_lease_seconds,
    2×collection interval, 3×ingest heartbeat interval), so tests can age
    rows a few seconds instead of minutes.
    """
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        task_lease_seconds=30,
        reachability_interval_seconds=5,
        metrics_interval_seconds=10,
        logs_interval_seconds=20,
        discovery_interval_seconds=300,
        ingest_heartbeat_interval_seconds=1,
        file_store_root=tmp_path / "status-files",
    )


@pytest.fixture
def system_app(system_settings: WardenSettings) -> Iterator[FastAPI]:
    app = create_app(system_settings)
    try:
        yield app
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.fixture
def status_client(system_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(system_app) as test_client:
        yield test_client


def _as_admin(db: Session, client: TestClient) -> None:
    create_admin(db)
    response, _csrf = login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200


@pytest.mark.integration
def test_permission_matrix_admin_only(status_client: TestClient, db_session: Session) -> None:
    """system.read is admin-only: operator/viewer get 403 (SECURITY §3.1)."""
    create_admin(db_session)
    create_user(db_session, username="op.1", password="Oper!ator-2026-Pass", role="operator")
    create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")

    anonymous = status_client.get(SYSTEM_STATUS_PATH)
    assert anonymous.status_code == 401

    for username, password in (("op.1", "Oper!ator-2026-Pass"), ("viewer.1", "View!er-2026-Pass")):
        response, _csrf = login_csrf(status_client, username, password)
        assert response.status_code == 200
        denied = status_client.get(SYSTEM_STATUS_PATH)
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "permission_denied"

    admin_response, _csrf = login_csrf(status_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert admin_response.status_code == 200
    assert status_client.get(SYSTEM_STATUS_PATH).status_code == 200


@pytest.mark.integration
def test_status_shape_on_empty_deployment(status_client: TestClient, db_session: Session) -> None:
    """Fresh state: maintenance off; api/database/file/worker/ingest honest.

    worker/ingest have NO rows at all: worker reports the documented idle
    convention (no evidence either way) and ingest reports stopped (its
    heartbeat row is written by the ingest process at startup — an absent
    row means the receiver never started here).
    """
    _as_admin(db_session, status_client)
    response = status_client.get(SYSTEM_STATUS_PATH)
    assert response.status_code == 200
    body = response.json()

    assert "as_of" in body
    assert body["maintenance"] == {"active": False, "since": None, "reason": None}

    components = body["components"]
    assert components["api"]["status"] == "ok"
    assert components["database"]["status"] == "ok"
    assert components["file_storage"]["status"] == "ok"
    worker = components["worker"]
    assert worker["status"] == "ok"
    assert worker["last_activity_at"] is None
    assert worker["collection_lag_seconds"] is None
    ingest = components["ingest"]
    assert ingest["status"] == "stopped"
    assert ingest["events_received_total"] == 0
    assert ingest["last_received_at"] is None

    assert body["queues"]["operation_tasks"] == {
        "queued": 0,
        "running": 0,
        "waiting_device": 0,
        "verification_required": 0,
    }
    assert body["queues"]["oldest_queued_age_seconds"] is None
    assert body["collection"]["last_24h"] == {"succeeded": 0, "partial": 0, "failed": 0}
    assert body["collection"]["current_failures"] == []
    assert body["verification_required"] == {"count": 0, "oldest_at": None}


@pytest.mark.integration
def test_maintenance_state_reported_when_active(status_client: TestClient, db_session: Session) -> None:
    _as_admin(db_session, status_client)
    enter_maintenance(db_session, reason="发布窗口")
    db_session.commit()
    response = status_client.get(SYSTEM_STATUS_PATH)
    assert response.status_code == 200
    maintenance = response.json()["maintenance"]
    assert maintenance["active"] is True
    assert maintenance["reason"] == "发布窗口"
    assert maintenance["since"] is not None
    exit_maintenance(db_session)
    db_session.commit()
    refreshed = status_client.get(SYSTEM_STATUS_PATH).json()["maintenance"]
    assert refreshed["active"] is False
    assert refreshed["since"] is None
    assert refreshed["reason"] is None


@pytest.mark.integration
def test_worker_stopped_when_activity_stale(status_client: TestClient, db_session: Session) -> None:
    """No DB activity within 2× task_lease_seconds (30s settings) → stopped."""
    _as_admin(db_session, status_client)
    user = make_user(db_session, index=1)
    device = make_device(db_session, index=1)
    stale_task = make_task(
        db_session,
        device_id=device.id,
        requested_by=user.id,
        index=1,
        state="succeeded",
    )
    stale_task.updated_at = datetime.datetime.now(UTC) - datetime.timedelta(seconds=90)
    db_session.commit()

    body = status_client.get(SYSTEM_STATUS_PATH).json()
    worker = body["components"]["worker"]
    assert worker["status"] == "stopped"
    assert worker["collection_lag_seconds"] is None


@pytest.mark.integration
def test_worker_degraded_when_collection_lag_severe(status_client: TestClient, db_session: Session) -> None:
    """Oldest scheduled-but-unclaimed run older than 2× its interval → degraded.

    Fresh activity (a succeeded run) keeps the stopped check quiet so the lag
    derivation (DEPLOYMENT §9.2: 超过两个采集周期) is what degrades the worker.
    """
    _as_admin(db_session, status_client)
    device = make_collection_device(db_session, index=1)
    now = datetime.datetime.now(UTC)
    fresh = make_collection_run(db_session, device_id=device.id, collection_type="metrics", state="succeeded")
    fresh.finished_at = now
    fresh.updated_at = now
    lagged = make_collection_run(
        db_session,
        device_id=device.id,
        collection_type="reachability",
        state="scheduled",
        scheduled_at=now - datetime.timedelta(seconds=25),
    )
    assert lagged.scheduled_at is not None
    db_session.commit()

    body = status_client.get(SYSTEM_STATUS_PATH).json()
    worker = body["components"]["worker"]
    assert worker["status"] == "degraded"
    assert worker["collection_lag_seconds"] is not None
    assert worker["collection_lag_seconds"] >= 25


@pytest.mark.integration
def test_ingest_idle_is_ok_and_stale_stops(status_client: TestClient, db_session: Session) -> None:
    """Idle (alive stamp, no events) is ok — NOT degraded; stale stamp stops."""
    _as_admin(db_session, status_client)
    db_session.add(
        IngestHeartbeat(
            id=1,
            events_received_total=0,
            updated_at=datetime.datetime.now(UTC) - datetime.timedelta(seconds=1),
        )
    )
    db_session.commit()
    body = status_client.get(SYSTEM_STATUS_PATH).json()
    ingest = body["components"]["ingest"]
    assert ingest["status"] == "ok"
    assert ingest["events_received_total"] == 0
    assert ingest["last_received_at"] is None

    # 3× heartbeat interval (1s settings) elapsed without a stamp → stopped.
    row = db_session.get(IngestHeartbeat, 1)
    assert row is not None
    row.updated_at = datetime.datetime.now(UTC) - datetime.timedelta(seconds=10)
    db_session.commit()
    stale = status_client.get(SYSTEM_STATUS_PATH).json()["components"]["ingest"]
    assert stale["status"] == "stopped"


@pytest.mark.integration
def test_file_storage_unavailable_when_root_not_writable(system_settings: WardenSettings, db_session: Session) -> None:
    """Root path under a FILE → mkdir fails → unavailable (no paths in detail)."""
    from fastapi.testclient import TestClient

    blocker = system_settings.file_store_root.parent / "not-a-dir"
    blocker.write_text("occupied", encoding="utf-8")
    blocked_root = blocker / "files"
    app = create_app(system_settings.model_copy(update={"file_store_root": blocked_root}))
    try:
        with TestClient(app) as client:
            create_admin(db_session)
            login_csrf(client, ADMIN_USERNAME, ADMIN_PASSWORD)
            body = client.get(SYSTEM_STATUS_PATH).json()
            storage = body["components"]["file_storage"]
            assert storage["status"] == "unavailable"
            assert storage["detail"] != ""
            assert "file_store" not in storage["detail"]
            assert str(blocked_root) not in storage["detail"]
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.mark.integration
def test_queue_collection_and_verification_summaries(status_client: TestClient, db_session: Session) -> None:
    _as_admin(db_session, status_client)
    user = make_user(db_session, index=2)
    now = datetime.datetime.now(UTC)
    # The device mutex (uq_operation_tasks_active_mutex) allows ONE active
    # change task per device, so each state gets its own device.
    queued_device = make_device(db_session, index=2)
    running_device = make_device(db_session, index=3)
    verification_device = make_device(db_session, index=4)
    make_task(
        db_session,
        device_id=queued_device.id,
        requested_by=user.id,
        index=1,
        state="queued",
    )
    make_task(
        db_session,
        device_id=running_device.id,
        requested_by=user.id,
        index=2,
        state="running",
    )
    make_task(
        db_session,
        device_id=verification_device.id,
        requested_by=user.id,
        index=3,
        state="verification_required",
    )

    collection_device = make_collection_device(db_session, index=2)
    ok_run = make_collection_run(
        db_session,
        device_id=collection_device.id,
        collection_type="metrics",
        state="succeeded",
    )
    ok_run.finished_at = now - datetime.timedelta(minutes=5)
    fail_run = make_collection_run(
        db_session,
        device_id=collection_device.id,
        collection_type="logs",
        state="failed",
    )
    fail_run.finished_at = now - datetime.timedelta(minutes=2)
    fail_run.error_code = "network_unreachable"
    partial_run = make_collection_run(
        db_session,
        device_id=collection_device.id,
        collection_type="reachability",
        state="partial",
    )
    partial_run.finished_at = now - datetime.timedelta(minutes=1)
    # Outside the 24h window: must not count.
    old_run = make_collection_run(
        db_session,
        device_id=collection_device.id,
        collection_type="discovery",
        state="failed",
    )
    old_run.finished_at = now - datetime.timedelta(hours=30)
    db_session.commit()

    body = status_client.get(SYSTEM_STATUS_PATH).json()
    queues = body["queues"]["operation_tasks"]
    assert queues["queued"] == 1
    assert queues["running"] == 1
    assert queues["waiting_device"] == 0
    assert queues["verification_required"] == 1
    assert body["queues"]["oldest_queued_age_seconds"] is not None

    outcomes = body["collection"]["last_24h"]
    assert outcomes == {"succeeded": 1, "partial": 1, "failed": 1}
    failures = body["collection"]["current_failures"]
    assert len(failures) == 1
    assert failures[0]["device_id"] == str(collection_device.id)
    assert failures[0]["collection_type"] == "logs"
    assert failures[0]["error_code"] == "network_unreachable"

    verification = body["verification_required"]
    assert verification["count"] == 1
    assert verification["oldest_at"] is not None


# ---------------------------------------------------------------------------
# Maintenance gate (DEPLOYMENT §8): new tasks/launches refused 503; the rest ok
# ---------------------------------------------------------------------------


def _enable_maintenance(db_session: Session) -> None:
    enter_maintenance(db_session, reason="升级窗口")
    db_session.commit()


@pytest.mark.integration
def test_operations_create_refused_during_maintenance_with_since_reason(
    status_client: TestClient, db_session: Session
) -> None:
    _as_admin(db_session, status_client)
    _enable_maintenance(db_session)
    response, csrf = login_csrf(status_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    del response
    body = {"preview_token": "tok-" + "x" * 20, "confirmation_text": "test-device-0"}
    denied = status_client.post(
        f"{API}/devices/{NONEXISTENT_DEVICE}/operations",
        json=body,
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 503
    error = denied.json()["error"]
    assert error["code"] == "maintenance_mode"
    assert "since" in error["details"]
    assert error["details"]["reason"] == "升级窗口"


@pytest.mark.integration
def test_launches_create_refused_during_maintenance(status_client: TestClient, db_session: Session) -> None:
    _as_admin(db_session, status_client)
    _enable_maintenance(db_session)
    _response, csrf = login_csrf(status_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    denied = status_client.post(
        f"{API}/devices/{NONEXISTENT_DEVICE}/launches",
        json={"capability_key": "console.ssh.open"},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 503
    assert denied.json()["error"]["code"] == "maintenance_mode"


@pytest.mark.integration
def test_previews_reads_and_uploads_stay_allowed_during_maintenance(
    status_client: TestClient, db_session: Session
) -> None:
    """Previews are read-only planning, not tasks: 404 (device unknown), never
    503. Reads and upload creation also stay available (DEPLOYMENT §8)."""
    _as_admin(db_session, status_client)
    _enable_maintenance(db_session)
    response, csrf = login_csrf(status_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    del response

    preview = status_client.post(
        f"{API}/devices/{NONEXISTENT_DEVICE}/operation-previews",
        json={"capability_key": "power.on", "parameters": {}},
        headers={"X-CSRF-Token": csrf},
    )
    assert preview.status_code == 404
    assert preview.json()["error"]["code"] == "resource_not_found"

    # Monitoring read (operator-visible data) stays available.
    listing = status_client.get(f"{API}/devices")
    assert listing.status_code == 200

    # File upload session creation is an input, not a task/launch: it reaches
    # the service layer (here a contract validation error because firmware
    # uploads require a matching file type flow — anything but a 503 proves
    # the gate is not applied).
    upload = status_client.post(
        f"{API}/files/uploads",
        json={
            "file_type": "firmware",
            "size_bytes": 1,
            "original_filename": "fw.bin",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert upload.status_code != 503

    # Reads of the system status itself are fine during maintenance.
    assert status_client.get(SYSTEM_STATUS_PATH).status_code == 200


@pytest.mark.integration
def test_operations_create_allowed_again_after_exit(status_client: TestClient, db_session: Session) -> None:
    _as_admin(db_session, status_client)
    _enable_maintenance(db_session)
    response, csrf = login_csrf(status_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    del response
    denied = status_client.post(
        f"{API}/devices/{NONEXISTENT_DEVICE}/operations",
        json={"preview_token": "tok-" + "x" * 20, "confirmation_text": "x"},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 503
    exit_maintenance(db_session)
    db_session.commit()
    allowed = status_client.post(
        f"{API}/devices/{NONEXISTENT_DEVICE}/operations",
        json={"preview_token": "tok-" + "x" * 20, "confirmation_text": "x"},
        headers={"X-CSRF-Token": csrf},
    )
    # The gate no longer blocks: the request proceeds to normal validation
    # (unknown device → 404, NOT 503).
    assert allowed.status_code == 404
    assert allowed.json()["error"]["code"] == "resource_not_found"
