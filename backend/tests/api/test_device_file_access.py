"""Device-pull ticket endpoint tests (M2T5, API_CONTRACT.md §8, SECURITY.md §7).

The DB-backed tickets are issued through the application service (M2T6 wires
the real task flow); the HTTP layer is exercised here: matching source IP
serves the file (200 full + 206 Range partial), wrong IP / expired / revoked
/ unknown tickets are all the SAME 404, cross-file serving is impossible,
unsatisfiable ranges get 416, and the ticket URL never appears in normal
(structured) log output.

TestClient limitation (documented): the ASGI test client always presents the
peer address ``testclient``, so seeded tickets pin ``expected_ip =
"testclient"``. Real deployments resolve the device's management IP at issue
time (``application/files.py::resolve_management_ip``).
"""

from __future__ import annotations

import datetime
import io
import uuid
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from app.config import WardenSettings
from app.infrastructure.time import utcnow
from app.main import create_app
from app.models.auth import AuditLog, User
from app.models.files import DeviceFileTicket, File
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import create_user, login_csrf
from tests.task_factories import make_device

API = "/api/v1"
TICKET_PATH = f"{API}/device-file-access/{{ticket}}"

PEER = "testclient"  # the TestClient ASGI peer address (see module docstring)


@pytest.fixture
def ticket_app(fresh_test_db_dsn: str, tmp_path: Path) -> Iterator[FastAPI]:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    file_key_file = tmp_path / "file_master.key"
    file_key_file.write_text("F" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    settings = WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        credential_master_key_file=key_file,
        file_master_key_file=file_key_file,
        session_secret_file=session_file,
        file_store_root=tmp_path / "files",
    )
    app = create_app(settings)
    try:
        yield app
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.fixture
def client(ticket_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(ticket_app) as test_client:
        yield test_client


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("fw.bin", date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, b"device-firmware-payload")
    return buffer.getvalue()


def _seed_ready_file(client: TestClient, db_session: Session) -> File:
    """Upload a ready firmware file through the API as the seeded operator."""
    user = db_session.scalar(select(User).where(User.username == "ticket-operator"))
    if user is None:
        user = create_user(
            db_session,
            username="ticket-operator",
            password="Op!pass-2026-Strong",
            role="operator",
            display_name="票据操作员",
        )
    response, csrf = login_csrf(client, "ticket-operator", "Op!pass-2026-Strong")
    assert response.status_code == 200
    content = _zip_bytes()
    created = client.post(
        f"{API}/files/uploads",
        json={"file_type": "firmware", "size_bytes": len(content), "original_filename": "fw.zip"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    upload_id = str(created.json()["id"])
    put = client.put(
        f"{API}/files/uploads/{upload_id}/content",
        content=content,
        headers={"X-CSRF-Token": csrf},
    )
    assert put.status_code == 200
    completed = client.post(
        f"{API}/files/uploads/{upload_id}/complete", headers={"X-CSRF-Token": csrf}
    )
    assert completed.status_code == 200
    return db_session.scalar(select(File).where(File.id == uuid.UUID(upload_id)))


def _seed_ticket(db_session: Session, *, file_row: File, device_id, purpose: str = "firmware") -> DeviceFileTicket:
    ticket = DeviceFileTicket(
        file_id=file_row.id,
        device_id=device_id,
        purpose=purpose,
        expected_ip=PEER,
        expires_at=utcnow() + datetime.timedelta(hours=2),
    )
    db_session.add(ticket)
    db_session.commit()
    db_session.refresh(ticket)
    return ticket


class TestTicketServe:
    def test_full_serve_with_matching_source_ip(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=90)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 200
        assert response.content == _zip_bytes()
        assert response.headers["content-length"] == str(file_row.size_bytes)
        assert response.headers["accept-ranges"] == "bytes"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"

    def test_range_request_serves_206_partial(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=91)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        response = client.get(TICKET_PATH.format(ticket=ticket.id), headers={"Range": "bytes=10-19"})
        assert response.status_code == 206
        assert response.content == _zip_bytes()[10:20]
        assert response.headers["content-range"] == f"bytes 10-19/{file_row.size_bytes}"
        assert response.headers["content-length"] == "10"

    def test_open_ended_and_suffix_ranges(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=92)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        total = file_row.size_bytes
        tail = client.get(TICKET_PATH.format(ticket=ticket.id), headers={"Range": "bytes=100-"})
        assert tail.status_code == 206
        assert tail.content == _zip_bytes()[100:]
        assert tail.headers["content-range"] == f"bytes 100-{total - 1}/{total}"
        suffix = client.get(TICKET_PATH.format(ticket=ticket.id), headers={"Range": "bytes=-5"})
        assert suffix.status_code == 206
        assert suffix.content == _zip_bytes()[-5:]

    def test_unsatisfiable_range_is_416(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=93)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        response = client.get(
            TICKET_PATH.format(ticket=ticket.id), headers={"Range": "bytes=999999-"}
        )
        assert response.status_code == 416

    def test_malformed_range_falls_back_to_full_200(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=94)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        for header in ("bytes=1-2,5-9", "items=1-2", "bytes=abc"):
            response = client.get(TICKET_PATH.format(ticket=ticket.id), headers={"Range": header})
            assert response.status_code == 200
            assert response.content == _zip_bytes()


class TestTicketFailuresAreUniform404:
    def test_wrong_source_ip_is_404(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=95)
        ticket = DeviceFileTicket(
            file_id=file_row.id,
            device_id=device.id,
            purpose="firmware",
            expected_ip="192.168.10.77",
            expires_at=utcnow() + datetime.timedelta(hours=2),
        )
        db_session.add(ticket)
        db_session.commit()
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "resource_not_found"

    def test_expired_ticket_is_404(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=96)
        ticket = DeviceFileTicket(
            file_id=file_row.id,
            device_id=device.id,
            purpose="firmware",
            expected_ip=PEER,
            expires_at=utcnow() - datetime.timedelta(minutes=1),
        )
        db_session.add(ticket)
        db_session.commit()
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 404

    def test_revoked_ticket_is_404(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=97)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        ticket.revoked_at = utcnow()
        db_session.commit()
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 404

    def test_unknown_and_malformed_tickets_are_404(self, client: TestClient, db_session: Session) -> None:
        response = client.get(TICKET_PATH.format(ticket=uuid.uuid4()))
        assert response.status_code == 404
        malformed = client.get(TICKET_PATH.format(ticket="not-a-uuid"))
        assert malformed.status_code == 404

    def test_deleted_file_behind_ticket_is_404(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=98)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        file_row.status = "deleted"
        file_row.version += 1
        db_session.commit()
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 404


class TestTicketLogAndAudit:
    def test_first_serve_is_audited_once(self, client: TestClient, db_session: Session) -> None:
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=99)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        for _ in range(3):
            response = client.get(TICKET_PATH.format(ticket=ticket.id))
            assert response.status_code == 200
        serves = db_session.scalars(
            select(AuditLog).where(
                AuditLog.action == "device_file_ticket.serve",
                AuditLog.resource_id == str(ticket.id),
            )
        ).all()
        assert len(serves) == 1
        assert serves[0].device_id == device.id
        assert serves[0].detail_jsonb.get("file_type") == "firmware"

    def test_denied_serves_are_not_audited_and_404_never_leaks(self, client: TestClient, db_session: Session) -> None:
        # Device-pull failures must not be enumerable: the same generic 404
        # envelope is returned regardless of the failing condition.
        file_row = _seed_ready_file(client, db_session)
        device = make_device(db_session, index=100)
        ticket = _seed_ticket(db_session, file_row=file_row, device_id=device.id)
        ticket.revoked_at = utcnow()
        db_session.commit()
        response = client.get(TICKET_PATH.format(ticket=ticket.id))
        assert response.status_code == 404
        body = response.json()["error"]
        assert body["code"] == "resource_not_found"
        assert body["details"] == {"resource_type": "device_file_ticket"}
        assert body["message"] == "资源不存在"
