"""Controlled-file API integration tests (M2T5, real PostgreSQL, API_CONTRACT §8).

End-to-end over HTTP: upload session create -> streamed PUT -> complete
(ready), metadata list/get, permission matrix (viewer metadata only),
admin logical delete (409 on active-task links via the route), the
concurrent-upload 429, and the exact operationIds of contracts/http-api.json
(the whitelist endpoints exist with identical paths/methods).
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
import zipfile
from collections.abc import Iterator

import pytest
from app.config import WardenSettings
from app.domain.roles import FILE_MANAGE_INPUT
from app.generated.http_api import HTTP_ENDPOINTS
from app.main import create_app
from app.models.auth import AuditLog, User
from app.models.files import File, FileLink
from app.tools.openapi_export import OPENAPI_PATH, run
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import create_user, login_csrf
from tests.task_factories import make_device, make_task

API = "/api/v1"
FILES_PATH = f"{API}/files"
UPLOADS_PATH = f"{API}/files/uploads"

ADMIN_PASSWORD = "Adm!n-2026-StrongPass"
OPERATOR_PASSWORD = "Op!pass-2026-Strong"
VIEWER_PASSWORD = "V!ew-2026-Strong"


@pytest.fixture
def files_app(fresh_test_db_dsn: str, tmp_path) -> Iterator[FastAPI]:
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
def client(files_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(files_app) as test_client:
        yield test_client


def _signin(client: TestClient, db_session: Session, *, username: str, password: str, role: str) -> tuple[User, str]:
    existing = db_session.scalar(select(User).where(User.username == username))
    if existing is None:
        existing = create_user(
            db_session,
            username=username,
            password=password,
            role=role,
            display_name=f"测试-{username}",
        )
    response, csrf = login_csrf(client, username, password)
    assert response.status_code == 200
    return existing, csrf


def _admin(client: TestClient, db_session: Session) -> tuple[User, str]:
    existing = db_session.scalar(select(User).where(User.username == "file-admin"))
    if existing is None:
        existing = create_user(
            db_session, username="file-admin", password=ADMIN_PASSWORD, role="admin", display_name="文件管理员"
        )
    response, csrf = login_csrf(client, "file-admin", ADMIN_PASSWORD)
    assert response.status_code == 200
    return existing, csrf


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("payload.txt", date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, b"firmware-payload-001")
    return buffer.getvalue()


def _upload_firmware(
    client: TestClient, csrf: str, content: bytes, *, declared: int | None = None
) -> tuple[object, str]:
    """POST /files/uploads + PUT content + POST complete; returns (view, id)."""
    created = client.post(
        f"{UPLOADS_PATH}",
        json={
            "file_type": "firmware",
            "size_bytes": declared if declared is not None else len(content),
            "original_filename": "fw-image.bin",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.text
    upload_id = str(created.json()["id"])
    put = client.put(
        f"{UPLOADS_PATH}/{upload_id}/content",
        content=content,
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/octet-stream"},
    )
    assert put.status_code == 200, put.text
    assert put.json()["received_bytes"] == len(content)
    completed = client.post(
        f"{UPLOADS_PATH}/{upload_id}/complete",
        headers={"X-CSRF-Token": csrf},
    )
    assert completed.status_code == 200, completed.text
    return completed.json(), upload_id


class TestUploadApi:
    def test_full_upload_flow_and_metadata_readback(self, client: TestClient, db_session: Session) -> None:
        admin, csrf = _admin(client, db_session)
        content = _zip_bytes()
        view, upload_id = _upload_firmware(client, csrf, content)
        assert view["status"] == "ready"
        assert view["file_type"] == "firmware"
        assert view["encrypted"] is False
        assert view["sha256"] == hashlib.sha256(content).hexdigest()
        assert view["original_filename"] == "fw-image.bin"
        assert view["mime_type"] == "application/zip"
        assert view["uploaded_by"]["id"] == str(admin.id)
        assert view["links"] == []
        # List shows the file; detail repeats it.
        listing = client.get(f"{FILES_PATH}", headers={"X-CSRF-Token": csrf})
        assert listing.status_code == 200
        assert [item["id"] for item in listing.json()["items"]] == [str(uuid.UUID(upload_id))]
        detail = client.get(f"{FILES_PATH}/{upload_id}")
        assert detail.status_code == 200
        assert detail.json()["id"] == upload_id

    def test_streamed_upload_overquota_aborts_with_422(self, client: TestClient, db_session: Session) -> None:
        admin, csrf = _admin(client, db_session)
        created = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "firmware", "size_bytes": 10, "original_filename": "tiny.bin"},
            headers={"X-CSRF-Token": csrf},
        )
        upload_id = str(created.json()["id"])
        put = client.put(
            f"{UPLOADS_PATH}/{upload_id}/content",
            content=b"0123456789ABCDEF",
            headers={"X-CSRF-Token": csrf},
        )
        assert put.status_code == 422
        assert put.json()["error"]["code"] == "validation_failed"
        # Session is gone: complete returns 404.
        completed = client.post(f"{UPLOADS_PATH}/{upload_id}/complete", headers={"X-CSRF-Token": csrf})
        assert completed.status_code == 404

    def test_create_rejects_unknown_type_and_oversize(self, client: TestClient, db_session: Session) -> None:
        admin, csrf = _admin(client, db_session)
        response = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "backup_tape", "size_bytes": 10, "original_filename": "x.bin"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"
        huge = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "firmware", "size_bytes": 11 * 1024**3, "original_filename": "huge.bin"},
            headers={"X-CSRF-Token": csrf},
        )
        assert huge.status_code == 422

    def test_concurrent_upload_limit_returns_429(self, client: TestClient, db_session: Session) -> None:
        admin, csrf = _admin(client, db_session)
        for _ in range(2):
            created = client.post(
                f"{UPLOADS_PATH}",
                json={"file_type": "firmware", "size_bytes": 10, "original_filename": "s.bin"},
                headers={"X-CSRF-Token": csrf},
            )
            assert created.status_code == 201
        limited = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "firmware", "size_bytes": 10, "original_filename": "s.bin"},
            headers={"X-CSRF-Token": csrf},
        )
        assert limited.status_code == 429
        body = limited.json()["error"]
        assert body["code"] == "rate_limited"
        assert body["details"]["scope"] == "file_upload"


class TestDownloadAndDeleteApi:
    def test_operator_downloads_ready_firmware(self, client: TestClient, db_session: Session) -> None:
        operator, csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        content = _zip_bytes()
        view, upload_id = _upload_firmware(client, csrf, content)
        response = client.get(f"{FILES_PATH}/{upload_id}/download")
        assert response.status_code == 200
        assert response.headers["content-disposition"].startswith("attachment")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == content
        assert response.headers["content-type"].startswith("application/zip")

    def test_encrypted_output_download_round_trips(self, client: TestClient, db_session: Session) -> None:
        operator, csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        content = _zip_bytes()
        created = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "support_bundle", "size_bytes": len(content), "original_filename": "bundle.zip"},
            headers={"X-CSRF-Token": csrf},
        )
        upload_id = str(created.json()["id"])
        put = client.put(f"{UPLOADS_PATH}/{upload_id}/content", content=content, headers={"X-CSRF-Token": csrf})
        assert put.status_code == 200
        completed = client.post(f"{UPLOADS_PATH}/{upload_id}/complete", headers={"X-CSRF-Token": csrf})
        assert completed.status_code == 200
        view = completed.json()
        assert view["status"] == "ready"
        assert view["encrypted"] is True
        assert view["key_version"] == 1
        response = client.get(f"{FILES_PATH}/{upload_id}/download")
        assert response.status_code == 200
        assert response.content == content

    def test_non_ascii_filename_download_serves_200_with_a_valid_header(
        self, client: TestClient, db_session: Session
    ) -> None:
        # Regression (M2T5 review): raw non-latin-1 characters in the
        # Content-Disposition filename crashed header serialization (500);
        # the original name must ride as RFC 5987 filename*.
        operator, csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        original = "固件升级包-v2.zip"
        content = _zip_bytes()
        created = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "firmware", "size_bytes": len(content), "original_filename": original},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201
        upload_id = str(created.json()["id"])
        put = client.put(f"{UPLOADS_PATH}/{upload_id}/content", content=content, headers={"X-CSRF-Token": csrf})
        assert put.status_code == 200
        completed = client.post(f"{UPLOADS_PATH}/{upload_id}/complete", headers={"X-CSRF-Token": csrf})
        assert completed.status_code == 200
        assert completed.json()["original_filename"] == original
        response = client.get(f"{FILES_PATH}/{upload_id}/download")
        assert response.status_code == 200
        assert response.content == content
        disposition = response.headers["content-disposition"]
        assert disposition.startswith("attachment")
        assert all(ord(char) < 128 for char in disposition)  # latin-1 serializable
        assert "filename*=UTF-8''" in disposition
        from urllib.parse import unquote

        assert unquote(disposition.split("filename*=UTF-8''", 1)[1]) == original

    def test_viewer_is_metadata_only(self, client: TestClient, db_session: Session) -> None:
        operator, csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        content = _zip_bytes()
        view, upload_id = _upload_firmware(client, csrf, content)
        viewer, viewer_csrf = _signin(
            client, db_session, username="file-viewer", password=VIEWER_PASSWORD, role="viewer"
        )
        listing = client.get(f"{FILES_PATH}")
        assert listing.status_code == 200
        detail = client.get(f"{FILES_PATH}/{upload_id}")
        assert detail.status_code == 200
        # Viewer cannot create uploads, cannot download, cannot delete.
        denied_create = client.post(
            f"{UPLOADS_PATH}",
            json={"file_type": "firmware", "size_bytes": 10, "original_filename": "x.bin"},
            headers={"X-CSRF-Token": viewer_csrf},
        )
        assert denied_create.status_code == 403
        assert denied_create.json()["error"]["details"]["permission"] == FILE_MANAGE_INPUT
        denied_download = client.get(f"{FILES_PATH}/{upload_id}/download")
        assert denied_download.status_code == 403
        denied_delete = client.delete(f"{FILES_PATH}/{upload_id}", headers={"X-CSRF-Token": viewer_csrf})
        assert denied_delete.status_code == 403

    def test_operator_delete_is_forbidden_admin_delete_logical(self, client: TestClient, db_session: Session) -> None:
        operator, operator_csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        content = _zip_bytes()
        view, upload_id = _upload_firmware(client, operator_csrf, content)
        denied = client.delete(f"{FILES_PATH}/{upload_id}", headers={"X-CSRF-Token": operator_csrf})
        assert denied.status_code == 403
        # Switch actor: a fresh admin session replaces the operator cookie —
        # every mutating request carries the CSRF token of ITS session.
        admin, admin_csrf = _admin(client, db_session)
        deleted = client.delete(f"{FILES_PATH}/{upload_id}", headers={"X-CSRF-Token": admin_csrf})
        assert deleted.status_code == 200
        assert deleted.json()["status"] == "deleted"
        # Deleted file is not downloadable.
        download = client.get(f"{FILES_PATH}/{upload_id}/download")
        assert download.status_code == 422

    def test_delete_409_on_active_task_link(self, client: TestClient, db_session: Session) -> None:
        operator, operator_csrf = _signin(
            client, db_session, username="file-operator", password=OPERATOR_PASSWORD, role="operator"
        )
        content = _zip_bytes()
        view, upload_id = _upload_firmware(client, operator_csrf, content)
        # Switch actor to the admin before the mutating delete.
        admin, admin_csrf = _admin(client, db_session)
        file_row = db_session.scalar(select(File).where(File.id == uuid.UUID(upload_id)))
        device = make_device(db_session, index=80)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=admin.id,
            index=80,
            requirement_id="SRV-ACT-06",
            capability_key="firmware.update",
            state="running",
            idempotency_key="api-delete-80",
        )
        db_session.add(
            FileLink(
                file_id=file_row.id,
                device_id=device.id,
                task_id=task.id,
                purpose="input_firmware",
                created_by=admin.id,
            )
        )
        db_session.commit()
        deleted = client.delete(f"{FILES_PATH}/{upload_id}", headers={"X-CSRF-Token": admin_csrf})
        assert deleted.status_code == 409
        body = deleted.json()["error"]
        assert body["code"] == "device_busy"
        assert body["details"]["conflict_task_id"] == str(task.id)
        # Audit rows exist for create/complete and the flows above.
        actions = list(db_session.scalars(select(AuditLog.action)).all())
        assert "file.upload_create" in actions
        assert "file.upload_complete" in actions

    def test_delete_409_not_reachable_for_audit_logged_denial(self, client: TestClient, db_session: Session) -> None:
        # Viewer delete denial is audited (mutating denial pattern, M1T4).
        viewer, viewer_csrf = _signin(
            client, db_session, username="file-viewer", password=VIEWER_PASSWORD, role="viewer"
        )
        client.delete(f"{FILES_PATH}/{uuid.uuid4()}", headers={"X-CSRF-Token": viewer_csrf})
        denials = db_session.scalars(
            select(AuditLog).where(AuditLog.action == "access.denied", AuditLog.result == "permission_denied")
        ).all()
        assert any(row.detail_jsonb.get("permission") == "file.delete" for row in denials)


class TestFilesOperationIds:
    """The eight PLT-06 endpoints exist with the EXACT operationIds/paths."""

    FILES_ENDPOINTS = {
        "file_uploads_create": ("POST", "/files/uploads"),
        "file_uploads_put_content": ("PUT", "/files/uploads/{id}/content"),
        "file_uploads_complete": ("POST", "/files/uploads/{id}/complete"),
        "files_list": ("GET", "/files"),
        "files_get": ("GET", "/files/{id}"),
        "files_download": ("GET", "/files/{id}/download"),
        "files_delete": ("DELETE", "/files/{id}"),
        "device_file_access_get": ("GET", "/device-file-access/{ticket}"),
    }

    def test_exported_openapi_files_operation_ids_match_contract(self, files_app: FastAPI) -> None:
        run()
        schema = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
        paths = schema["paths"]
        assert isinstance(paths, dict)
        observed: dict[str, tuple[str, str]] = {}
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
                    observed[operation["operationId"]] = (method.upper(), path)
        for operation_id, (method, path) in self.FILES_ENDPOINTS.items():
            assert observed.get(operation_id) == (method, f"/api/v1{path}"), operation_id
            contract_endpoint = HTTP_ENDPOINTS[operation_id]
            assert contract_endpoint.path == path
            assert contract_endpoint.operation_id == operation_id
            assert contract_endpoint.method == method
        # The unauthenticated ticket endpoint must exist outside any auth gate.
        app_schema = files_app.openapi()
        ticket_path = "/api/v1/device-file-access/{ticket}"
        assert app_schema["paths"][ticket_path]["get"]["operationId"] == "device_file_access_get"
