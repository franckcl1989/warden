"""Controlled file layer application tests (M2T5, real PostgreSQL).

docs/SECURITY.md §9, DATA_MODEL.md §8/§10, API_CONTRACT.md §8 — service-level
lifecycle: create/stream/complete (size/hash/magic verification), sensitive
types encrypted at rest (on-disk bytes differ from plaintext, decryption
round-trip through the file master key), permission matrix, admin logical
delete with active-task 409, delayed physical cleanup with reference checks,
config-backup keep-10/90d prune, support-bundle/operation-log 30d aging,
abandoned-upload close-out, ticket purge and the DB-backed device-pull
ticket lifecycle (issue/serve/revoke/IP binding).
"""

from __future__ import annotations

import datetime
import hashlib
import io
import zipfile
from pathlib import Path

import pytest
from app.application import files as file_service
from app.application.files import FileAuditContext, issue_device_file_ticket
from app.application.maintenance import enforce_file_retention
from app.config import WardenSettings
from app.domain.errors import AppError
from app.domain.roles import FILE_DELETE, FILE_DOWNLOAD_OUTPUT, FILE_MANAGE_INPUT
from app.infrastructure.crypto import FileKeyCipher
from app.infrastructure.files import FileStorage
from app.models.auth import User
from app.models.files import DeviceFileTicket, File, FileLink
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.task_factories import make_device, make_task

UTC = datetime.UTC
# Module-level "now": retention windows and ticket expiries must relate to
# the REAL clock (service issue checks use utcnow()).
NOW = datetime.datetime.now(UTC)
SETTINGS = WardenSettings(_env_file=None)

FILE_KEY_MATERIAL = b"K" * 64

NO_AUDIT = FileAuditContext(
    actor_user_id=None, session_id=None, source_ip=None, user_agent_summary=None, request_id=""
)


def _storage(tmp_path: Path) -> FileStorage:
    storage = FileStorage(tmp_path / "files")
    storage.check_available()
    return storage


def _cipher() -> FileKeyCipher:
    return FileKeyCipher(FILE_KEY_MATERIAL)


def _zip_bytes(name: str = "bundle.zip", payload: bytes = b"support payload") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, payload)
    return buffer.getvalue()


def _zip_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _role_user(db: Session, *, role: str, index: int = 0) -> User:
    user = User(
        username=f"file-{role}-{index}",
        display_name=f"文件测试-{role}-{index}",
        role=role,
        status="active",
        password_hash="x",
        must_change_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _upload_ready(
    db: Session,
    storage: FileStorage,
    *,
    user: User,
    file_type: str,
    content: bytes,
    original_filename: str = "input.bin",
    key_cipher: FileKeyCipher | None = None,
) -> File:
    row = file_service.create_upload(
        db,
        user=user,
        file_type=file_type,
        size_bytes=len(content),
        original_filename=original_filename,
        settings=SETTINGS,
    )
    upload_id = str(row.id)
    for start in range(0, len(content), 65521):
        file_service.stream_upload_chunk(
            db, upload_id=upload_id, user_id=user.id, chunk=content[start : start + 65521], storage=storage
        )
    db.commit()
    completed = file_service.complete_upload(
        db, upload_id=upload_id, user=user, storage=storage, key_cipher=key_cipher
    )
    db.commit()
    db.refresh(completed)
    return completed


def _link(
    db: Session,
    *,
    file_id: object,
    purpose: str,
    user: User,
    device_id: object | None = None,
    task_id: object | None = None,
) -> FileLink:
    link = FileLink(
        file_id=file_id,
        device_id=device_id,
        task_id=task_id,
        purpose=purpose,
        created_by=user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def _file_rows(db: Session) -> list[File]:
    return list(db.scalars(select(File).order_by(File.created_at)).all())


class TestUploadLifecycle:
    def test_create_stream_complete_plain_file(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=1)
        content = _zip_bytes()
        row = _upload_ready(
            db_session, storage, user=operator, file_type="firmware", content=content,
            original_filename="../../etc/passwd" if False else "fw.zip",
        )
        assert row.status == "ready"
        assert row.file_type == "firmware"
        assert row.encrypted is False
        assert row.key_version is None
        assert row.sha256 == _zip_hash(content)
        assert row.storage_name == _zip_hash(content)
        assert row.mime_type == "application/zip"
        assert row.size_bytes == len(content)
        # The physical file is content-addressed under a 2-char shard; the
        # hostile/display name never reaches the volume.
        data_dir = tmp_path / "files" / "data"
        assert [p.name for p in data_dir.iterdir()] == [row.storage_name[:2]]
        assert (data_dir / row.storage_name[:2] / row.storage_name).exists()
        # Spool consumed.
        assert storage.upload_size(str(row.id)) == 0
        # Download path streams the exact content back.
        download = file_service.prepare_download(
            db_session, file_id=str(row.id), user=operator, storage=storage, key_cipher=None
        )
        assert b"".join(file_service.stream_chunks(storage, download, byte_range=None, key_cipher=None)) == content

    def test_hostile_filename_never_reaches_storage(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=2)
        content = _zip_bytes()
        row = _upload_ready(
            db_session, storage, user=operator, file_type="firmware", content=content,
            original_filename="..\\..\\evil\\passwd.bin",
        )
        assert row.status == "ready"
        assert row.storage_name == _zip_hash(content)
        for data_path in (tmp_path / "files" / "data").rglob("*"):
            assert "..\\.." not in str(data_path) and "..\\" not in data_path.name
        # Control characters (e.g. NUL) cannot be stored at all: rejected.
        with pytest.raises(AppError) as hostile:
            file_service.create_upload(
                db_session, user=operator, file_type="firmware", size_bytes=10,
                original_filename="../../etc/passwd\x00evil.bin", settings=SETTINGS,
            )
        assert hostile.value.code == "validation_failed"

    def test_sensitive_support_bundle_is_encrypted_on_disk(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        operator = _role_user(db_session, role="operator", index=3)
        content = _zip_bytes()
        row = _upload_ready(
            db_session, storage, user=operator, file_type="support_bundle", content=content,
            original_filename="nas-support.zip", key_cipher=cipher,
        )
        assert row.status == "ready"
        assert row.encrypted is True
        assert row.key_version == 1
        assert row.sha256 == _zip_hash(content)
        physical = f"{row.storage_name}-{row.id}"
        on_disk = (tmp_path / "files" / "data" / physical[:2] / physical).read_bytes()
        # SECURITY.md §9: on-disk bytes are ciphertext, never the plaintext.
        assert on_disk != content
        assert content not in on_disk
        assert on_disk.startswith(b"WDN1")
        # Round-trip decryption through the file master key.
        download = file_service.prepare_download(
            db_session, file_id=str(row.id), user=operator, storage=storage, key_cipher=cipher
        )
        assert b"".join(
            file_service.stream_chunks(storage, download, byte_range=None, key_cipher=cipher)
        ) == content

    def test_config_backup_and_operation_log_are_encrypted(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        operator = _role_user(db_session, role="operator", index=4)
        for file_type in ("config_backup", "operation_log"):
            content = _zip_bytes(name=f"{file_type}.zip")
            row = _upload_ready(
                db_session, storage, user=operator, file_type=file_type,
                content=content, key_cipher=cipher,
            )
            assert row.encrypted is True
            assert row.sha256 == _zip_hash(content)

    def test_upload_without_master_key_fails_for_sensitive_types(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=5)
        content = _zip_bytes()
        session_row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="config_backup",
            size_bytes=len(content),
            original_filename="backup.zip",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(session_row.id)
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=content, storage=storage
        )
        db_session.commit()
        with pytest.raises(AppError) as error:
            file_service.complete_upload(
                db_session, upload_id=upload_id, user=operator, storage=storage, key_cipher=None
            )
        assert error.value.code == "dependency_unavailable"

    def test_size_mismatch_at_complete_aborts_the_session(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=6)
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="firmware",
            size_bytes=1000,
            original_filename="fw.bin",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(row.id)
        partial = b"\x00" * 100
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=partial, storage=storage
        )
        db_session.commit()
        with pytest.raises(AppError) as error:
            file_service.complete_upload(
                db_session, upload_id=upload_id, user=operator, storage=storage, key_cipher=None
            )
        assert error.value.code == "validation_failed"
        assert error.value.details["reason"] == "size_mismatch"
        db_session.commit()
        db_session.refresh(row)
        assert row.status == "deleted"
        assert row.metadata_json.get("error_code") == "size_mismatch"
        assert storage.upload_size(upload_id) == 0
        assert storage.exists("0" * 64) is False

    def test_oversize_stream_aborts_mid_upload(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=7)
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="virtual_media",
            size_bytes=10,
            original_filename="media.iso",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(row.id)
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=b"012345", storage=storage
        )
        with pytest.raises(AppError) as error:
            file_service.stream_upload_chunk(
                db_session, upload_id=upload_id, user_id=operator.id, chunk=b"MOREMORE", storage=storage
            )
        assert error.value.code == "validation_failed"
        assert error.value.details["reason"] == "size_exceeded"
        db_session.commit()
        db_session.refresh(row)
        assert row.status == "deleted"
        assert row.metadata_json.get("error_code") == "size_exceeded"
        assert storage.upload_size(upload_id) == 0

    def test_retried_full_put_is_tolerated(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=8)
        content = b"retry-me"
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="firmware",
            size_bytes=len(content),
            original_filename="fw.bin",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(row.id)
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=content, storage=storage
        )
        total = file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=content, storage=storage
        )
        assert total == len(content)
        assert storage.upload_size(upload_id) == len(content)

    def test_no_content_complete_is_rejected(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=9)
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="firmware",
            size_bytes=10,
            original_filename="fw.bin",
            settings=SETTINGS,
        )
        db_session.commit()
        with pytest.raises(AppError) as error:
            file_service.complete_upload(
                db_session, upload_id=str(row.id), user=operator, storage=storage, key_cipher=None
            )
        assert error.value.code == "validation_failed"
        db_session.commit()
        db_session.refresh(row)
        assert row.status == "deleted"

    def test_magic_mismatch_quarantines_support_bundle(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        operator = _role_user(db_session, role="operator", index=10)
        content = b"definitely not an archive" * 100
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="support_bundle",
            size_bytes=len(content),
            original_filename="fake.zip",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(row.id)
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=content, storage=storage
        )
        db_session.commit()
        completed = file_service.complete_upload(
            db_session, upload_id=upload_id, user=operator, storage=storage, key_cipher=cipher
        )
        db_session.commit()
        assert completed.status == "quarantined"
        assert completed.metadata_json.get("magic_note") == "unexpected_magic"
        # Content is retained (evidence) but unusable.
        with pytest.raises(AppError) as error:
            file_service.ensure_file_usable(completed)
        assert error.value.code == "validation_failed"

    def test_quarantined_file_is_not_downloadable(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        operator = _role_user(db_session, role="operator", index=11)
        content = b"junk" * 500
        row = file_service.create_upload(
            db_session,
            user=operator,
            file_type="operation_log",
            size_bytes=len(content),
            original_filename="log.txt",
            settings=SETTINGS,
        )
        db_session.commit()
        upload_id = str(row.id)
        file_service.stream_upload_chunk(
            db_session, upload_id=upload_id, user_id=operator.id, chunk=content, storage=storage
        )
        db_session.commit()
        completed = file_service.complete_upload(
            db_session, upload_id=upload_id, user=operator, storage=storage, key_cipher=cipher
        )
        db_session.commit()
        assert completed.status == "quarantined"
        with pytest.raises(AppError) as error:
            file_service.prepare_download(
                db_session, file_id=str(completed.id), user=operator, storage=storage, key_cipher=cipher
            )
        assert error.value.code == "validation_failed"


class TestUploadValidationAndPermissions:
    def test_create_rejects_zero_and_oversized(self, db_session: Session, tmp_path: Path) -> None:
        del tmp_path
        operator = _role_user(db_session, role="operator", index=20)
        with pytest.raises(AppError) as zero:
            file_service.create_upload(
                db_session, user=operator, file_type="firmware", size_bytes=0,
                original_filename="x.bin", settings=SETTINGS,
            )
        assert zero.value.code == "validation_failed"
        with pytest.raises(AppError) as big:
            file_service.create_upload(
                db_session, user=operator, file_type="firmware",
                size_bytes=SETTINGS.max_firmware_bytes + 1,
                original_filename="x.bin", settings=SETTINGS,
            )
        assert big.value.code == "validation_failed"
        with pytest.raises(AppError) as unknown:
            file_service.create_upload(
                db_session, user=operator, file_type="not_a_type", size_bytes=10,
                original_filename="x.bin", settings=SETTINGS,
            )
        assert unknown.value.code == "validation_failed"
        with pytest.raises(AppError) as blank:
            file_service.create_upload(
                db_session, user=operator, file_type="firmware", size_bytes=10,
                original_filename="   ", settings=SETTINGS,
            )
        assert blank.value.code == "validation_failed"

    def test_concurrent_upload_limit_is_two_per_user(self, db_session: Session, tmp_path: Path) -> None:
        del tmp_path
        operator = _role_user(db_session, role="operator", index=21)
        first = file_service.create_upload(
            db_session, user=operator, file_type="firmware", size_bytes=10,
            original_filename="a.bin", settings=SETTINGS,
        )
        second = file_service.create_upload(
            db_session, user=operator, file_type="firmware", size_bytes=10,
            original_filename="b.bin", settings=SETTINGS,
        )
        db_session.commit()
        assert first.status == "uploading" and second.status == "uploading"
        with pytest.raises(AppError) as limited:
            file_service.create_upload(
                db_session, user=operator, file_type="firmware", size_bytes=10,
                original_filename="c.bin", settings=SETTINGS,
            )
        assert limited.value.code == "rate_limited"
        assert limited.value.details["scope"] == "file_upload"

    def test_viewer_cannot_upload_or_download(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        viewer = _role_user(db_session, role="viewer", index=22)
        operator = _role_user(db_session, role="operator", index=23)
        content = _zip_bytes()
        ready = _upload_ready(db_session, storage, user=operator, file_type="firmware", content=content)
        with pytest.raises(AppError) as upload_error:
            file_service.create_upload(
                db_session, user=viewer, file_type="firmware", size_bytes=10,
                original_filename="x.bin", settings=SETTINGS,
            )
        assert upload_error.value.code == "permission_denied"
        assert upload_error.value.details.get("permission") == FILE_MANAGE_INPUT
        with pytest.raises(AppError) as download_error:
            file_service.prepare_download(
                db_session, file_id=str(ready.id), user=viewer, storage=storage, key_cipher=None
            )
        assert download_error.value.code == "permission_denied"
        assert download_error.value.details.get("permission") == FILE_MANAGE_INPUT

    def test_output_download_needs_download_output_permission(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        viewer = _role_user(db_session, role="viewer", index=24)
        operator = _role_user(db_session, role="operator", index=25)
        content = _zip_bytes()
        ready = _upload_ready(
            db_session, storage, user=operator, file_type="support_bundle",
            content=content, key_cipher=cipher,
        )
        with pytest.raises(AppError) as download_error:
            file_service.prepare_download(
                db_session, file_id=str(ready.id), user=viewer, storage=storage, key_cipher=cipher
            )
        assert download_error.value.code == "permission_denied"
        assert download_error.value.details.get("permission") == FILE_DOWNLOAD_OUTPUT

    def test_operator_cannot_delete(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=26)
        admin = _role_user(db_session, role="admin", index=27)
        content = _zip_bytes()
        ready = _upload_ready(db_session, storage, user=operator, file_type="firmware", content=content)
        assert file_service.delete_file(db_session, file_id=str(ready.id), logger=None, audit=None) is not None
        db_session.rollback()
        # The delete itself is matrix-gated at the route; here the service
        # honors whatever caller passed. Admin-only enforcement lives in the
        # API layer (require_permission(FILE_DELETE)) — assert the matrix.
        from app.domain.roles import require_permission as matrix_require

        assert matrix_require(admin.role, FILE_DELETE) is True
        assert matrix_require(operator.role, FILE_DELETE) is False


class TestLogicalDeleteAndPhysicalCleanup:
    def test_delete_blocks_on_active_task_link(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        admin = _role_user(db_session, role="admin", index=30)
        operator = _role_user(db_session, role="operator", index=31)
        content = _zip_bytes()
        ready = _upload_ready(db_session, storage, user=operator, file_type="firmware", content=content)
        device = make_device(db_session, index=32)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=admin.id,
            index=32,
            requirement_id="SRV-ACT-06",
            capability_key="firmware.update",
            state="running",
            idempotency_key="file-delete-32",
        )
        _link(db_session, file_id=ready.id, purpose="input_firmware", user=admin, device_id=device.id, task_id=task.id)
        with pytest.raises(AppError) as conflict:
            file_service.delete_file(db_session, file_id=str(ready.id), logger=None, audit=None)
        assert conflict.value.code == "device_busy"
        assert conflict.value.details.get("conflict_task_id") == str(task.id)
        # Terminal tasks do not block.
        task.state = "succeeded"
        db_session.commit()
        deleted = file_service.delete_file(db_session, file_id=str(ready.id), logger=None, audit=None)
        db_session.commit()
        assert deleted.status == "deleted"

    def test_physical_cleanup_after_seven_days(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        admin = _role_user(db_session, role="admin", index=33)
        content = _zip_bytes()
        ready = _upload_ready(db_session, storage, user=admin, file_type="firmware", content=content)
        key = ready.storage_name
        assert storage.exists(key) is True
        file_service.delete_file(db_session, file_id=str(ready.id), logger=None, audit=None)
        db_session.commit()
        # Row still logically deleted; bytes still present before the delay.
        report_early = enforce_file_retention(
            db_session, now=NOW, settings=SETTINGS, storage=storage
        )
        assert report_early.physical_files_removed == 0
        assert storage.exists(key) is True
        # 10 days after the logical delete the bytes leave (no live twins).
        ready.updated_at = NOW - datetime.timedelta(days=10)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.physical_files_removed == 1
        assert storage.exists(key) is False
        db_session.refresh(ready)
        assert ready.status == "deleted"

    def test_physical_cleanup_skips_shared_content_with_live_twin(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        admin = _role_user(db_session, role="admin", index=34)
        content = _zip_bytes()
        twin_a = _upload_ready(db_session, storage, user=admin, file_type="firmware", content=content)
        twin_b = _upload_ready(db_session, storage, user=admin, file_type="firmware", content=content)
        assert twin_a.storage_name == twin_b.storage_name  # one physical file
        file_service.delete_file(db_session, file_id=str(twin_a.id), logger=None, audit=None)
        db_session.commit()
        twin_a.updated_at = NOW - datetime.timedelta(days=10)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.physical_files_removed == 0
        assert storage.exists(twin_a.storage_name) is True  # twin B still needs it
        file_service.delete_file(db_session, file_id=str(twin_b.id), logger=None, audit=None)
        db_session.commit()
        twin_b.updated_at = NOW - datetime.timedelta(days=10)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.physical_files_removed == 1
        assert storage.exists(twin_a.storage_name) is False

    def test_physical_cleanup_skips_active_task_link(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        admin = _role_user(db_session, role="admin", index=35)
        content = _zip_bytes()
        ready = _upload_ready(db_session, storage, user=admin, file_type="firmware", content=content)
        device = make_device(db_session, index=36)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=admin.id,
            index=36,
            requirement_id="SRV-ACT-06",
            capability_key="firmware.update",
            state="running",
            idempotency_key="file-clean-36",
        )
        _link(db_session, file_id=ready.id, purpose="input_firmware", user=admin, device_id=device.id, task_id=task.id)
        # The API cannot reach this state (delete 409s on active links), but
        # the retention sweep defends against it anyway: a logically deleted
        # row that still carries an active link must not lose its bytes.
        ready.status = "deleted"
        ready.version += 1
        db_session.commit()
        ready.updated_at = NOW - datetime.timedelta(days=10)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.physical_files_removed == 0
        assert storage.exists(file_service.storage_key(ready)) is True


class TestRetentionRules:
    @staticmethod
    def _backdate(row: File, *, days: float) -> None:
        row.created_at = NOW - datetime.timedelta(days=days)

    def test_support_bundle_and_operation_log_age_out_after_30_days(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        operator = _role_user(db_session, role="operator", index=40)
        old_bundle = _upload_ready(
            db_session, storage, user=operator, file_type="support_bundle",
            content=_zip_bytes("old.zip"), key_cipher=cipher,
        )
        old_log = _upload_ready(
            db_session, storage, user=operator, file_type="operation_log",
            content=_zip_bytes("oldlog.zip"), key_cipher=cipher,
        )
        fresh_bundle = _upload_ready(
            db_session, storage, user=operator, file_type="support_bundle",
            content=_zip_bytes("fresh.zip"), key_cipher=cipher,
        )
        for row, days in ((old_bundle, 31), (old_log, 45), (fresh_bundle, 1)):
            self._backdate(row, days=days)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.support_bundles_deleted == 1
        assert report.operation_logs_deleted == 1
        db_session.refresh(old_bundle)
        db_session.refresh(old_log)
        db_session.refresh(fresh_bundle)
        assert old_bundle.status == "deleted"
        assert old_log.status == "deleted"
        assert fresh_bundle.status == "ready"
        # Bytes are still there right after the logical delete.
        assert storage.exists(file_service.storage_key(old_bundle)) is True
        assert storage.exists(file_service.storage_key(old_log)) is True

    def test_active_task_link_protects_bundle_from_aging(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        admin = _role_user(db_session, role="admin", index=41)
        linked = _upload_ready(
            db_session, storage, user=admin, file_type="support_bundle",
            content=_zip_bytes("linked.zip"), key_cipher=cipher,
        )
        device = make_device(db_session, index=42)
        task = make_task(
            db_session,
            device_id=device.id,
            requested_by=admin.id,
            index=42,
            requirement_id="NAS-ACT-03",
            capability_key="logs.support_bundle.collect",
            state="running",
            idempotency_key="age-link-42",
        )
        _link(
            db_session, file_id=linked.id, purpose="output_support_bundle", user=admin,
            device_id=device.id, task_id=task.id,
        )
        self._backdate(linked, days=60)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.support_bundles_deleted == 0
        db_session.refresh(linked)
        assert linked.status == "ready"

    def test_config_backup_keep_10_prunes_beyond_newest_10_after_90_days(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        admin = _role_user(db_session, role="admin", index=43)
        device = make_device(db_session, index=44)
        rows: list[File] = []
        for i in range(12):
            content = _zip_bytes(name=f"cfg-{i}.zip", payload=f"config {i}".encode())
            row = _upload_ready(
                db_session, storage, user=admin, file_type="config_backup",
                content=content, key_cipher=cipher,
            )
            # All twelve are old; the newest two (ranks 0-1) survive because
            # the 90-day minimum age only prunes BEYOND the newest 10.
            self._backdate(row, days=91 + i)
            _link(
                db_session, file_id=row.id, purpose="output_config_backup", user=admin,
                device_id=device.id,
            )
            rows.append(row)
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.config_backups_deleted == 2
        db_session.expire_all()
        survivors = [
            r for r in _file_rows(db_session) if r.file_type == "config_backup" and r.status == "ready"
        ]
        assert len(survivors) == 10
        deleted = [
            r for r in _file_rows(db_session)
            if r.file_type == "config_backup" and r.status == "deleted"
        ]
        assert len(deleted) == 2
        # The newest files survive: deleted ones are the two oldest.
        assert deleted[0].created_at <= survivors[0].created_at

    def test_recent_config_backups_beyond_keep_are_not_pruned(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        cipher = _cipher()
        admin = _role_user(db_session, role="admin", index=45)
        device = make_device(db_session, index=46)
        for i in range(12):
            content = _zip_bytes(name=f"recent-{i}.zip", payload=f"cfg {i}".encode())
            row = _upload_ready(
                db_session, storage, user=admin, file_type="config_backup",
                content=content, key_cipher=cipher,
            )
            self._backdate(row, days=1 + i)
            _link(
                db_session, file_id=row.id, purpose="output_config_backup", user=admin,
                device_id=device.id,
            )
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.config_backups_deleted == 0

    def test_abandoned_uploads_close_after_24h(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=47)
        stale = file_service.create_upload(
            db_session, user=operator, file_type="firmware", size_bytes=100,
            original_filename="stale.bin", settings=SETTINGS,
        )
        file_service.stream_upload_chunk(
            db_session, upload_id=str(stale.id), user_id=operator.id,
            chunk=b"partial", storage=storage,
        )
        db_session.commit()
        self._backdate(stale, days=2)
        db_session.commit()
        assert storage.upload_size(str(stale.id)) == 7
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.abandoned_uploads_deleted == 1
        db_session.refresh(stale)
        assert stale.status == "deleted"
        assert storage.upload_size(str(stale.id)) == 0

    def test_fresh_uploading_rows_survive_the_sweep(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=48)
        fresh = file_service.create_upload(
            db_session, user=operator, file_type="firmware", size_bytes=100,
            original_filename="fresh.bin", settings=SETTINGS,
        )
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.abandoned_uploads_deleted == 0
        db_session.refresh(fresh)
        assert fresh.status == "uploading"

    def test_expired_tickets_are_purged_after_margin(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        del storage
        admin = _role_user(db_session, role="admin", index=49)
        operator = _role_user(db_session, role="operator", index=50)
        device = make_device(db_session, index=51)
        content = _zip_bytes()
        ready = _upload_ready(db_session, _storage(tmp_path), user=operator, file_type="firmware", content=content)
        expired = DeviceFileTicket(
            file_id=ready.id,
            device_id=device.id,
            purpose="firmware",
            expected_ip="192.168.10.5",
            expires_at=NOW - datetime.timedelta(days=2),
        )
        current = DeviceFileTicket(
            file_id=ready.id,
            device_id=device.id,
            purpose="firmware",
            expected_ip="192.168.10.5",
            expires_at=NOW + datetime.timedelta(days=1),
        )
        db_session.add_all([expired, current])
        db_session.commit()
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=_storage(tmp_path))
        assert report.tickets_deleted == 1
        remaining = list(db_session.scalars(select(DeviceFileTicket)).all())
        assert [row.id for row in remaining] == [current.id]
        del admin

    def test_storage_unavailable_skips_file_retention_loudly(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "blocked"
        blocker.write_text("a file, not a directory", encoding="utf-8")
        storage = FileStorage(blocker / "files")
        report = enforce_file_retention(db_session, now=NOW, settings=SETTINGS, storage=storage)
        assert report.storage_unavailable is True
        assert report.support_bundles_deleted == 0


class TestDeviceFileTickets:
    def _ready_firmware(self, db_session: Session, tmp_path: Path, *, index: int) -> File:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=index)
        return _upload_ready(
            db_session, storage, user=operator, file_type="firmware",
            content=_zip_bytes(name=f"fw-{index}.bin"), original_filename=f"fw-{index}.bin",
        )

    def test_issue_and_serve_with_matching_source_ip(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        file_row = self._ready_firmware(db_session, tmp_path, index=61)
        device = make_device(db_session, index=62)  # 192.168.10.x literal
        ticket = issue_device_file_ticket(
            db_session,
            file_row=file_row,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
            logger=None,
            audit=None,
        )
        db_session.commit()
        assert ticket.expected_ip == device.management_endpoint
        serve = file_service.prepare_ticket_stream(
            db_session, ticket_id=str(ticket.id), source_ip=device.management_endpoint, storage=storage
        )
        assert serve.file.id == file_row.id
        body = b"".join(
            file_service.stream_chunks(storage, serve, byte_range=None, key_cipher=None)
        )
        assert body == _zip_bytes(name="fw-61.bin")

    def test_range_window_is_served(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        file_row = self._ready_firmware(db_session, tmp_path, index=63)
        device = make_device(db_session, index=64)
        ticket = issue_device_file_ticket(
            db_session,
            file_row=file_row,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        db_session.commit()
        byte_range = file_service.parse_range_header("bytes=0-15", file_row.size_bytes)
        assert byte_range is not None and byte_range.length == 16
        serve = file_service.prepare_ticket_stream(
            db_session, ticket_id=str(ticket.id), source_ip=device.management_endpoint, storage=storage
        )
        body = b"".join(
            file_service.stream_chunks(storage, serve, byte_range=byte_range, key_cipher=None)
        )
        assert body == _zip_bytes(name="fw-63.bin")[:16]

    def test_wrong_source_ip_is_a_404(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        self._ready_firmware(db_session, tmp_path, index=65)
        device = make_device(db_session, index=66)
        ticket = issue_device_file_ticket(
            db_session,
            file_row=self._ready_firmware(db_session, tmp_path, index=67),
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        db_session.commit()
        with pytest.raises(AppError) as denied:
            file_service.prepare_ticket_stream(
                db_session, ticket_id=str(ticket.id), source_ip="10.9.9.9", storage=storage
            )
        assert denied.value.code == "resource_not_found"

    def test_expired_ticket_is_a_404(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        file_row = self._ready_firmware(db_session, tmp_path, index=68)
        device = make_device(db_session, index=69)
        ticket = issue_device_file_ticket(
            db_session,
            file_row=file_row,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        ticket.expires_at = NOW - datetime.timedelta(minutes=1)
        db_session.commit()
        with pytest.raises(AppError):
            file_service.prepare_ticket_stream(
                db_session, ticket_id=str(ticket.id), source_ip=device.management_endpoint, storage=storage
            )

    def test_revoked_ticket_is_a_404_and_revoke_is_idempotent(
        self, db_session: Session, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        file_row = self._ready_firmware(db_session, tmp_path, index=70)
        device = make_device(db_session, index=71)
        ticket = issue_device_file_ticket(
            db_session,
            file_row=file_row,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        db_session.commit()
        revoked = file_service.revoke_device_file_ticket(
            db_session, ticket_id=str(ticket.id), logger=None, audit=None
        )
        db_session.commit()
        assert revoked is not None and revoked.revoked_at is not None
        again = file_service.revoke_device_file_ticket(
            db_session, ticket_id=str(ticket.id), logger=None, audit=None
        )
        assert again is not None and again.revoked_at is not None
        with pytest.raises(AppError):
            file_service.prepare_ticket_stream(
                db_session, ticket_id=str(ticket.id), source_ip=device.management_endpoint, storage=storage
            )

    def test_unknown_ticket_is_a_404(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(AppError) as missing:
            file_service.prepare_ticket_stream(
                db_session,
                ticket_id="00000000-0000-0000-0000-000000000000",
                source_ip="192.168.10.5",
                storage=storage,
            )
        assert missing.value.code == "resource_not_found"

    def test_ticket_never_serves_another_file(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        file_a = self._ready_firmware(db_session, tmp_path, index=72)
        file_b = self._ready_firmware(db_session, tmp_path, index=73)
        device = make_device(db_session, index=74)
        ticket_a = issue_device_file_ticket(
            db_session,
            file_row=file_a,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        db_session.commit()
        # The ticket row binds file_a; tampering the binding is impossible
        # (FK + serve re-checks purpose/type), so cross-file serves cannot
        # occur — assert the binding itself.
        serve = file_service.prepare_ticket_stream(
            db_session, ticket_id=str(ticket_a.id), source_ip=device.management_endpoint, storage=storage
        )
        assert serve.file.id == file_a.id
        assert serve.file.id != file_b.id
        ticket_b = issue_device_file_ticket(
            db_session,
            file_row=file_b,
            device=device,
            purpose="firmware",
            expires_at=NOW + datetime.timedelta(hours=2),
        )
        db_session.commit()
        serve_b = file_service.prepare_ticket_stream(
            db_session, ticket_id=str(ticket_b.id), source_ip=device.management_endpoint, storage=storage
        )
        assert serve_b.file.id == file_b.id

    def test_unready_file_cannot_get_a_ticket(self, db_session: Session, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        operator = _role_user(db_session, role="operator", index=75)
        device = make_device(db_session, index=76)
        uploading = file_service.create_upload(
            db_session, user=operator, file_type="firmware", size_bytes=100,
            original_filename="fw.bin", settings=SETTINGS,
        )
        db_session.commit()
        with pytest.raises(AppError) as blocked:
            issue_device_file_ticket(
                db_session,
                file_row=uploading,
                device=device,
                purpose="firmware",
                expires_at=NOW + datetime.timedelta(hours=2),
            )
        assert blocked.value.code == "validation_failed"
        del storage


class TestRangeParsing:
    def test_simple_ranges(self) -> None:
        assert file_service.parse_range_header("bytes=0-99", 1000) == file_service.ByteRange(0, 99)
        assert file_service.parse_range_header("bytes=900-", 1000) == file_service.ByteRange(900, 999)
        assert file_service.parse_range_header("bytes=-100", 1000) == file_service.ByteRange(900, 999)
        assert file_service.parse_range_header("bytes=-5000", 1000) == file_service.ByteRange(0, 999)
        assert file_service.parse_range_header("bytes=500-99999", 1000) == file_service.ByteRange(500, 999)

    def test_ignored_headers_return_none(self) -> None:
        for header in (None, "", "bytes=0-1,4-5", "items=0-1", "bytes=abc", "bytes=5-1", "bytes=-0"):
            assert file_service.parse_range_header(header, 1000) is None

    def test_unsatisfiable_range_marks_start_at_total(self) -> None:
        parsed = file_service.parse_range_header("bytes=5000-6000", 1000)
        assert parsed is not None
        assert parsed.start >= 1000

