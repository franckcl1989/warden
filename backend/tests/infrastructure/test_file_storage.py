"""File storage infrastructure tests: streaming writes, quotas, envelopes.

docs/SECURITY.md §9 (存储名只由内容散列/内部标识生成, 禁止路径拼接和符号链接,
流式上传配额在写入前检查), ARCHITECTURE.md §3.6 (受控文件存储). Pure file-
system tests (no PostgreSQL): hash-and-shard layout, quota abort leaves no
residue, traversal-proof name handling, the AES-GCM on-disk envelope
round-trip, tamper detection and bounded chunk streaming.
"""

from __future__ import annotations

import datetime
import hashlib
from pathlib import Path

import pytest
from app.domain.uuid7 import uuid7
from app.infrastructure.crypto import FileKeyCipher
from app.infrastructure.files import (
    CONTENT_CHUNK_SIZE,
    ENVELOPE_MAGIC,
    GCM_TAG_BYTES,
    FileCorruptionError,
    FileStorage,
    FileStorageError,
    QuotaExceededError,
    StoredFile,
)

KEY_MATERIAL = b"F" * 64

UPLOAD_ID = str(uuid7())
STORAGE_KEY = "a" * 64


def _storage(tmp_path: Path) -> FileStorage:
    storage = FileStorage(tmp_path / "files")
    storage.check_available()
    return storage


def _cipher() -> FileKeyCipher:
    return FileKeyCipher(KEY_MATERIAL)


def _upload_bytes(storage: FileStorage, payload: bytes, *, declared: int | None = None) -> None:
    _spool_bytes(storage, UPLOAD_ID, payload, declared=declared)


def _spool_bytes(
    storage: FileStorage, upload_id: str, payload: bytes, *, declared: int | None = None
) -> None:
    limit = declared if declared is not None else len(payload)
    step = 8191  # non-round chunking still exercises the multi-chunk path
    for start in range(0, len(payload), step):
        storage.write_upload_chunk(upload_id, payload[start : start + step], declared_size=limit)


def _multichunk_encrypted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FileStorage, bytes, StoredFile]:
    """A 4-chunk + tail encrypted file whose envelope payload chunks are 4096 B.

    Patching the module chunk size makes multi-chunk envelopes cheap; the
    envelope header records the chunk size, so reads are independent of the
    current global.
    """
    monkeypatch.setattr("app.infrastructure.files.CONTENT_CHUNK_SIZE", 4096)
    storage = _storage(tmp_path)
    payload = (bytes(range(251)) * 200)[: 4096 * 4 + 1234]
    _spool_bytes(storage, UPLOAD_ID, payload)
    return storage, payload, storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())


class TestStreamingWrites:
    def test_chunked_write_then_plain_finalize_round_trips(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = bytes(range(256)) * 40
        _upload_bytes(storage, payload)
        assert storage.upload_size(UPLOAD_ID) == len(payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        assert stored.encrypted is False
        assert stored.size_bytes == len(payload)
        assert stored.key_version is None
        assert storage.exists(STORAGE_KEY)
        assert b"".join(storage.open_chunks(stored, key_cipher=None)) == payload

    def test_final_file_lives_in_two_char_shard_and_content_matches(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"sharded-bytes" * 100
        key = hashlib.sha256(payload).hexdigest()
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, key, key_cipher=None)
        shard = tmp_path / "files" / "data" / key[:2]
        candidates = list(shard.iterdir())
        assert [candidate.name for candidate in candidates] == [key]
        assert candidates[0].read_bytes() == payload
        assert stored.size_bytes == len(payload)

    def test_upload_tmp_is_removed_after_finalize(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"x" * 100)
        storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        assert storage.upload_size(UPLOAD_ID) == 0

    def test_upload_without_chunks_cannot_finalize(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(FileStorageError):
            storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)

    def test_remove_upload_cleans_everything(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"y" * 64)
        storage.remove_upload(UPLOAD_ID)
        assert storage.upload_size(UPLOAD_ID) == 0
        tmp_dir = tmp_path / "files" / "tmp"
        assert list(tmp_dir.iterdir()) == []
        data_dir = tmp_path / "files" / "data"
        assert list(data_dir.iterdir()) == []


class TestQuotaAbort:
    def test_chunk_past_declared_size_is_rejected_and_writes_nothing(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"abc")
        with pytest.raises(QuotaExceededError):
            storage.write_upload_chunk(UPLOAD_ID, b"0123456789", declared_size=3)
        assert storage.upload_size(UPLOAD_ID) == 3
        data_dir = tmp_path / "files" / "data"
        assert list(data_dir.iterdir()) == []

    def test_quota_abort_residue_free_after_remove(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(QuotaExceededError):
            storage.write_upload_chunk(UPLOAD_ID, b"big" * 10, declared_size=5)
        storage.remove_upload(UPLOAD_ID)
        assert list((tmp_path / "files" / "tmp").iterdir()) == []
        assert list((tmp_path / "files" / "data").iterdir()) == []

    def test_aborted_upload_cannot_finalize(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.write_upload_chunk(UPLOAD_ID, b"ok", declared_size=2)
        with pytest.raises(QuotaExceededError):
            storage.write_upload_chunk(UPLOAD_ID, b"more", declared_size=2)
        storage.remove_upload(UPLOAD_ID)
        with pytest.raises(FileStorageError):
            storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)


class TestNameHardening:
    """Storage keys are derived (sha256 / internal ids) — never user input."""

    BAD_KEYS = (
        "../../etc/passwd",
        "..\\..\\evil",
        "abc",
        "ZZ",
        "not-a-hash",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "a" * 64 + "/../b" * 8,
        "",
        "PK\x03\x04" + "x" * 60,
    )

    @pytest.mark.parametrize("key", BAD_KEYS)
    def test_hostile_storage_keys_are_rejected(self, tmp_path: Path, key: str) -> None:
        storage = _storage(tmp_path)
        for call in (storage.exists, storage.delete):
            with pytest.raises(FileStorageError):
                call(key)
        with pytest.raises(FileStorageError):
            storage.store_final(UPLOAD_ID, key, key_cipher=None)

    @pytest.mark.parametrize("key", BAD_KEYS)
    def test_hostile_upload_ids_are_rejected(self, tmp_path: Path, key: str) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(FileStorageError):
            storage.write_upload_chunk(key, b"x", declared_size=1)
        with pytest.raises(FileStorageError):
            storage.remove_upload(key)

    def test_sha256_with_encrypted_row_suffix_is_accepted(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        key = STORAGE_KEY + "-" + str(uuid7())
        _upload_bytes(storage, b"enc" * 50)
        stored = storage.store_final(UPLOAD_ID, key, key_cipher=_cipher())
        assert stored.encrypted is True
        assert b"".join(storage.open_chunks(stored, key_cipher=_cipher())) == b"enc" * 50

    def test_storage_delete_only_removes_its_own_file(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        other_id = str(uuid7())
        _upload_bytes(storage, b"keep-me")
        storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        other = b"other-content"
        for start in range(0, len(other), 3):
            storage.write_upload_chunk(other_id, other[start : start + 3], declared_size=len(other))
        other_key = hashlib.sha256(other).hexdigest()
        storage.store_final(other_id, other_key, key_cipher=None)
        assert storage.delete(STORAGE_KEY) is True
        assert storage.delete(STORAGE_KEY) is False
        assert storage.exists(other_key) is True

    def test_stale_tmp_uploads_are_removed_by_age(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        fresh_id = str(uuid7())
        storage.write_upload_chunk(fresh_id, b"fresh", declared_size=5)
        stale_id = str(uuid7())
        storage.write_upload_chunk(stale_id, b"stale", declared_size=5)
        stale_path = tmp_path / "files" / "tmp" / stale_id
        old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2)
        stale_path.touch()
        import os
        os.utime(stale_path, (old.timestamp(), old.timestamp()))
        removed = storage.delete_stale_uploads(
            cutoff=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        )
        assert removed == 1
        assert storage.upload_size(fresh_id) == 5
        assert storage.upload_size(stale_id) == 0


class TestEnvelope:
    def test_encrypted_bytes_differ_from_plaintext_and_carry_envelope(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"secret support bundle payload " * 1000
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        assert stored.encrypted is True
        assert stored.size_bytes == len(payload)
        assert stored.key_version == 1
        on_disk = (tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY).read_bytes()
        assert on_disk != payload
        assert payload not in on_disk
        assert on_disk.startswith(ENVELOPE_MAGIC)
        assert b"".join(storage.open_chunks(stored, key_cipher=_cipher())) == payload

    def test_large_payload_round_trips_across_many_chunks(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        base = bytes(range(251))
        payload = base * ((CONTENT_CHUNK_SIZE * 3) // 251 + 2)
        assert len(payload) > CONTENT_CHUNK_SIZE * 3
        for start in range(0, len(payload), 65521):
            storage.write_upload_chunk(
                UPLOAD_ID, payload[start : start + 65521], declared_size=len(payload)
            )
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        assert b"".join(storage.open_chunks(stored, key_cipher=_cipher())) == payload

    def test_wrong_master_key_fails_to_unwrap(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"payload " * 100)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        wrong = FileKeyCipher(b"E" * 64)
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=wrong))

    def test_missing_cipher_for_encrypted_file_is_refused(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"payload " * 100)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        with pytest.raises(FileStorageError):
            list(storage.open_chunks(stored, key_cipher=None))

    def test_tampered_payload_chunk_fails_authentication(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"tamper-me " * 300_000
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        path = tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY
        raw = bytearray(path.read_bytes())
        # Flip one bit in the middle of the first payload chunk region.
        raw[len(raw) // 2] ^= 0x01
        path.write_bytes(bytes(raw))
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=_cipher()))

    def test_tampered_header_is_detected(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"payload " * 100)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        path = tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY
        raw = bytearray(path.read_bytes())
        raw[0] ^= 0xFF
        path.write_bytes(bytes(raw))
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=_cipher()))

    def test_truncated_envelope_is_detected_at_eof(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"truncate-me " * 300_000
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        path = tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY
        raw = path.read_bytes()
        path.write_bytes(raw[: len(raw) - 5])
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=_cipher()))

    def test_plain_file_opened_as_encrypted_is_rejected(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"plain" * 100
        _upload_bytes(storage, payload)
        storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        # A plain file on disk forced into the encrypted reader (metadata
        # says encrypted but the volume holds raw bytes) must fail loudly.
        mislabeled = StoredFile(
            storage_key=STORAGE_KEY, encrypted=True, size_bytes=len(payload), key_version=1
        )
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(mislabeled, key_cipher=_cipher()))

    def test_appended_garbage_is_detected(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"payload " * 10
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        path = tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY
        with path.open("ab") as handle:
            handle.write(b"garbage-at-eof")
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=_cipher()))


class TestBoundedStreaming:
    def test_chunks_are_bounded(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = b"z" * (CONTENT_CHUNK_SIZE * 2 + 13)
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        assert all(len(chunk) <= CONTENT_CHUNK_SIZE for chunk in storage.open_chunks(stored, key_cipher=None))

    def test_range_read_returns_only_the_requested_window(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = bytes(range(256)) * 100
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        for start, end in ((0, 1), (1000, 2000), (len(payload) - 5, len(payload) - 1)):
            window = b"".join(
                storage.open_chunks(stored, key_cipher=None, start=start, limit=end - start + 1)
            )
            assert window == payload[start : end + 1]

    def test_encrypted_range_read_returns_only_the_requested_window(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = bytes(range(256)) * 5000
        _upload_bytes(storage, payload)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=_cipher())
        window = b"".join(
            storage.open_chunks(stored, key_cipher=_cipher(), start=1_000_000, limit=200_000)
        )
        assert window == payload[1_000_000 : 1_200_000]

    def test_out_of_bounds_range_is_rejected(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"x" * 100)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        for start, limit in ((-1, 10), (100, 1), (50, 100)):
            with pytest.raises(FileStorageError):
                list(storage.open_chunks(stored, key_cipher=None, start=start, limit=limit))


class TestEnvelopeWindows:
    """Regression (M2T5 review): windowed reads of ENCRYPTED files must end
    cleanly at the window edge.

    The old reader kept decrypting one chunk past the window and then raised
    FileCorruptionError (decrypted total != metadata size) whenever the file
    had data beyond the window — a mid-stream failure after 206 headers.
    """

    def test_window_ending_on_a_chunk_boundary_serves_exact_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage, payload, stored = _multichunk_encrypted(tmp_path, monkeypatch)
        for start, limit in ((0, 4096), (4096, 4096), (8192, 4096)):
            window = b"".join(
                storage.open_chunks(stored, key_cipher=_cipher(), start=start, limit=limit)
            )
            assert window == payload[start : start + limit]

    def test_window_ending_mid_chunk_serves_exact_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage, payload, stored = _multichunk_encrypted(tmp_path, monkeypatch)
        for start, limit in ((6000, 1000), (4096, 2048), (0, 4096 + 100)):
            window = b"".join(
                storage.open_chunks(stored, key_cipher=_cipher(), start=start, limit=limit)
            )
            assert window == payload[start : start + limit]

    def test_full_read_still_verifies_the_decrypted_total(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage, payload, stored = _multichunk_encrypted(tmp_path, monkeypatch)
        assert b"".join(storage.open_chunks(stored, key_cipher=_cipher())) == payload
        # A file truncated exactly at a chunk boundary must still fail a FULL
        # pass (the total-length cross-check stays on full reads).
        path = tmp_path / "files" / "data" / STORAGE_KEY[:2] / STORAGE_KEY
        path.write_bytes(path.read_bytes()[: -(1234 + GCM_TAG_BYTES)])
        with pytest.raises(FileCorruptionError):
            list(storage.open_chunks(stored, key_cipher=_cipher()))
        # A window fully inside the surviving chunks still serves.
        window = b"".join(
            storage.open_chunks(stored, key_cipher=_cipher(), start=0, limit=4096)
        )
        assert window == payload[:4096]


class TestIncrementalDigest:
    """The spool SHA-256 accumulates while chunks stream (no full re-read at
    complete); the in-memory state is per storage instance (a process restart
    loses it and the caller falls back to a re-read)."""

    def test_digest_accumulates_across_chunked_writes(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = bytes(range(256)) * 1000
        _upload_bytes(storage, payload)
        assert storage.upload_digest(UPLOAD_ID) == hashlib.sha256(payload).hexdigest()

    def test_digest_follows_the_spool_lifecycle(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"x" * 512)
        assert storage.upload_digest(UPLOAD_ID) is not None
        storage.remove_upload(UPLOAD_ID)
        assert storage.upload_digest(UPLOAD_ID) is None
        _upload_bytes(storage, b"y" * 512)
        stored = storage.store_final(UPLOAD_ID, STORAGE_KEY, key_cipher=None)
        assert stored.size_bytes == 512
        assert storage.upload_digest(UPLOAD_ID) is None

    def test_digest_state_is_lost_on_a_fresh_instance(self, tmp_path: Path) -> None:
        first = _storage(tmp_path)
        payload = b"z" * 777
        _upload_bytes(first, payload)
        # A second instance over the same root has no in-memory digest state
        # (the process-restart case): it must report unknown so the caller
        # falls back to a spool re-read instead of trusting stale state.
        second = _storage(tmp_path)
        assert second.upload_digest(UPLOAD_ID) is None
        assert first.upload_digest(UPLOAD_ID) == hashlib.sha256(payload).hexdigest()

    def test_digest_ignores_rejected_quota_writes(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        _upload_bytes(storage, b"abc", declared=3)
        with pytest.raises(QuotaExceededError):
            storage.write_upload_chunk(UPLOAD_ID, b"more", declared_size=3)
        assert storage.upload_digest(UPLOAD_ID) == hashlib.sha256(b"abc").hexdigest()


class TestReadHead:
    def test_read_head_returns_only_the_requested_prefix(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        payload = bytes(range(256)) * 100
        _upload_bytes(storage, payload)
        assert storage.read_head(UPLOAD_ID, 17) == payload[:17]
        assert storage.read_head(UPLOAD_ID, 4096) == payload[:4096]
        # A request larger than the spool returns the whole file, never raises.
        assert storage.read_head(UPLOAD_ID, 10**9) == payload

    def test_read_head_missing_upload_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(FileStorageError):
            storage.read_head(UPLOAD_ID, 10)


class TestAtomicFinalize:
    """Regression (M2T5 review): finalizing over a shared content-addressed
    key must never truncate a live ready file — writes go to a temp + atomic
    rename, and an existing target is dedup-skipped (identical by hash
    construction) or refused (size anomaly) instead of being overwritten."""

    def test_duplicate_plain_finalize_skips_copy_and_consumes_both_spools(
        self, tmp_path: Path
    ) -> None:
        storage = _storage(tmp_path)
        payload = b"dup-content" * 5000
        key = hashlib.sha256(payload).hexdigest()
        first, second = str(uuid7()), str(uuid7())
        _spool_bytes(storage, first, payload)
        _spool_bytes(storage, second, payload)
        first_stored = storage.store_final(first, key, key_cipher=None)
        second_stored = storage.store_final(second, key, key_cipher=None)
        assert first_stored.size_bytes == second_stored.size_bytes == len(payload)
        target = tmp_path / "files" / "data" / key[:2] / key
        assert target.read_bytes() == payload
        assert storage.upload_size(first) == 0
        assert storage.upload_size(second) == 0

    def test_finalize_never_truncates_an_existing_ready_file(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        key = "b" * 64
        ready_bytes = b"ready-bytes-" * 10
        ready_id = str(uuid7())
        _spool_bytes(storage, ready_id, ready_bytes)
        storage.store_final(ready_id, key, key_cipher=None)
        assert storage.exists(key)
        # A second spool claiming the same key with a DIFFERENT size is an
        # integrity anomaly: fail fast and leave the ready bytes untouched.
        hostile = str(uuid7())
        _spool_bytes(storage, hostile, b"other-size-" * 20)
        with pytest.raises(FileStorageError):
            storage.store_final(hostile, key, key_cipher=None)
        target = tmp_path / "files" / "data" / key[:2] / key
        assert target.read_bytes() == ready_bytes

    def test_finalize_leaves_no_temp_residue(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        tmp_dir = tmp_path / "files" / "tmp"
        for _ in range(2):
            upload_id = str(uuid7())
            _spool_bytes(storage, upload_id, b"enc-finalize" * 500)
            storage.store_final(upload_id, STORAGE_KEY + "-" + str(uuid7()), key_cipher=_cipher())
        assert list(tmp_dir.iterdir()) == []

    def test_stale_finalize_residue_is_removed_by_age(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        residue = tmp_path / "files" / "tmp" / ("finalize-" + "ab" * 16)
        residue.write_bytes(b"partial")
        old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2)
        import os

        os.utime(residue, (old.timestamp(), old.timestamp()))
        removed = storage.delete_stale_uploads(
            cutoff=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        )
        assert removed == 1
        assert not residue.exists()
