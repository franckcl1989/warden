"""Controlled file storage over a local volume (docs/SECURITY.md §9, M2T5).

Layout (the storage root is deployment configuration — ``file_store_root``,
default ``.warden-data/files`` in dev; production mounts a persistent volume):

    <root>/tmp/<upload-uuid>            in-progress upload spool (single file)
    <root>/data/<xy>/<storage_key>      final files sharded by key's first 2 hex

Storage keys are NEVER derived from user input (SECURITY.md §9: 上传文件名只作
显示, 存储名由内容散列/内部标识生成; 禁止路径拼接): plain files use the content
SHA-256 hex; encrypted files use ``<content-sha256>-<file-row-uuid>`` because
AES-GCM randomization means two identical plaintexts produce different
ciphertexts, so each row needs its own physical file. The application layer
derives the key from the row (``application/files.py::storage_key``); this
module validates the key charset before touching any path.

Encryption (sensitive types only — support bundles/config backups/operation
logs; firmware/ISO stay plain but content-hash-named and volume-private —
ARCHITECTURE.md §3.6):

- each file gets a fresh random 32-byte content key, AES-256-GCM encrypted in
  1 MiB chunks with nonce = random-4-byte prefix || 8-byte big-endian chunk
  index (unique per chunk, no counter reuse across files);
- the content key itself is wrapped by the file master key
  (``infrastructure.crypto.FileKeyCipher``, key material from the read-only
  ``file_master_key_file`` secret; AAD binds the wrap to its storage name);
- the on-disk envelope (all integers unsigned big-endian, documented format
  version 1):

      offset  size  field
      0       4     magic b"WDN1"
      4       1     envelope version = 1
      5       4     master key_version that wrapped the content key
      9       4     wrap nonce length (12)
      13      12    wrap nonce
      25      2     wrapped content-key length (48 for a 32-byte key)
      27      L     wrapped content key (AES-GCM ciphertext + tag)
      27+L    4     plaintext chunk size (1 MiB)
      31+L    4     random nonce prefix
      35+L    ...   payload: per chunk AES-GCM(nonce||index).encrypt(chunk)

  Decryption verifies every chunk tag and the total plaintext length against
  the logical size recorded in the files row (truncation at a chunk boundary
  is therefore detected too). Memory stays bounded: one chunk in flight.

Quotas: ``write_upload_chunk`` enforces the declared size BEFORE writing —
a chunk that would exceed the declaration is rejected and nothing is written
(SECURITY.md §9: 流式上传并在写入前检查配额). The declared size itself was
validated against the type quota at session creation (settings only).
"""

from __future__ import annotations

import datetime
import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.infrastructure.crypto import DecryptionError, EncryptedSecret, FileKeyCipher

ENVELOPE_MAGIC = b"WDN1"
ENVELOPE_VERSION = 1
# Content key: 32 random bytes per file (AES-256-GCM).
FILE_KEY_BYTES = 32
# Plaintext chunk size for the chunked AEAD payload.
CONTENT_CHUNK_SIZE = 1024 * 1024
# Sanity ceiling for the chunk_size header field (16 MiB): protects the
# reader from a hostile envelope claiming an absurd chunk length.
MAX_CHUNK_SIZE = 16 * 1024 * 1024
NONCE_PREFIX_BYTES = 4
CHUNK_INDEX_BYTES = 8
GCM_TAG_BYTES = 16

_UPLOAD_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_STORAGE_KEY_PATTERN = re.compile(
    r"^[0-9a-f]{64}(-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$"
)


class FileStorageError(RuntimeError):
    """Storage-level failure (mapped to ``storage_unavailable`` at the boundary)."""


class QuotaExceededError(FileStorageError):
    """A chunk would exceed the declared upload size (abort, nothing written)."""


class FileCorruptionError(FileStorageError):
    """The stored file failed integrity checks (bad envelope, tamper, truncation)."""


@dataclass(frozen=True)
class StoredFile:
    """A finalized file's identity + storage facts (mirrors the files row).

    ``size_bytes`` is the LOGICAL (plaintext) size — downloads and range
    responses are sized against it, never against the on-disk byte count
    (which includes envelope overhead for encrypted files).
    """

    storage_key: str
    encrypted: bool
    size_bytes: int
    key_version: int | None


def _validate_upload_id(upload_id: str) -> None:
    if _UPLOAD_ID_PATTERN.fullmatch(upload_id) is None:
        raise FileStorageError(f"invalid upload id: {upload_id!r}")


def _validate_storage_key(storage_key: str) -> None:
    if _STORAGE_KEY_PATTERN.fullmatch(storage_key) is None:
        raise FileStorageError(f"invalid storage key: {storage_key!r}")


class FileStorage:
    """Hash-addressed local volume with spooled streaming uploads."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    @property
    def root(self) -> Path:
        return self._root

    def check_available(self) -> None:
        """Create the root/tmp/data directories; raise when the volume is unusable."""
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            (self._root / "tmp").mkdir(parents=True, exist_ok=True)
            (self._root / "data").mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise FileStorageError(f"file volume unavailable: {exc}") from exc

    def _tmp_path(self, upload_id: str) -> Path:
        _validate_upload_id(upload_id)
        return self._root / "tmp" / upload_id

    def _data_path(self, storage_key: str) -> Path:
        _validate_storage_key(storage_key)
        return self._root / "data" / storage_key[:2] / storage_key

    def write_upload_chunk(self, upload_id: str, chunk: bytes, *, declared_size: int) -> None:
        """Append one chunk of the spooled upload; quota checked BEFORE writing."""
        if not chunk:
            return
        target = self._tmp_path(upload_id)
        current = target.stat().st_size if target.exists() else 0
        if current + len(chunk) > declared_size:
            raise QuotaExceededError(
                f"upload would exceed declared size {declared_size} (at {current})"
            )
        try:
            with target.open("ab") as handle:
                handle.write(chunk)
                handle.flush()
        except OSError as exc:
            raise FileStorageError(f"upload write failed: {exc}") from exc

    def upload_size(self, upload_id: str) -> int:
        """Bytes currently spooled for the upload (0 when absent/empty)."""
        target = self._tmp_path(upload_id)
        if not target.exists():
            return 0
        return target.stat().st_size

    def remove_upload(self, upload_id: str) -> None:
        """Drop the spooled upload (abort/oversize/abandoned sessions)."""
        try:
            self._tmp_path(upload_id).unlink(missing_ok=True)
        except OSError as exc:
            raise FileStorageError(f"upload removal failed: {exc}") from exc

    def read_upload_chunks(self, upload_id: str) -> Iterator[bytes]:
        """Bounded reads of the spooled upload (hashing/sniffing at complete)."""
        source = self._tmp_path(upload_id)
        if not source.exists():
            raise FileStorageError(f"upload has no spooled content: {upload_id}")
        try:
            with source.open("rb") as handle:
                while True:
                    data = handle.read(CONTENT_CHUNK_SIZE)
                    if not data:
                        return
                    yield data
        except OSError as exc:
            raise FileStorageError(f"upload read failed: {exc}") from exc

    def store_final(
        self,
        upload_id: str,
        storage_key: str,
        *,
        key_cipher: FileKeyCipher | None,
    ) -> StoredFile:
        """Move the spooled upload to its final sharded path.

        ``key_cipher=None`` stores the raw bytes (firmware/ISO: plain on
        disk, content-hash-named, volume-private — ARCHITECTURE.md §3.6);
        a cipher encrypts the envelope described in the module docstring.
        The spool file is consumed on success.
        """
        _validate_storage_key(storage_key)
        source = self._tmp_path(upload_id)
        if not source.exists():
            raise FileStorageError(f"upload has no spooled content: {upload_id}")
        plaintext_size = source.stat().st_size
        target = self._data_path(storage_key)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if key_cipher is None:
                _copy_plain(source, target)
                key_version: int | None = None
            else:
                key_version = _write_envelope(source, target, key_cipher=key_cipher)
        except FileStorageError:
            raise
        except OSError as exc:
            target.unlink(missing_ok=True)
            raise FileStorageError(f"finalize failed: {exc}") from exc
        try:
            source.unlink(missing_ok=True)
        except OSError as exc:
            raise FileStorageError(f"spool cleanup failed: {exc}") from exc
        return StoredFile(
            storage_key=storage_key,
            encrypted=key_cipher is not None,
            size_bytes=plaintext_size,
            key_version=key_version,
        )

    def exists(self, storage_key: str) -> bool:
        _validate_storage_key(storage_key)
        return self._data_path(storage_key).exists()

    def delete(self, storage_key: str) -> bool:
        """Remove one physical file; returns True when a file was removed.

        Callers (retention/physical cleanup) are responsible for the
        reference checks — this only touches the volume.
        """
        _validate_storage_key(storage_key)
        target = self._data_path(storage_key)
        if not target.exists():
            return False
        try:
            target.unlink()
        except OSError as exc:
            raise FileStorageError(f"physical delete failed: {exc}") from exc
        return True

    def delete_stale_uploads(self, *, cutoff: datetime.datetime) -> int:
        """Remove abandoned spool files older than ``cutoff`` (mtime); count.

        Used by the retention sweep for upload sessions that never finished
        (client vanished mid-stream) — the files row side is handled by
        ``application/maintenance.py``.
        """
        removed = 0
        tmp_dir = self._root / "tmp"
        if not tmp_dir.exists():
            return 0
        cutoff_ts = cutoff.timestamp()
        for entry in tmp_dir.iterdir():
            if not entry.is_file() or _UPLOAD_ID_PATTERN.fullmatch(entry.name) is None:
                continue
            try:
                if entry.stat().st_mtime < cutoff_ts:
                    entry.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def open_chunks(
        self,
        stored: StoredFile,
        *,
        key_cipher: FileKeyCipher | None,
        start: int = 0,
        limit: int | None = None,
    ) -> Iterator[bytes]:
        """Stream ``stored`` in bounded chunks, optionally a byte window.

        ``start`` inclusive; ``limit`` = number of bytes (HTTP Range end is
        converted by the caller to ``limit = end - start + 1``). Encrypted
        files authenticate every chunk they are read through (the reader is a
        full sequential pass; plain files seek directly). Ranges are bounds
        checked against the LOGICAL size.
        """
        if not 0 <= start <= stored.size_bytes:
            raise FileStorageError(f"range start {start} outside size {stored.size_bytes}")
        if limit is not None and (limit < 0 or start + limit > stored.size_bytes):
            raise FileStorageError(f"range start+limit {start}+{limit} exceeds size {stored.size_bytes}")
        if stored.encrypted:
            if key_cipher is None:
                raise FileStorageError("encrypted file opened without a file key cipher")
            return _envelope_chunks(
                self._data_path(stored.storage_key),
                stored=stored,
                key_cipher=key_cipher,
                start=start,
                limit=limit,
            )
        return _plain_chunks(self._data_path(stored.storage_key), stored=stored, start=start, limit=limit)

    def probe_read(self, stored: StoredFile, *, key_cipher: FileKeyCipher | None) -> None:
        """Eager integrity probe BEFORE a response starts streaming.

        Plain files: disk size parity with the metadata. Encrypted files:
        envelope header parse + master-key unwrap (verifies the wrap tag) —
        so a missing/corrupt volume copy surfaces as a clean error instead
        of a connection killed mid-stream. Payload chunks are still
        authenticated during streaming.
        """
        path = self._data_path(stored.storage_key)
        try:
            if not path.exists():
                raise FileStorageError(f"stored file missing: {stored.storage_key}")
            if stored.encrypted:
                if key_cipher is None:
                    raise FileStorageError("encrypted file opened without a file key cipher")
                with path.open("rb") as handle:
                    _read_header(handle, key_cipher=key_cipher, storage_key=stored.storage_key)
            elif path.stat().st_size != stored.size_bytes:
                raise FileStorageError(
                    f"stored file size mismatch for {stored.storage_key}"
                )
        except FileCorruptionError:
            raise
        except OSError as exc:
            raise FileStorageError(f"stored probe failed: {exc}") from exc


def _copy_plain(source: Path, target: Path) -> None:
    with source.open("rb") as src, target.open("wb") as dst:
        while True:
            data = src.read(CONTENT_CHUNK_SIZE)
            if not data:
                break
            dst.write(data)
        dst.flush()


def _chunk_nonce(nonce_prefix: bytes, index: int) -> bytes:
    return nonce_prefix + index.to_bytes(CHUNK_INDEX_BYTES, "big")


def _write_envelope(source: Path, target: Path, *, key_cipher: FileKeyCipher) -> int:
    """Write the encrypted envelope (module docstring format) and stream the
    spooled upload through the chunked AEAD. Returns the master key_version."""
    file_key = secrets.token_bytes(FILE_KEY_BYTES)
    wrapped = key_cipher.wrap(file_key, storage_name=target.name)
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_BYTES)
    header = b"".join(
        (
            ENVELOPE_MAGIC,
            bytes([ENVELOPE_VERSION]),
            wrapped.key_version.to_bytes(4, "big"),
            len(wrapped.nonce).to_bytes(4, "big"),
            wrapped.nonce,
            len(wrapped.ciphertext).to_bytes(2, "big"),
            wrapped.ciphertext,
            CONTENT_CHUNK_SIZE.to_bytes(4, "big"),
            nonce_prefix,
        )
    )
    try:
        aesgcm = AESGCM(file_key)
        with source.open("rb") as src, target.open("wb") as dst:
            dst.write(header)
            index = 0
            while True:
                chunk = src.read(CONTENT_CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(aesgcm.encrypt(_chunk_nonce(nonce_prefix, index), chunk, None))
                index += 1
            dst.flush()
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise FileStorageError(f"envelope write failed: {exc}") from exc
    return wrapped.key_version


def _plain_chunks(path: Path, *, stored: StoredFile, start: int, limit: int | None) -> Iterator[bytes]:
    try:
        disk_size = path.stat().st_size
        if disk_size != stored.size_bytes:
            raise FileStorageError(
                f"stored file size {disk_size} != metadata size {stored.size_bytes}"
            )
        remaining = stored.size_bytes - start if limit is None else limit
        with path.open("rb") as handle:
            if start:
                handle.seek(start)
            while remaining > 0:
                data = handle.read(min(CONTENT_CHUNK_SIZE, remaining))
                if not data:
                    raise FileStorageError("stored file shorter than metadata")
                remaining -= len(data)
                yield data
    except OSError as exc:
        raise FileStorageError(f"stored read failed: {exc}") from exc


def _read_header(
    handle: BinaryIO, key_cipher: FileKeyCipher, storage_key: str
) -> tuple[bytes, AESGCM, int]:
    """Read + validate the envelope header from an open handle.

    Returns (nonce_prefix, file-key AESGCM, chunk_size) with the handle left
    at the first payload chunk. Raises FileCorruptionError on any deviation.
    """
    magic = handle.read(len(ENVELOPE_MAGIC))
    if magic != ENVELOPE_MAGIC:
        raise FileCorruptionError("envelope magic mismatch (not a WDN1 file)")
    version_bytes = handle.read(1)
    if len(version_bytes) != 1 or version_bytes[0] != ENVELOPE_VERSION:
        raise FileCorruptionError(f"unsupported envelope version: {version_bytes!r}")
    key_version = int.from_bytes(handle.read(4), "big")
    nonce_len = int.from_bytes(handle.read(4), "big")
    wrap_nonce = handle.read(nonce_len) if 0 < nonce_len <= 64 else None
    wrapped_len = int.from_bytes(handle.read(2), "big")
    if wrap_nonce is None or len(wrap_nonce) != nonce_len:
        raise FileCorruptionError("invalid wrap nonce length")
    wrapped_ct = handle.read(wrapped_len) if 0 < wrapped_len <= 4096 else None
    if wrapped_ct is None or len(wrapped_ct) != wrapped_len:
        raise FileCorruptionError("invalid wrapped key length")
    chunk_size = int.from_bytes(handle.read(4), "big")
    if not 0 < chunk_size <= MAX_CHUNK_SIZE:
        raise FileCorruptionError(f"invalid chunk size: {chunk_size}")
    nonce_prefix = handle.read(NONCE_PREFIX_BYTES)
    if len(nonce_prefix) != NONCE_PREFIX_BYTES:
        raise FileCorruptionError("truncated envelope header")
    wrapped = EncryptedSecret(ciphertext=wrapped_ct, nonce=wrap_nonce, key_version=key_version)
    try:
        file_key = key_cipher.unwrap(wrapped, storage_name=storage_key)
    except DecryptionError as exc:
        raise FileCorruptionError("envelope unwrap failed (wrong master key or tamper)") from exc
    return nonce_prefix, AESGCM(file_key), chunk_size


def _envelope_chunks(
    path: Path,
    *,
    stored: StoredFile,
    key_cipher: FileKeyCipher,
    start: int,
    limit: int | None,
) -> Iterator[bytes]:
    """Sequential envelope reader: every chunk through the window is
    authenticated, and the decrypted total must match the metadata size
    (truncation at a chunk boundary cannot hide)."""
    try:
        with path.open("rb") as handle:
            nonce_prefix, aesgcm, chunk_size = _read_header(
                handle, key_cipher, storage_key=stored.storage_key
            )
            window_end = stored.size_bytes if limit is None else start + limit
            position = 0
            total = 0
            index = 0
            while True:
                encoded = handle.read(chunk_size + GCM_TAG_BYTES)
                if not encoded:
                    break
                if len(encoded) < GCM_TAG_BYTES:
                    raise FileCorruptionError("truncated payload chunk")
                try:
                    plain = aesgcm.decrypt(_chunk_nonce(nonce_prefix, index), encoded, None)
                except Exception as exc:
                    raise FileCorruptionError("payload chunk authentication failed") from exc
                index += 1
                total += len(plain)
                if position + len(plain) <= start:
                    position += len(plain)
                    continue
                if position >= window_end:
                    break
                slice_start = max(0, start - position)
                slice_end = min(len(plain), window_end - position)
                yield plain[slice_start:slice_end]
                position += len(plain)
            if total != stored.size_bytes:
                raise FileCorruptionError(
                    f"decrypted size {total} != metadata size {stored.size_bytes}"
                )
    except OSError as exc:
        raise FileStorageError(f"envelope read failed: {exc}") from exc
