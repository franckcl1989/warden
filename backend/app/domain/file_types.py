"""File-type vocabulary, quota mapping and minimal magic sniffing (PLT-06).

docs/SECURITY.md §9 (计算 SHA-256、识别 MIME/魔数、检查类型与用途; 扩展名不
作为唯一依据), API_CONTRACT.md §8 (类型配额: 支持包/配置 5 GiB, 固件 10 GiB,
虚拟介质 50 GiB), DATA_MODEL.md §8/§10 (files 状态机 uploading/ready/
quarantined/deleted; 配置备份/支持包/操作日志为敏感类型).

Quota mapping decision (M2T5): ``config_backup`` and ``operation_log`` share
the support-bundle quota (5 GiB) — API_CONTRACT.md §8 names only three quota
bands and both types are platform-generated artifacts of the same output
class (DATA_MODEL.md §10 groups 支持包/操作日志 for retention). Values always
come from settings (ADR-027: deployment may lower, never raise without
capacity evidence) — never from a second hardcoded map.

Magic sniffing decision (M2T5, no new dependencies): built-in magic checks
only — zip (PK), gzip (1f 8b), ELF (7f 45 4c 46) and ISO9660 ``CD001`` at
offset 0x8001. Formats without a reliable magic are accepted with a
documented ``magic_unverified`` note in metadata (SECURITY.md §9: 识别 MIME/
魔数 — 不能识别的不假装已验证). ``support_bundle`` / ``operation_log`` are
archives by platform convention: foreign magic quarantines the upload
(status=quarantined, content retained, never usable by tasks).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import WardenSettings
from app.domain.roles import FILE_DOWNLOAD_OUTPUT, FILE_MANAGE_INPUT

FILE_TYPES = (
    "firmware",
    "virtual_media",
    "support_bundle",
    "config_backup",
    "operation_log",
)
FILE_STATUSES = ("uploading", "ready", "quarantined", "deleted")
FILE_LINK_PURPOSES = (
    "input_firmware",
    "input_virtual_media",
    "output_support_bundle",
    "output_config_backup",
    "output_operation_log",
)
# Device-pull ticket purposes (API_CONTRACT.md §8): firmware operations and
# virtual-media mounts are the only device-pulled payloads.
TICKET_PURPOSES = ("firmware", "virtual_media")

# File types encrypted at rest with AES-GCM (SECURITY.md §9: 配置备份和支持包
# 使用 AES-GCM 文件密钥加密; operation_log belongs to the same output class).
ENCRYPTED_FILE_TYPES = frozenset({"support_bundle", "config_backup", "operation_log"})
# Inputs consumed by device operations; outputs are platform artifacts.
INPUT_FILE_TYPES = frozenset({"firmware", "virtual_media"})

# storage_backend value (DATA_MODEL.md §8.1: 存储后端; local volume is the only
# 0.1.0 backend — ADR-012).
STORAGE_BACKEND = "local-volume"

# Sniffing needs bytes up to the ISO9660 magic location (0x8001) + 5.
ISO_MAGIC_OFFSET = 0x8001
SNIFF_PREFIX_BYTES = ISO_MAGIC_OFFSET + 5

ZIP_MAGIC = b"PK\x03\x04"
ZIP_EMPTY_MAGIC = b"PK\x05\x06"
GZIP_MAGIC = b"\x1f\x8b"
ELF_MAGIC = b"\x7fELF"  # recognized but NOT verifiable without a magic database
ISO_MAGIC = b"CD001"

MIME_ZIP = "application/zip"
MIME_GZIP = "application/gzip"
MIME_ISO = "application/x-iso9660-image"
MIME_BINARY = "application/octet-stream"

# Quarantine reason (SECURITY.md §9: 类型与用途不符的文件不得进入可用状态).
NOTE_UNEXPECTED_MAGIC = "unexpected_magic"
# Accept-with-note reason: no reliable built-in magic for the format; the
# content is NOT claimed as verified (never invent a false success).
NOTE_UNVERIFIED = "magic_unverified"


def file_type_is_sensitive(file_type: str) -> bool:
    """True for types stored encrypted at rest (support bundle/config/op log)."""
    return file_type in ENCRYPTED_FILE_TYPES


def file_type_is_input(file_type: str) -> bool:
    return file_type in INPUT_FILE_TYPES


def upload_permission_for(file_type: str) -> str:
    """SECURITY.md §3.1 matrix: inputs need file.manage.input, outputs the
    output-download permission class (the same users that handle outputs)."""
    return FILE_MANAGE_INPUT if file_type_is_input(file_type) else FILE_DOWNLOAD_OUTPUT


def download_permission_for(file_type: str) -> str:
    """Viewers never download (SECURITY.md §3.1): inputs require
    file.manage.input, outputs require file.download.output."""
    return upload_permission_for(file_type)


def quota_bytes_for(file_type: str, settings: WardenSettings) -> int:
    """Per-type upload quota straight from settings (API_CONTRACT.md §8).

    Quotas are deployment configuration (ADR-027): the map below only picks a
    settings field — config_backup/operation_log share the support-bundle
    quota band (5 GiB default; see the module docstring decision).
    """
    if file_type == "firmware":
        return settings.max_firmware_bytes
    if file_type == "virtual_media":
        return settings.max_virtual_media_bytes
    if file_type in ENCRYPTED_FILE_TYPES:
        return settings.max_support_bundle_bytes
    raise ValueError(f"unknown file_type: {file_type}")


@dataclass(frozen=True)
class MagicVerdict:
    """Sniff result for one upload: mime + whether the type's magic matched.

    ``verified=False`` means either the declared type demands a magic that was
    absent (quarantine, ``note=unexpected_magic``) or the type has no reliable
    built-in magic (accept-with-note, ``note=magic_unverified``).
    """

    mime_type: str
    verified: bool
    note: str | None


def _detect_mime(prefix: bytes) -> str | None:
    """Return a VERIFYING mime (zip/gzip/ISO9660) or None.

    ELF and other vendor formats are deliberately not verifiable here (no
    dependency for a full file(1)-style database): they fall through to the
    per-type accept-with-note / quarantine policy instead of being claimed
    verified (SECURITY.md §9: 识别 MIME/魔数 — 不能识别的不假装已验证).
    """
    if prefix.startswith((ZIP_MAGIC, ZIP_EMPTY_MAGIC)):
        return MIME_ZIP
    if prefix.startswith(GZIP_MAGIC):
        return MIME_GZIP
    if len(prefix) > ISO_MAGIC_OFFSET + len(ISO_MAGIC) and (
        prefix[ISO_MAGIC_OFFSET : ISO_MAGIC_OFFSET + len(ISO_MAGIC)] == ISO_MAGIC
    ):
        return MIME_ISO
    return None


def sniff_magic(prefix: bytes, file_type: str) -> MagicVerdict:
    """Classify ``prefix`` (up to SNIFF_PREFIX_BYTES of file start) per type.

    support_bundle / operation_log: must be a zip/gzip archive (platform
    convention) — anything else is quarantined. config_backup / firmware /
    virtual_media: verified only when a defining magic matches; vendor
    formats without reliable built-in magic are accepted with a documented
    note (never marked verified). ``file_type`` must be a known type — an
    unknown type is a programming error, not a sniffing decision.
    """
    if file_type not in FILE_TYPES:
        raise ValueError(f"unknown file_type: {file_type}")
    detected = _detect_mime(prefix)
    if detected is not None:
        return MagicVerdict(mime_type=detected, verified=True, note=None)
    if file_type in ("support_bundle", "operation_log"):
        return MagicVerdict(
            mime_type=MIME_BINARY, verified=False, note=NOTE_UNEXPECTED_MAGIC
        )
    if file_type in ("firmware", "config_backup", "virtual_media"):
        return MagicVerdict(mime_type=MIME_BINARY, verified=False, note=NOTE_UNVERIFIED)
    raise ValueError(f"unknown file_type: {file_type}")
