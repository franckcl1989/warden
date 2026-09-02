"""Pure unit tests for the file-type vocabulary, quotas and magic sniffing.

docs/SECURITY.md §9 (魔数识别、类型与用途检查、扩展名不作为唯一依据),
API_CONTRACT.md §8 (配额: 支持包/配置 5 GiB, 固件 10 GiB, 虚拟介质 50 GiB),
DATA_MODEL.md §8 (类型/状态/用途枚举). No new dependencies: sniffing is
minimal built-in magic (zip/gzip/ELF/ISO9660); formats without a reliable
magic are accepted with a documented note (never guessed as verified).
"""

from __future__ import annotations

import pytest
from app.config import WardenSettings
from app.domain.file_types import (
    FILE_LINK_PURPOSES,
    FILE_STATUSES,
    FILE_TYPES,
    download_permission_for,
    file_type_is_sensitive,
    quota_bytes_for,
    sniff_magic,
    upload_permission_for,
)
from app.domain.roles import FILE_DOWNLOAD_OUTPUT, FILE_MANAGE_INPUT

ZIP_HEADER = b"PK\x03\x04" + b"\x00" * 64
GZIP_HEADER = b"\x1f\x8b\x08" + b"\x00" * 64
ELF_HEADER = b"\x7fELF\x02\x01\x01" + b"\x00" * 64
TEXT_HEADER = b"# plain text config\nkey value\n" + b"x" * 256


def _iso_header() -> bytes:
    header = bytearray(b"\x00" * 0x8010)
    header[0x8001 : 0x8001 + 5] = b"CD001"
    return bytes(header)


class TestVocabulary:
    def test_type_status_and_purpose_enums(self) -> None:
        assert FILE_TYPES == (
            "firmware",
            "virtual_media",
            "support_bundle",
            "config_backup",
            "operation_log",
        )
        assert FILE_STATUSES == ("uploading", "ready", "quarantined", "deleted")
        assert FILE_LINK_PURPOSES == (
            "input_firmware",
            "input_virtual_media",
            "output_support_bundle",
            "output_config_backup",
            "output_operation_log",
        )

    def test_sensitive_types_are_the_encrypted_group(self) -> None:
        for file_type in ("support_bundle", "config_backup", "operation_log"):
            assert file_type_is_sensitive(file_type) is True
        for file_type in ("firmware", "virtual_media"):
            assert file_type_is_sensitive(file_type) is False

    def test_input_types_need_manage_input_permission(self) -> None:
        assert upload_permission_for("firmware") == FILE_MANAGE_INPUT
        assert upload_permission_for("virtual_media") == FILE_MANAGE_INPUT
        assert download_permission_for("firmware") == FILE_MANAGE_INPUT

    def test_output_types_need_download_output_permission(self) -> None:
        for file_type in ("support_bundle", "config_backup", "operation_log"):
            assert upload_permission_for(file_type) == FILE_DOWNLOAD_OUTPUT
            assert download_permission_for(file_type) == FILE_DOWNLOAD_OUTPUT

    def test_quota_map_reads_only_settings_values(self) -> None:
        settings = WardenSettings(_env_file=None)
        five = 5 * 1024**3
        assert quota_bytes_for("support_bundle", settings) == five
        assert quota_bytes_for("config_backup", settings) == five
        assert quota_bytes_for("operation_log", settings) == five
        assert quota_bytes_for("firmware", settings) == 10 * 1024**3
        assert quota_bytes_for("virtual_media", settings) == 50 * 1024**3


class TestSniffMagic:
    def test_zip_is_verified_for_archive_types(self) -> None:
        for file_type in ("support_bundle", "operation_log", "config_backup", "firmware"):
            verdict = sniff_magic(ZIP_HEADER, file_type)
            assert verdict.verified is True
            assert verdict.mime_type == "application/zip"
            assert verdict.note is None

    def test_gzip_is_verified_for_archive_types(self) -> None:
        for file_type in ("support_bundle", "operation_log", "config_backup", "firmware"):
            verdict = sniff_magic(GZIP_HEADER, file_type)
            assert verdict.verified is True
            assert verdict.mime_type == "application/gzip"

    def test_support_bundle_with_foreign_magic_is_quarantined(self) -> None:
        verdict = sniff_magic(TEXT_HEADER, "support_bundle")
        assert verdict.verified is False
        assert verdict.note == "unexpected_magic"
        assert verdict.mime_type == "application/octet-stream"

    def test_operation_log_with_foreign_magic_is_quarantined(self) -> None:
        assert sniff_magic(ELF_HEADER, "operation_log").note == "unexpected_magic"

    def test_config_backup_text_is_accepted_with_note(self) -> None:
        verdict = sniff_magic(TEXT_HEADER, "config_backup")
        assert verdict.verified is False
        assert verdict.note == "magic_unverified"
        assert verdict.mime_type == "application/octet-stream"

    def test_firmware_foreign_magic_is_accepted_with_note(self) -> None:
        verdict = sniff_magic(TEXT_HEADER, "firmware")
        assert verdict.verified is False
        assert verdict.note == "magic_unverified"

    def test_virtual_media_iso_is_verified(self) -> None:
        verdict = sniff_magic(_iso_header(), "virtual_media")
        assert verdict.verified is True
        assert verdict.mime_type == "application/x-iso9660-image"

    def test_virtual_media_without_iso_magic_is_accepted_with_note(self) -> None:
        # Raw disk images have no reliable magic: accept with a documented
        # note instead of inventing a false rejection (SECURITY.md §9).
        verdict = sniff_magic(TEXT_HEADER, "virtual_media")
        assert verdict.verified is False
        assert verdict.note == "magic_unverified"

    def test_small_virtual_media_cannot_claim_iso_verification(self) -> None:
        short_prefix = b"\x00" * 0x100
        verdict = sniff_magic(short_prefix, "virtual_media")
        assert verdict.verified is False
        assert verdict.note == "magic_unverified"

    def test_unknown_file_type_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError):
            sniff_magic(ZIP_HEADER, "not-a-type")  # type: ignore[arg-type]

    def test_iso_magic_at_wrong_offset_is_not_verified(self) -> None:
        wrong = bytearray(b"\x00" * 0x8010)
        wrong[0x8000] = ord("C")
        wrong[0x8002 : 0x8002 + 4] = b"D001"
        verdict = sniff_magic(bytes(wrong), "virtual_media")
        assert verdict.verified is False
