"""Key rotation CLI tests (docs/SECURITY.md §5 rotation skeleton).

The CLI lists/validates key versions from key files; the database sweep that
re-encrypts old records lands with M1T3's credentials table.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.tools.key_rotation import run


def _write_secret(path: Path, material: str) -> None:
    path.write_text(material + "\n", encoding="utf-8")


@pytest.mark.unit
def test_list_single_key(tmp_path: Path) -> None:
    key_file = tmp_path / "credential.key"
    _write_secret(key_file, "k" * 32)
    out = run(["--current-key-file", str(key_file)])
    assert out == 0


@pytest.mark.unit
def test_list_previous_and_current(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    prev = tmp_path / "prev.key"
    curr = tmp_path / "curr.key"
    _write_secret(prev, "p" * 32)
    _write_secret(curr, "c" * 32)
    out = run(["--current-key-file", str(curr), "--previous-key-file", str(prev)])
    captured = capsys.readouterr()
    assert out == 0
    assert "current" in captured.out
    assert "version 2" in captured.out
    assert "version 1" in captured.out


@pytest.mark.unit
def test_rejects_short_key_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key_file = tmp_path / "credential.key"
    _write_secret(key_file, "short")
    out = run(["--current-key-file", str(key_file)])
    captured = capsys.readouterr()
    assert out == 2
    assert "at least 32 bytes" in captured.err


@pytest.mark.unit
def test_rejects_missing_key_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = run(["--current-key-file", str(tmp_path / "missing.key")])
    captured = capsys.readouterr()
    assert out == 2
    assert "cannot read" in captured.err


@pytest.mark.unit
def test_requires_key_file_when_settings_unconfigured(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = run([])
    captured = capsys.readouterr()
    assert out == 2
    assert "key file" in captured.err
