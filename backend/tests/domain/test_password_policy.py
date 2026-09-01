"""Password policy tests (docs/SECURITY.md §2)."""

from __future__ import annotations

import pytest
from app.domain.password_policy import (
    COMMON_PASSWORDS,
    MIN_PASSWORD_LENGTH,
    REASON_COMMON_PASSWORD,
    REASON_CONTAINS_USERNAME,
    REASON_TOO_SHORT,
    validate_password,
)

STRONG_PASSWORD = "K7#mNp2!vQx9$LzR"  # 16 chars, mixed, not common, no username


@pytest.mark.unit
def test_short_password_rejected() -> None:
    assert validate_password("abc", "alice") == [REASON_TOO_SHORT]
    assert validate_password("a" * (MIN_PASSWORD_LENGTH - 1), "alice") == [REASON_TOO_SHORT]


@pytest.mark.unit
def test_username_substring_rejected_case_insensitive() -> None:
    assert validate_password("XxAlicexx1234!", "alice") == [REASON_CONTAINS_USERNAME]
    assert validate_password("ALICEpass1234", "alice") == [REASON_CONTAINS_USERNAME]
    assert validate_password("alicepass1234", "alice") == [REASON_CONTAINS_USERNAME]


@pytest.mark.unit
def test_common_password_rejected() -> None:
    assert validate_password("password1234", "alice") == [REASON_COMMON_PASSWORD]
    assert validate_password("12345678", "alice") == [REASON_TOO_SHORT, REASON_COMMON_PASSWORD]
    # Every entry in the built-in list is rejected regardless of length.
    for common in COMMON_PASSWORDS:
        assert REASON_COMMON_PASSWORD in validate_password(common, "someone")


@pytest.mark.unit
def test_strong_password_accepted() -> None:
    assert validate_password(STRONG_PASSWORD, "alice") == []
    assert validate_password("Correct-Horse-9!Battery-Staple", "alice") == []


@pytest.mark.unit
def test_multiple_violations_reported_together() -> None:
    assert set(validate_password("12345678", "alice")) == {REASON_TOO_SHORT, REASON_COMMON_PASSWORD}
    assert set(validate_password("Alicealice1", "alice")) == {
        REASON_TOO_SHORT,
        REASON_CONTAINS_USERNAME,
    }


@pytest.mark.unit
def test_empty_username_skips_substring_rule() -> None:
    assert validate_password(STRONG_PASSWORD, "") == []
    assert validate_password("abcdefghijkl", "") == []
