"""Argon2id password hashing tests (docs/SECURITY.md §2)."""

from __future__ import annotations

import pytest
from app.infrastructure.passwords import (
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    hash_password,
    verify_password,
)


@pytest.mark.unit
def test_hash_verify_round_trip() -> None:
    stored = hash_password("S3cret-Pass-2026!")
    assert stored.startswith("$argon2id$")
    ok, needs_rehash = verify_password(stored, "S3cret-Pass-2026!")
    assert ok is True
    assert needs_rehash is False


@pytest.mark.unit
def test_wrong_password_fails() -> None:
    stored = hash_password("S3cret-Pass-2026!")
    ok, needs_rehash = verify_password(stored, "wrong-password")
    assert ok is False
    assert needs_rehash is False


@pytest.mark.unit
def test_two_hashes_of_same_password_differ() -> None:
    first = hash_password("S3cret-Pass-2026!")
    second = hash_password("S3cret-Pass-2026!")
    assert first != second
    assert verify_password(first, "S3cret-Pass-2026!") == (True, False)
    assert verify_password(second, "S3cret-Pass-2026!") == (True, False)


@pytest.mark.unit
def test_parameters_meet_the_security_floor() -> None:
    assert ARGON2_MEMORY_COST_KIB == 64 * 1024
    assert ARGON2_TIME_COST == 3
    assert ARGON2_PARALLELISM == 1


@pytest.mark.unit
def test_verify_with_older_parameters_reports_rehash_flag() -> None:
    # Hash produced with memory 32 MiB (below the 64 MiB floor) and verified
    # with the current policy: the password matches but the hash is stale.
    weak_hash = (
        "$argon2id$v=19$m=32768,t=3,p=1$"
        "IqxJwY71lBnxxnAQEJVHLg$lMw5Ucod+JtN5NHT7IkeCJZrU+Fh0LYLJNEAwEcpERA"
    )
    ok, needs_rehash = verify_password(weak_hash, "S3cret-Pass-2026!")
    assert ok is True
    assert needs_rehash is True


@pytest.mark.unit
def test_verify_current_params_do_not_require_rehash() -> None:
    stored = hash_password("S3cret-Pass-2026!")
    ok, needs_rehash = verify_password(stored, "S3cret-Pass-2026!")
    assert ok is True
    assert needs_rehash is False


@pytest.mark.unit
def test_hash_values_never_contain_the_plaintext() -> None:
    plaintext = "S3cret-Pass-2026!"
    stored = hash_password(plaintext)
    assert plaintext not in stored
    assert plaintext.lower() not in stored.lower()
