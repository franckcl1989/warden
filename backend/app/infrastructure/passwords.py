"""Argon2id password hashing (docs/SECURITY.md §2).

Parameters: memory 64 MiB, 3 iterations, parallelism 1. Deployment calibrates
the parameters on the target host towards ~250 ms per hash; the constants
below are the documented minimum floor. Verify is hash-version-aware: when the
stored hash uses older parameters the caller gets ``needs_rehash=True`` so the
hash can be upgraded on the next successful login.
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2PasswordHasher
from argon2.exceptions import VerifyMismatchError

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024
ARGON2_PARALLELISM = 1

_hasher = _Argon2PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=32,
)


def hash_password(plaintext: str) -> str:
    """Hash ``plaintext`` with Argon2id and return the encoded hash string."""
    return _hasher.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> tuple[bool, bool]:
    """Verify ``plaintext`` against ``stored_hash``.

    Returns ``(ok, needs_rehash)``; ``needs_rehash`` is only True when the
    password matched AND the stored hash was produced with parameters older
    than the current policy. Corrupt hashes raise ``InvalidHashError`` instead
    of pretending success.
    """
    try:
        ok = _hasher.verify(stored_hash, plaintext)
    except VerifyMismatchError:
        return False, False
    if not ok:
        return False, False
    return True, _hasher.check_needs_rehash(stored_hash)
