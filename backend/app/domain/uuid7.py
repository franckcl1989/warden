"""RFC 9562 UUIDv7 generation (docs/DATA_MODEL.md §1: primary keys are UUIDv7).

Layout: 48-bit milliseconds Unix timestamp, 4-bit version 7, 12-bit random
``rand_a`` (monotonically incremented within the same millisecond), 2-bit
variant 10 and 62-bit random ``rand_b``. Timestamp ordering holds for up to
4096 values per millisecond, far beyond this codebase's rates. Not thread-safe
by design; callers needing cross-thread ordering must serialize or lock.
"""

from __future__ import annotations

import os
import time
import uuid

_LAST_TIMESTAMP_MS: int | None = None
_LAST_RAND_A: int = 0


def uuid7() -> uuid.UUID:
    """Generate a timestamp-ordered, random UUIDv7 value."""
    global _LAST_TIMESTAMP_MS, _LAST_RAND_A

    now_ms = time.time_ns() // 1_000_000
    if now_ms == _LAST_TIMESTAMP_MS:
        _LAST_RAND_A = (_LAST_RAND_A + 1) & 0xFFF
    else:
        _LAST_TIMESTAMP_MS = now_ms
        _LAST_RAND_A = 0

    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF
    uuid_int = (now_ms << 80) | (0x7 << 76) | (_LAST_RAND_A << 64) | (0x2 << 62) | rand_b
    return uuid.UUID(int=uuid_int)
