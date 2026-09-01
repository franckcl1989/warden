"""UTC time provider and display-timezone helper (docs/PROJECT_SPEC.md §5).

Internal storage and computation use aware UTC; interfaces display times in
Asia/Shanghai. The display timezone mirrors the default of the
``WARDEN_DISPLAY_TIMEZONE`` deployment setting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

SHANGHAI = ZoneInfo("Asia/Shanghai")


def utcnow() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def to_shanghai(value: datetime) -> datetime:
    """Convert ``value`` to Asia/Shanghai for display.

    Naive datetimes are treated as UTC: the database stores ``timestamptz`` so
    values read back are always aware; the fallback keeps callers honest about
    accidental naive input instead of silently interpreting local time.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(SHANGHAI)
