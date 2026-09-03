"""Tolerant DSM payload parsing per metric/event needs.

The mapping tables below are the certified DSM-value -> contracts-enum
ledgers for M4T1: every row is documented and fixture-certified against the
Warden DSM TEST SIMULATOR only. Real-DSM field/value vocabularies are
target-model certification territory (ADR-018, M4T2): a DSM literal NOT in a
table decodes to the contract's ``unknown`` sentinel — it is never guessed
into a plausible value, and missing/wrong-typed fields decode to ``None``
(never 0/normal). The adapter turns ``None``/``unknown`` into observation
errors (DEVICE_ADAPTERS.md §2.3, ADR-014) — this module only parses.

Contracts enum sets (``contracts/metrics.json``): component_status =
unknown/ok/warning/critical/absent; smart_status = unknown/passed/warning/
failed/running; raid_status = unknown/optimal/degraded/rebuilding/failed;
ups_state = unknown/normal/on_battery/low_battery/communication_lost/fault.
Event severity normalization per ``contracts/events.json`` rule:
unknown/info/warning/critical, never a defaulted normal.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# --- certified DSM -> contract enum tables (simulator-DSL rows) -------------
# Every table decodes STRICT DSM literals; anything else yields the contract
# ``unknown`` sentinel. Basis column values: [sim] = fixture-certified
# against the Warden DSM test simulator (tests/simulators/dsm); real-DSM
# certification pending (M4T2).

# disk.status (component_status): the DSM Storage Manager disk state.
DISK_STATUS_TABLE: Mapping[str, str] = {
    "Healthy": "ok",  # [sim]
    "Cached": "ok",  # [sim] disk serving as cache and healthy
    "Degraded": "warning",  # [sim]
    "Broken": "critical",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# disk.smart (smart_status): DSM SMART health vocabulary.
DISK_SMART_TABLE: Mapping[str, str] = {
    "Normal": "passed",  # [sim]
    "Warning": "warning",  # [sim]
    "Fail": "failed",  # [sim]
    "Testing": "running",  # [sim] SMART test in progress
    "Unknown": "unknown",  # [sim]
}

# storage_pool.status / raid.status (raid_status).
POOL_STATUS_TABLE: Mapping[str, str] = {
    "Normal": "optimal",  # [sim]
    "Degraded": "degraded",  # [sim]
    "Rebuilding": "rebuilding",  # [sim]
    "Failed": "failed",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# fan.status (component_status): DSM system fan state.
FAN_STATUS_TABLE: Mapping[str, str] = {
    "Normal": "ok",  # [sim]
    "Error": "critical",  # [sim]
    "Absent": "absent",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# ups.status (ups_state).
UPS_STATUS_TABLE: Mapping[str, str] = {
    "Normal": "normal",  # [sim]
    "On Battery": "on_battery",  # [sim]
    "Low Battery": "low_battery",  # [sim]
    "Comms Lost": "communication_lost",  # [sim]
    "Fault": "fault",  # [sim]
    "Unknown": "unknown",  # [sim]
}

# DSM log level -> event severity (events.json normalization rule; unknown is
# never defaulted to info).
LOG_LEVEL_TABLE: Mapping[str, str] = {
    "INFO": "info",  # [sim]
    "WARNING": "warning",  # [sim]
    "ERROR": "critical",  # [sim]
    "CRITICAL": "critical",  # [sim]
    "UNKNOWN": "unknown",  # [sim]
}

# --- enum decoders ----------------------------------------------------------

UNKNOWN = "unknown"


def _decode(table: Mapping[str, str], raw: object) -> str:
    if isinstance(raw, str):
        literal = raw.strip()
        if literal in table:
            return table[literal]
    return UNKNOWN


def disk_status(raw: object) -> str:
    """DSM disk state -> component_status; unknown DSM values -> unknown."""
    return _decode(DISK_STATUS_TABLE, raw)


def disk_smart(raw: object) -> str:
    """DSM SMART health -> smart_status; unknown DSM values -> unknown."""
    return _decode(DISK_SMART_TABLE, raw)


def pool_status(raw: object) -> str:
    """DSM storage pool/RAID state -> raid_status."""
    return _decode(POOL_STATUS_TABLE, raw)


def fan_status(raw: object) -> str:
    """DSM fan state -> component_status."""
    return _decode(FAN_STATUS_TABLE, raw)


def ups_status(raw: object) -> str:
    """DSM UPS state -> ups_state."""
    return _decode(UPS_STATUS_TABLE, raw)


def log_severity(raw: object) -> str:
    """DSM log level -> event severity (unknown/info/warning/critical)."""
    return _decode(LOG_LEVEL_TABLE, raw)


# --- scalar readers ---------------------------------------------------------

_UNAVAILABLE_TEXT = frozenset({"", "n/a", "na", "-", "not available", "unavailable"})
_INT_RE = re.compile(r"[+-]?\d+")


def text_value(raw: object) -> str | None:
    """Trimmed text; unavailable markers / wrong types -> None."""
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    if stripped.lower() in _UNAVAILABLE_TEXT:
        return None
    return stripped or None


def int_value(raw: object) -> int | None:
    """Integer tolerant of integer strings; never coerced from floats/bools."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw) if raw.is_integer() else None
    if isinstance(raw, str):
        stripped = raw.strip()
        if _INT_RE.fullmatch(stripped):
            try:
                return int(stripped)
            except ValueError:
                return None
    return None


def float_value(raw: object) -> float | None:
    """Float tolerant of numeric strings; bools and junk -> None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.lower() in _UNAVAILABLE_TEXT:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    return None


def epoch_seconds(raw: object) -> float | None:
    """Unix epoch seconds (DSM log timestamps); int/float/string tolerant."""
    return float_value(raw)


def usage_percent(*, used: object, total: object) -> float | None:
    """Volume/share usage as a percent computed from used/total bytes.

    NAS-MON-04 rule (DEVICE_ADAPTERS.md §5.1): a percentage must come from
    used bytes over a capacity/quota denominator — a missing or non-positive
    denominator never yields a fabricated percentage (None instead). An
    overshoot (used > total) is untrustworthy accounting and yields None
    too; it is never clamped into a fake 100 %.
    """
    used_value = float_value(used)
    total_value = float_value(total)
    if used_value is None or total_value is None or total_value <= 0 or used_value < 0:
        return None
    if used_value > total_value:
        return None
    return round(used_value / total_value * 100.0, 2)
