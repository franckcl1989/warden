"""DSM simulator payload builders + profiles.

This is a TEST DEVICE SIMULATOR — see ``tests/simulators/dsm/README.md``
for the honest framing and the API-name basis table. Payloads below are
SIMULATOR DSL: their shapes and value vocabularies serve the M4 protocol
client and contract parsing tests only and are NOT real-DSM evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

BASE = "/webapi"

# API map the simulator advertises via SYNO.API.Info.Query. Per-API
# (path, minVersion, maxVersion); versions sit inside the platform ledger's
# certified rows except where a test inflates one (see README basis notes).
API_MAP: dict[str, dict[str, object]] = {
    "SYNO.API.Info": {"path": "query.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 6},
    "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
    "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.UPS": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.System.Log": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Upgrade": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
}

PROFILES = ("healthy", "degraded", "auth_fail", "api_map_missing", "slow_paginated")

# Values (readable disk sizes for simulator data; all synthetic).
_SIM_IDENTITY = {
    "model": "DS224+ (simulated)",
    "serial": "SIM-DS224P-0001",
    "firmware": "7.2.1-69057-update5 (simulated)",
}
_FAN_COUNT = 2

# Log centre entries start at this instant and advance 1 s per entry so the
# pagination fixture is deterministic (ids/time strictly increasing).
LOG_EPOCH = datetime(2026, 9, 3, 0, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class SimulatorConfig:
    """Constructor configuration (tests may also switch live via control)."""

    username: str = "admin"
    password: str = "sim-pass-1"
    profile: str = "healthy"
    task_duration_seconds: float = 0.15
    log_total: int = 24
    log_page_size: int = 20
    # Knobs — each exercises one honest adapter edge:
    # - storage_degraded: pool 1 Degraded, disk 2 Broken + SMART Fail with
    #   bad-sector data, volume used/total near capacity (usage is DATA);
    # - ups_on_battery: the UPS reports On Battery;
    # - fan_broken: fan 1 spins at 0 rpm with status Error;
    # - missing_apis: API names dropped from the SYNO.API.Info map (the
    #   adapter must report the gap instead of guessing a path).
    storage_degraded: bool = False
    ups_on_battery: bool = False
    fan_broken: bool = False
    missing_apis: tuple[str, ...] = ()

    def effective_map(self) -> dict[str, dict[str, object]]:
        excluded = frozenset(self.missing_apis)
        return {name: dict(entry) for name, entry in API_MAP.items() if name not in excluded}

    def inflated_map(self, *, storage_max_version: int | None = None) -> dict[str, dict[str, object]]:
        """Effective map with an optional inflated Storage maxVersion.

        ``storage_max_version`` lets tests prove the client never calls
        above its certified version: the device advertises a higher
        maxVersion than the platform ledger row, and the client must still
        negotiate down to its certified version.
        """
        result = self.effective_map()
        if storage_max_version is not None:
            entry = dict(result["SYNO.Storage.CGI.Storage"])
            entry["maxVersion"] = int(storage_max_version)
            result["SYNO.Storage.CGI.Storage"] = entry
        return result


@dataclass
class TaskRecord:
    task_id: int
    kind: str
    created_monotonic: float
    duration_seconds: float
    fails: bool = False

    def state_at(self, now: float) -> tuple[str, int]:
        elapsed = now - self.created_monotonic
        if elapsed < self.duration_seconds:
            return "running", 40
        if self.fails:
            return "failure", 100
        return "success", 100


def _profiled_config(profile: str, cfg: SimulatorConfig) -> SimulatorConfig:
    """Profile presets over an identity/base config (deterministic).

    Knobs not owned by the chosen profile keep their base values; knobs the
    profile owns are forced to the preset so a switch is always repeatable.
    """
    if profile == "degraded":
        return replace(
            cfg,
            profile=profile,
            storage_degraded=True,
            ups_on_battery=True,
            fan_broken=True,
            missing_apis=(),
        )
    if profile == "auth_fail":
        return replace(cfg, profile=profile, missing_apis=())
    if profile == "api_map_missing":
        # The monitoring-critical Storage API is absent from the map: the
        # adapter's discovery must report the per-API gap (DEVICE_ADAPTERS
        # §5.1 — no guessing URLs).
        return replace(cfg, profile=profile, missing_apis=("SYNO.Storage.CGI.Storage",))
    if profile == "slow_paginated":
        return replace(
            cfg,
            profile=profile,
            log_total=150,
            log_page_size=20,
            missing_apis=(),
        )
    return replace(cfg, profile="healthy", missing_apis=())


def profile_config(profile: str, base: SimulatorConfig | None = None) -> SimulatorConfig:
    """SimulatorConfig for a profile over an optional base config."""
    return _profiled_config(profile, base if base is not None else SimulatorConfig())


# --- payload builders --------------------------------------------------------


def success(data: object) -> dict[str, Any]:
    return {"success": True, "data": data}


def error(code: int) -> dict[str, Any]:
    return {"success": False, "error": {"code": code}}


def api_info_payload(api_map: dict[str, dict[str, object]]) -> dict[str, Any]:
    """SYNO.API.Info.Query data member (path/minVersion/maxVersion per API)."""
    return success({name: dict(entry) for name, entry in api_map.items()})


def login_payload(sid: str) -> dict[str, Any]:
    return success({"sid": sid})


def logout_payload() -> dict[str, Any]:
    return success({})


def system_info_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Core.System method=info: identity, temperature, fans, power."""
    fans: list[dict[str, object]] = []
    for index in range(1, _FAN_COUNT + 1):
        if cfg.fan_broken and index == 1:
            fans.append({"id": index, "name": f"Fan {index}", "rpm": 0, "status": "Error"})
        else:
            fans.append({"id": index, "name": f"Fan {index}", "rpm": 2100, "status": "Normal"})
    return success(
        {
            "model": _SIM_IDENTITY["model"],
            "serial": _SIM_IDENTITY["serial"],
            "firmware": _SIM_IDENTITY["firmware"],
            "temperature": [
                {"id": "system", "name": "System", "temp_c": 41.0},
                {"id": "disk", "name": "Disk", "temp_c": 38.0},
            ],
            "fan": fans,
            "uptime_seconds": 86400 * 21,
        }
    )


def storage_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Storage.CGI.Storage method=load_info: disk/pool/volume state."""
    if cfg.storage_degraded:
        disk = [
            {"id": "sata1", "name": "Disk 1", "status": "Healthy", "smart": "Normal", "bad_sectors": 0},
            {"id": "sata2", "name": "Disk 2", "status": "Broken", "smart": "Fail", "bad_sectors": 512},
        ]
        pool = [{"id": "pool1", "name": "Pool 1", "status": "Degraded", "raid_type": "SHR-1", "rebuild_progress": 0}]
        volume = [
            {
                "id": "vol1",
                "name": "Volume 1",
                "status": "Normal",
                "used_bytes": 3_912_318_193_664,
                "total_bytes": 4_000_000_000_000,
            }
        ]
    else:
        disk = [
            {"id": "sata1", "name": "Disk 1", "status": "Healthy", "smart": "Normal", "bad_sectors": 0},
            {"id": "sata2", "name": "Disk 2", "status": "Healthy", "smart": "Normal", "bad_sectors": 0},
        ]
        pool = [{"id": "pool1", "name": "Pool 1", "status": "Normal", "raid_type": "SHR-1", "rebuild_progress": 0}]
        volume = [
            {
                "id": "vol1",
                "name": "Volume 1",
                "status": "Normal",
                "used_bytes": 1_500_000_000_000,
                "total_bytes": 4_000_000_000_000,
            }
        ]
    return success({"disk": disk, "pool": pool, "volume": volume})


def ups_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Core.UPS method=get: UPS state (data, no invented thresholds)."""
    status = "On Battery" if cfg.ups_on_battery else "Normal"
    return success({"ups": {"id": "ups1", "status": status, "name": "Simulated UPS"}})


def log_entries_payload(cfg: SimulatorConfig, *, offset: int, limit: int) -> dict[str, Any]:
    """SYNO.Core.System.Log method=list: paginated log entries.

    Entries carry 1-based ``id`` (dedupe key), epoch ``time`` and a level;
    severity normalization is the parser's job.
    """
    total = cfg.log_total
    entries: list[dict[str, object]] = []
    for index in range(offset + 1, min(offset + limit, total) + 1):
        level = "INFO" if index % 5 else "WARNING"
        entries.append(
            {
                "id": index,
                "time": int(LOG_EPOCH.timestamp()) + index,
                "level": level,
                "message": f"Simulated DSM log entry {index}",
                "user": "system",
            }
        )
    return success({"total": total, "log": entries})


def smart_test_payload(task_id: int) -> dict[str, Any]:
    return success({"taskid": task_id})


def smart_task_status_payload(task_id: int, status: str, progress: int) -> dict[str, Any]:
    return success({"taskid": task_id, "status": status, "progress": progress})


def upgrade_payload(task_id: int) -> dict[str, Any]:
    return success({"taskid": task_id})


def update_task_status_payload(task_id: int, status: str, progress: int) -> dict[str, Any]:
    return success({"taskid": task_id, "status": status, "progress": progress})
