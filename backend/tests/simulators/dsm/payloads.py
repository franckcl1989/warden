"""DSM simulator payload builders + profiles.

This is a TEST DEVICE SIMULATOR — see ``tests/simulators/dsm/README.md``
for the honest framing and the API-name basis table. Payloads below are
SIMULATOR DSL: their shapes and value vocabularies serve the M4 protocol
client and contract parsing tests only and are NOT real-DSM evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

BASE = "/webapi"

# API map the simulator advertises via SYNO.API.Info.Query. Per-API
# (path, minVersion, maxVersion); versions sit inside the platform ledger's
# certified rows except where a test inflates one (see README basis notes).
# SYNO.Core.Support / SYNO.Core.Backup / SYNO.Core.Network.SNMP are the
# M4T3 operation-family rows (NAS-ACT-03/05/06), same simulator-DSL basis as
# the other control-panel families (README basis table).
API_MAP: dict[str, dict[str, object]] = {
    "SYNO.API.Info": {"path": "query.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 6},
    "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
    "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Share": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.UPS": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.System.Log": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Upgrade": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Support": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Backup": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Network.SNMP": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
}

# Operation-family task/DSL defaults (M4T3): SMART quick/full async durations,
# the DSM update install + reboot windows and the restart blip. Tests shorten
# every duration through the live control endpoint; the defaults below are
# the documented DSL behavior the operation verify loops are built against.
DEFAULT_SMART_QUICK_SECONDS = 2.0
DEFAULT_SMART_FULL_SECONDS = 5.0
DEFAULT_UPGRADE_DURATION_SECONDS = 2.0
DEFAULT_UPGRADE_OFFLINE_SECONDS = 0.6
DEFAULT_RESTART_BLIP_SECONDS = 0.5

# Fixed backup-job timestamps (deterministic DSL data, ISO-8601 UTC).
BACKUP_JOB_LAST_RUN_AT = "2026-09-03T00:30:00+00:00"
BACKUP_SNAPSHOT_LAST_RUN_AT = "2026-09-03T01:00:00+00:00"

PROFILES = (
    "healthy",
    "ds224plus",
    "ds225plus",
    "degraded",
    "auth_fail",
    "api_map_missing",
    "slow_paginated",
)

# Identity per profile (all synthetic simulator data). "healthy" keeps the
# M4T1 DS224+ identity so the frozen M4T1 fixtures never drift; ds224plus and
# ds225plus are the M4T2 vendor-model profiles that name the hardware-targets
# certification units (nas.synology_ds224plus / nas.synology_ds225plus) and
# carry "(simulated)" markers so a record can never be mistaken for a real
# device. The DS225+ model/DSM version rows are simulator DSL placeholders
# (ADR-018: real-DSM identity certification pending).
_IDENTITY_DS224PLUS = {
    "model": "DS224+ (simulated)",
    "serial": "SIM-DS224P-0001",
    "firmware": "7.2.1-69057-update5 (simulated)",
}
_IDENTITY_DS225PLUS = {
    "model": "DS225+ (simulated)",
    "serial": "SIM-DS225P-0001",
    "firmware": "7.2.2-72806-update1 (simulated)",
}
_FAN_COUNT = 2

# Log centre entries start at this instant and advance 1 s per entry so the
# pagination fixture is deterministic (ids/time strictly increasing).
LOG_EPOCH = datetime(2026, 9, 3, 0, 0, 0, tzinfo=UTC)


def _identity_for(profile: str) -> dict[str, str]:
    if profile == "ds225plus":
        return _IDENTITY_DS225PLUS
    return _IDENTITY_DS224PLUS


def identity_of(cfg: SimulatorConfig) -> dict[str, str]:
    """The profile's identity block (model/serial/firmware, DSL data)."""
    return _identity_for(cfg.profile)


@dataclass(frozen=True)
class SimulatorConfig:
    """Constructor configuration (tests may also switch live via control).

    Task/operation timing knobs (M4T3): SMART quick/full async tests run for
    ``smart_quick_duration_seconds`` / ``smart_full_duration_seconds`` then
    complete (or fail / never complete via failure injection); a DSM update
    installs for ``upgrade_duration_seconds`` then reboots (all /webapi
    endpoints answer 503) for ``upgrade_offline_seconds`` before the new
    firmware version is served; a restart is an offline blip of
    ``restart_blip_seconds``. ``upgrade_fetch_required`` makes the update
    flow fetch the platform PAT ticket URL (device-pull evidence, like the
    Redfish simulator's update fetch) and apply the header version;
    ``upgrade_target_version`` overrides the auto-bumped version when the
    device does not fetch. ``storage_maintenance`` reports an active scrub
    on SYNO.Core.System info (blocks power/update preflight in the DSL);
    ``backup_no_jobs`` serves an empty SYNO.Core.Backup job list.
    """

    username: str = "admin"
    password: str = "sim-pass-1"
    profile: str = "healthy"
    smart_quick_duration_seconds: float = DEFAULT_SMART_QUICK_SECONDS
    smart_full_duration_seconds: float = DEFAULT_SMART_FULL_SECONDS
    upgrade_duration_seconds: float = DEFAULT_UPGRADE_DURATION_SECONDS
    upgrade_offline_seconds: float = DEFAULT_UPGRADE_OFFLINE_SECONDS
    restart_blip_seconds: float = DEFAULT_RESTART_BLIP_SECONDS
    log_total: int = 24
    log_page_size: int = 20
    # Knobs — each exercises one honest adapter edge:
    # - storage_degraded: pool 1 Degraded, disk 2 Broken + SMART Fail with
    #   bad-sector data, volume used/total near capacity (usage is DATA);
    # - pool_rebuilding: pool 1 Rebuilding with a device-reported
    #   rebuild_progress value (raid.rebuild_progress only while rebuilding);
    # - ups_on_battery: the UPS reports On Battery;
    # - ups_absent: no UPS is connected (no ups point/component at all);
    # - fan_broken: fan 1 spins at 0 rpm with status Error;
    # - fan_zero_rpm: every fan reports 0 rpm with status Normal — 0 rpm is
    #   DEVICE-REPORTED data (never fabricated); it must not alert by itself;
    # - share_no_quota: one shared folder has quota 0 (无配额) — the
    #   usage-percent denominator is missing (ADR-016: never bytes-as-percent);
    # - missing_apis: API names dropped from the SYNO.API.Info map (the
    #   adapter must report the gap instead of guessing a path);
    # - log_append: extra log entries appended after the profile's base total
    #   (ids/timestamps continue the deterministic cadence) so delta log
    #   reads can see genuinely new entries past a cursor.
    storage_degraded: bool = False
    pool_rebuilding: bool = False
    ups_on_battery: bool = False
    ups_absent: bool = False
    fan_broken: bool = False
    fan_zero_rpm: bool = False
    share_no_quota: bool = False
    log_append: int = 0
    missing_apis: tuple[str, ...] = ()
    # M4T3 operation knobs (see class docstring).
    upgrade_fetch_required: bool = False
    upgrade_target_version: str = ""
    storage_maintenance: bool = False
    backup_no_jobs: bool = False
    backup_snapshot_available: bool = False

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
    never_completes: bool = False
    target_version: str | None = None
    reboot_seconds: float = 0.0
    disk: str | None = None

    def state_at(self, now: float) -> tuple[str, int]:
        elapsed = now - self.created_monotonic
        if self.never_completes or elapsed < self.duration_seconds:
            return "running", 40
        if self.fails:
            return "failure", 100
        return "success", 100


def _profiled_config(profile: str, cfg: SimulatorConfig) -> SimulatorConfig:
    """Profile presets over a base config (deterministic).

    A profile forces the knobs it OWNS to its preset values; knobs it does
    not own keep their base values, so constructor combinations such as
    ``SimulatorConfig(profile="ds224plus", pool_rebuilding=True)`` work.
    Live control switches go through the same path (the DSM adapter test
    conftest resets every knob explicitly for repeatable per-test state).
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
    if profile in ("ds224plus", "ds225plus"):
        # Vendor-model profiles: identity only (model/serial/DSM version); the
        # served API map is identical across the two certified consumer units
        # in this DSL (any real difference is certification evidence, ADR-018).
        return replace(cfg, profile=profile, missing_apis=())
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
        elif cfg.fan_zero_rpm:
            # 0 rpm is DEVICE-REPORTED data here (status Normal): the fan
            # control may stop the fans while the device reports them healthy.
            fans.append({"id": index, "name": f"Fan {index}", "rpm": 0, "status": "Normal"})
        else:
            fans.append({"id": index, "name": f"Fan {index}", "rpm": 2100, "status": "Normal"})
    identity = _identity_for(cfg.profile)
    data: dict[str, object] = {
        "model": identity["model"],
        "serial": identity["serial"],
        "firmware": identity["firmware"],
        "temperature": [
            {"id": "system", "name": "System", "temp_c": 41.0},
            {"id": "disk", "name": "Disk", "temp_c": 38.0},
        ],
        "fan": fans,
        "uptime_seconds": 86400 * 21,
    }
    if cfg.storage_maintenance:
        # M4T3 DSL: DSM reports an ACTIVE storage maintenance only while it
        # runs (mirrors the rebuild_progress-only-while-rebuilding rule).
        data["maintenance"] = {"active": True, "kind": "scrub"}
    return success(data)


def identity_firmware_version(cfg: SimulatorConfig) -> str:
    """The profile's default DSM firmware version (runtime override base)."""
    return _identity_for(cfg.profile)["firmware"]


def bump_firmware_version(version: str) -> str:
    """Auto-bump a simulator firmware version ``...-update<N>`` to N+1.

    The M4T3 DSL default upgrade target when the device does not fetch the
    PAT (deterministic version-bump knob semantics); a version without an
    ``update<N>`` suffix is returned unchanged (never invented).
    """
    match = re.search(r"update(\d+)", version)
    if match is None:
        return version
    return version[: match.start()] + f"update{int(match.group(1)) + 1}" + version[match.end() :]


def storage_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Storage.CGI.Storage method=load_info: disk/pool/volume state."""
    if cfg.pool_rebuilding:
        disk = [
            {"id": "sata1", "name": "Disk 1", "status": "Healthy", "smart": "Normal", "bad_sectors": 0},
            {"id": "sata2", "name": "Disk 2", "status": "Healthy", "smart": "Normal", "bad_sectors": 0},
        ]
        pool = [{"id": "pool1", "name": "Pool 1", "status": "Rebuilding", "raid_type": "SHR-1", "rebuild_progress": 45}]
        volume = [
            {
                "id": "vol1",
                "name": "Volume 1",
                "status": "Normal",
                "used_bytes": 1_500_000_000_000,
                "total_bytes": 4_000_000_000_000,
            }
        ]
    elif cfg.storage_degraded:
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


def share_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Core.Share method=list: shared folders with usage + quota.

    The quota member is the usage-percent DENOMINATOR (ADR-016 —
    DEVICE_ADAPTERS.md §5.1: 缺少分母时不以字节数冒充百分比). ``quota_bytes``
    0 means 无配额 (unlimited): the adapter must report the missing
    denominator, never a fabricated percent.
    """
    shares: list[dict[str, object]] = [
        {
            "id": "homes",
            "name": "homes",
            "used_bytes": 2_000_000_000_000,
            "quota_bytes": 4_000_000_000_000,
        }
    ]
    if cfg.share_no_quota:
        shares.append(
            {
                "id": "backup",
                "name": "backup",
                "used_bytes": 1_200_000_000_000,
                "quota_bytes": 0,
            }
        )
    return success({"shares": shares, "total": len(shares)})


def ups_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Core.UPS method=get: UPS state (data, no invented thresholds)."""
    if cfg.ups_absent:
        # No UPS unit is connected: the payload says so explicitly (None) —
        # the adapter emits no ups point and no ups component.
        return success({"ups": None})
    status = "On Battery" if cfg.ups_on_battery else "Normal"
    return success({"ups": {"id": "ups1", "status": status, "name": "Simulated UPS"}})


def log_entries_payload(cfg: SimulatorConfig, *, offset: int, limit: int) -> dict[str, Any]:
    """SYNO.Core.System.Log method=list: paginated log entries.

    Entries carry 1-based ``id`` (dedupe key), epoch ``time`` and a level;
    severity normalization is the parser's job. ``log_append`` adds strictly
    newer entries AFTER the profile's base total (the deterministic cadence
    continues) so delta reads can observe genuinely new tail entries.
    """
    total = cfg.log_total + cfg.log_append
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


# --- M4T3 operation-family payload builders -----------------------------------
# All rows below are SIMULATOR DSL (README basis table): the DSM log-centre
# export/support-package, Hyper Backup/Snapshot Replication and Control-Panel
# SNMP families are NOT in the public Login guide and stay simulator-invented
# placeholders until real-DSM certification (ADR-018) records the exact
# target-model API shapes.


def backup_payload(cfg: SimulatorConfig) -> dict[str, Any]:
    """SYNO.Core.Backup method=list: backup/snapshot package + job statuses.

    Snapshot Replication is reported unavailable (``not_installed``) by
    default so a refresh always carries an explicit unavailable package
    (contracts/operations.json backup.status.refresh success: 不可用包必须
    显式); ``backup_snapshot_available`` adds it plus its snapshot job rows.
    Job status/timestamps are device-reported DSL data (fixed deterministic
    ISO-8601 timestamps); ``backup_no_jobs`` serves an empty job list.
    """
    packages: list[dict[str, object]] = [
        {"name": "Hyper Backup", "package": "hyper_backup", "available": True},
    ]
    jobs: list[dict[str, object]] = []
    if not cfg.backup_no_jobs:
        jobs = [
            {
                "name": "Daily Backup",
                "type": "hyper_backup",
                "status": "success",
                "last_run_at": BACKUP_JOB_LAST_RUN_AT,
            },
            {
                "name": "Weekly Backup",
                "type": "hyper_backup",
                "status": "success",
                "last_run_at": BACKUP_JOB_LAST_RUN_AT,
            },
        ]
    if cfg.backup_snapshot_available:
        packages.append({"name": "Snapshot Replication", "package": "snapshot_replication", "available": True})
        if not cfg.backup_no_jobs:
            jobs.append(
                {
                    "name": "Snapshot Schedule 1",
                    "type": "snapshot",
                    "status": "success",
                    "last_run_at": BACKUP_SNAPSHOT_LAST_RUN_AT,
                }
            )
    else:
        packages.append(
            {
                "name": "Snapshot Replication",
                "package": "snapshot_replication",
                "available": False,
                "reason": "not_installed",
            }
        )
    return success({"packages": packages, "jobs": jobs, "total": len(jobs)})


def snmp_config_payload(enabled: bool, receiver_address: str) -> dict[str, Any]:
    """SYNO.Core.Network.SNMP get/set data member (trap config, DSL).

    Only the trap enable state + the platform receiver address are modeled:
    the platform NEVER accepts a user-supplied receiver (operations.json
    snmp.configure prohibition); community/USM credential rows are ingest
    (M5) territory and are not invented here.
    """
    return success({"enabled": enabled, "receiver_address": receiver_address})


def _source_blob(name: str, payload: object) -> tuple[str, bytes, str]:
    blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return name, blob, hashlib.sha256(blob).hexdigest()


def support_bundle_bytes(cfg: SimulatorConfig) -> bytes:
    """The DSM support-package export content (deterministic zip, DSL).

    Layout mirrors what the M4T3 adapter expects: a top-level
    ``manifest.json`` (``warden-dsm-support-bundle/1``) listing every
    included source with its SHA-256, plus one JSON member per source. The
    log-centre entries reuse the deterministic LOG_EPOCH cadence so the
    export is repeatable; ``created_at`` is the only live member.
    """
    total = cfg.log_total + cfg.log_append
    entries: list[dict[str, object]] = []
    for index in range(1, total + 1):
        entries.append(
            {
                "id": index,
                "time": int(LOG_EPOCH.timestamp()) + index,
                "level": "INFO" if index % 5 else "WARNING",
                "message": f"Simulated DSM log entry {index}",
            }
        )
    identity = _identity_for(cfg.profile)
    sources: list[dict[str, object]] = []
    files: list[tuple[str, bytes]] = []
    log_name, log_blob, log_sha = _source_blob(
        "log-entries.json",
        {"source": "system_log", "entries": entries, "total": total},
    )
    files.append((log_name, log_blob))
    sources.append({"name": "system_log", "file": log_name, "entries": total, "sha256": log_sha})
    sys_name, sys_blob, sys_sha = _source_blob(
        "system.json",
        {
            "source": "system_info",
            "system": {
                "model": identity["model"],
                "serial": identity["serial"],
                "firmware": identity["firmware"],
                "maintenance": "scrub" if cfg.storage_maintenance else "none",
            },
        },
    )
    files.append((sys_name, sys_blob))
    sources.append({"name": "system_info", "file": sys_name, "entries": 1, "sha256": sys_sha})
    manifest: dict[str, object] = {
        "format": "warden-dsm-support-bundle/1",
        "created_at": datetime.now(UTC).isoformat(),
        "sources": sources,
        "unavailable": [],
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2)
        )
        for name, blob in files:
            archive.writestr(name, blob)
    return buffer.getvalue()
