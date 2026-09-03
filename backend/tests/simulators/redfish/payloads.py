"""Redfish simulator payload builders.

This is a TEST DEVICE SIMULATOR used only for repeatable automated tests. It
is NOT evidence of hardware support: fixtures captured from it must state
their 模拟器 origin, and the hardware certification matrix stays
``not_started`` until real-device runs exist (HARDWARE_CERTIFICATION.md §3,
TEST_STRATEGY.md §2.2). Vendor OEM blocks are intentionally generic stubs;
vendor overlays (M3T5) define real shapes per vendor certification fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

BASE = "/redfish/v1"

# Profiles the simulator serves (constructor config or the control endpoint).
PROFILES = ("healthy", "critical", "auth_fail", "slow_paginated")
VENDORS = ("generic", "dell", "inspur", "xfusion", "lenovo", "huawei")

_VENDOR_TITLES = {
    "generic": "Vendor",
    "dell": "Dell",
    "inspur": "Inspur",
    "xfusion": "XFusion",
    "lenovo": "Lenovo",
    "huawei": "Huawei",
}

SEL_EPOCH = datetime(2026, 9, 1, 0, 0, 0, tzinfo=UTC)
SYSTEM_UUID = "11111111-2222-3333-4444-555555555555"
MANAGER_UUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"


@dataclass(frozen=True)
class SimulatorConfig:
    """Constructor configuration (tests may also switch live via control)."""

    username: str = "admin"
    password: str = "sim-pass-1"
    profile: str = "healthy"
    vendor: str = "generic"
    pagination: str = "skip"  # "skip" | "next_link"
    sel_total: int = 150  # honored by slow_paginated
    sel_page_size: int = 20
    task_duration_seconds: float = 0.15
    media_hosts_required: bool = False
    media_hosts: tuple[str, ...] = ()
    # Emit absolute same-origin URIs (http://host:port/redfish/v1/...) in
    # @odata.id/@odata.nextLink/target/Location/TaskMonitor instead of bare
    # paths — a spec-legal style some real managers use (client must accept).
    absolute_links: bool = False
    # SRV-MON surface knobs (M3T2) — each exercises one strict adapter edge
    # (missing value -> observation error / unsupported capability row):
    # - missing_memory_metrics: DIMM OEM blocks carry no ECC counter;
    # - no_raid_volume: Storage/Volumes collection is empty;
    # - empty_sel: the SEL log service exists but has zero entries;
    # - thermal_missing_context: adds a temperature sensor without a
    #   PhysicalContext (and a name with no certified heuristic);
    # - no_virtual_media: the Manager resource has no VirtualMedia link;
    # - no_storage: the ComputerSystem has no Storage link;
    # - missing_system_status: the ComputerSystem has no Status block;
    # - sel_oem_timestamps: SEL entries carry an OEM timestamp member instead
    #   of the standard Created field.
    missing_memory_metrics: bool = False
    no_raid_volume: bool = False
    empty_sel: bool = False
    thermal_missing_context: bool = False
    no_virtual_media: bool = False
    no_storage: bool = False
    missing_system_status: bool = False
    sel_oem_timestamps: bool = False
    # - missing_fan_reading: the first fan carries no Reading member;
    # - drives_without_oem: drives exist but carry no OEM SMART/predictive
    #   members.
    missing_fan_reading: bool = False
    drives_without_oem: bool = False
    # - sel_append: extra SEL entries appended AFTER the profile's base count
    #   (continuing the Id/timestamp sequence, so they are strictly newer
    #   than every base entry) — lets tests grow a live SEL past the delta
    #   cursor across page boundaries.
    sel_append: int = 0
    # M3T3 operation knobs:
    # - power_blip_seconds: how long the system reports PowerState Off after a
    #   restart/cycle reset task completes (reboot window);
    # - manager_blip_seconds: how long every Redfish request 503s after a
    #   manager reset (the device offline window);
    # - firmware_update_version: version the firmware inventory bumps to when
    #   an update task completes without an image fetch (contract tests);
    # - power_readback_stale: system power effects never apply (read-back can
    #   never observe the target state);
    # - media_insert_rejects_foreign_url: InsertMedia checks the Image host
    #   against ``media_hosts`` (a non-platform URL is rejected with 400);
    # - media_fetch_required / update_fetch_required: InsertMedia/SimpleUpdate
    #   emulate the device actually fetching the Image URL (the platform
    #   ticket route must be live); a failed fetch rejects the action;
    # - update_reboot_loop: the update task completes but the inventory
    #   version never bumps and the system reboots (read-back can never match
    #   the expected version);
    # - reset_never_completes / update_never_completes: the reset/update task
    #   never reaches a terminal state (verification times out -> ambiguous).
    # - no_graceful_shutdown: the ComputerSystem Reset action neither
    #   advertises nor accepts GracefulShutdown (power.off must fail as
    #   unsupported — ForceOff fallback is forbidden).
    power_blip_seconds: float = 0.5
    manager_blip_seconds: float = 1.2
    firmware_update_version: str = ""
    power_readback_stale: bool = False
    media_insert_rejects_foreign_url: bool = False
    media_fetch_required: bool = False
    update_fetch_required: bool = False
    update_reboot_loop: bool = False
    reset_never_completes: bool = False
    update_never_completes: bool = False
    no_graceful_shutdown: bool = False

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ValueError(f"unknown profile {self.profile!r}")
        if self.vendor not in VENDORS:
            raise ValueError(f"unknown vendor {self.vendor!r}")
        if self.pagination not in ("skip", "next_link"):
            raise ValueError(f"unknown pagination {self.pagination!r}")


class _View:
    """Profile-dependent values shared by the payload builders."""

    def __init__(self, cfg: SimulatorConfig) -> None:
        self.cfg = cfg
        self.profile = cfg.profile
        self.vendor = cfg.vendor
        self.health_ok = self.profile != "critical"

    @property
    def health(self) -> str:
        return "OK" if self.health_ok else "Critical"

    @property
    def sel_count(self) -> int:
        if self.cfg.empty_sel:
            return 0
        base = {  # type: ignore[no-any-return]
            "healthy": 4,
            "critical": 25,
            "slow_paginated": self.cfg.sel_total,
            "auth_fail": 4,
        }[self.profile]
        return base + self.cfg.sel_append

    @property
    def sel_page_size(self) -> int:
        if self.profile == "slow_paginated":
            return self.cfg.sel_page_size
        return 100

    def oem_key(self) -> str:
        return _VENDOR_TITLES[self.vendor]

    def oem_type(self, stem: str) -> str:
        title = _VENDOR_TITLES[self.vendor]
        if self.vendor == "generic":
            return f"#WardenSim{stem}.v1_0_0.WardenSim{stem}"
        # Vendor namespace shape (e.g. "#Dell.v1_0_0.DellMemoryMetrics") — the
        # real per-vendor shapes are overlay territory (M3T5).
        return f"#{title}.v1_0_0.{title}{stem}"


def _odata(payload: dict[str, Any], odata_id: str, odata_type: str) -> dict[str, Any]:
    payload["@odata.id"] = odata_id
    payload["@odata.type"] = odata_type
    return payload


def _status(health: str, state: str = "Enabled") -> dict[str, str]:
    return {"State": state, "Health": health}


def service_root(view: _View, *, date_time: datetime) -> dict[str, Any]:
    oem: dict[str, Any] = {}
    if view.profile == "auth_fail":
        oem = {}
    oem[view.oem_key()] = {"@odata.type": view.oem_type("ServiceRoot")}
    return _odata(
        {
            "Id": "RootService",
            "Name": "Root Service",
            "RedfishVersion": "1.16.0",
            "UUID": SYSTEM_UUID,
            "Product": "Warden Simulated BMC (test device simulator)",
            "Systems": {"@odata.id": f"{BASE}/Systems"},
            "Chassis": {"@odata.id": f"{BASE}/Chassis"},
            "Managers": {"@odata.id": f"{BASE}/Managers"},
            "AccountService": {"@odata.id": f"{BASE}/AccountService"},
            "SessionService": {"@odata.id": f"{BASE}/SessionService"},
            "TaskService": {"@odata.id": f"{BASE}/TaskService"},
            "UpdateService": {"@odata.id": f"{BASE}/UpdateService"},
            "Oem": oem,
        },
        f"{BASE}/",
        "#ServiceRoot.v1_16_0.ServiceRoot",
    )


def systems_collection() -> dict[str, Any]:
    return _odata(
        {
            "Members@odata.count": 1,
            "Members": [{"@odata.id": f"{BASE}/Systems/1"}],
        },
        f"{BASE}/Systems",
        "#ComputerSystemCollection.ComputerSystemCollection",
    )


def system(view: _View, *, power_state: str = "On", bios_version: str = "SIM-BIOS-2.0") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "Id": "1",
        "Name": "Warden Simulated Server",
        "SystemType": "Physical",
        "Manufacturer": "Warden Simulator",
        "Model": "Warden SimServer 1U (simulated)",
        "SerialNumber": "WARDEN-SIM-0001",
        "SKU": "SIM-1U",
        "BiosVersion": bios_version,
        "PowerState": power_state,
        "Status": _status(view.health),
        "ProcessorSummary": {
            "Count": 2,
            "Model": "Simulated Xeon 8C",
            "Status": _status("OK"),
        },
        "MemorySummary": {
            "TotalSystemMemoryGiB": 128,
            "Status": _status("OK"),
        },
        "Boot": {"BootSourceOverrideTarget": "None", "BootSourceOverrideEnabled": "Disabled"},
        "Actions": {
            "#ComputerSystem.Reset": {
                "target": f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
                "ResetType@Redfish.AllowableValues": (
                    [
                        "On",
                        "ForceOff",
                        "GracefulRestart",
                        "ForceRestart",
                        "PowerCycle",
                        "Nmi",
                        "PushPowerButton",
                    ]
                    if view.cfg.no_graceful_shutdown
                    else [
                        "On",
                        "ForceOff",
                        "GracefulShutdown",
                        "GracefulRestart",
                        "ForceRestart",
                        "PowerCycle",
                        "Nmi",
                        "PushPowerButton",
                    ]
                ),
            }
        },
        "Memory": {"@odata.id": f"{BASE}/Systems/1/Memory"},
        "Storage": {"@odata.id": f"{BASE}/Systems/1/Storage"},
    }
    if view.profile == "critical":
        payload["Status"] = _status("Critical")
    if view.cfg.missing_system_status:
        payload.pop("Status", None)
    if view.cfg.no_storage:
        payload.pop("Storage", None)
    return _odata(payload, f"{BASE}/Systems/1", "#ComputerSystem.v1_16_0.ComputerSystem")


def memory_collection() -> dict[str, Any]:
    members = [{"@odata.id": f"{BASE}/Systems/1/Memory/DIMM{i}"} for i in range(5)]
    return _odata(
        {"Members@odata.count": len(members), "Members": members},
        f"{BASE}/Systems/1/Memory",
        "#MemoryCollection.MemoryCollection",
    )


def memory_dimm(view: _View, dimm_id: str) -> dict[str, Any]:
    slots = {
        "DIMM0": "DIMM_A1",
        "DIMM1": "DIMM_A2",
        "DIMM2": "DIMM_B1",
        "DIMM3": "DIMM_B2",
        "DIMM4": "DIMM_C1",
    }
    slot = slots[dimm_id]
    if dimm_id == "DIMM4":
        # An EMPTY DIMM slot: no memory device installed (State Absent, no
        # capacity/type/counters). The adapter reports the absent component
        # and no memory points for it.
        return _odata(
            {
                "Id": dimm_id,
                "Name": slot,
                "DeviceLocator": slot,
                "CapacityMiB": 0,
                "Status": _status("OK", state="Absent"),
            },
            f"{BASE}/Systems/1/Memory/{dimm_id}",
            "#Memory.v1_11_0.Memory",
        )
    critical_dimm = view.profile == "critical" and dimm_id == "DIMM1"
    ecc_correctable = 3 + int(dimm_id[-1])
    ecc_uncorrectable = 7 if critical_dimm else 0
    if view.cfg.missing_memory_metrics:
        # No explicit ECC counter anywhere in the OEM block: the adapter must
        # NOT infer one and reports memory.ecc_errors as missing.
        oem_block: dict[str, Any] = {"@odata.type": view.oem_type("MemoryMetrics")}
    else:
        oem_block = {
            "@odata.type": view.oem_type("MemoryMetrics"),
            # Explicit aggregate ECC error counter (correctable + uncorrectable)
            # — the generic shape this simulator certifies for the common
            # adapter (simulator origin only, never 真机).
            "ECCErrorCount": ecc_correctable + ecc_uncorrectable,
            "CorrectableECCErrorCount": ecc_correctable,
            "UncorrectableECCErrorCount": ecc_uncorrectable,
        }
    return _odata(
        {
            "Id": dimm_id,
            "Name": slot,
            "DeviceLocator": slot,
            "MemoryDeviceType": "DDR5",
            "CapacityMiB": 16384,
            "OperatingSpeedMhz": 4800,
            "Status": _status("Critical" if critical_dimm else "OK"),
            "Oem": {view.oem_key(): oem_block},
        },
        f"{BASE}/Systems/1/Memory/{dimm_id}",
        "#Memory.v1_11_0.Memory",
    )


def storage_collection() -> dict[str, Any]:
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/Systems/1/Storage/SATA1"}]},
        f"{BASE}/Systems/1/Storage",
        "#StorageCollection.StorageCollection",
    )


def storage_controller(view: _View) -> dict[str, Any]:
    return {
        "@odata.id": f"{BASE}/Systems/1/Storage/SATA1#/StorageControllers/0",
        "MemberId": "0",
        "Name": "Simulated SATA RAID Controller",
        "Status": _status("OK" if view.health_ok else "Warning"),
    }


def drive(view: _View, drive_id: str) -> dict[str, Any]:
    critical_drive = view.profile == "critical" and drive_id == "sdb"
    health = "Critical" if critical_drive else "OK"
    payload: dict[str, Any] = {
        "Id": drive_id,
        "Name": f"Simulated drive {drive_id}",
        "MediaType": "SSD" if drive_id == "sda" else "HDD",
        "CapacityBytes": 480_000_000_000 if drive_id == "sda" else 4_000_000_000_000,
        "Model": "Warden Sim SSD 480G" if drive_id == "sda" else "Warden Sim HDD 4T",
        "Manufacturer": "Warden Simulator",
        "SerialNumber": f"WARDEN-DSK-{drive_id.upper()}",
        "Revision": "SIM1",
        "Status": _status(health),
    }
    if not view.cfg.drives_without_oem:
        payload["Oem"] = {
            view.oem_key(): {
                "@odata.type": view.oem_type("DriveMetrics"),
                "PredictiveFailure": critical_drive,
                "SMARTStatus": "Failed" if critical_drive else "OK",
            }
        }
    return _odata(payload, f"{BASE}/Systems/1/Storage/SATA1/Drives/{drive_id}", "#Drive.v1_15_0.Drive")


def drives_collection() -> dict[str, Any]:
    members = [
        {"@odata.id": f"{BASE}/Systems/1/Storage/SATA1/Drives/sda"},
        {"@odata.id": f"{BASE}/Systems/1/Storage/SATA1/Drives/sdb"},
    ]
    return _odata(
        {"Members@odata.count": len(members), "Members": members},
        f"{BASE}/Systems/1/Storage/SATA1/Drives",
        "#DriveCollection.DriveCollection",
    )


def volume(view: _View) -> dict[str, Any]:
    degraded = view.profile == "critical"
    oem_block = {
        "@odata.type": view.oem_type("VolumeMetrics"),
        "RAIDStatus": "Degraded" if degraded else "Optimal",
        "RebuildProgressPercent": 62 if degraded else None,
    }
    return _odata(
        {
            "Id": "RAID6_1",
            "Name": "Simulated RAID6 volume",
            "RAIDType": "RAID6",
            "VolumeType": "RAID6",
            "CapacityBytes": 8_000_000_000_000,
            "Status": _status("Critical" if degraded else "OK"),
            "Oem": {view.oem_key(): oem_block},
        },
        f"{BASE}/Systems/1/Storage/SATA1/Volumes/RAID6_1",
        "#Volume.v1_7_0.Volume",
    )


def volumes_collection(view: _View) -> dict[str, Any]:
    if view.cfg.no_raid_volume:
        return _odata(
            {"Members@odata.count": 0, "Members": []},
            f"{BASE}/Systems/1/Storage/SATA1/Volumes",
            "#VolumeCollection.VolumeCollection",
        )
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/Systems/1/Storage/SATA1/Volumes/RAID6_1"}]},
        f"{BASE}/Systems/1/Storage/SATA1/Volumes",
        "#VolumeCollection.VolumeCollection",
    )


def storage_sata1(view: _View) -> dict[str, Any]:
    return _odata(
        {
            "Id": "SATA1",
            "Name": "Simulated SATA storage",
            "Status": _status("OK"),
            "StorageControllers": [storage_controller(view)],
            "Drives": {"@odata.id": f"{BASE}/Systems/1/Storage/SATA1/Drives"},
            "Volumes": {"@odata.id": f"{BASE}/Systems/1/Storage/SATA1/Volumes"},
        },
        f"{BASE}/Systems/1/Storage/SATA1",
        "#Storage.v1_12_0.Storage",
    )


def chassis_collection() -> dict[str, Any]:
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/Chassis/1"}]},
        f"{BASE}/Chassis",
        "#ChassisCollection.ChassisCollection",
    )


def chassis(view: _View) -> dict[str, Any]:
    intrusion = "HardwareIntrusionDetected" if view.profile == "critical" else "Normal"
    payload: dict[str, Any] = {
        "Id": "1",
        "Name": "Warden Simulated Chassis",
        "ChassisType": "RackMount",
        "Manufacturer": "Warden Simulator",
        "Model": "SIM-1U-CHASSIS",
        "SerialNumber": "WARDEN-SIM-CH-1",
        "PartNumber": "SIM-CH-1U-A",
        "PowerState": "On",
        "Status": _status(view.health),
        "IndicatorLED": "Blinking" if view.profile == "critical" else "Off",
        "PhysicalSecurity": {
            "IntrusionSensor": intrusion,
            "IntrusionSensorNumber": 1,
        },
        "Thermal": {"@odata.id": f"{BASE}/Chassis/1/Thermal"},
        "Power": {"@odata.id": f"{BASE}/Chassis/1/Power"},
    }
    return _odata(payload, f"{BASE}/Chassis/1", "#Chassis.v1_19_0.Chassis")


_TEMP_SENSORS = (
    ("CPU1 Temp", "CPU", 42, 85, 40),
    ("CPU2 Temp", "CPU", 41, 85, 40),
    ("Memory Zone Temp", "Memory", 38, 70, 35),
    ("System Board Temp", "Board", 35, 60, 30),
    ("Inlet Temp", "Intake", 24, 45, 20),
)


def thermal(view: _View) -> dict[str, Any]:
    critical = view.profile == "critical"
    temperatures: list[dict[str, Any]] = []
    for name, context, healthy_reading, upper, lower in _TEMP_SENSORS:
        reading = 93 if critical and name == "CPU1 Temp" else healthy_reading
        sensor_health = "Critical" if critical and name == "CPU1 Temp" else "OK"
        temperatures.append(
            {
                "@odata.id": f"{BASE}/Chassis/1/Thermal#/Temperatures/{len(temperatures)}",
                "MemberId": str(len(temperatures)),
                "Name": name,
                "PhysicalContext": context,
                "ReadingCelsius": reading,
                "UpperThresholdCritical": upper,
                "LowerThresholdCritical": lower,
                "Status": _status(sensor_health),
            }
        )
    if view.cfg.thermal_missing_context:
        # A sensor with NO PhysicalContext and a name the common adapter has
        # no certified heuristic for: collect must report an explicit error
        # instead of fabricating a classification.
        temperatures.append(
            {
                "@odata.id": f"{BASE}/Chassis/1/Thermal#/Temperatures/{len(temperatures)}",
                "MemberId": str(len(temperatures)),
                "Name": "Misc Zone Temp",
                "ReadingCelsius": 33,
                "Status": _status("OK"),
            }
        )
    fans: list[dict[str, Any]] = []
    for index in range(1, 5):
        name = f"FAN{index}"
        low = index == 3 and critical
        fan: dict[str, Any] = {
            "@odata.id": f"{BASE}/Chassis/1/Thermal#/Fans/{index - 1}",
            "MemberId": str(index - 1),
            "Name": name,
            "ReadingUnits": "RPM",
            "LowerThresholdCritical": 1200,
            "Status": _status("Critical" if low else "OK"),
        }
        if not (view.cfg.missing_fan_reading and index == 1):
            fan["Reading"] = 800 if low else 7000 + index * 500
        fans.append(fan)
    return _odata(
        {
            "Id": "1",
            "Name": "Simulated thermal",
            "Temperatures": temperatures,
            "Fans": fans,
            "Redundancy": [],
        },
        f"{BASE}/Chassis/1/Thermal",
        "#Thermal.v1_7_0.Thermal",
    )


def power(view: _View) -> dict[str, Any]:
    critical = view.profile == "critical"
    supplies: list[dict[str, Any]] = []
    for index in range(1, 3):
        name = f"PSU{index}"
        absent = critical and index == 2
        supplies.append(
            {
                "@odata.id": f"{BASE}/Chassis/1/Power#/PowerSupplies/{index - 1}",
                "MemberId": str(index - 1),
                "Name": name,
                "Id": name,
                "PowerCapacityWatts": 800,
                # Current output power/voltage readings (M3T2 SRV-MON-05):
                # an ABSENT supply reports null readings — never a fake 0.
                "OutputPowerWatts": None if absent else 240 + index * 20,
                "LastPowerOutputWatts": None if absent else 260 + index * 20,
                "OutputVoltage": None if absent else (12.2 if index == 1 else 12.3),
                "LineInputVoltage": None if absent else 230.0,
                "Voltage": {"ReadingVolts": None if absent else 231.2},
                "Status": _status("OK", state="Absent" if absent else "Enabled"),
            }
        )
    return _odata(
        {
            "Id": "1",
            "Name": "Simulated power",
            "PowerControl": [
                {
                    "@odata.id": f"{BASE}/Chassis/1/Power#/PowerControl/0",
                    "MemberId": "0",
                    "Name": "Simulated system power control",
                    "PowerConsumedWatts": 420 if not critical else 480,
                    "PowerCapacityWatts": 1600,
                }
            ],
            "PowerSupplies": supplies,
            "Redundancy": [],
        },
        f"{BASE}/Chassis/1/Power",
        "#Power.v1_7_1.Power",
    )


def managers_collection() -> dict[str, Any]:
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/Managers/1"}]},
        f"{BASE}/Managers",
        "#ManagerCollection.ManagerCollection",
    )


def manager(
    view: _View, *, date_time: datetime, firmware_version: str = "SIM-BMC-1.0.0"
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "Id": "1",
        "Name": "Simulated BMC",
        "ManagerType": "BMC",
        "Manufacturer": "Warden Simulator",
        "Model": "SIM-BMC",
        "SerialNumber": "WARDEN-SIM-BMC-SN-1",
        "PartNumber": "SIM-BMC-CARD-A1",
        "FirmwareVersion": firmware_version,
        "UUID": MANAGER_UUID,
        "DateTime": date_time.isoformat(),
        "DateTimeLocalOffset": "+00:00",
        "PowerState": "On",
        "Status": _status("OK" if view.health_ok else "Warning"),
        "GraphicalConsole": {
            "ServiceEnabled": True,
            "MaxConcurrentSessions": 1,
        },
        "Actions": {
            "#Manager.Reset": {
                "target": f"{BASE}/Managers/1/Actions/Manager.Reset",
                "ResetType@Redfish.AllowableValues": ["GracefulRestart", "ForceRestart"],
            }
        },
        "LogServices": {"@odata.id": f"{BASE}/Managers/1/LogServices"},
        "VirtualMedia": {"@odata.id": f"{BASE}/Managers/1/VirtualMedia"},
        "NetworkProtocol": {"@odata.id": f"{BASE}/Managers/1/NetworkProtocol"},
        "EthernetInterfaces": {"@odata.id": f"{BASE}/Managers/1/EthernetInterfaces"},
    }
    if view.cfg.no_virtual_media:
        payload.pop("VirtualMedia", None)
    return _odata(payload, f"{BASE}/Managers/1", "#Manager.v1_14_0.Manager")


def log_services_collection() -> dict[str, Any]:
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/Managers/1/LogServices/SEL"}]},
        f"{BASE}/Managers/1/LogServices",
        "#LogServiceCollection.LogServiceCollection",
    )


def sel_log_service(view: _View) -> dict[str, Any]:
    return _odata(
        {
            "Id": "SEL",
            "Name": "System Event Log",
            "LogEntryType": "SEL",
            "OverWritePolicy": "WrapsWhenFull",
            "MaxNumberOfRecords": 4096,
            "Entries": {"@odata.id": f"{BASE}/Managers/1/LogServices/SEL/Entries"},
            "Actions": {
                "#LogService.ClearLog": {"target": f"{BASE}/Managers/1/LogServices/SEL/Actions/LogService.ClearLog"}
            },
        },
        f"{BASE}/Managers/1/LogServices/SEL",
        "#LogService.v1_5_0.LogService",
    )


_SEL_TEMPLATES = (
    ("Critical", "Simulated uncorrectable memory error detected"),
    ("Warning", "Simulated fan below lower critical threshold"),
    ("OK", "Simulated system boot completed"),
    ("OK", "Simulated user login succeeded"),
    ("Warning", "Simulated redundant power supply degraded"),
    ("OK", "Simulated firmware check completed"),
)


def _sel_entries(view: _View) -> list[dict[str, Any]]:
    count = view.sel_count
    entries: list[dict[str, Any]] = []
    for index in range(count):
        severity, message = _SEL_TEMPLATES[index % len(_SEL_TEMPLATES)]
        created = (SEL_EPOCH + timedelta(minutes=13 * index)).isoformat()
        entry: dict[str, Any] = {
            "Id": f"SEL{index + 1:06d}",
            "Name": f"SEL Entry {index + 1}",
            "EntryType": "SEL",
            "Severity": severity,
            "Message": message,
            "SensorType": "Memory" if severity == "Critical" else "Other",
        }
        if view.cfg.sel_oem_timestamps:
            # OEM-timestamp variant: no standard Created; the timestamp lives
            # in an OEM member (adapter must fall back to it).
            entry["Oem"] = {
                view.oem_key(): {
                    "@odata.type": view.oem_type("LogEntryTimestamp"),
                    "Timestamp": created,
                }
            }
        else:
            entry["Created"] = created
        entries.append(
            _odata(
                entry,
                f"{BASE}/Managers/1/LogServices/SEL/Entries/{index + 1}",
                "#LogEntry.v1_8_0.LogEntry",
            )
        )
    return entries


def sel_entries_page(view: _View, *, skip: int, top: int) -> dict[str, Any]:
    entries = _sel_entries(view)
    page = entries[skip : skip + top]
    body: dict[str, Any] = {
        "Members@odata.count": len(entries),
        "Members": page,
    }
    if view.cfg.pagination == "next_link" and skip + len(page) < len(entries):
        body["@odata.nextLink"] = f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip={skip + len(page)}"
    return _odata(
        body,
        f"{BASE}/Managers/1/LogServices/SEL/Entries",
        "#LogEntryCollection.LogEntryCollection",
    )


def media_records() -> dict[str, dict[str, Any]]:
    return {
        "1": {"inserted": False, "image": None, "image_name": None},
        "2": {"inserted": False, "image": None, "image_name": None},
    }


def virtual_media_collection() -> dict[str, Any]:
    return _odata(
        {
            "Members@odata.count": 2,
            "Members": [
                {"@odata.id": f"{BASE}/Managers/1/VirtualMedia/1"},
                {"@odata.id": f"{BASE}/Managers/1/VirtualMedia/2"},
            ],
        },
        f"{BASE}/Managers/1/VirtualMedia",
        "#VirtualMediaCollection.VirtualMediaCollection",
    )


def virtual_media(media_id: str, record: dict[str, Any]) -> dict[str, Any]:
    return _odata(
        {
            "Id": media_id,
            "Name": "CD/DVD" if media_id == "1" else "USB",
            "MediaTypes": ["CD", "DVD"] if media_id == "1" else ["USB"],
            "Inserted": record["inserted"],
            "Image": record["image"],
            "ImageName": record["image_name"],
            "WriteProtected": True,
            "Actions": {
                "#VirtualMedia.InsertMedia": {
                    "target": f"{BASE}/Managers/1/VirtualMedia/{media_id}/Actions/VirtualMedia.InsertMedia"
                },
                "#VirtualMedia.EjectMedia": {
                    "target": f"{BASE}/Managers/1/VirtualMedia/{media_id}/Actions/VirtualMedia.EjectMedia"
                },
            },
        },
        f"{BASE}/Managers/1/VirtualMedia/{media_id}",
        "#VirtualMedia.v1_4_0.VirtualMedia",
    )


def update_service(view: _View) -> dict[str, Any]:
    return _odata(
        {
            "Id": "UpdateService",
            "Name": "Update Service",
            "ServiceEnabled": True,
            "FirmwareInventory": {"@odata.id": f"{BASE}/UpdateService/FirmwareInventory"},
            "Actions": {
                "#UpdateService.SimpleUpdate": {
                    "target": f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
                    "TransferProtocol@Redfish.AllowableValues": ["HTTP", "HTTPS"],
                    "Targets@Redfish.AllowableValues": [
                        f"{BASE}/UpdateService/FirmwareInventory/BMC",
                        f"{BASE}/UpdateService/FirmwareInventory/BIOS",
                    ],
                }
            },
        },
        f"{BASE}/UpdateService",
        "#UpdateService.v1_11_0.UpdateService",
    )


def firmware_inventory_collection() -> dict[str, Any]:
    return _odata(
        {
            "Members@odata.count": 2,
            "Members": [
                {"@odata.id": f"{BASE}/UpdateService/FirmwareInventory/BMC"},
                {"@odata.id": f"{BASE}/UpdateService/FirmwareInventory/BIOS"},
            ],
        },
        f"{BASE}/UpdateService/FirmwareInventory",
        "#SoftwareInventoryCollection.SoftwareInventoryCollection",
    )


def firmware_inventory(component_id: str, *, version: str) -> dict[str, Any]:
    return _odata(
        {
            "Id": component_id,
            "Name": f"{component_id} firmware",
            "Version": version,
            "Updateable": True,
            "Status": _status("OK"),
        },
        f"{BASE}/UpdateService/FirmwareInventory/{component_id}",
        "#SoftwareInventory.v1_6_0.SoftwareInventory",
    )


def session_service() -> dict[str, Any]:
    return _odata(
        {
            "Id": "SessionService",
            "Name": "Session Service",
            "ServiceEnabled": True,
            "SessionTimeout": 1800,
            "Sessions": {"@odata.id": f"{BASE}/SessionService/Sessions"},
        },
        f"{BASE}/SessionService",
        "#SessionService.v1_1_8.SessionService",
    )


def sessions_collection(session_ids: list[str]) -> dict[str, Any]:
    members = [{"@odata.id": f"{BASE}/SessionService/Sessions/{session_id}"} for session_id in session_ids]
    return _odata(
        {"Members@odata.count": len(members), "Members": members},
        f"{BASE}/SessionService/Sessions",
        "#SessionCollection.SessionCollection",
    )


def session(session_id: str, username: str) -> dict[str, Any]:
    return _odata(
        {
            "Id": session_id,
            "Name": "User Session",
            "UserName": username,
        },
        f"{BASE}/SessionService/Sessions/{session_id}",
        "#Session.v1_2_1.Session",
    )


def account_service() -> dict[str, Any]:
    return _odata(
        {
            "Id": "AccountService",
            "Name": "Account Service",
            "ServiceEnabled": True,
            "MinPasswordLength": 8,
            "Accounts": {"@odata.id": f"{BASE}/AccountService/Accounts"},
        },
        f"{BASE}/AccountService",
        "#AccountService.v1_12_0.AccountService",
    )


def accounts_collection() -> dict[str, Any]:
    return _odata(
        {"Members@odata.count": 1, "Members": [{"@odata.id": f"{BASE}/AccountService/Accounts/1"}]},
        f"{BASE}/AccountService/Accounts",
        "#ManagerAccountCollection.ManagerAccountCollection",
    )


def account(username: str) -> dict[str, Any]:
    return _odata(
        {
            "Id": "1",
            "Name": username,
            "UserName": username,
            "RoleId": "Administrator",
            "Enabled": True,
        },
        f"{BASE}/AccountService/Accounts/1",
        "#ManagerAccount.v1_9_0.ManagerAccount",
    )


def task_service() -> dict[str, Any]:
    return _odata(
        {
            "Id": "TaskService",
            "Name": "Task Service",
            "ServiceEnabled": True,
            "Tasks": {"@odata.id": f"{BASE}/TaskService/Tasks"},
        },
        f"{BASE}/TaskService",
        "#TaskService.v1_2_0.TaskService",
    )


def tasks_collection(task_ids: list[str]) -> dict[str, Any]:
    members = [{"@odata.id": f"{BASE}/TaskService/Tasks/{task_id}"} for task_id in task_ids]
    return _odata(
        {"Members@odata.count": len(members), "Members": members},
        f"{BASE}/TaskService/Tasks",
        "#TaskCollection.TaskCollection",
    )


def task(
    task_id: str,
    name: str,
    *,
    created_at: datetime,
    state: str,
    status: str,
    messages: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "Id": task_id,
        "Name": name,
        "TaskState": state,
        "TaskStatus": status,
        "StartTime": created_at.isoformat(),
        "Messages": messages or [],
        "TaskMonitor": f"{BASE}/TaskService/Tasks/{task_id}/TaskMonitor",
    }
    if state in ("Completed", "Exception", "Killed", "Cancelled"):
        payload["EndTime"] = created_at.isoformat()
    return _odata(payload, f"{BASE}/TaskService/Tasks/{task_id}", "#Task.v1_7_1.Task")


def task_monitor(task_id: str, *, state: str, percent: int) -> dict[str, Any]:
    return _odata(
        {
            "Id": task_id,
            "Name": f"Task {task_id} monitor",
            "TaskState": state,
            "PercentComplete": percent,
        },
        f"{BASE}/TaskService/Tasks/{task_id}/TaskMonitor",
        "#TaskMonitor.v1_5_1.TaskMonitor",
    )
