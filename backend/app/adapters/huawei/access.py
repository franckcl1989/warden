"""Access-switch Huawei VRP SNMP adapter — ``switch.huawei_vrp_access`` (M5T2).

Certified target (contracts/hardware-targets.json, exact_model):
S5735-L48P4S-A1. Implements the ACCESS-MON-01..05 SNMP mappings: system
cpu/memory, interfaces (status + 64-bit counter rates + errors), PoE
per-port + device power/budget/percent/alarm, PSU/fan/temperature entities,
and uplink-port transceiver rx/tx power — OIDs and semantics per the ledger
in ``oids.py`` and the mapping notes in ``base.py``/DEVICE_ADAPTERS.md §6.4.

ACCESS-MON-05 reads only rx/tx power; ACCESS-MON-03 PoE percent requires
the device budget denominator and alarms come only from the device's own
alarm state (ADR-016/025; base module docs).
"""

from __future__ import annotations

from app.adapters.huawei.base import MODEL_S5735_L48P4S_A1, HuaweiVrpAdapter

CERTIFIED_ACCESS_MODELS: tuple[str, ...] = (MODEL_S5735_L48P4S_A1,)


class HuaweiVrpAccessAdapter(HuaweiVrpAdapter):
    """Huawei VRP access-switch adapter (S5735-L48P4S-A1)."""

    adapter_key = "switch.huawei_vrp_access"
    supported_device_types: frozenset[str] = frozenset({"access_switch"})
    certified_models = CERTIFIED_ACCESS_MODELS

    #: ACCESS-ACT keys wired over the VRP SSH executor (DEVICE_ADAPTERS.md
    #: §6.4).
    ssh_operation_keys: frozenset[str] = frozenset(
        {
            "device.restart",
            "interface.admin.set",
            "poe.port.set",
            "logs.collect",
            "config.backup",
            "config.restore",
            "firmware.update",
        }
    )

    #: M5T4 browser-terminal keys (ADR-007): ACCESS-ACT-04 has SSH + Web —
    #: only console.ssh.open is a terminal; console.web.open is the M5T5
    #: Web-management URL descriptor (ADR-006) pinned in ``web_console_keys``.
    terminal_console_keys: frozenset[str] = frozenset({"console.ssh.open"})

    #: M5T5 Web-management console keys (ACCESS-ACT-04, ADR-006).
    web_console_keys: frozenset[str] = frozenset({"console.web.open"})

    family_keys: dict[str, tuple[str, ...]] = {
        "system": ("system.cpu_percent", "system.memory_percent"),
        "interfaces": (
            "interface.admin_status",
            "interface.oper_status",
            "interface.in_bps",
            "interface.out_bps",
            "interface.errors",
        ),
        "optics": ("transceiver.rx_dbm", "transceiver.tx_dbm"),
        "entities": ("psu.status", "fan.rpm", "fan.status", "temperature.system"),
        "poe": (
            "poe.port.status",
            "poe.port.power_w",
            "poe.total_power_w",
            "poe.power_budget_w",
            "poe.total_power_percent",
            "poe.total_power_alarm",
        ),
    }
