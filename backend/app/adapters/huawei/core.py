"""Core-switch Huawei VRP SNMP adapter — ``switch.huawei_vrp_core`` (M5T2).

Certified targets (contracts/hardware-targets.json, exact_model):
S5732-H48XUM2CC and S5731S-S48P4X-A. Implements the CORE-MON-01..05 SNMP
mappings (CORE-MON-06 events flow through the M5T1 ingest path):
system cpu/memory, interfaces (incl. 64-bit counter rates + CRC/drops),
transceiver diagnostics, PSU/fan/temperature entities, layer2
loop/broadcast/STP — OIDs and semantics per the ledger in ``oids.py`` and
the mapping notes in ``base.py``/DEVICE_ADAPTERS.md §6.2.
"""

from __future__ import annotations

from app.adapters.huawei.base import (
    MODEL_S5731S_S48P4X_A,
    MODEL_S5732_H48XUM2CC,
    HuaweiVrpAdapter,
)

CERTIFIED_CORE_MODELS: tuple[str, ...] = (MODEL_S5732_H48XUM2CC, MODEL_S5731S_S48P4X_A)


class HuaweiVrpCoreAdapter(HuaweiVrpAdapter):
    """Huawei VRP core-switch adapter (S5732-H48XUM2CC / S5731S-S48P4X-A)."""

    adapter_key = "switch.huawei_vrp_core"
    supported_device_types: frozenset[str] = frozenset({"core_switch"})
    certified_models = CERTIFIED_CORE_MODELS
    event_keys = ("event.port_flap", "event.device_restart", "event.auth_failure")

    family_keys: dict[str, tuple[str, ...]] = {
        "system": ("system.cpu_percent", "system.memory_percent"),
        "interfaces": (
            "interface.admin_status",
            "interface.oper_status",
            "interface.in_bps",
            "interface.out_bps",
            "interface.crc_errors",
            "interface.errors",
            "interface.drops",
        ),
        "optics": (
            "transceiver.rx_dbm",
            "transceiver.tx_dbm",
            "transceiver.temperature_c",
            "transceiver.voltage_v",
            "transceiver.current_ma",
        ),
        "entities": ("psu.present", "psu.status", "fan.rpm", "fan.status", "temperature.system"),
        "layer2": ("loop.status", "broadcast_storm.status", "stp.port_state"),
    }
