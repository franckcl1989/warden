"""Device adapter registry (docs/DEVICE_ADAPTERS.md §3).

M1T3 registers the fake CI adapter; M3T2 adds the common Redfish base
(``server.redfish``, a real registered adapter for server-type devices —
dev/testing flows against the Redfish simulator; NOT a certification target);
M3T5 registers the five certification-target vendor overlays
(server.dell_idrac, server.inspur_ibmc, server.xfusion_ibmc,
server.lenovo_xcc, server.huawei_ibmc) subclassing the common base; M4T2
registers ``nas.synology_dsm`` (the certification-target adapter for
synology_nas — DS224+/DS225+, monitoring probe/discover/collect only until
the NAS-ACT milestones); M5T2 registers the two Huawei VRP switch adapters
(``switch.huawei_vrp_core`` for S5732-H48XUM2CC / S5731S-S48P4X-A and
``switch.huawei_vrp_access`` for S5735-L48P4S-A1 — SNMP monitoring
probe/discover/collect; the SSH/CLI operation surface arrives in M5T3).
The device API rejects any adapter_key not present
here (422 validation_failed field=adapter_key) — unknown drivers are never
accepted for onboarding.
"""

from __future__ import annotations

from app.adapters.dsm import SynologyDsmAdapter
from app.adapters.fake import FakeSimpleAdapter
from app.adapters.huawei.access import HuaweiVrpAccessAdapter
from app.adapters.huawei.core import HuaweiVrpCoreAdapter
from app.adapters.redfish.common import RedfishCommonAdapter
from app.adapters.redfish.dell import DellIdracAdapter
from app.adapters.redfish.huawei import HuaweiIbmcAdapter
from app.adapters.redfish.inspur import InspurIbmcAdapter
from app.adapters.redfish.lenovo import LenovoXccAdapter
from app.adapters.redfish.xfusion import XfusionIbmcAdapter
from app.domain.adapter import DeviceAdapter


class UnknownAdapterError(KeyError):
    """Raised for adapter_keys not present in the registry."""


ADAPTERS: dict[str, DeviceAdapter] = {}


def register(adapter: DeviceAdapter) -> None:
    if adapter.adapter_key in ADAPTERS:
        msg = f"adapter {adapter.adapter_key!r} is already registered"
        raise ValueError(msg)
    ADAPTERS[adapter.adapter_key] = adapter


def get_adapter(adapter_key: str) -> DeviceAdapter:
    try:
        return ADAPTERS[adapter_key]
    except KeyError as exc:
        raise UnknownAdapterError(adapter_key) from exc


def adapter_for_device_type(device_type: str) -> DeviceAdapter:
    """The single registered adapter serving ``device_type``.

    Raises ``UnknownAdapterError`` when no adapter serves the type, or when
    several do (two server adapters exist since M3T2: fake.simple and
    server.redfish; onboarding always selects by adapter_key, so callers that
    need a unique per-type adapter must filter explicitly).
    """
    matches = [adapter for adapter in ADAPTERS.values() if device_type in adapter.supported_device_types]
    if len(matches) != 1:
        msg = f"no unique adapter for device_type {device_type!r} (matches={len(matches)})"
        raise UnknownAdapterError(msg)
    return matches[0]


register(FakeSimpleAdapter())
register(RedfishCommonAdapter())
register(DellIdracAdapter())
register(InspurIbmcAdapter())
register(XfusionIbmcAdapter())
register(LenovoXccAdapter())
register(HuaweiIbmcAdapter())
register(SynologyDsmAdapter())
register(HuaweiVrpCoreAdapter())
register(HuaweiVrpAccessAdapter())
