"""Device adapter registry (docs/DEVICE_ADAPTERS.md §3).

M1T3 registers only the fake CI adapter; the real vendor adapters
(server.dell_idrac, nas.synology_dsm, switch.huawei_vrp_*) land with M3. The
device API must reject any adapter_key not present here (422 validation_failed
field=adapter_key) — unknown drivers are never accepted for onboarding.
"""

from __future__ import annotations

from app.adapters.fake import FakeSimpleAdapter
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

    Raises ``UnknownAdapterError`` when no adapter (or more than one — future
    milestone) serves the type.
    """
    matches = [adapter for adapter in ADAPTERS.values() if device_type in adapter.supported_device_types]
    if len(matches) != 1:
        msg = f"no unique adapter for device_type {device_type!r} (matches={len(matches)})"
        raise UnknownAdapterError(msg)
    return matches[0]


register(FakeSimpleAdapter())
