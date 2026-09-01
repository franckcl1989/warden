"""Device adapters (docs/DEVICE_ADAPTERS.md §3).

M1T3 ships only the fake CI onboarding adapter; the real vendor adapters
arrive with M3 (server.dell_idrac etc.), at which point the registry grows.
"""

from app.adapters.registry import ADAPTERS, UnknownAdapterError, adapter_for_device_type, get_adapter

__all__ = ["ADAPTERS", "UnknownAdapterError", "adapter_for_device_type", "get_adapter"]
