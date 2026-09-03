"""Redfish device adapters (docs/DEVICE_ADAPTERS.md §3/§4).

``common.py`` hosts the shared Redfish base adapter (``server.redfish`` — a
registered dev/test adapter for server-type devices). The certification-target
vendor adapter keys (server.dell_idrac, server.inspur_ibmc,
server.xfusion_ibmc, server.lenovo_xcc, server.huawei_ibmc) arrive in M3T5 by
subclassing this base; nothing vendor-specific lives here.
"""
