"""Redfish device adapters (docs/DEVICE_ADAPTERS.md §3/§4).

``common.py`` hosts the shared Redfish base adapter (``server.redfish`` — a
registered dev/test adapter for server-type devices). The certification-target
vendor overlays (server.dell_idrac, server.inspur_ibmc, server.xfusion_ibmc,
server.lenovo_xcc, server.huawei_ibmc — M3T5: dell.py/inspur.py/xfusion.py/
lenovo.py/huawei.py) subclass this base and carry ONLY certified vendor
differences (probe identity gates + power.cycle ResetType pins where
simulator-verified); every OEM-specific collect/ops path stays experimental
or unsupported-until-real-hardware until sanitized 真机 fixtures exist
(module ledgers + docs/DEVICE_ADAPTERS.md §10).
"""
