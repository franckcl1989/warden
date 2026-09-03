"""Huawei iBMC overlay — adapter_key ``server.huawei_ibmc`` (M3T5).

Registration: a REAL registered adapter for server-type devices subclassing
``RedfishCommonAdapter``; devices saved with this key probe-verify that the
device self-identifies as a Huawei server (hardware-targets.json target
``server.huawei_ibmc``, certification_scope=management_family,
exact_model_must_be_recorded).

Honesty ledger for this overlay (docs/DEVICE_ADAPTERS.md §4/§10,
HARDWARE_CERTIFICATION.md §3 — simulator is NOT 真机; the certification
matrix stays ``not_started`` and real-device runs are the release gate):

- **simulator-verified** (covered by the Huawei vendor-profile fixture
  tests, tests/fixtures/redfish/system-huawei-healthy.json + memory/drive
  profile fixtures, captured 2026-09-03 from the TEST-DEVICE simulator):
  - probe identity gate: ComputerSystem.Manufacturer must contain
    ``huawei``;
  - power.cycle certified ResetType pin per the M3T5 brief:
    ``PowerCycle`` when the device advertises it, else ``ForceRestart``
    when advertised; a device advertising neither is refused at preflight
    (the recorded evidence shows which mapping ran);
  - manager.reset / KVM launch / support bundle / firmware update /
    virtual media keep the common Redfish-standard paths.
- **experimental / unsupported-until-real-hardware** (no 真机 or
  vendor-doc-verified basis; discovery and the UI never claim support for
  them):
  - real iBMC OEM member names for ECC/SMART/predictive-failure/RAID and
    the Huawei OEM namespace (the vendor profile only emits the generic OEM
    members under the Huawei namespace; nothing vendor-only is parsed
    until a sanitized 真机 fixture exists);
  - Huawei OEM Actions/Oem/Huawei TSR/support-dump job (SRV-ACT-04),
    HTML5 KVM session creation API (SRV-ACT-03), cold-reset OEM variants
    (SRV-ACT-01) and Huawei OEM firmware/job update paths (SRV-ACT-06).
- **doc URLs consulted** (2026-09-03; the Huawei support pages were not
  reachable from this environment — login/JS-walled, no response — so no
  vendor member name or endpoint below is doc-verified):
  - https://support.huawei.com/enterprise/en/ (iBMC Redfish user guide
    entries require enterprise login);
  - Redfish standard baseline cited in DEVICE_ADAPTERS.md §4:
    https://redfish.dmtf.org/schemas/DSP8010_2026.1.html.
"""

from __future__ import annotations

from app.adapters.redfish.common import RedfishCommonAdapter
from app.domain.adapter import AdapterError
from app.infrastructure.protocols.redfish.parse import RedfishResource

IDENTITY_MANUFACTURER_KEYWORD = "huawei"
IDENTITY_MANUFACTURER_EXAMPLE = "Huawei"

#: Vendor identity requirements (probe gate; shown in stage detail on
#: mismatch). Simulator-verified against the Huawei vendor profile — the
#: exact real iBMC Manufacturer string is re-recorded at certification time
#: (hardware-targets.json: exact_model_must_be_recorded).
vendor_identity_checks: tuple[str, ...] = (
    "ComputerSystem.Manufacturer 必须包含 'huawei'（iBMC 自述如 'Huawei'）",
)


def _identity_failures(system: RedfishResource, adapter_key: str) -> tuple[str, ...]:
    raw = system.get("Manufacturer")
    manufacturer = raw if isinstance(raw, str) else ""
    normalized = "".join(manufacturer.split()).lower()
    if IDENTITY_MANUFACTURER_KEYWORD in normalized:
        return ()
    return (
        f"设备自述厂商 {manufacturer or '(缺失)'} 与适配器 {adapter_key} 认证厂商不符"
        f"（Manufacturer 需包含 {IDENTITY_MANUFACTURER_KEYWORD!r}）",
    )


class HuaweiIbmcAdapter(RedfishCommonAdapter):
    """Huawei iBMC Redfish adapter (target server.huawei_ibmc, M3T5).

    Certified differences over the common adapter are ONLY: the probe
    identity gate and the power.cycle ResetType pin below; every other
    surface is the common Redfish path (module ledger lists what stays
    experimental/unsupported-until-real-hardware).
    """

    adapter_key = "server.huawei_ibmc"
    supported_device_types = frozenset({"server"})
    adapter_version = "0.1.0"
    secret_schema_version = 1
    secret_schema: dict[str, object] = {
        "type": "object",
        "required": ["username", "password"],
        "additionalProperties": False,
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
        },
    }

    def _probe_identity_checks(self, system: RedfishResource) -> tuple[str, ...]:
        # basis: tests/fixtures/redfish/system-huawei-healthy.json (simulator-verified)
        return _identity_failures(system, self.adapter_key)

    def _reset_type_for_cycle(self, allowable: frozenset[str] | None) -> tuple[str, str]:
        # basis: tests/fixtures/redfish/system-huawei-healthy.json (simulator-verified)
        #   M3T5 brief iBMC mapping: PowerCycle if advertised else
        #   ForceRestart; the real-firmware semantics stay experimental until
        #   a real-device run records them (overlay docstring ledger).
        if allowable is None:
            raise AdapterError(
                "unsupported_capability",
                "iBMC 认证映射为 PowerCycle/ForceRestart，但设备未通告可用类型（不静默猜测）",
                stage="execute",
            )
        if "PowerCycle" in allowable:
            return "PowerCycle", "PowerCycle（iBMC 强制重启语义优先，模拟器夹具验证；真机语义待认证）"
        if "ForceRestart" in allowable:
            return "ForceRestart", "ForceRestart（iBMC 未通告 PowerCycle 时的回退映射，模拟器夹具验证；真机语义待认证）"
        raise AdapterError(
            "unsupported_capability",
            "iBMC 认证映射为 PowerCycle/ForceRestart，但设备未通告其中任一类型（不静默替换）",
            stage="execute",
        )
