"""Dell iDRAC overlay — adapter_key ``server.dell_idrac`` (M3T5).

Registration: a REAL registered adapter for server-type devices subclassing
``RedfishCommonAdapter``; devices saved with this key probe-verify that the
device self-identifies as a Dell server (hardware-targets.json target
``server.dell_idrac``, certification_scope=management_family,
exact_model_must_be_recorded).

Honesty ledger for this overlay (docs/DEVICE_ADAPTERS.md §4/§10,
HARDWARE_CERTIFICATION.md §3 — simulator is NOT 真机; the certification
matrix stays ``not_started`` and real-device runs are the release gate):

- **simulator-verified** (covered by the Dell vendor-profile fixture tests,
  tests/fixtures/redfish/system-dell-healthy.json + memory/drive profile
  fixtures, captured 2026-09-03 from the TEST-DEVICE simulator):
  - probe identity gate: ComputerSystem.Manufacturer must contain ``dell``
    (the simulated iDRAC self-reports "Dell Inc.");
  - power.cycle certified ResetType pin: ``ForceRestart`` only (the M3T5
    brief mapping — iDRAC maps ForceRestart to the 强制重启/power-cycle
    semantic); a device that does not advertise ForceRestart is refused at
    preflight (never a silent PowerCycle substitution — contracts/
    operations.json precondition "mapped in the certified overlay");
  - manager.reset / KVM launch / support bundle / firmware update /
    virtual media keep the common Redfish-standard paths (Manager.Reset
    GracefulRestart, GraphicalConsole URL descriptor, SEL+LogService export,
    SimpleUpdate) — the standard surface the simulator profile emits.
- **experimental / unsupported-until-real-hardware** (no 真机 or
  vendor-doc-verified basis; discovery and the UI never claim support for
  them):
  - real iDRAC OEM member names for ECC/SMART/predictive-failure/RAID
    (Oem.Dell shapes such as DellMemory/DellPhysicalDisk member names are
    NOT fixture-verified — the vendor profile only emits the generic OEM
    members under the Dell namespace; the overlay parses nothing vendor-only
    until a sanitized 真机 fixture exists);
  - TSR via the Dell OEM support-assist API (SRV-ACT-04 OEM job path);
  - iDRAC HTML5 KVM session creation API (SRV-ACT-03 — launch keeps the
    common GraphicalConsole URL descriptor, never a fabricated session);
  - OEM cold-reset variants (Actions/Oem/Dell/... Manager.Reset) and Dell
    OEM firmware/job update paths (SRV-ACT-06).
- **doc URLs consulted** (2026-09-03; external vendor pages were blocked in
  this environment — 403/reCAPTCHA — so no vendor member name or endpoint
  below is doc-verified):
  - https://www.dell.com/support/kbdoc/en-us/000176965 (iDRAC9 Redfish API
    Guide KBA — HTTP 403);
  - https://infohub.delltechnologies.com/en-us/l/dell-poweredge-servers-idrac9-redfish-api-guide-7/
    (reCAPTCHA wall);
  - Redfish standard baseline cited in DEVICE_ADAPTERS.md §4:
    https://redfish.dmtf.org/schemas/DSP8010_2026.1.html.
"""

from __future__ import annotations

from app.adapters.redfish.common import RedfishCommonAdapter
from app.domain.adapter import AdapterError
from app.infrastructure.protocols.redfish.parse import RedfishResource

IDENTITY_MANUFACTURER_KEYWORD = "dell"
IDENTITY_MANUFACTURER_EXAMPLE = "Dell Inc."

#: Vendor identity requirements (probe gate; shown in stage detail on
#: mismatch). Simulator-verified against the Dell vendor profile — the exact
#: real iDRAC Manufacturer string is re-recorded at certification time
#: (hardware-targets.json: exact_model_must_be_recorded).
vendor_identity_checks: tuple[str, ...] = (
    "ComputerSystem.Manufacturer 必须包含 'dell'（iDRAC 自述如 'Dell Inc.'）",
    "设备自述型号与 PowerEdge 系列一致（真机认证时记录精确型号）",
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


class DellIdracAdapter(RedfishCommonAdapter):
    """Dell iDRAC Redfish adapter (target server.dell_idrac, M3T5).

    Certified differences over the common adapter are ONLY: the probe
    identity gate and the power.cycle ResetType pin below; every other
    surface is the common Redfish path (module ledger lists what stays
    experimental/unsupported-until-real-hardware).
    """

    adapter_key = "server.dell_idrac"
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
        # basis: tests/fixtures/redfish/system-dell-healthy.json (simulator-verified)
        return _identity_failures(system, self.adapter_key)

    def _reset_type_for_cycle(self, allowable: frozenset[str] | None) -> tuple[str, str]:
        # basis: tests/fixtures/redfish/system-dell-healthy.json (simulator-verified)
        #   M3T5 brief iDRAC mapping: ForceRestart = 强制重启语义; the
        #   real-firmware semantics stay experimental until a real-device run
        #   records them (overlay docstring ledger).
        if allowable is None or "ForceRestart" not in allowable:
            raise AdapterError(
                "unsupported_capability",
                "iDRAC 认证映射为 ForceRestart，但设备未通告该类型（不静默回退 PowerCycle）",
                stage="execute",
            )
        return "ForceRestart", "ForceRestart（iDRAC 强制重启语义，模拟器夹具验证；真机语义待认证）"
