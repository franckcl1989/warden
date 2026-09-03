"""xFusion iBMC overlay — adapter_key ``server.xfusion_ibmc`` (M3T5).

Registration: a REAL registered adapter for server-type devices subclassing
``RedfishCommonAdapter``; devices saved with this key probe-verify that the
device self-identifies as an xFusion server (hardware-targets.json target
``server.xfusion_ibmc``, certification_scope=management_family,
exact_model_must_be_recorded). xFusion iBMC and Inspur iBMC are separate
certification targets (same iBMC family); they are implemented as separate
overlay modules on purpose so each target's identity gate and future
certified differences stay independently traceable — no shared iBMC code is
introduced before a documented identical behavior exists (M3T5 brief rule).

Honesty ledger for this overlay (docs/DEVICE_ADAPTERS.md §4/§10,
HARDWARE_CERTIFICATION.md §3 — simulator is NOT 真机; the certification
matrix stays ``not_started`` and real-device runs are the release gate):

- **simulator-verified** (covered by the xFusion vendor-profile fixture
  tests, tests/fixtures/redfish/system-xfusion-healthy.json + memory/drive
  profile fixtures, captured 2026-09-03 from the TEST-DEVICE simulator):
  - probe identity gate: ComputerSystem.Manufacturer must contain
    ``xfusion`` (case-insensitive; the simulated iBMC self-reports
    "XFusion" — the exact real-device string is re-recorded at
    certification time);
  - power.cycle mapping: inherited from the common adapter rule
    (ForceRestart when advertised else PowerCycle). iBMC ResetType
    semantics are NOT doc/真机-verified, so NO vendor pin is claimed here;
    a certified iBMC pin lands with real-device evidence;
  - manager.reset / KVM launch / support bundle / firmware update /
    virtual media keep the common Redfish-standard paths.
- **experimental / unsupported-until-real-hardware** (no 真机 or
  vendor-doc-verified basis; discovery and the UI never claim support for
  them):
  - real iBMC OEM member names for ECC/SMART/predictive-failure/RAID and
    the xFusion OEM namespace (the vendor profile only emits the generic
    OEM members under the XFusion namespace; nothing vendor-only is parsed
    until a sanitized 真机 fixture exists);
  - iBMC TSR/support-dump OEM job (SRV-ACT-04), HTML5 KVM session creation
    API (SRV-ACT-03), cold-reset OEM variants (SRV-ACT-01) and iBMC OEM
    firmware/job update paths (SRV-ACT-06);
  - the xFusion public iBMC Redfish documentation was NOT reachable from
    this environment, so no mapping below is doc-verified.
- **doc URLs consulted** (2026-09-03):
  - https://www.xfusion.com/ (support portal; no public iBMC Redfish guide
    reachable without login);
  - Redfish standard baseline cited in DEVICE_ADAPTERS.md §4:
    https://redfish.dmtf.org/schemas/DSP8010_2026.1.html.
"""

from __future__ import annotations

from app.adapters.redfish.common import RedfishCommonAdapter
from app.infrastructure.protocols.redfish.parse import RedfishResource

IDENTITY_MANUFACTURER_KEYWORD = "xfusion"
IDENTITY_MANUFACTURER_EXAMPLE = "XFusion"

#: Vendor identity requirements (probe gate; shown in stage detail on
#: mismatch). Simulator-verified against the xFusion vendor profile — the
#: exact real iBMC Manufacturer string is re-recorded at certification time
#: (hardware-targets.json: exact_model_must_be_recorded).
vendor_identity_checks: tuple[str, ...] = (
    "ComputerSystem.Manufacturer 必须包含 'xfusion'（iBMC 自述如 'XFusion'）",
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


class XfusionIbmcAdapter(RedfishCommonAdapter):
    """xFusion iBMC Redfish adapter (target server.xfusion_ibmc, M3T5).

    Certified difference over the common adapter is ONLY the probe identity
    gate; every other surface is the common Redfish path (module ledger
    lists what stays experimental/unsupported-until-real-hardware). The
    power.cycle mapping stays the common rule — no iBMC-specific pin is
    claimed without real-device or vendor-doc evidence.
    """

    adapter_key = "server.xfusion_ibmc"
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
        # basis: tests/fixtures/redfish/system-xfusion-healthy.json (simulator-verified)
        return _identity_failures(system, self.adapter_key)
