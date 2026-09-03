"""Switch model profiles for the Warden Huawei-switch TEST-DEVICE SIMULATOR.

Every profile is SIMULATOR DSL (basis [sim]): the exact model strings come
from contracts/hardware-targets.json, but the sysDescr wording, VRP version
strings, port layouts and engine ids are simulator-declared fixtures that
M5 hardware certification must replace with per-model/VRP evidence (ADR-018;
see README.md in this package). Nothing here is evidence of real hardware
support.
"""

from __future__ import annotations

from dataclasses import dataclass

# Hardware-target declared model strings (contracts/hardware-targets.json).
MODEL_S5732_H48XUM2CC = "S5732-H48XUM2CC"
MODEL_S5731S_S48P4X_A = "S5731S-S48P4X-A"
MODEL_S5735_L48P4S_A1 = "S5735-L48P4S-A1"

# Fixed USM engine id per profile (hex, authoritative sender id the platform
# receiver registers; see M5T1 report). Deterministic per profile so tests
# and device configs agree.
_ENGINE_IDS = {
    MODEL_S5732_H48XUM2CC: "73353733322d6869642d30303031",  # s5732-hid-0001
    MODEL_S5731S_S48P4X_A: "7335373331732d6869642d30303031",  # s5731s-hid-0001
    MODEL_S5735_L48P4S_A1: "73353733352d6869642d30303031",  # s5735-hid-0001
}


@dataclass(frozen=True)
class SwitchProfile:
    """One simulator profile: identity + served hardware layout ([sim] DSL)."""

    profile_key: str  # core_s5732 | core_s5731s | access_s5735
    device_type: str  # core_switch | access_switch (contracts vocabulary)
    adapter_key: str
    target_id: str  # contracts/hardware-targets.json target_id
    model: str
    vrp_version: str
    sys_descr: str
    sys_name: str
    ge_port_count: int
    xge_port_count: int
    engine_id_hex: str


def _core_profile(
    profile_key: str, model: str, target_id: str, vrp: str, sys_name: str, ge: int, xge: int
) -> SwitchProfile:
    return SwitchProfile(
        profile_key=profile_key,
        device_type="core_switch",
        adapter_key="switch.huawei_vrp_core",
        target_id=target_id,
        model=model,
        vrp_version=vrp,
        sys_descr=(
            f"Huawei Technologies Co., Ltd. {model} simulator, "
            f"VRP (R) software, Version {vrp} ({model})"
        ),
        sys_name=sys_name,
        ge_port_count=ge,
        xge_port_count=xge,
        engine_id_hex=_ENGINE_IDS[model],
    )


def _access_profile(
    profile_key: str, model: str, target_id: str, vrp: str, sys_name: str, ge: int, sfp: int
) -> SwitchProfile:
    return SwitchProfile(
        profile_key=profile_key,
        device_type="access_switch",
        adapter_key="switch.huawei_vrp_access",
        target_id=target_id,
        model=model,
        vrp_version=vrp,
        sys_descr=(
            f"Huawei Technologies Co., Ltd. {model} simulator, "
            f"VRP (R) software, Version {vrp} ({model})"
        ),
        sys_name=sys_name,
        ge_port_count=ge,
        xge_port_count=sfp,
        engine_id_hex=_ENGINE_IDS[model],
    )


PROFILES: tuple[SwitchProfile, ...] = (
    _core_profile(
        "core_s5732",
        MODEL_S5732_H48XUM2CC,
        "core.huawei_s5732_h48xum2cc",
        "V200R021C10SPC600",
        "sim-s5732-h48xum2cc-1",
        ge=48,
        xge=4,
    ),
    _core_profile(
        "core_s5731s",
        MODEL_S5731S_S48P4X_A,
        "core.huawei_s5731s_s48p4x_a",
        "V200R019C10SPC600",
        "sim-s5731s-s48p4x-a-1",
        ge=48,
        xge=4,
    ),
    _access_profile(
        "access_s5735",
        MODEL_S5735_L48P4S_A1,
        "access.huawei_s5735_l48p4s_a1",
        "V200R019C10SPC600",
        "sim-s5735-l48p4s-a1-1",
        ge=48,
        sfp=4,
    ),
)

PROFILE_BY_KEY: dict[str, SwitchProfile] = {profile.profile_key: profile for profile in PROFILES}


def profile_by_key(key: str) -> SwitchProfile:
    try:
        return PROFILE_BY_KEY[key]
    except KeyError as exc:
        msg = f"unknown switch simulator profile {key!r}"
        raise ValueError(msg) from exc
