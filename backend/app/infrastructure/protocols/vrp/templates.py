"""VRP command template registry ([sim] DSL, M5T3).

EVERY command the platform may send to a Huawei VRP switch lives here as a
typed template — there is NO free-text command path anywhere in the VRP
protocol layer (SECURITY.md §8, DEVICE_ADAPTERS.md §6.1, AGENTS.md).

Template semantics:

- ``mode`` is the view the commands run in: ``user`` (one command at the
  user-view prompt), ``config`` (``system-view`` -> one or more commands at
  the system-view prompt -> ``return``), ``interface`` (``system-view`` ->
  ``interface {interface_id}`` -> one or more commands at the interface-view
  prompt -> ``return``);
- every ``{placeholder}`` in the command text is a strictly typed parameter:
  the value must match the param's allowlist REGEX in full and its length
  bound BEFORE any composition (CLI injection defense — params containing
  ``& ; | ` ] $ ( )`` newlines or whitespace never reach a command line);
  composition itself is a plain string format after validation;
- ``basis`` tags every template with its evidence provenance. Today every
  template is ``[sim] vrp-cli-sim-1``: the Huawei command reference was
  unreachable from this environment (same outcome as M5T1/M5T2), the text
  below is the simulator DSL of ``tests/simulators/vrp`` (verbatim match),
  and hardware certification must replace it with per-model/VRP evidence
  (ADR-018, DEVICE_ADAPTERS.md §10). ``template_version`` is the registry
  version that travels into operation evidence;
- the certified-model scope: all three hardware-targets models share the
  DSL text (the [sim] basis); ``template_ids_for_model`` returns the keys an
  adapter may use for a certified model.

The templates registry maps a template KEY to one template; the keys are
the protocol vocabulary the Huawei adapter ops use (never free text).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The template-set identity that travels into operation evidence; every
# template below carries the same [sim] basis until hardware certification.
TEMPLATE_VERSION = "vrp-cli-sim-1"
TEMPLATE_BASIS = (
    "[sim] vrp-cli-sim-1（模拟器 DSL，2026-09-04；华为命令参考不可达 — "
    "真机命令模板认证时替换，ADR-018）"
)

# Certified model set (contracts/hardware-targets.json exact_model tokens).
MODEL_S5732_H48XUM2CC = "S5732-H48XUM2CC"
MODEL_S5731S_S48P4X_A = "S5731S-S48P4X-A"
MODEL_S5735_L48P4S_A1 = "S5735-L48P4S-A1"
CERTIFIED_MODELS: tuple[str, ...] = (
    MODEL_S5732_H48XUM2CC,
    MODEL_S5731S_S48P4X_A,
    MODEL_S5735_L48P4S_A1,
)

#: interface-id allowlist (VRP native naming; chars, digits and slashes
#: only — anything else is rejected before composition).
_INTERFACE_ID_RE = re.compile(
    r"^(?:GigabitEthernet|XGigabitEthernet|10GE|25GE|40GE|100GE)"
    r"[0-9]+/[0-9]+(?:/[0-9]+)?|Eth-Trunk[0-9]+$"
)
#: flash file names the platform may reference in commands (its own
#: composed names only — warden-restore-<hex8>.cfg / firmware-<slug>.bin).
_FILE_NAME_RE = re.compile(r"^(?:warden-restore-[0-9a-f]{8}\.cfg|firmware-[A-Za-z0-9._-]+\.bin)$")

#: Static (parameter-free) template keys.
USER_VIEW_KEYS = frozenset(
    {
        "display.version",
        "paging.off",
        "display.current_configuration",
        "display.saved_configuration",
        "display.startup",
        "compare.configuration",
        "reboot",
        "display.diagnostic_information",
        "display.logbuffer",
        "dir.flash",
    }
)
CONFIG_VIEW_KEYS = frozenset({"system.view.enter"})
INTERFACE_VIEW_KEYS = frozenset(
    {"interface.shutdown", "interface.undo_shutdown", "interface.poe_on", "interface.poe_off"}
)
PARAM_KEYS = frozenset({"display.interface", "display.poe", "startup.system_software", "startup.saved_configuration"})


@dataclass(frozen=True)
class ParamSpec:
    """One typed template parameter (allowlist-validated before use)."""

    name: str
    pattern: re.Pattern[str]
    max_length: int
    description: str


@dataclass(frozen=True)
class VrpTemplate:
    """One certified command template (basis-tagged, typed params only).

    ``steps`` lists the command lines in order; a ``config``-mode template
    starts with ``system-view`` and runs its remaining steps at the system
    prompt; an ``interface``-mode template starts with ``system-view`` +
    ``interface {interface_id}`` and runs its remaining steps at the
    interface prompt. The executor leaves every deeper view (``return``)
    after the run.
    """

    key: str
    mode: str  # user | config | interface
    steps: tuple[str, ...]  # static text with {param} placeholders
    params: tuple[ParamSpec, ...] = ()
    basis: str = TEMPLATE_BASIS
    template_version: str = TEMPLATE_VERSION
    timeout_seconds: int = 60  # command timeout default (DEVICE_ADAPTERS §8)

    def param_spec(self, name: str) -> ParamSpec | None:
        for spec in self.params:
            if spec.name == name:
                return spec
        return None

    def compose(self, params: dict[str, str]) -> tuple[str, ...]:
        """Validate every declared param against its allowlist and compose.

        Raises ``ValueError`` on any violation BEFORE any string formatting
        (the injection boundary; tests pin this order). Undeclared params
        are refused; values are validated for full-match + length.
        """
        declared = {spec.name for spec in self.params}
        unknown = set(params) - declared
        if unknown:
            names = "、".join(sorted(unknown))
            raise ValueError(f"模板 {self.key} 不接受参数 {names}")
        missing = declared - set(params)
        if missing:
            names = "、".join(sorted(missing))
            raise ValueError(f"模板 {self.key} 缺少参数 {names}")
        checked: dict[str, str] = {}
        for spec in self.params:
            raw = params[spec.name]
            if not isinstance(raw, str) or len(raw) > spec.max_length:
                raise ValueError(
                    f"参数 {spec.name}（{spec.description}）长度非法：拒绝 CLI 注入候选"
                )
            if spec.pattern.fullmatch(raw) is None:
                raise ValueError(
                    f"参数 {spec.name}（{spec.description}）含不允许的字符：拒绝 CLI 注入候选"
                )
            checked[spec.name] = raw
        return tuple(step.format(**checked) for step in self.steps)


def _t(key: str, mode: str, steps: tuple[str, ...], timeout: int = 60) -> VrpTemplate:
    return VrpTemplate(key=key, mode=mode, steps=steps, timeout_seconds=timeout)


INTERFACE_PARAM = ParamSpec(
    name="interface_id",
    pattern=_INTERFACE_ID_RE,
    max_length=128,
    description="VRP 接口 ID（仅允许字母/数字/斜杠的厂商命名；如 GigabitEthernet0/0/1）",
)
FILE_NAME_PARAM = ParamSpec(
    name="file_name",
    pattern=_FILE_NAME_RE,
    max_length=80,
    description="平台生成的 flash 文件名（仅 warden-restore-<hex8>.cfg / firmware-<slug>.bin）",
)

# NOTE: every command text below matches the simulator DSL VERBATIM
# (tests/simulators/vrp/device.py); the parser tests pin both sides.
TEMPLATES: dict[str, VrpTemplate] = {
    "display.version": _t("display.version", "user", ("display version",)),
    "paging.off": _t("paging.off", "user", ("screen-length 0 temporary",)),
    "display.current_configuration": _t(
        "display.current_configuration", "user", ("display current-configuration",), timeout=120
    ),
    "display.saved_configuration": _t(
        "display.saved_configuration", "user", ("display saved-configuration",), timeout=120
    ),
    "display.startup": _t("display.startup", "user", ("display startup",)),
    "compare.configuration": _t("compare.configuration", "user", ("compare configuration",)),
    "reboot": _t("reboot", "user", ("reboot",), timeout=60),
    "display.diagnostic_information": _t(
        "display.diagnostic_information", "user", ("display diagnostic-information",), timeout=1800
    ),
    "display.logbuffer": _t("display.logbuffer", "user", ("display logbuffer",), timeout=120),
    "dir.flash": _t("dir.flash", "user", ("dir flash:",)),
    "display.interface": VrpTemplate(
        key="display.interface",
        mode="user",
        steps=("display interface {interface_id}",),
        params=(INTERFACE_PARAM,),
    ),
    "display.poe": VrpTemplate(
        key="display.poe",
        mode="user",
        steps=("display poe-power interface {interface_id}",),
        params=(INTERFACE_PARAM,),
    ),
    "system.view.enter": _t("system.view.enter", "config", ("system-view",)),
    "interface.shutdown": VrpTemplate(
        key="interface.shutdown",
        mode="interface",
        steps=("system-view", "interface {interface_id}", "shutdown"),
        params=(INTERFACE_PARAM,),
    ),
    "interface.undo_shutdown": VrpTemplate(
        key="interface.undo_shutdown",
        mode="interface",
        steps=("system-view", "interface {interface_id}", "undo shutdown"),
        params=(INTERFACE_PARAM,),
    ),
    "interface.poe_on": VrpTemplate(
        key="interface.poe_on",
        mode="interface",
        steps=("system-view", "interface {interface_id}", "poe-power on"),
        params=(INTERFACE_PARAM,),
    ),
    "interface.poe_off": VrpTemplate(
        key="interface.poe_off",
        mode="interface",
        steps=("system-view", "interface {interface_id}", "poe-power off"),
        params=(INTERFACE_PARAM,),
    ),
    "startup.system_software": VrpTemplate(
        key="startup.system_software",
        mode="user",
        steps=("startup system-software {file_name}",),
        params=(FILE_NAME_PARAM,),
    ),
    "startup.saved_configuration": VrpTemplate(
        key="startup.saved_configuration",
        mode="user",
        steps=("startup saved-configuration {file_name}",),
        params=(FILE_NAME_PARAM,),
    ),
}


def template_for(key: str) -> VrpTemplate:
    try:
        return TEMPLATES[key]
    except KeyError as exc:
        msg = f"未知的 VRP 命令模板键 {key!r}"
        raise KeyError(msg) from exc


def certified_model_keys() -> frozenset[str]:
    """Every template key valid for the certified [sim] model set."""
    return frozenset(TEMPLATES)


#: The registry ledger version for evidence/audit.
def template_evidence(key: str) -> str:
    template = template_for(key)
    return (
        f"{template.template_version}:{template.key}（{template.mode}）"
        f" {template.basis}"
    )
