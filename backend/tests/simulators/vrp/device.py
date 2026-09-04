"""VRP simulator device model + the [sim] CLI DSL (M5T3, tests only).

Every behavior below is SIMULATOR-DECLARED DSL (basis ``[sim] vrp-cli-sim-1``
2026-09-04): the Huawei command reference pages were unreachable from this
environment (same outcome as M5T1/M5T2), so no ``[huawei-doc-url]`` exists.
The adapter template registry (`app/infrastructure/protocols/vrp/templates.py`)
and this simulator implement the SAME DSL text verbatim; hardware
certification must replace both with per-model/VRP CLI evidence (ADR-018,
DEVICE_ADAPTERS.md §10).

DSL contract (each command's response is a pure function of device state):

- prompt grammar: user view ``<{sysname}>``, system view ``[{sysname}]``,
  interface view ``[{sysname}-{InterfaceName}]`` (a trailing space follows
  every prompt); there is NO client echo (scripted SSH like real VRP without
  a pty);
- ``system-view`` / ``interface {id}`` / ``quit`` / ``return`` walk the
  view stack (user -> system -> interface); ``return`` always returns to the
  user view; ``quit`` in the user view closes the session;
- view enforcement: a command is only accepted in its DSL view, otherwise
  ``Error: Unrecognized command found at '^' position.`` (+ a caret line);
- ``display version`` -> banner + model/VRP tokens + serial + uptime:
    ``VRP (R) software, Version {version} ({model} {version})``
    ``Device serial number : {serial}``
    ``System uptime is {N} seconds``
- ``display interface {id}`` -> three current-state forms only:
    ``{id} current state : up``                      (admin up, link up)
    ``{id} current state : down``                    (admin up, link down)
    ``{id} current state : Administratively down``   (admin down)
    ``Line protocol current state : {up|down}``
- ``display poe-power interface {id}`` (access GE ports only):
    ``Port : {id}`` / ``Power state : {on|off}``
- ``shutdown`` / ``undo shutdown`` (interface view) apply immediately and
  mark the configuration dirty (like a real switch, interface admin state is
  running configuration); ``poe-power on|off`` likewise (GE ports of the
  access profile only; other ports answer the PoE error below);
- ``display current-configuration`` -> deterministic text derived from the
  device state (``#`` / ``sysname {name}`` / per-port blocks / ``return``);
  ``display saved-configuration`` -> the startup file content;
- ``compare configuration`` -> dirty ? the "not saved" warning : the
  "same as saved" info line (this is the restart/restore unsaved-config
  check);
- ``reboot``: when the configuration is dirty AND the startup file is still
  the profile's original config AND ``knobs.save_prompt`` is set, the device
  first asks ``Warning: The current configuration has not been saved. Save
  it now? [Y/N]:`` — answering ``y`` saves and continues, anything else
  cancels the reboot with ``Info: Reboot canceled.``; then (or directly)
  ``System will reboot. Continue? [Y/N]:`` — ``y`` applies the boot
  (state reloaded from the startup file, uptime reset, firmware version
  applied when a new boot image was set via ``startup system-software``),
  prints ``Info: System is rebooting now.`` and closes the session; the
  device then rejects new connections for ``knobs.restart_blip_seconds``
  (``restart_long`` = a far-future window);
- ``display diagnostic-information`` -> a long deterministic multi-section
  text; ``display logbuffer`` (access profile only) -> a shorter log text;
  both honor paging: when the session paging is active (default 24 lines)
  the output stops at ``-- More --`` and waits for input (space/any key
  continues, ``q`` cancels the remainder); ``screen-length 0 temporary``
  disables paging for the session;
- ``dir flash:`` -> ``Directory of flash:`` + sorted entries + the free
  line ``Total {total} KB ({free} KB free)`` (the flash area is a real
  bounded directory the test owns);
- ``display startup`` -> ``System software : {boot image}`` and
  ``Startup saved-configuration file : {startup file}``;
- ``startup system-software {name}`` / ``startup saved-configuration
  {name}`` validate the file exists in flash and update the boot/startup
  binding (errors are ``Error: Wrong parameter...``);
- firmware images are the warden-sim shape: first line
  ``WARDEN-SIM-FW {json}`` (model + version); at reboot the boot image
  header decides the reported VRP version (missing/foreign header keeps the
  old version — honest "no bump" for an invalid image);
- error lines always start with ``Error:``; the wrong-parameter signature
  is ``Error: Wrong parameter found at '^' position.``; unknown commands add
  a ``^`` caret line; ``knobs.error_on_command`` makes every command whose
  text contains the knob value answer ``Error: Simulated device failure.``;
- ``knobs.poe_delayed_seconds`` delays PoE state changes (command accepted,
  state flips later) so a read-back can legitimately see the old state;
- ``knobs.sftp_fail`` makes every SFTP write fail with the no-space error;
- ``knobs.config_inject_marker`` appends an extra interface block to the
  state-derived running configuration after a restore reboot (its
  fingerprint then differs from the uploaded backup — the mismatch the
  restore verification must detect).
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# Hardware-target declared model strings (contracts/hardware-targets.json).
MODEL_S5732_H48XUM2CC = "S5732-H48XUM2CC"
MODEL_S5731S_S48P4X_A = "S5731S-S48P4X-A"
MODEL_S5735_L48P4S_A1 = "S5735-L48P4S-A1"

# Simulator credential defaults (password auth only, like the adapter).
SSH_USERNAME = "admin"
SSH_PASSWORD = "sim-ssh-pass-1"

# DSL banners/answers.
BANNER_LINES = (
    "************************************************************************",
    "*   Huawei simulator - VRP CLI test device ([sim] DSL, never hardware)  *",
    "************************************************************************",
)
INFO_ENTER_SYSTEM_VIEW = "Info: Enter system view, return user view with Ctrl+Z."
WARNING_NOT_SAVED = "Warning: The current configuration has not been saved. Save it now? [Y/N]:"
CONFIRM_REBOOT = "System will reboot. Continue? [Y/N]:"
INFO_REBOOTING = "Info: System is rebooting now."
INFO_REBOOT_CANCELED = "Info: Reboot canceled."
ERR_UNKNOWN_COMMAND = "Error: Unrecognized command found at '^' position."
ERR_CARET_LINE = "  ^"
ERR_WRONG_PARAMETER = "Error: Wrong parameter found at '^' position."
ERR_POE_UNSUPPORTED = "Error: The interface does not support PoE."
ERR_SIMULATED_FAILURE = "Error: Simulated device failure."
ERR_NO_SPACE = "Error: No space left on device (simulated flash full)."
COMPARE_SAVED = "Info: The current configuration is the same as the saved configuration."
COMPARE_DIRTY = "Warning: The current configuration is different from the saved configuration (not saved)."
MORE_MARKER = "-- More --"
CONFIG_BASE_FILE = "vrpcfg.cfg"
BOOT_BASE_IMAGE = "sim-vrp-base.bin"

# Flash layout defaults ([sim] DSL).
FLASH_TOTAL_KB = 65536
FLASH_FILE_HEADER_BYTES = 0  # files occupy exactly their byte size
FW_HEADER_MARKER = "WARDEN-SIM-FW "
CONFIG_NAME_RE = re.compile(r"^warden-restore-[0-9a-f]{8}\.cfg$")
IMAGE_NAME_RE = re.compile(r"^firmware-[A-Za-z0-9._-]+\.bin$")
FLASH_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Prompt/answer punctuation.
USER_PROMPT = ">"
CONFIG_PROMPT = "]"
PROMPT_SUFFIX = " "


def normalize_config_text(text: str) -> str:
    """DSL config normalization the adapter + simulator agree on.

    CRLF -> LF, per-line trailing whitespace stripped, blank lines dropped;
    the result is deterministic for a given device state. The adapter hashes
    the normalized text (config backup fingerprint) and the restored-config
    comparison uses the same rule.
    """
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.strip():
            lines.append(line)
    return "\n".join(lines) + "\n"


def _interface_lines(
    profile: VrpProfile, admin: dict[str, bool], poe: dict[str, bool]
) -> list[str]:
    lines: list[str] = []
    for name in profile.interface_names:
        lines.append(f"interface {name}")
        if profile.device_type == "access_switch":
            lines.append(f" poe-power {'on' if poe.get(name, False) else 'off'}")
        lines.append(" undo shutdown" if admin.get(name, True) else " shutdown")
        lines.append("#")
    return lines


def config_text_for_state(profile: VrpProfile, state: VrpState) -> str:
    """Deterministic ``display current-configuration`` text for the state."""
    lines: list[str] = ["#", f"sysname {profile.sys_name}", "#"]
    lines.extend(_interface_lines(profile, state.admin, state.poe))
    marker = state.inject_marker
    if marker:
        lines.extend(["#", f"interface {marker['name']}", f" {marker['command']}", "#"])
    lines.append("return")
    return "\n".join(lines) + "\n"


def config_text_to_state(text: str, profile: VrpProfile) -> VrpState:
    """Reload the modeled state from a config file (reboot/restore path).

    Only the state the simulator models is derived (sysname is fixed by the
    profile; interface admin + PoE lines); anything else in a config file is
    carried by the text itself (display current-configuration keeps printing
    the full file text while the model only tracks what it can honor).
    """
    admin = dict.fromkeys(profile.interface_names, True)
    poe = dict.fromkeys(profile.interface_names, False)
    current_iface: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("interface "):
            candidate = line[len("interface ") :].strip()
            current_iface = candidate if candidate in profile.interface_names else None
            continue
        if current_iface is None:
            continue
        if line == "shutdown":
            admin[current_iface] = False
        elif line == "undo shutdown":
            admin[current_iface] = True
        elif line == "poe-power off" and current_iface in poe:
            poe[current_iface] = False
        elif line == "poe-power on" and current_iface in poe:
            poe[current_iface] = True
    return VrpState(
        sysname=profile.sys_name,
        admin=admin,
        poe=poe,
        dirty=False,
        startup_file=CONFIG_BASE_FILE,
        boot_image=BOOT_BASE_IMAGE,
        version=profile.vrp_version,
        inject_marker=None,
    )


@dataclass(frozen=True)
class VrpProfile:
    """One simulator profile: identity + hardware layout ([sim] DSL).

    Model strings are the certified contracts/hardware-targets.json tokens;
    everything else (VRP tokens, serials, port layouts, initial config) is
    simulator-declared fixture material for M5 certification to replace.
    """

    profile_key: str  # core_s5732 | core_s5731s | access_s5735
    device_type: str  # core_switch | access_switch
    model: str
    vrp_version: str
    sys_name: str
    serial: str
    ge_count: int
    xge_count: int
    initial_uptime_seconds: int = 3600

    @property
    def interface_names(self) -> tuple[str, ...]:
        names = [f"GigabitEthernet0/0/{index}" for index in range(1, self.ge_count + 1)]
        names.extend(
            f"XGigabitEthernet0/0/{index}" for index in range(1, self.xge_count + 1)
        )
        return tuple(names)

    def is_poe_port(self, name: str) -> bool:
        return self.device_type == "access_switch" and name.startswith("GigabitEthernet")


def _core_profile(
    key: str, model: str, vrp: str, sys_name: str, serial: str
) -> VrpProfile:
    return VrpProfile(
        profile_key=key,
        device_type="core_switch",
        model=model,
        vrp_version=vrp,
        sys_name=sys_name,
        serial=serial,
        ge_count=48,
        xge_count=4,
    )


def _access_profile(key: str, model: str, vrp: str, sys_name: str, serial: str) -> VrpProfile:
    return VrpProfile(
        profile_key=key,
        device_type="access_switch",
        model=model,
        vrp_version=vrp,
        sys_name=sys_name,
        serial=serial,
        ge_count=48,
        xge_count=4,
    )


PROFILES: tuple[VrpProfile, ...] = (
    _core_profile(
        "core_s5732",
        MODEL_S5732_H48XUM2CC,
        "V200R021C10SPC600",
        "sim-s5732",
        "SIM-S5732-0001",
    ),
    _core_profile(
        "core_s5731s",
        MODEL_S5731S_S48P4X_A,
        "V200R019C10SPC600",
        "sim-s5731s",
        "SIM-S5731S-0001",
    ),
    _access_profile(
        "access_s5735",
        MODEL_S5735_L48P4S_A1,
        "V200R019C10SPC600",
        "sim-s5735",
        "SIM-S5735-0001",
    ),
)

PROFILE_BY_KEY: dict[str, VrpProfile] = {profile.profile_key: profile for profile in PROFILES}


def profile_by_key(key: str) -> VrpProfile:
    try:
        return PROFILE_BY_KEY[key]
    except KeyError as exc:
        msg = f"unknown vrp simulator profile {key!r}"
        raise ValueError(msg) from exc


@dataclass
class VrpKnobs:
    """Failure/behavior knobs (defaults = a healthy device)."""

    error_on_command: str | None = None  # command containing this text -> Error
    save_prompt: bool = False  # dirty reboots ask the save prompt
    restart_blip_seconds: float = 1.0  # unreachable window after a reboot
    restart_long: bool = False  # unreachable window far beyond reconnect caps
    sftp_fail: bool = False  # every SFTP write fails
    poe_delayed_seconds: float = 0.0  # poe commands apply after this delay
    config_inject_marker: bool = False  # restore reboot injects a config block

    def offline_until(self) -> float:
        if self.restart_long:
            return time.monotonic() + 3600.0
        return time.monotonic() + max(0.0, self.restart_blip_seconds)


@dataclass
class VrpState:
    """Mutable modeled device state ([sim] DSL; locked per device)."""

    sysname: str
    admin: dict[str, bool]  # name -> administratively up
    poe: dict[str, bool]  # name -> powered (access GE ports)
    dirty: bool = False  # unsaved running-configuration changes
    startup_file: str = CONFIG_BASE_FILE  # flash file loaded at boot
    boot_image: str = BOOT_BASE_IMAGE  # flash file booted as system software
    version: str = ""
    inject_marker: dict[str, str] | None = None  # config_inject_marker block

    def applied_poe(self) -> dict[str, bool]:
        return dict(self.poe)

    def applied_admin(self) -> dict[str, bool]:
        return dict(self.admin)


@dataclass
class VrpBootTimes:
    """Wall-clock bookkeeping for uptime/reboot windows."""

    booted_at_monotonic: float
    uptime_offset_seconds: int
    offline_until: float = 0.0


class VrpDevice:
    """One simulator device: profile + state + flash area + knobs.

    Thread-safe: the asyncssh server handlers and the tests live in
    different threads and poke the same object.
    """

    def __init__(self, profile: VrpProfile, *, flash_root: Path | None = None) -> None:
        self.profile = profile
        self.knobs = VrpKnobs()
        self._lock = threading.Lock()
        pristine = config_text_to_state(
            _initial_config_text(profile, flash_root), profile
        )
        pristine.version = profile.vrp_version
        self._state = pristine
        self.flash_root = flash_root
        if flash_root is not None:
            flash_root.mkdir(parents=True, exist_ok=True)
        self._times = VrpBootTimes(
            booted_at_monotonic=time.monotonic(),
            uptime_offset_seconds=profile.initial_uptime_seconds,
        )
        # PoE delayed-apply bookkeeping: target state vs effective state.
        self._delayed_poe: dict[str, tuple[float, bool]] = {}
        self._effective_poe: dict[str, bool] = {}
        self._seed_flash()

    # -- state access ------------------------------------------------------

    @property
    def sysname(self) -> str:
        with self._lock:
            return self._state.sysname

    @property
    def version(self) -> str:
        with self._lock:
            return self._state.version

    @property
    def boot_image(self) -> str:
        with self._lock:
            return self._state.boot_image

    @property
    def startup_file(self) -> str:
        with self._lock:
            return self._state.startup_file

    @property
    def dirty(self) -> bool:
        with self._lock:
            return self._state.dirty

    def snapshot(self) -> dict[str, object]:
        """Test/control snapshot (states, version, uptime, flash)."""
        with self._lock:
            return {
                "model": self.profile.model,
                "device_type": self.profile.device_type,
                "sysname": self._state.sysname,
                "version": self._state.version,
                "serial": self.profile.serial,
                "uptime_seconds": self.uptime_seconds_locked(),
                "dirty": self._state.dirty,
                "startup_file": self._state.startup_file,
                "boot_image": self._state.boot_image,
                "admin_down": [
                    name for name, up in sorted(self._state.admin.items()) if not up
                ],
                "poe_off": [
                    name for name, powered in sorted(self._state.poe.items()) if not powered
                ],
                "flash_files": sorted(self._flash_names_locked()),
                "inject_marker": self._state.inject_marker is not None,
            }

    def state_view(self) -> VrpState:
        with self._lock:
            admin = dict(self._state.admin)
            poe = dict(self._state.poe)
            return VrpState(
                sysname=self._state.sysname,
                admin=admin,
                poe=poe,
                dirty=self._state.dirty,
                startup_file=self._state.startup_file,
                boot_image=self._state.boot_image,
                version=self._state.version,
                inject_marker=dict(self._state.inject_marker)
                if self._state.inject_marker
                else None,
            )

    def apply_state(self, state: VrpState) -> None:
        with self._lock:
            self._state.admin = dict(state.admin)
            self._state.poe = dict(state.poe)
            self._state.dirty = state.dirty
            self._state.startup_file = state.startup_file
            self._state.boot_image = state.boot_image
            self._state.version = state.version
            self._state.inject_marker = (
                dict(state.inject_marker) if state.inject_marker else None
            )

    # -- helpers ------------------------------------------------------------

    def _seed_flash(self) -> None:
        if self.flash_root is None:
            return
        base = _initial_config_text(self.profile, self.flash_root)
        files = {
            CONFIG_BASE_FILE: base.encode("utf-8"),
            BOOT_BASE_IMAGE: self._fw_image_bytes(self.profile.vrp_version),
        }
        for name, content in files.items():
            target = self.flash_root / name
            if not target.exists():
                target.write_bytes(content)

    def _flash_names_locked(self) -> list[str]:
        if self.flash_root is None or not self.flash_root.is_dir():
            return []
        return sorted(
            path.name
            for path in self.flash_root.iterdir()
            if path.is_file() and FLASH_NAME_RE.match(path.name)
        )

    def _flash_usage_kb_locked(self) -> int:
        if self.flash_root is None:
            return 0
        total = sum(
            path.stat().st_size
            for path in self.flash_root.iterdir()
            if path.is_file() and FLASH_NAME_RE.match(path.name)
        )
        return (total + 1023) // 1024

    def flash_free_kb(self) -> int:
        with self._lock:
            return FLASH_TOTAL_KB - self._flash_usage_kb_locked()

    def _fw_image_bytes(self, version: str) -> bytes:
        header = (
            FW_HEADER_MARKER
            + json.dumps(
                {"model": self.profile.model, "version": version},
                ensure_ascii=False,
            )
            + "\n"
        )
        return (header + "padding-bytes-for-the-base-image\n").encode("utf-8")

    # -- CLI-facing reads ----------------------------------------------------

    def version_text(self) -> str:
        with self._lock:
            return (
                "Huawei Versatile Routing Platform Software\n"
                f"VRP (R) software, Version {self._state.version} "
                f"({self.profile.model} {self._state.version})\n"
                "Copyright (c) Huawei Technologies Co., Ltd. 2000-2026. All rights reserved.\n"
                f"Device serial number : {self.profile.serial}\n"
                f"System uptime is {self.uptime_seconds_locked()} seconds\n"
            )

    def uptime_seconds_locked(self) -> int:
        return int(
            time.monotonic() - self._times.booted_at_monotonic
        ) + self._times.uptime_offset_seconds

    def current_config_text(self) -> str:
        with self._lock:
            return config_text_for_state(self.profile, self._state)

    def saved_config_text(self) -> str:
        with self._lock:
            return self._read_flash_text_locked(self._state.startup_file)

    def startup_text(self) -> str:
        with self._lock:
            return (
                f"System software    : {self._state.boot_image}\n"
                f"Startup saved-configuration file : {self._state.startup_file}\n"
            )

    def dir_text(self) -> str:
        with self._lock:
            return self._dir_text_locked()

    def _dir_text_locked(self) -> str:
        if self.flash_root is None or not self.flash_root.is_dir():
            return "Directory of flash:\n"
        lines = ["Directory of flash:"]
        for index, path in enumerate(
            sorted(self.flash_root.iterdir(), key=lambda item: item.name),
            start=1,
        ):
            if not path.is_file() or not FLASH_NAME_RE.match(path.name):
                continue
            size = path.stat().st_size
            lines.append(
                f" {index:>3}  -rw-  {size:>9}  Sep 04 2026 06:00:00  {path.name}"
            )
        used_kb = self._flash_usage_kb_locked()
        lines.append(f"Total {FLASH_TOTAL_KB} KB ({FLASH_TOTAL_KB - used_kb} KB free)")
        return "\n".join(lines) + "\n"

    # -- CLI-facing mutations -------------------------------------------------

    def admin_up(self, name: str) -> bool | None:
        with self._lock:
            return self._state.admin.get(name)

    def set_interface_admin(self, name: str, *, up: bool) -> None:
        with self._lock:
            if name not in self._state.admin:
                return
            if self._state.admin[name] == up:
                return
            self._state.admin[name] = up
            self._state.dirty = True

    def has_flash_file(self, name: str) -> bool:
        if self.flash_root is None:
            return False
        target = self.flash_root / name
        return target.is_file()

    def flash_file_size(self, name: str) -> int | None:
        if self.flash_root is None:
            return None
        target = self.flash_root / name
        try:
            return target.stat().st_size
        except OSError:
            return None

    def set_boot_image(self, name: str) -> None:
        with self._lock:
            if name in self._flash_names_locked():
                self._state.boot_image = name

    def set_startup_file(self, name: str) -> None:
        with self._lock:
            if name in self._flash_names_locked():
                self._state.startup_file = name

    def save_running_config(self) -> None:
        """Persist the running configuration over the startup file.

        The platform NEVER answers the save prompt with Y (that would be an
        auto-save); this path exists only so the simulator's own prompt
        semantics can be exercised honestly (answering Y = the operator
        saved, answering anything else = reboot canceled).
        """
        with self._lock:
            text = config_text_for_state(self.profile, self._state)
            if self.flash_root is not None:
                target = self.flash_root / self._state.startup_file
                try:
                    target.write_text(text, encoding="utf-8")
                except OSError:
                    return
            self._state.dirty = False

    def set_poe(self, name: str, *, on: bool) -> None:
        with self._lock:
            if name not in self._state.poe:
                return
            if self._state.poe[name] == on:
                return
            self._state.poe[name] = on
            self._state.dirty = True

    def poe_state(self, name: str) -> bool | None:
        """Effective PoE state honoring ``poe_delayed_seconds``.

        The command marks the TARGET state immediately; when a delay is
        configured the *effective* state only flips after the delay has
        passed (so read-backs can observe the old state — poe_delayed knob).
        """
        with self._lock:
            target = self._state.poe.get(name)
            delayed = self._delayed_poe.get(name)
        if target is None:
            return None
        if delayed is not None:
            flip_at, flip_to = delayed
            if time.monotonic() < flip_at:
                return self._effective_poe.get(name, target)
        self._apply_poe_effective(name, target)
        return target

    def _apply_poe_effective(self, name: str, value: bool) -> None:
        with self._lock:
            self._effective_poe[name] = value
            self._delayed_poe.pop(name, None)

    def request_poe(self, name: str, *, on: bool) -> None:
        """PoE command entry point (interface-view ``poe-power``).

        The TARGET state is recorded immediately; the effective state flips
        after ``poe_delayed_seconds`` when the knob is set (read-backs see
        the old state until then — the knob's honest purpose).
        """
        with self._lock:
            delay = self.knobs.poe_delayed_seconds
            if name not in self._state.poe:
                return
            if delay > 0:
                self._delayed_poe[name] = (time.monotonic() + delay, on)
                return
            if self._state.poe[name] == on:
                return
            self._state.poe[name] = on
            self._state.dirty = True

    # -- reboot ----------------------------------------------------------------

    def reboot_window_open(self) -> bool:
        with self._lock:
            return self._times.offline_until <= time.monotonic()

    def perform_reboot(self) -> None:
        """Apply the boot while holding the lock: state reload + boot image."""
        with self._lock:
            now = time.monotonic()
            self._times.booted_at_monotonic = now
            self._times.uptime_offset_seconds = 0
            self._times.offline_until = self.knobs.offline_until()
            text = self._read_flash_text_locked(self._state.startup_file)
            reloaded = config_text_to_state(text, self.profile)
            self._state.admin = reloaded.admin
            self._state.poe = reloaded.poe
            self._state.dirty = False
            self._state.sysname = self.profile.sys_name
            header = self._read_image_header_locked(self._state.boot_image)
            if header is not None:
                self._state.version = header
            if self.knobs.config_inject_marker and self._state.startup_file.startswith(
                "warden-restore-"
            ):
                self._state.inject_marker = {
                    "name": "LoopBack0",
                    "command": "description WARDEN-SIM-INJECTED",
                }
            else:
                self._state.inject_marker = None
            self._delayed_poe.clear()
            self._effective_poe.clear()

    def _read_flash_text_locked(self, name: str) -> str:
        if self.flash_root is None:
            return ""
        path = self.flash_root / name
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    def _read_image_header_locked(self, name: str) -> str | None:
        """VRP version carried by the boot image header (warden-sim shape)."""
        if self.flash_root is None:
            return None
        path = self.flash_root / name
        try:
            with path.open("rb") as handle:
                head = handle.readline(4096)
        except OSError:
            return None
        if not head.startswith(FW_HEADER_MARKER.encode("utf-8")):
            return None
        raw = head[len(FW_HEADER_MARKER) :].strip()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        model = payload.get("model")
        version = payload.get("version")
        if model != self.profile.model or not isinstance(version, str) or not version:
            return None
        return version

    def _read_flash_bytes_locked(self, name: str) -> bytes | None:
        if self.flash_root is None:
            return None
        path = self.flash_root / name
        try:
            return path.read_bytes()
        except OSError:
            return None


def _initial_config_text(profile: VrpProfile, flash_root: Path | None) -> str:
    """Pristine startup config of a fresh device (all ports up, poe off)."""
    del flash_root
    pristine = VrpState(
        sysname=profile.sys_name,
        admin=dict.fromkeys(profile.interface_names, True),
        poe=dict.fromkeys(profile.interface_names, False),
    )
    return config_text_for_state(profile, pristine)
