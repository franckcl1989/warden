"""asyncssh server for the VRP simulator (M5T3, tests only).

Boots one real SSH server per device on 127.0.0.1 with an OS-assigned port
(``asyncssh.create_server`` with ``server_factory`` for the per-connection
authentication object + ``process_factory`` for the CLI shell +
``sftp_factory`` for the flash SFTP root):

- password authentication against the fixed simulator credential
  (tests/simulators/vrp/device.py); inside the restart blip every
  authentication attempt is refused (the device is "rebooting" — the client
  classifies the handshake loss as unreachable);
- the shell process implements the ``[sim]`` CLI DSL of ``device.py``:
  banner, prompt stack (user/system/interface views), command responses,
  the paging marker (``-- More --`` when ``screen-length`` is not 0,
  space/any key continues, ``q`` cancels) and the reboot flow (save-prompt
  knob, continue prompt, session close + blip + boot side effects);
- the SFTP subsystem is rooted at the device's flash directory (a real
  bounded folder); writes enforce the allowlisted names and refuse when the
  flash budget would overflow or the ``sftp_fail`` knob is set.

The host key is generated per boot by the hosting layer; the canonical
SHA-256 fingerprint the adapter enforces is ``SSHKey.get_fingerprint('sha256')``
(``host_fingerprint_of`` below).

Everything here is TEST-ONLY simulator machinery — never hardware evidence.
"""

from __future__ import annotations

import asyncio
import errno
import os
import posixpath
from typing import Any

import asyncssh
from asyncssh import SFTPAttrs, SFTPError, SFTPServer, SSHServer, SSHServerProcess

from tests.simulators.vrp.device import (
    BANNER_LINES,
    BOOT_BASE_IMAGE,
    COMPARE_DIRTY,
    COMPARE_SAVED,
    CONFIG_BASE_FILE,
    CONFIRM_REBOOT,
    ERR_CARET_LINE,
    ERR_NO_SPACE,
    ERR_POE_UNSUPPORTED,
    ERR_SIMULATED_FAILURE,
    ERR_UNKNOWN_COMMAND,
    ERR_WRONG_PARAMETER,
    FLASH_NAME_RE,
    INFO_ENTER_SYSTEM_VIEW,
    INFO_REBOOT_CANCELED,
    INFO_REBOOTING,
    MORE_MARKER,
    SSH_PASSWORD,
    SSH_USERNAME,
    VrpDevice,
)

#: SFTP open-mode flag bits asyncssh passes to SFTPServer.open (FXF_*).
_FXF_READ = 0x00000001
_FXF_WRITE = 0x00000002

_DEFAULT_SCREEN_LENGTH = 24


def host_fingerprint_of(key: asyncssh.SSHKey) -> str:
    """Canonical SHA-256 host-key fingerprint (asyncssh base64 form)."""
    return key.get_fingerprint("sha256")


class _AuthServer(SSHServer):
    """Per-connection authentication server (password + blip refusal)."""

    def __init__(self, device: VrpDevice) -> None:
        self._device = device

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if not self._device.reboot_window_open():
            raise asyncssh.DisconnectError(
                asyncssh.DISC_CONNECTION_LOST,
                "device rebooting (simulator restart blip)",
            )
        return username == SSH_USERNAME and password == SSH_PASSWORD


class _PageCancel(Exception):
    """The user cancelled the rest of an output with 'q'."""


async def _cli_session(process: SSHServerProcess, device: VrpDevice) -> None:
    """The interactive CLI shell handler (process style)."""
    view: list[str] = ["user"]  # user | config | [interface, name]
    screen_length = _DEFAULT_SCREEN_LENGTH
    out = process.stdout
    stdin = process.stdin

    async def write(text: str) -> None:
        out.write(text)
        await out.drain()

    def prompt() -> str:
        if view[0] == "interface":
            return f"[{device.sysname}-{view[1]}] "
        if view[0] == "config":
            return f"[{device.sysname}] "
        return f"<{device.sysname}> "

    async def read_line(wait_seconds: float = 15.0) -> str | None:
        try:
            line = await asyncio.wait_for(stdin.readline(), timeout=wait_seconds)
        except TimeoutError:
            raise
        return line.strip() if line else None

    async def read_key() -> str:
        try:
            data = await stdin.read(1)
        except asyncio.IncompleteReadError:
            return ""
        return data if data else ""

    async def emit_paged(text: str) -> None:
        """Emit output honoring the session paging state."""
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        emitted = 0
        try:
            for index, chunk in enumerate(lines):
                if index < len(lines) - 1 or chunk:
                    await write(chunk + "\n")
                    emitted += 1
                    if screen_length > 0 and emitted >= max(1, screen_length - 1):
                        emitted = 0
                        await write("\n" + MORE_MARKER)
                        key = await read_key()
                        if key in ("q", "Q"):
                            raise _PageCancel()
        except _PageCancel:
            return

    def error_unknown() -> None:
        write_to_out(ERR_UNKNOWN_COMMAND + "\n" + ERR_CARET_LINE + "\n")

    def error_wrong_param() -> None:
        write_to_out(ERR_WRONG_PARAMETER + "\n" + ERR_CARET_LINE + "\n")

    # A tiny wrapper so error helpers can fire without await; drains happen
    # on the next await boundary anyway.
    def write_to_out(text: str) -> None:
        out.write(text)

    await write("\n".join(BANNER_LINES) + "\n")
    await write(prompt())
    while True:
        line = await read_line()
        if line is None:
            return
        text = line.strip()
        if not text:
            await write(prompt())
            continue
        lowered = text.lower()
        knob = device.knobs.error_on_command
        if knob is not None and knob in text:
            write_to_out(ERR_SIMULATED_FAILURE + "\n" + ERR_CARET_LINE + "\n")
            await write(prompt())
            continue

        # -- view handling -------------------------------------------------
        if view[0] == "user":
            if lowered == "system-view":
                write_to_out(INFO_ENTER_SYSTEM_VIEW + "\n")
                view[0] = "config"
            elif lowered == "screen-length 0 temporary":
                screen_length = 0
                write_to_out("Info: Paging is disabled for this session.\n")
            elif lowered.startswith("reboot"):
                closed = await _do_reboot(process, device, write, read_line)
                if closed:
                    return
            elif lowered.startswith("display version"):
                await emit_paged(device.version_text())
            elif lowered.startswith("display current-configuration"):
                await emit_paged(device.current_config_text())
            elif lowered.startswith("display saved-configuration"):
                await emit_paged(device.saved_config_text())
            elif lowered.startswith("display startup"):
                await emit_paged(device.startup_text())
            elif lowered.startswith("compare configuration"):
                write_to_out(
                    (COMPARE_DIRTY if device.dirty else COMPARE_SAVED) + "\n"
                )
            elif lowered.startswith("display interface "):
                name = text[len("display interface ") :].strip()
                if name not in device.profile.interface_names:
                    error_wrong_param()
                else:
                    state = device.admin_up(name)
                    if state is None:
                        error_wrong_param()
                    elif state:
                        await write(
                            f"{name} current state : up\nLine protocol current state : up\n"
                        )
                    else:
                        await write(
                            f"{name} current state : Administratively down\n"
                            "Line protocol current state : down\n"
                        )
            elif lowered.startswith("display poe-power"):
                await _display_poe(process, device, text, lowered, write, error_wrong_param)
            elif lowered.startswith("display diagnostic-information"):
                await emit_paged(_diagnostic_text(device))
            elif lowered.startswith("display logbuffer"):
                if device.profile.device_type != "access_switch":
                    error_unknown()
                else:
                    await emit_paged(_logbuffer_text(device))
            elif lowered.startswith("dir flash:"):
                await emit_paged(device.dir_text())
            elif lowered.startswith("startup system-software"):
                name = text[len("startup system-software") :].strip()
                if not _image_name_ok(name) or not device.has_flash_file(name):
                    error_wrong_param()
                else:
                    device.set_boot_image(name)
            elif lowered.startswith("startup saved-configuration"):
                name = text[len("startup saved-configuration") :].strip()
                if not _config_name_ok(name) or not device.has_flash_file(name):
                    error_wrong_param()
                else:
                    device.set_startup_file(name)
            elif lowered in ("return",):
                write_to_out("")
                await write(prompt())
                continue
            elif lowered in ("quit", "exit"):
                process.exit(0)
                return
            else:
                error_unknown()
        elif view[0] == "config":
            if lowered.startswith("interface "):
                name = text[len("interface ") :].strip()
                if name not in device.profile.interface_names:
                    error_wrong_param()
                else:
                    view[0] = "interface"
                    view.append(name)
            elif lowered in ("quit", "return"):
                view[0] = "user"
                view.clear()
                view.append("user")
            else:
                error_unknown()
        elif view[0] == "interface":
            if lowered == "shutdown":
                device.set_interface_admin(view[1], up=False)
            elif lowered == "undo shutdown":
                device.set_interface_admin(view[1], up=True)
            elif lowered in ("poe-power on", "poe-power off"):
                name = view[1]
                if not device.profile.is_poe_port(name):
                    write_to_out(ERR_POE_UNSUPPORTED + "\n")
                else:
                    device.request_poe(name, on=lowered == "poe-power on")
            elif lowered == "quit":
                view[0] = "config"
                view.pop()
            elif lowered == "return":
                view[0] = "user"
                view.clear()
                view.append("user")
            else:
                error_unknown()
        await write(prompt())


def _image_name_ok(name: str) -> bool:
    return bool(name.startswith("firmware-") and name.endswith(".bin") and FLASH_NAME_RE.match(name))


def _config_name_ok(name: str) -> bool:
    return bool(name.endswith(".cfg") and FLASH_NAME_RE.match(name))


async def _display_poe(process, device, text, lowered, write, error_wrong_param) -> None:
    del process
    if device.profile.device_type != "access_switch" or not lowered.startswith(
        "display poe-power interface "
    ):
        error_wrong_param()
        return
    name = text[len("display poe-power interface ") :].strip()
    if name not in device.profile.interface_names:
        error_wrong_param()
        return
    if not device.profile.is_poe_port(name):
        await write("Error: The interface does not support PoE.\n")
        return
    state = device.poe_state(name)
    if state is None:
        error_wrong_param()
        return
    await write(f"Port : {name}\nPower state : {'on' if state else 'off'}\n")


async def _do_reboot(process: SSHServerProcess, device: VrpDevice, write, read_line) -> bool:
    """The DSL reboot flow. Returns True when the session must close.

    Save-prompt (dirty + original startup file + knob): the platform NEVER
    answers Y here — an executor that sees this prompt aborts; answering
    anything but y cancels the reboot (the EOF path cancels too).
    """
    if (
        device.dirty
        and device.startup_file == CONFIG_BASE_FILE
        and device.knobs.save_prompt
    ):
        await write("\n" + "Warning: The current configuration has not been saved. Save it now? [Y/N]:")
        answer = await read_line()
        if answer is None or answer.strip().lower() != "y":
            await write("\n" + INFO_REBOOT_CANCELED + "\n")
            return False
        device.save_running_config()
    await write("\n" + CONFIRM_REBOOT)
    answer = await read_line()
    if answer is None or answer.strip().lower() != "y":
        await write("\n" + INFO_REBOOT_CANCELED + "\n")
        return False
    device.perform_reboot()
    await write("\n" + INFO_REBOOTING + "\n")
    process.exit(0)
    return True


def _diagnostic_text(device: VrpDevice) -> str:
    """Long deterministic multi-section diagnostic text ([sim] DSL)."""
    snapshot = device.snapshot()
    sections = [
        "------------------display diagnostic-information------------------",
        "CPU utilization statistics:",
        "  CPU Usage: 12%",
        "Memory utilization statistics:",
        "  Memory Usage: 41%",
        "Interface state statistics:",
        "  Up interfaces : 52",
        "  Down interfaces : 0",
    ]
    admin_down = snapshot["admin_down"]
    if admin_down:
        sections.append(f"  Administratively down : {' '.join(str(x) for x in admin_down)}")
    sections.append("Device information:")
    sections.append(f"  Model : {snapshot['model']}")
    sections.append(f"  Serial number : {snapshot['serial']}")
    sections.append(f"  VRP version : {snapshot['version']}")
    sections.append("Flash file list:")
    for name in snapshot["flash_files"]:
        sections.append(f"  {name}")
    sections.append("Log buffer excerpt:")
    sections.append("  No log information")
    sections.append("--------------End of diagnostic information--------------")
    sections.append("")
    # Deliberately long output: the paging path (when the executor forgets
    # to disable it) must pause on ``-- More --``; the executor disables
    # paging so the full text arrives without pauses.
    sections.extend(
        f"Section fill line {index}: deterministic diagnostic filler."
        for index in range(1, 61)
    )
    sections.append("")
    return "\n".join(sections)


def _logbuffer_text(device: VrpDevice) -> str:
    snapshot = device.snapshot()
    return (
        "Syslog logging: enabled\n"
        "Display log buffer:\n"
        f"Sep  4 2026 06:00:00 {snapshot['sysname']} %%01IFNET/4/LINK_STATE(l)[1]:"
        "The state of the link is UP.\n"
        "--- End of log buffer ---\n"
    )


# ---------------------------------------------------------------------------
# SFTP server rooted at the real flash directory


class FlashSFTPServer(SFTPServer):
    """SFTPServer over the device flash directory with name/size guards.

    The default SFTPServer implementation maps paths into a real directory
    (``chroot``-style); this subclass keeps the default mapping but guards
    every write: allowlisted names only, no overwrite of the pristine
    config/base-image files, bounded flash budget, and the ``sftp_fail``
    knob turns every write into a "no space" error.
    """

    def __init__(self, device: VrpDevice) -> None:
        root = device.flash_root
        if root is None:
            msg = "vrp simulator device needs a flash root for SFTP"
            raise ValueError(msg)
        super().__init__(None, chroot=root)  # type: ignore[arg-type]
        self._device = device

    def _map(self, path: bytes) -> bytes:
        decoded = os.fsdecode(path)
        name = posixpath.basename(decoded)
        if not FLASH_NAME_RE.match(name):
            raise SFTPError(errno.EACCES, "file name not allowed")
        return path

    def open(self, path: bytes, pflags: int, attrs: SFTPAttrs) -> object:
        path = self._map(path)
        name = posixpath.basename(os.fsdecode(path))
        writing = bool(pflags & _FXF_WRITE)
        if writing:
            if self._device.knobs.sftp_fail:
                raise SFTPError(errno.ENOSPC, ERR_NO_SPACE)
            if name in (CONFIG_BASE_FILE, BOOT_BASE_IMAGE):
                raise SFTPError(errno.EACCES, "file name not allowed")
            if name.endswith(".bin") and not _image_name_ok(name):
                raise SFTPError(errno.EACCES, "file name not allowed")
            if not (name.endswith(".cfg") or name.endswith(".bin")):
                raise SFTPError(errno.EACCES, "file name not allowed")
            existing = self._device.flash_file_size(name) or 0
            free_bytes = self._device.flash_free_kb() * 1024
            if existing == 0 and free_bytes < 16 * 1024:
                raise SFTPError(errno.ENOSPC, ERR_NO_SPACE)
        return super().open(path, pflags, attrs)


# ---------------------------------------------------------------------------
# Boot helpers (the hosting layer owns the event loop + host key)


async def start_server(device: VrpDevice, host_key: asyncssh.SSHKey) -> Any:
    """Start one asyncssh server bound to 127.0.0.1 with an OS port."""
    async def sftp_factory(chan: Any) -> FlashSFTPServer:
        del chan
        return FlashSFTPServer(device)

    async def process_factory(process: SSHServerProcess) -> None:
        await _cli_session(process, device)

    return await asyncssh.create_server(
        server_factory=lambda: _AuthServer(device),
        process_factory=process_factory,
        sftp_factory=sftp_factory,
        host="127.0.0.1",
        port=0,
        server_host_keys=[host_key],
        server_version="SSH-2.0-WardenSim",
        # Raw sessions: no server-side line editor/echo — the executor
        # drives single-key page answers and reads prompts itself.
        line_editor=False,
        line_echo=False,
    )
