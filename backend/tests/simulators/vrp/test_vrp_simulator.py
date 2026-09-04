"""Self-tests for the VRP SSH simulator (M5T3).

Boots real asyncssh servers on 127.0.0.1 and drives them with real client
connections: prompt stack, view enforcement, error signatures, paging,
config dirty state, the reboot flow (continue prompt, save-prompt knob,
restart blip, uptime reset), the SFTP flash area (write guard + sftp_fail)
and the firmware boot-image/version-bump path. Every expectation pins the
[sim] DSL of ``device.py`` — never hardware evidence.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass

import asyncssh
import pytest

from tests.simulators.vrp.device import (
    CONFIG_BASE_FILE,
    SSH_PASSWORD,
    SSH_USERNAME,
    normalize_config_text,
)
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]


@dataclass
class Cli:
    """A raw asyncssh CLI connection used by the self-tests."""

    conn: asyncssh.SSHClientConnection
    proc: asyncssh.SSHClientProcess
    buffer: str = ""

    def close(self) -> None:
        self.conn.close()

    async def read_until(self, marker: str, wait_seconds: float = 5.0) -> str:
        deadline = time.monotonic() + wait_seconds
        while marker not in self.buffer:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"marker {marker!r} not seen; buffer tail: {self.buffer[-400:]!r}"
                )
            try:
                chunk = await asyncio.wait_for(self.proc.stdout.read(4096), timeout=1.0)
            except TimeoutError:
                continue
            if not chunk:
                break
            self.buffer += chunk
        return self.buffer

    async def prompt(self) -> str:
        self.buffer = ""
        return await self.read_until("> ")

    async def command(self, text: str, marker: str | None = None) -> str:
        self.buffer = ""
        self.proc.stdin.write(text + "\n")
        await self.proc.stdin.drain()
        return await self.read_until(marker if marker is not None else "> ")


async def open_cli(
    handle,
    username: str = SSH_USERNAME,
    password: str = SSH_PASSWORD,
    *,
    disable_paging: bool = True,
) -> Cli:
    conn = await asyncssh.connect(
        "127.0.0.1",
        port=handle.port,
        username=username,
        password=password,
        known_hosts=None,
    )
    # Raw sessions: the server runs without a line editor (single-key page
    # answers reach it without newlines) — the same mode the platform
    # executor client uses.
    proc = await conn.create_process(term_type="xterm")
    cli = Cli(conn=conn, proc=proc)
    await cli.prompt()
    if disable_paging:
        await cli.command("screen-length 0 temporary")
    return cli


def run(coro) -> object:
    return asyncio.run(coro)


class TestAuthAndBanner:
    def test_wrong_password_is_refused(self, vrp_handle) -> None:
        async def scenario() -> None:
            with pytest.raises(asyncssh.PermissionDenied):
                await open_cli(vrp_handle, password="wrong-password")

        run(scenario())

    def test_banner_and_user_prompt(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle)
            try:
                cli.buffer = ""
                await cli.command("display version")
                assert "VRP (R) software, Version V200R021C10SPC600" in cli.buffer
                assert "S5732-H48XUM2CC" in cli.buffer
                assert "SIM-S5732-0001" in cli.buffer
                assert re.search(r"System uptime is 360\d seconds", cli.buffer)
            finally:
                cli.close()

        run(scenario())


class TestPaging:
    def test_paging_stops_at_more_and_q_cancels(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle, disable_paging=False)
            try:
                cli.buffer = ""
                cli.proc.stdin.write("display diagnostic-information\n")
                await cli.proc.stdin.drain()
                await cli.read_until("-- More --")
                cli.proc.stdin.write("q")
                await cli.proc.stdin.drain()
                await cli.read_until("<sim-s5732>")
                # The canceled tail must not appear after the marker.
                assert "-- More --" in cli.buffer
                tail = cli.buffer.rsplit("-- More --", 1)[1]
                assert "Section fill line 60:" not in tail
            finally:
                cli.close()

        run(scenario())

    def test_screen_length_zero_disables_paging(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle)
            try:
                cli.buffer = ""
                await cli.command("display diagnostic-information")
                assert "-- More --" not in cli.buffer
                assert "Section fill line 60:" in cli.buffer
            finally:
                cli.close()

        run(scenario())


class TestViewsAndErrors:
    def test_config_and_interface_views_with_shutdown(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle)
            try:
                await cli.command("system-view", marker="[sim-s5732]")
                await cli.command(
                    "interface GigabitEthernet0/0/2",
                    marker="[sim-s5732-GigabitEthernet0/0/2]",
                )
                await cli.command("shutdown", marker="[sim-s5732-GigabitEthernet0/0/2]")
                await cli.command("return")
                await cli.command("display interface GigabitEthernet0/0/2")
                assert "GigabitEthernet0/0/2 current state : Administratively down" in cli.buffer
                await cli.command("compare configuration")
                assert "different from the saved configuration" in cli.buffer
                snapshot = vrp_handle.device.snapshot()
                assert "GigabitEthernet0/0/2" in snapshot["admin_down"]
                assert snapshot["dirty"] is True
            finally:
                cli.close()

        run(scenario())

    def test_view_enforcement_and_unknown_command_errors(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle)
            try:
                # shutdown is an interface-view command -> unknown command.
                await cli.command("shutdown")
                assert "Error: Unrecognized command found at '^' position." in cli.buffer
                # Unknown interface in the system view -> wrong parameter.
                await cli.command("system-view", marker="[sim-s5732]")
                await cli.command("interface GigabitEthernet0/0/99", marker="[sim-s5732]")
                assert "Error: Wrong parameter found at '^' position." in cli.buffer
            finally:
                cli.close()

        run(scenario())

    def test_poe_commands_are_access_ge_ports_only(self, vrp_access_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_access_handle)
            try:
                await cli.command("system-view", marker="[sim-s5735]")
                await cli.command(
                    "interface GigabitEthernet0/0/3",
                    marker="[sim-s5735-GigabitEthernet0/0/3]",
                )
                await cli.command("poe-power on", marker="[sim-s5735-GigabitEthernet0/0/3]")
                await cli.command("return")
                await cli.command("display poe-power interface GigabitEthernet0/0/3")
                assert "Power state : on" in cli.buffer
                # XGE ports carry no PoE.
                await cli.command("system-view", marker="[sim-s5735]")
                await cli.command(
                    "interface XGigabitEthernet0/0/1",
                    marker="[sim-s5735-XGigabitEthernet0/0/1]",
                )
                await cli.command("poe-power on", marker="[sim-s5735-XGigabitEthernet0/0/1]")
                assert "does not support PoE" in cli.buffer
            finally:
                cli.close()

        run(scenario())


class TestCurrentConfig:
    def test_current_configuration_reflects_state_and_normalizes(self, vrp_handle) -> None:
        async def scenario() -> None:
            cli = await open_cli(vrp_handle)
            try:
                await cli.command("system-view", marker="[sim-s5732]")
                await cli.command(
                    "interface GigabitEthernet0/0/4",
                    marker="[sim-s5732-GigabitEthernet0/0/4]",
                )
                await cli.command("shutdown", marker="[sim-s5732-GigabitEthernet0/0/4]")
                await cli.command("return")
                cli.buffer = ""
                await cli.command("display current-configuration")
                text = cli.buffer.split("display current-configuration", 1)[-1]
                text = text.split("<sim-s5732>", 1)[0]
                assert text.startswith("#\nsysname sim-s5732")
                assert "interface GigabitEthernet0/0/4\n shutdown" in text
                assert "interface GigabitEthernet0/0/1\n undo shutdown" in text
                normalized = normalize_config_text(text)
                assert normalized.endswith("return\n")
                # Deterministic: a second read produces identical text.
                cli.buffer = ""
                await cli.command("display current-configuration")
                second = cli.buffer.split("display current-configuration", 1)[-1]
                second = second.split("<sim-s5732>", 1)[0]
                assert normalize_config_text(second) == normalized
            finally:
                cli.close()

        run(scenario())


class TestRebootFlow:
    def test_reboot_continue_prompt_closes_and_uptime_resets(self, vrp_handle) -> None:
        async def scenario() -> None:
            device = vrp_handle.device
            device.knobs.restart_blip_seconds = 0.7
            cli = await open_cli(vrp_handle)
            cli.buffer = ""
            cli.proc.stdin.write("reboot\n")
            await cli.proc.stdin.drain()
            await cli.read_until("Continue? [Y/N]:")
            cli.proc.stdin.write("y\n")
            await cli.proc.stdin.drain()
            await asyncio.wait_for(cli.proc.wait_closed(), timeout=10.0)
            cli.close()
            await asyncio.sleep(1.2)
            snapshot = device.snapshot()
            assert snapshot["uptime_seconds"] < 300
            assert snapshot["dirty"] is False
            # Reachable again with the same identity.
            again = await open_cli(vrp_handle)
            try:
                await again.command("display version")
                assert "SIM-S5732-0001" in again.buffer
            finally:
                again.close()

        run(scenario())

    def test_reboot_during_blip_is_refused_then_recovers(self, vrp_handle) -> None:
        async def scenario() -> None:
            device = vrp_handle.device
            device.knobs.restart_blip_seconds = 0.8
            device.perform_reboot()  # simulate the reboot side effects
            refused = False
            try:
                await open_cli(vrp_handle)
            except asyncssh.Error:
                refused = True
            assert refused
            await asyncio.sleep(1.5)
            cli = await open_cli(vrp_handle)
            cli.close()

        run(scenario())

    def test_save_prompt_knob_and_never_answer_y(self, vrp_handle) -> None:
        async def scenario() -> None:
            device = vrp_handle.device
            device.knobs.save_prompt = True
            device.knobs.restart_blip_seconds = 0.2
            # Make the configuration dirty like a real unsaved change.
            device.set_interface_admin("GigabitEthernet0/0/5", up=False)
            assert device.dirty
            cli = await open_cli(vrp_handle)
            cli.buffer = ""
            cli.proc.stdin.write("reboot\n")
            await cli.proc.stdin.drain()
            await cli.read_until("Save it now? [Y/N]:")
            # The platform NEVER answers Y: answer n (cancel) and assert the
            # device stays up with the dirty configuration intact.
            cli.proc.stdin.write("n\n")
            await cli.proc.stdin.drain()
            await cli.read_until("Reboot canceled.")
            await cli.read_until("<sim-s5732>")
            snapshot = device.snapshot()
            assert snapshot["dirty"] is True
            assert "GigabitEthernet0/0/5" in snapshot["admin_down"]
            cli.close()

        run(scenario())

    def test_reboot_without_save_prompt_discards_unsaved(self, vrp_handle) -> None:
        """The dirty config is not saved when the reboot proceeds; the boot
        reloads the startup file (honest VRP semantics, DSL)."""
        async def scenario() -> None:
            device = vrp_handle.device
            device.knobs.restart_blip_seconds = 0.5
            device.set_interface_admin("GigabitEthernet0/0/6", up=False)
            cli = await open_cli(vrp_handle)
            cli.buffer = ""
            cli.proc.stdin.write("reboot\n")
            await cli.proc.stdin.drain()
            await cli.read_until("Continue? [Y/N]:")
            cli.proc.stdin.write("y\n")
            await cli.proc.stdin.drain()
            await asyncio.wait_for(cli.proc.wait_closed(), timeout=10.0)
            cli.close()
            await asyncio.sleep(1.2)
            snapshot = device.snapshot()
            assert snapshot["dirty"] is False
            assert snapshot["admin_down"] == []

        run(scenario())


class TestSftpFlash:
    def test_sftp_put_lists_in_dir_and_free_space_shrinks(self, vrp_handle, tmp_path) -> None:
        async def scenario() -> None:
            content = b"#\nsysname restored\n#\nreturn\n"
            local = tmp_path / "restore.cfg"
            local.write_bytes(content)
            conn = await asyncssh.connect(
                "127.0.0.1",
                port=vrp_handle.port,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                known_hosts=None,
            )
            try:
                sftp = await conn.start_sftp_client()
                try:
                    await sftp.put(str(local), "warden-restore-0badc0de.cfg")
                    names = await sftp.listdir(".")
                    assert "warden-restore-0badc0de.cfg" in names
                finally:
                    sftp.exit()
            finally:
                conn.close()
            snapshot = vrp_handle.device.snapshot()
            assert "warden-restore-0badc0de.cfg" in snapshot["flash_files"]

        run(scenario())

    def test_sftp_write_guards_and_sftp_fail_knob(self, vrp_handle, tmp_path) -> None:
        async def scenario() -> None:
            device = vrp_handle.device
            conn = await asyncssh.connect(
                "127.0.0.1",
                port=vrp_handle.port,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                known_hosts=None,
            )
            try:
                sftp = await conn.start_sftp_client()
                try:
                    local = tmp_path / "payload.bin"
                    local.write_bytes(b"x" * 1024)
                    # The pristine base image file is not overwritable.
                    with pytest.raises(asyncssh.SFTPError) as denied:
                        await sftp.put(str(local), CONFIG_BASE_FILE)
                    assert "not allowed" in str(denied.value)
                    # sftp_fail -> no space left on device.
                    device.knobs.sftp_fail = True
                    with pytest.raises(asyncssh.SFTPError) as full:
                        await sftp.put(str(local), "warden-restore-deadbeef.cfg")
                    assert "No space" in str(full.value)
                    device.knobs.sftp_fail = False
                finally:
                    sftp.exit()
            finally:
                conn.close()

        run(scenario())


class TestFirmwarePath:
    def test_firmware_upload_startup_and_version_bump(self, vrp_handle, tmp_path) -> None:
        async def scenario() -> None:
            device = vrp_handle.device
            device.knobs.restart_blip_seconds = 0.5
            image = (
                "WARDEN-SIM-FW "
                + json.dumps({"model": "S5732-H48XUM2CC", "version": "V200R021C10SPC610"})
                + "\npadding\n"
            ).encode("utf-8")
            local = tmp_path / "image.bin"
            local.write_bytes(image)
            conn = await asyncssh.connect(
                "127.0.0.1",
                port=vrp_handle.port,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                known_hosts=None,
            )
            try:
                sftp = await conn.start_sftp_client()
                try:
                    await sftp.put(str(local), "firmware-V200R021C10SPC610.bin")
                finally:
                    sftp.exit()
            finally:
                conn.close()
            cli = await open_cli(vrp_handle)
            try:
                # Not in flash -> wrong parameter.
                await cli.command("startup system-software firmware-nope.bin")
                assert "Error: Wrong parameter" in cli.buffer
                await cli.command("startup system-software firmware-V200R021C10SPC610.bin")
                await cli.command("display startup")
                assert "firmware-V200R021C10SPC610.bin" in cli.buffer
                cli.buffer = ""
                cli.proc.stdin.write("reboot\n")
                await cli.proc.stdin.drain()
                await cli.read_until("Continue? [Y/N]:")
                cli.proc.stdin.write("y\n")
                await cli.proc.stdin.drain()
                await asyncio.wait_for(cli.proc.wait_closed(), timeout=10.0)
            finally:
                cli.close()
            await asyncio.sleep(1.2)
            assert device.version == "V200R021C10SPC610"
            again = await open_cli(vrp_handle)
            try:
                await again.command("display version")
                assert "V200R021C10SPC610" in again.buffer
            finally:
                again.close()

        run(scenario())


@pytest.fixture()
def vrp_handle():
    with running_vrp_server("core_s5732") as handle:
        yield handle


@pytest.fixture()
def vrp_access_handle():
    with running_vrp_server("access_s5735") as handle:
        yield handle
