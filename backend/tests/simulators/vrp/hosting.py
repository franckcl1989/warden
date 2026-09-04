"""Sync hosting for the VRP simulator (test-only).

Binds one asyncssh VRP server (shell + SFTP) on 127.0.0.1 with an
OS-assigned port on a private thread with its own event loop, mirroring the
sync-hosting helper the M5T1/M5T2 switch agent uses. A per-boot ed25519 host
key is generated inside the loop; the handle exposes the canonical host-key
fingerprint so adapter tests and platform slices can pin it in device
connection configs (the automation connect refuses unpinned hosts).

The simulator is a TEST DEVICE SIMULATOR — never hardware evidence.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from tests.simulators.vrp.app import host_fingerprint_of, start_server
from tests.simulators.vrp.device import VrpDevice, profile_by_key


@dataclass
class VrpServerHandle:
    """A booted VRP server + the device it serves."""

    device: VrpDevice
    port: int
    host_fingerprint: str
    host_key: asyncssh.SSHKey


class _VrpLoop:
    """One VRP server on a private thread with its own event loop."""

    def __init__(self, device: VrpDevice, flash_root: Path) -> None:
        self._device = device
        self._flash_root = flash_root
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._thread: threading.Thread | None = None
        self._failures: list[BaseException] = []
        self.handle: VrpServerHandle | None = None

    def start(self) -> None:
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop_event = asyncio.Event()
            self._loop = loop
            self._stop_event = stop_event

            async def serve() -> None:
                host_key = asyncssh.generate_private_key("ssh-ed25519")
                server = await start_server(self._device, host_key)
                port = int(server.get_port() or 0)
                self.handle = VrpServerHandle(
                    device=self._device,
                    port=port,
                    host_fingerprint=host_fingerprint_of(host_key),
                    host_key=host_key,
                )
                ready.set()
                await stop_event.wait()
                server.close()
                await server.wait_closed()

            try:
                loop.run_until_complete(serve())
            except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
                self._failures.append(exc)
                ready.set()
            finally:
                with contextlib.suppress(BaseException):  # noqa: S110 - best-effort teardown
                    loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()

        self._thread = threading.Thread(target=run, name="vrp-sim-server", daemon=True)
        self._thread.start()
        if not ready.wait(20.0):
            raise AssertionError("vrp simulator server did not start in time")
        if self._failures:
            raise AssertionError(f"vrp simulator server failed to start: {self._failures[0]!r}")
        assert self.handle is not None and self.handle.port > 0

    def stop(self) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None


@contextmanager
def running_vrp_server(
    profile_key: str = "core_s5732",
    *,
    flash_root: Path | None = None,
    username: str | None = None,
    password: str | None = None,
) -> Iterator[VrpServerHandle]:
    """Boot one VRP simulator for the ``with`` block.

    ``username/password`` exist only for symmetry/documentation: the device
    authenticates the fixed simulator credential from ``device.py`` (the
    platform stores whatever the operator declared, and the credential is a
    test fixture — real credentials are hardware-certification territory).
    """
    del username, password
    owned_tmp: tempfile.TemporaryDirectory[str] | None = None
    if flash_root is None:
        owned_tmp = tempfile.TemporaryDirectory(prefix="vrp-sim-flash-")
        flash_root = Path(owned_tmp.name)
    device = VrpDevice(profile_by_key(profile_key), flash_root=flash_root)
    loop = _VrpLoop(device, flash_root)
    loop.start()
    try:
        yield loop.handle  # type: ignore[misc]
    finally:
        loop.stop()
        if owned_tmp is not None:
            owned_tmp.cleanup()
