"""Sync hosting for the switch simulator agent (test-only).

The M5T2 adapter suite is plain sync pytest while the pysnmp agent is
asyncio-based: this helper boots one ``SwitchAgent`` on a private thread
with its own event loop and yields the started agent (real UDP on
127.0.0.1 with an OS-assigned port). The SnmpClient used by the adapters is
sync (``asyncio.run`` per call on the CALLING thread), exactly like the
platform workers run it.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from tests.simulators.switch.agent import SwitchAgent


class _AgentLoop:
    """One agent on a private thread with its own event loop."""

    def __init__(self, agent: SwitchAgent) -> None:
        self._agent = agent
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._thread: threading.Thread | None = None
        self._failures: list[BaseException] = []

    def start(self) -> None:
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop_event = asyncio.Event()
            self._loop = loop
            self._stop_event = stop_event

            async def serve() -> None:
                await self._agent.start()
                ready.set()
                await stop_event.wait()
                await self._agent.stop()

            try:
                loop.run_until_complete(serve())
            except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
                self._failures.append(exc)
                ready.set()
            finally:
                with contextlib.suppress(BaseException):  # noqa: S110 - best-effort teardown
                    loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()

        self._thread = threading.Thread(target=run, name="switch-sim-agent", daemon=True)
        self._thread.start()
        if not ready.wait(15.0):
            raise AssertionError("switch simulator agent did not start in time")
        if self._failures:
            raise AssertionError(f"switch simulator agent failed to start: {self._failures[0]!r}")

    def stop(self) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None


@contextmanager
def running_agent(agent: SwitchAgent) -> Iterator[SwitchAgent]:
    """Boot ``agent`` (real UDP) for the duration of the ``with`` block."""
    loop = _AgentLoop(agent)
    loop.start()
    try:
        yield agent
    finally:
        loop.stop()
