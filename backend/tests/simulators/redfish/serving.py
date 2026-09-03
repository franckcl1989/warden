"""Boot the Redfish simulator as a real HTTP server for integration tests.

The simulator is a TEST device simulator; booting it does not create any
hardware evidence. A plain localhost httpx client is used deliberately:
production adapter wiring applies the M1T2 SSRF policy (which denies
loopback) and TLS rules — this helper only proves the protocol client works
over real HTTP/1.1 against the simulator.
"""

from __future__ import annotations

import gc
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn

from tests.simulators.redfish.app import SimulatorConfig, create_simulator

WAIT_TIMEOUT_SECONDS = 15.0


@contextmanager
def serve_simulator(config: SimulatorConfig | None = None) -> Iterator[str]:
    """Run the simulator on 127.0.0.1 with an OS-assigned port.

    Yields the base URL (``http://127.0.0.1:<port>``). The server is stopped
    when the context exits.
    """
    server = uvicorn.Server(
        uvicorn.Config(
            create_simulator(config if config is not None else SimulatorConfig()),
            host="127.0.0.1",
            port=0,
            log_level="warning",
            access_log=False,
            timeout_keep_alive=1,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        if not thread.is_alive():
            msg = "simulator server thread exited before startup"
            raise RuntimeError(msg)
        time.sleep(0.02)
    if not getattr(server, "started", False):
        msg = "simulator server did not start in time"
        raise RuntimeError(msg)
    sockets = server.servers[0].sockets if server.servers else []
    if not sockets:
        msg = "simulator server has no bound socket"
        raise RuntimeError(msg)
    port = sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=WAIT_TIMEOUT_SECONDS)
        # uvicorn on Windows leaves idle keep-alive sockets to be closed by
        # GC after the server thread exits; collect them HERE so the
        # unraisable-socket noise stays inside this test's scope instead of
        # surfacing in whichever later test triggers the next collection.
        gc.collect()
