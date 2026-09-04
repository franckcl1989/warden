"""Browser-terminal transport errors (M5T4, infrastructure layer).

Terminal transports speak the SAME stable error vocabulary as the rest of
the device-protocol layer (contracts/error-codes.json subset:
``authentication_failed`` / ``network_unreachable`` / ``validation_failed`` /
``protocol_error``); the WebSocket boundary maps them to a handshake-failed
close plus an audit row carrying only the stable code — never terminal
content (SECURITY.md §8).
"""

from __future__ import annotations


class TerminalTransportError(Exception):
    """One terminal-connect failure with a stable error code."""

    def __init__(self, code: str, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        #: Safe, content-free detail (e.g. host_key_mismatch); never payload.
        self.detail = detail
