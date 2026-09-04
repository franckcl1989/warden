"""VRP SSH protocol errors (docs/DEVICE_ADAPTERS.md §7 adapter subset).

The protocol layer raises ``VrpError`` with a stable contracts/error-codes.json
code (the subset the VRP SSH paths may produce) plus a stage; the Huawei
adapter boundary maps them onto ``AdapterError``/``AdapterTimeoutError``.

Codes produced here:

- ``network_unreachable`` — TCP/SSH handshake lost, refused, or timed out
  (incl. the device's restart blip and mid-session drops);
- ``authentication_failed`` — password auth refused by the device;
- ``validation_failed`` — host-key fingerprint missing (automation
  refusal) or mismatched (``host_key_mismatch``), template/param
  validation failures;
- ``protocol_error`` — the session does not behave like the [sim] CLI DSL
  (unexpected prompt state, paging marker while paging was disabled,
  unparseable banner);
- ``operation_failed`` — the device answered a command with an explicit
  ``Error:`` marker that is NOT a parameter problem (``wrong parameter`` /
  ``unrecognized command`` markers classify as ``validation_failed``);
- ``ambiguous_result`` — the connection dropped in the middle of a command
  whose application state cannot be proven (never replayed).

``message`` carries a sanitized summary — never credentials or raw device
payloads (SECURITY.md §10).
"""

from __future__ import annotations


class VrpError(Exception):
    """VRP SSH client failure with a stable error code + stage."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        stage: str = "command",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage


class VrpTimeoutError(VrpError):
    """A command/read did not complete within its bounded wait.

    Explicitly NOT a confirmed device failure: the device may still be
    working (e.g. an accepted reboot whose connection dropped). The adapter
    boundary converts this into ``AdapterTimeoutError`` so the worker maps
    it through the timeout transitions (fenced side effects ->
    verification_required, never a clean retryable failure).
    """

    def __init__(self, message: str, *, stage: str = "command") -> None:
        super().__init__("protocol_error", message, stage=stage)
