"""SNMP protocol client errors (docs/DEVICE_ADAPTERS.md §7 adapter subset).

The client only raises ``SnmpError`` with a stable contracts/error-codes.json
code (the adapter subset the SNMP client may produce):

- ``network_unreachable`` — request timed out after bounded retries (no
  response at all; for v2c a wrong community also looks like this at the
  protocol level — community is not authenticated in v2c, so the client can
  never claim authentication_failed for v2c);
- ``authentication_failed`` — SNMPv3 USM refused the message
  (WrongDigest / UnknownUserName / unsupported security level /
  decryption failure);
- ``protocol_error`` — tooBig / genErr / malformed response / unrecognized
  value type.

``message`` carries a sanitized summary — never keys, communities or raw
device payloads (SECURITY.md §10).
"""

from __future__ import annotations


class SnmpError(Exception):
    """SNMP client failure with a stable error code.

    ``code`` must be a contracts/error-codes.json code; ``stage`` is the
    failing phase (request/auth/parse). ``detail_safe`` is display-safe free
    text; ``hint`` carries non-secret structured context (e.g. the batch size
    suggestion after a tooBig).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        stage: str = "request",
        detail_safe: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage
        self.detail_safe = detail_safe
        self.hint = hint
