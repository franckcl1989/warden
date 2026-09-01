"""Weak-protocol configuration change detection (docs/SECURITY.md §6, M1T4).

SECURITY.md §6: SNMPv3 is the default (SNMPv2c requires an explicit admin
choice), Telnet is globally disabled by default, HTTPS verification must stay
on (fingerprints are pinned instead of permanently disabling ``verify_tls``),
and HTTP web management carries a cleartext risk. Every protocol-weakening
``connection_config`` change must be written to the security audit
(``security.config_changed``, via the devices route).

This module only decides WHICH denylisted keys changed between an old and a
new configuration; it holds no secrets and writes nothing. Keys count when:

- the NEW value is the weak direction and differs from the old value
  (idempotent re-PATCHes and strengthening changes produce no event), or
- the TLS fingerprint key changed at all (pinned / rotated / removed).
"""

from __future__ import annotations

from collections.abc import Mapping

# Key -> weak value: audited only when the config changes TO that value.
_WEAK_VALUES: dict[str, object] = {
    "snmp_version": "v2c",
    "telnet": True,
    "verify_tls": False,
    "protocol": "http",
}

# Any change of these keys is security-relevant (added/rotated/removed).
_CHANGE_SENSITIVE_KEYS: frozenset[str] = frozenset({"tls_fingerprint_sha256"})

# Full denylist (used by tests and documentation).
SENSITIVE_CONFIG_KEYS: frozenset[str] = frozenset(_WEAK_VALUES) | _CHANGE_SENSITIVE_KEYS


def security_sensitive_config_change(
    old_config: Mapping[str, object] | None,
    new_config: Mapping[str, object] | None,
) -> list[str]:
    """Return the denylisted ``connection_config`` keys that changed.

    ``old_config`` is the previously stored configuration, ``new_config`` the
    configuration about to be stored. Returns the changed keys in a
    deterministic order (``_WEAK_VALUES`` declaration order, then sorted
    change-sensitive keys); an empty list means no security-relevant change.
    """
    old = dict(old_config or {})
    new = dict(new_config or {})
    changed: list[str] = []
    for key, weak_value in _WEAK_VALUES.items():
        new_value = new.get(key)
        if new_value == weak_value and old.get(key) != weak_value:
            changed.append(key)
    for key in sorted(_CHANGE_SENSITIVE_KEYS):
        old_value = old.get(key)
        new_value = new.get(key)
        if new_value != old_value and (new_value is not None or old_value is not None):
            changed.append(key)
    return changed
