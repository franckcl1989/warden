"""DSM API discovery via SYNO.API.Info.Query (docs/DEVICE_ADAPTERS.md §5, ADR-018).

``SYNO.API.Info`` (path ``query.cgi``, version 1, method ``query``,
``query=all``) is the only DSM API documented in the public DSM Login Web API
guide besides ``SYNO.API.Auth`` — it returns the device's own API map:

    {"api_name": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 6}}

Everything else DSM serves is a ``vendor_private`` management API
(DEVICE_ADAPTERS.md §5): the client records the exact (api name, path,
version) basis of every call it makes (ADR-018 — precise-version evidence)
and NEVER calls an API at a version above the version this codebase is
certified for (``CERTIFIED_API_VERSIONS``). Version negotiation therefore
caps discovery's ``maxVersion`` at the certified version; if the device
cannot serve the certified version, the call is refused with a stable reason
instead of silently using an uncertified version.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.infrastructure.protocols.dsm.errors import DSMError

INFO_API_NAME = "SYNO.API.Info"
AUTH_API_NAME = "SYNO.API.Auth"

# Discovery's own certified row: SYNO.API.Info.Query is documented at
# version 1 in the DSM Login Web API guide.
INFO_CERTIFIED_VERSION = 1


@dataclass(frozen=True)
class ApiInfo:
    """One SYNO.API.Info.Query entry (device-advertised versions)."""

    name: str
    path: str
    min_version: int
    max_version: int


@dataclass(frozen=True)
class ApiCallSpec:
    """A resolved call basis: exact API name, endpoint path and version.

    This is the per-call (api, path, version) evidence unit ADR-018
    requires: adapters record specs from the call ledger into the device's
    discovery evidence/audit basis.
    """

    api_name: str
    path: str
    version: int


@dataclass(frozen=True)
class Negotiation:
    """Outcome of picking a call version for one API.

    ``spec`` is set only when the device's advertised range can serve the
    platform's certified version. ``reason`` is one of the stable
    ``NEGOTIATION_REASONS`` otherwise (never a guessed fallback version).
    """

    spec: ApiCallSpec | None = None
    reason: str | None = None

    @property
    def callable(self) -> bool:
        return self.spec is not None


# Stable negotiation reasons (adapter surfaces them as support gaps).
REASON_NOT_DISCOVERED = "not_discovered"  # device API map lacks the API
REASON_NOT_CERTIFIED = "not_certified"  # platform has no certified version row
REASON_DEVICE_TOO_OLD = "device_too_old"  # device maxVersion < certified version
REASON_RANGE_MISMATCH = "range_mismatch"  # certified version outside device range
NEGOTIATION_REASONS = frozenset(
    {REASON_NOT_DISCOVERED, REASON_NOT_CERTIFIED, REASON_DEVICE_TOO_OLD, REASON_RANGE_MISMATCH}
)


@dataclass(frozen=True)
class DiscoveryEvidence:
    """Immutable discovery evidence record (ADR-018 versioned basis).

    ``api_map`` is frozen at discovery time (sorted tuple of rows) so the
    evidence an adapter archives can never drift from what the client
    actually negotiated against. ``discovered_at`` is the capture timestamp.
    """

    api_map: tuple[tuple[str, str, int, int], ...] = ()
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def from_map(cls, api_map: dict[str, ApiInfo]) -> DiscoveryEvidence:
        rows = tuple(sorted((info.name, info.path, info.min_version, info.max_version) for info in api_map.values()))
        return cls(api_map=rows)


def parse_api_map(payload: object) -> dict[str, ApiInfo]:
    """Parse the ``SYNO.API.Info.Query`` envelope ``data`` member.

    Malformed entries are dropped with a ``protocol_error`` — a discovery
    payload that cannot be trusted must never yield guessed endpoints. An
    entry whose path is not a plain API path (no scheme, no query) is
    refused the same way.
    """
    if not isinstance(payload, dict):
        raise _parse_error("discovery data is not an object")
    result: dict[str, ApiInfo] = {}
    for name, entry in payload.items():
        if not isinstance(name, str) or not name:
            raise _parse_error("discovery data contains an unnamed API entry")
        if not isinstance(entry, dict):
            raise _parse_error(f"discovery entry for {name} is not an object")
        path = entry.get("path")
        min_version = entry.get("minVersion")
        max_version = entry.get("maxVersion")
        # DSM paths are endpoint file names (``query.cgi``/``entry.cgi``):
        # anything carrying a scheme, query or whitespace is not a callable
        # endpoint and must never be guessed into one.
        if not isinstance(path, str) or not path or any(ch in path for ch in ("?", ":", " ", "\t")):
            raise _parse_error(f"discovery entry for {name} has an invalid path")
        if not isinstance(min_version, int) or not isinstance(max_version, int) or min_version < 1:
            raise _parse_error(f"discovery entry for {name} has invalid version bounds")
        if max_version < min_version:
            raise _parse_error(f"discovery entry for {name} has an inverted version range")
        result[name] = ApiInfo(name=name, path=path, min_version=min_version, max_version=max_version)
    return result


def _parse_error(reason: str) -> DSMError:
    return DSMError("protocol_error", f"device discovery payload is invalid: {reason}", stage="parse")


def negotiate(api: ApiInfo | None, certified_version: int | None) -> Negotiation:
    """Pick the call version for one API.

    The negotiated version is ``min(device.maxVersion, certified_version)``
    and must sit inside the device's advertised ``[minVersion, maxVersion]``
    range — the client NEVER calls above the parser's certified version, and
    it never calls an uncertified version below it either.
    """
    if api is None:
        return Negotiation(reason=REASON_NOT_DISCOVERED)
    if certified_version is None:
        return Negotiation(reason=REASON_NOT_CERTIFIED)
    if api.max_version < certified_version:
        # The device is older than the certified version: an uncertified
        # fallback version is never used silently.
        return Negotiation(reason=REASON_DEVICE_TOO_OLD)
    version = min(api.max_version, certified_version)
    if version < api.min_version:
        return Negotiation(reason=REASON_RANGE_MISMATCH)
    return Negotiation(spec=ApiCallSpec(api_name=api.name, path=api.path, version=version))


def missing_apis(discovered: dict[str, ApiInfo], required: frozenset[str]) -> tuple[str, ...]:
    """Names from ``required`` absent from the discovered map (sorted)."""
    return tuple(sorted(required - set(discovered)))
