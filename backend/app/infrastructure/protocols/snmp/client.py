"""SNMPv3/v2c protocol client (docs/DEVICE_ADAPTERS.md §6.1/§7/§8, M5T1).

Sync facade over pysnmp-lextudio's asyncio-only hlapi: the platform's worker
threads are sync SQLAlchemy, so each public call runs ONE private event loop
via ``asyncio.run`` and a fresh pysnmp ``SnmpEngine`` (per-call engines are
the documented pysnmp pattern; per-call loops keep loop state out of worker
threads). Unit-tested decision logic lives in the module-level helpers; the
thin pysnmp glue is exercised against the switch simulator over real UDP.

Behaviour contract:

- SNMPv3 is the DEFAULT (SECURITY.md §6); v2c only via an explicit
  ``version="v2c"`` connection with a community. There is NEVER a silent
  downgrade — a v3 connection configured without v3 credentials fails
  construction.
- Timeouts 2 s, 2 retries (DEVICE_ADAPTERS.md §8: SNMP GET is idempotent);
  the varbind batch size for GET batches and bulk walk repetitions is
  configurable (``batch_size``).
- Missing leaves normalize to the typed ``NOT_PRESENT`` sentinel
  (noSuchInstance/noSuchObject/endOfMibView), never 0.
- Errors map to contracts/error-codes.json: request timeouts ->
  ``network_unreachable`` (bounded retries, read-backoff class); SNMPv3 USM
  refusals (wrongDigest/unknownUser/unsupported level/decryption) ->
  ``authentication_failed``; tooBig/genErr/malformed -> ``protocol_error``.
  A v2c wrong community is indistinguishable from silence at the protocol
  level (v2c authenticates nothing), so it surfaces as ``network_unreachable``
  — the adapter layer shows the v2c weak-protocol warning instead of ever
  claiming v2c authentication.
- Keys and communities are never logged; ``repr`` of the connection redacts
  them (SECURITY.md §10 redaction is value-level, the client additionally
  never places secrets in event payloads).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar, cast

import structlog
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulkCmd,
    getCmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from app.infrastructure.protocols.snmp.errors import SnmpError
from app.infrastructure.protocols.snmp.values import NOT_PRESENT, SnmpValue, normalize_value

DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_RETRIES = 2
DEFAULT_BATCH_SIZE = 20
WALK_MAX_ROWS = 5000

_AUTH_PROTOCOLS = {
    "none": usmNoAuthProtocol,
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
}
_PRIVACY_PROTOCOLS = {
    "none": usmNoPrivProtocol,
    "des": usmDESPrivProtocol,
    "aes128": usmAesCfb128Protocol,
}

# USM refusal classes whose meaning is "the USM refused the message". This
# set intentionally contains NO community semantics: v2c authenticates
# nothing, so a v2c wrong-community request surfaces as silence (timeout ->
# network_unreachable), never as a fake v3-style authentication failure.
_AUTH_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "WrongDigest",
        "UnknownUserName",
        "UnknownSecurityName",
        "AuthenticationFailure",
        "UnsupportedSecurityLevel",
        "DecryptionError",
    }
)

_LOG = structlog.get_logger("warden.protocols.snmp")

T = TypeVar("T")
Runner = Callable[[Awaitable[T]], T]


@dataclass(frozen=True)
class SnmpConnection:
    """One SNMP agent endpoint + credential configuration.

    Credentials are plaintext ONLY inside the client call boundary (the
    adapter decrypts them from the credential store and constructs this
    object; SECURITY.md §5). ``repr`` redacts keys and the community.
    """

    host: str
    port: int = 161
    version: str = "v3"  # v3 default; v2c explicit only (SECURITY.md §6)
    community: str | None = None  # v2c only
    username: str | None = None  # v3 only
    auth_protocol: str = "sha"  # v3: none | md5 | sha
    auth_key: str | None = None
    privacy_protocol: str = "aes128"  # v3: none | des | aes128
    privacy_key: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRIES
    batch_size: int = DEFAULT_BATCH_SIZE

    def __post_init__(self) -> None:
        if self.version not in ("v3", "v2c"):
            msg = f"unsupported snmp version {self.version!r} (v3 or v2c only)"
            raise ValueError(msg)
        if self.version == "v3":
            if not self.username:
                msg = "snmp v3 requires a username (no silent v2c downgrade)"
                raise ValueError(msg)
            if self.auth_protocol not in _AUTH_PROTOCOLS:
                msg = f"unsupported snmp auth protocol {self.auth_protocol!r}"
                raise ValueError(msg)
            if self.privacy_protocol not in _PRIVACY_PROTOCOLS:
                msg = f"unsupported snmp privacy protocol {self.privacy_protocol!r}"
                raise ValueError(msg)
            if self.auth_protocol != "none" and not self.auth_key:
                msg = "snmp v3 auth protocol requires an auth key"
                raise ValueError(msg)
            if self.privacy_protocol != "none" and not self.privacy_key:
                msg = "snmp v3 privacy protocol requires a privacy key"
                raise ValueError(msg)
        else:
            if not self.community:
                msg = "snmp v2c requires a community string"
                raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "snmp timeout must be positive"
            raise ValueError(msg)
        if self.retries < 0:
            msg = "snmp retries must be >= 0"
            raise ValueError(msg)
        if self.batch_size < 1:
            msg = "snmp batch_size must be >= 1"
            raise ValueError(msg)

    def __repr__(self) -> str:
        return (
            f"SnmpConnection(host={self.host!r}, port={self.port}, version={self.version!r}, "
            f"username={self.username!r}, auth_protocol={self.auth_protocol!r}, "
            f"privacy_protocol={self.privacy_protocol!r}, timeout_seconds={self.timeout_seconds}, "
            f"retries={self.retries}, batch_size={self.batch_size}, "
            f"secrets=<redacted>)"
        )


def chunk_oids(oids: Sequence[str], *, batch_size: int) -> Sequence[Sequence[str]]:
    """Split an OID batch request into ``batch_size`` chunks."""
    if batch_size < 1:
        msg = "snmp batch_size must be >= 1"
        raise ValueError(msg)
    return [oids[offset : offset + batch_size] for offset in range(0, len(oids), batch_size)]


def raise_for_error_indication(error_indication: Any, *, stage: str) -> None:
    """Map a pysnmp error indication to a contracts/error-codes.json SnmpError.

    ``None`` (no error) passes. Timeouts -> network_unreachable; USM refusal
    classes -> authentication_failed; anything else -> protocol_error.
    """
    if error_indication is None:
        return
    label = type(error_indication).__name__
    if label == "RequestTimedOut":
        raise SnmpError(
            "network_unreachable",
            "snmp request timed out after bounded retries",
            stage=stage,
            detail_safe="request-timeout",
        )
    if label in _AUTH_FAILURE_CODES:
        raise SnmpError(
            "authentication_failed",
            "snmp agent refused the request credentials",
            stage=stage,
            detail_safe=label,
        )
    raise SnmpError(
        "protocol_error",
        f"snmp request failed with indication {label}",
        stage=stage,
        detail_safe=label,
    )


def raise_for_error_status(error_status: Any, *, stage: str) -> None:
    """Map a response PDU error-status to a SnmpError (0 = noError passes)."""
    if error_status is None or int(error_status) == 0:
        return
    status = int(error_status)
    hint: str | None = None
    if status == 1:  # tooBig
        hint = "reduce snmp batch size"
    raise SnmpError(
        "protocol_error",
        f"snmp response carried error status {status}",
        stage=stage,
        detail_safe=f"error-status-{status}",
        hint=hint,
    )


def _object_type_of(var_bind: Any) -> Any:
    """Unwrap one response varbind to its ObjectType.

    pysnmp's v3arch hlapi returns BULK response entries as one-element
    lists ``[ObjectType(...)]`` (one per repetition) while GET responses are
    flat ``ObjectType`` entries — unwrap the wrapping list so both shapes
    normalize identically. Plain ``(name, value)`` pairs (unit tests /
    receivers) pass through untouched.
    """
    while isinstance(var_bind, (list, tuple)) and len(var_bind) == 1:
        inner = var_bind[0]
        if isinstance(inner, (list, tuple)) and len(inner) == 2 and isinstance(inner[0], str):
            return var_bind
        if not isinstance(inner, (list, tuple)):
            var_bind = inner
            continue
        if len(inner) == 2:
            return inner
        return var_bind
    return var_bind


def _varbind_oid(var_bind: Any) -> str | None:
    """Dotted OID of one response varbind (an ObjectType or name/value pair).

    The hlapi layer resolves returned names into ObjectIdentity wrappers
    whose ``str()`` is the dotted form (the wrapping ObjectType's own str()
    prints a symbolic ``MIB::name = value`` rendering — never parse that).
    pyasn1 OID objects expose ``asTuple()``; plain dotted strings (unit
    tests / receivers) pass through.
    """
    var_bind = _object_type_of(var_bind)
    try:
        name_obj = var_bind[0]
    except IndexError:
        return None
    for candidate in (name_obj,):
        if isinstance(candidate, str):
            return candidate
        as_tuple = getattr(candidate, "asTuple", None)
        if callable(as_tuple):
            try:
                parts = as_tuple()
            except Exception:
                parts = None
            if parts:
                return ".".join(str(part) for part in parts)
    try:
        inner = name_obj[0]
    except IndexError:
        return None
    if isinstance(inner, str):
        return inner
    as_tuple = getattr(inner, "asTuple", None)
    if callable(as_tuple):
        parts = as_tuple()
        if parts:
            return ".".join(str(part) for part in parts)
    return str(inner)


def _varbind_raw(var_bind: Any) -> Any:
    """The value part of one response varbind (raises IndexError when absent)."""
    return _object_type_of(var_bind)[1]


def map_varbinds(varbinds: Sequence[Any]) -> Sequence[SnmpValue | object]:
    """Normalize a response varbind list into typed values / NOT_PRESENT.

    pysnmp represents an endOfMibView tail in BULK responses as a
    name-only varbind; those normalize to NOT_PRESENT too.
    """
    values: list[SnmpValue | object] = []
    for var_bind in varbinds:
        try:
            raw = _varbind_raw(var_bind)
        except IndexError:
            values.append(NOT_PRESENT)
            continue
        oid = _varbind_oid(var_bind) or ""
        values.append(normalize_value(oid, raw))
    return values


class SnmpClient:
    """Sync SNMP client: GET / batched GET / bulk walk over one endpoint."""

    def __init__(
        self,
        connection: SnmpConnection,
        *,
        runner: Runner[Any] | None = None,
    ) -> None:
        self._connection = connection
        self._runner: Runner[Any] = runner if runner is not None else _asyncio_run

    # -- public sync API ----------------------------------------------------

    def _run(self, coro: Awaitable[T]) -> T:
        runner = self._runner
        return cast(Callable[[Awaitable[T]], T], runner)(coro)

    def get(self, oid: str) -> SnmpValue | object:
        """GET one OID; missing leaves normalize to the NOT_PRESENT sentinel."""
        values = self.get_many((oid,))
        return values[0]

    def get_many(self, oids: Sequence[str]) -> Sequence[SnmpValue | object]:
        """GET many OIDs in ``batch_size`` chunks (values aligned to the responses)."""
        if not oids:
            return []
        return self._run(self._get_many(oids))

    def walk(self, prefix: str) -> tuple[list[SnmpValue], bool]:
        """Bulk-walk ``prefix``; returns ``(rows, truncated)``.

        Mirrors the redfish ``walk_collection`` contract: ``truncated=True``
        means the walk hit the ``WALK_MAX_ROWS`` page guard while the agent
        still had rows under the prefix — never a fabricated full result.
        Callers (adapters) must treat truncated walks as partial.
        """
        rows, truncated = self._run(self._walk(prefix))
        if truncated:
            _LOG.warning(
                "snmp.walk.truncated",
                prefix=prefix,
                rows=len(rows),
                page_limit=WALK_MAX_ROWS,
            )
        return rows, truncated

    # -- internals ----------------------------------------------------------

    def _auth_data(self) -> CommunityData | UsmUserData:
        connection = self._connection
        if connection.version == "v2c":
            # v2c only after an explicit, audited admin choice (SECURITY.md
            # §6, weak-protocol audit); v3 is the default everywhere else.
            return CommunityData(connection.community, mpModel=1)  # noqa: S508
        return UsmUserData(
            connection.username,
            connection.auth_key,
            connection.privacy_key,
            _AUTH_PROTOCOLS[connection.auth_protocol],
            _PRIVACY_PROTOCOLS[connection.privacy_protocol],
        )

    def _target(self) -> UdpTransportTarget:
        connection = self._connection
        return UdpTransportTarget(
            (connection.host, connection.port),
            timeout=connection.timeout_seconds,
            retries=connection.retries,
        )

    def _deadline_seconds(self) -> float:
        connection = self._connection
        return connection.timeout_seconds * (connection.retries + 1) + 2.0

    async def _get_many(self, oids: Sequence[str]) -> Sequence[SnmpValue | object]:
        collected: list[SnmpValue | object] = []
        context = ContextData()
        auth = self._auth_data()
        target = self._target()
        for chunk in chunk_oids(oids, batch_size=self._connection.batch_size):
            var_binds = await asyncio.wait_for(
                self._get_chunk(auth, target, context, chunk),
                timeout=self._deadline_seconds(),
            )
            collected.extend(var_binds)
        return collected

    async def _get_chunk(
        self,
        auth: CommunityData | UsmUserData,
        target: UdpTransportTarget,
        context: ContextData,
        oids: Sequence[str],
    ) -> Sequence[SnmpValue | object]:
        engine = SnmpEngine()
        try:
            error_indication, error_status, _error_index, varbinds = await getCmd(
                engine,
                auth,
                target,
                context,
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            )
        finally:
            engine.transportDispatcher.closeDispatcher()
        raise_for_error_indication(error_indication, stage="request")
        raise_for_error_status(error_status, stage="request")
        return map_varbinds(varbinds)

    async def _walk(self, prefix: str) -> tuple[list[SnmpValue], bool]:
        connection = self._connection
        collected: list[SnmpValue] = []
        cursor = prefix
        for _ in range(WALK_MAX_ROWS):
            engine = SnmpEngine()
            try:
                error_indication, error_status, _error_index, varbinds = await asyncio.wait_for(
                    bulkCmd(
                        engine,
                        self._auth_data(),
                        self._target(),
                        ContextData(),
                        0,
                        connection.batch_size,
                        ObjectType(ObjectIdentity(cursor)),
                    ),
                    timeout=self._deadline_seconds(),
                )
            finally:
                engine.transportDispatcher.closeDispatcher()
            raise_for_error_indication(error_indication, stage="request")
            raise_for_error_status(error_status, stage="request")
            if not varbinds:
                return collected, False
            progressed = False
            reached_end = False
            for var_bind in varbinds:
                try:
                    raw = _varbind_raw(var_bind)
                except IndexError:
                    # endOfMibView tail (name-only varbind) terminates
                    # the walk.
                    reached_end = True
                    break
                name = _varbind_oid(var_bind)
                if name is None:
                    reached_end = True
                    break
                if not (name == prefix or name.startswith(prefix + ".")):
                    reached_end = True
                    break
                value = normalize_value(name, raw)
                if not isinstance(value, SnmpValue):
                    reached_end = True
                    break
                collected.append(value)
                if name != cursor:
                    progressed = True
                    cursor = name
            if reached_end or not progressed:
                return collected, False
        # The page guard fired while the subtree still had rows: the walk is
        # truncated, never silently partial.
        return collected, True


def _asyncio_run[T](coro: Awaitable[T]) -> T:
    return asyncio.run(cast(Coroutine[Any, Any, T], coro))
