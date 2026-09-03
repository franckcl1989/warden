"""Tolerant Redfish DTO layer (docs/DEVICE_ADAPTERS.md §4).

The reader never requires a specific schema minor version:

- ``@odata.type`` (``#Thermal.v1_5_0.Thermal``) is parsed by SCHEMA FAMILY —
  an old BMC implementing ``Thermal.v1_0_0`` is still a ``Thermal`` family;
- missing/unknown/unavailable fields return typed sentinels
  (``FieldSentinel.MISSING`` / ``FieldSentinel.UNPARSEABLE``) — never
  fabricated 0/normal values that later become fake observations;
- ``@odata.id`` links are followed with bounded depth and same-origin
  enforcement (SECURITY.md §7: a device payload must never point the client
  at a foreign host);
- collections walk ``Members`` + ``Members@odata.count`` with both real
  pagination styles: ``@odata.nextLink`` and ``$skip`` continuation when the
  server advertised more members than it returned without a next link.

Requests flow through a duck-typed client with ``request(method, url)``
returning ``HttpReply`` (or raising a mapped ``RedfishError`` for non-2xx).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

from app.infrastructure.protocols.redfish.errors import RedfishError

MAX_LINK_DEPTH = 8
MAX_COLLECTION_PAGES = 200

_ODATA_TYPE_RE = re.compile(r"^#([A-Za-z0-9_]+)\.v(\d+)_(\d+)_(\d+)\.([A-Za-z0-9_]+)$")
_ODATA_TYPE_NO_VERSION_RE = re.compile(r"^#([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$")
_UNAVAILABLE_TEXT = frozenset({"", "n/a", "na", "-", "not available", "unavailable"})


class FieldSentinel(StrEnum):
    """Typed sentinels for missing/unknown Redfish fields (never 0/normal)."""

    MISSING = "missing"
    UNPARSEABLE = "unparseable"


def is_sentinel(value: object) -> bool:
    return isinstance(value, FieldSentinel)


@dataclass(frozen=True)
class HttpReply:
    """Decoded 2xx response from the device.

    ``headers`` keys are lower-case; the real client passes ``httpx.Headers``
    (case-insensitive lookups). ``payload`` is the decoded JSON body or None.
    """

    status_code: int
    payload: object | None
    headers: Mapping[str, str] = field(default_factory=dict)


def _protocol_error(reason: str) -> RedfishError:
    return RedfishError(
        "protocol_error",
        reason,
        stage="parse",
        detail_safe="parse",
    )


def schema_family(odata_type: object) -> str | None:
    """Schema family of an ``@odata.type`` (``Thermal`` for any Thermal version)."""
    if not isinstance(odata_type, str):
        return None
    match = _ODATA_TYPE_RE.match(odata_type)
    if match:
        return match.group(1)
    match = _ODATA_TYPE_NO_VERSION_RE.match(odata_type)
    return match.group(1) if match else None


def schema_version(odata_type: object) -> tuple[int, int, int] | None:
    """Explicit schema version of an ``@odata.type`` or None when absent."""
    if not isinstance(odata_type, str):
        return None
    match = _ODATA_TYPE_RE.match(odata_type)
    if not match:
        return None
    return (int(match.group(2)), int(match.group(3)), int(match.group(4)))


# --- field readers ---------------------------------------------------------


def text_field(data: Mapping[str, Any], key: str) -> str | FieldSentinel:
    """Text value; absent/null/unavailable markers -> MISSING, wrong type -> UNPARSEABLE."""
    value = data.get(key)
    if value is None:
        return FieldSentinel.MISSING
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in _UNAVAILABLE_TEXT:
            return FieldSentinel.MISSING
        return stripped
    return FieldSentinel.UNPARSEABLE


def number_field(data: Mapping[str, Any], key: str) -> int | float | FieldSentinel:
    """Numeric value tolerant of numeric strings; unavailable -> MISSING, never 0."""
    value = data.get(key)
    if value is None:
        return FieldSentinel.MISSING
    if isinstance(value, bool):
        return FieldSentinel.UNPARSEABLE
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in _UNAVAILABLE_TEXT:
            return FieldSentinel.MISSING
        try:
            if re.fullmatch(r"[+-]?\d+", stripped):
                return int(stripped)
            parsed = float(stripped)
        except ValueError:
            return FieldSentinel.UNPARSEABLE
        if not math.isfinite(parsed):
            return FieldSentinel.UNPARSEABLE
        return parsed
    return FieldSentinel.UNPARSEABLE


def bool_field(data: Mapping[str, Any], key: str) -> bool | FieldSentinel:
    """Boolean value; JSON booleans only, anything else -> sentinel."""
    value = data.get(key)
    if value is None:
        return FieldSentinel.MISSING
    if isinstance(value, bool):
        return value
    return FieldSentinel.UNPARSEABLE


def datetime_field(data: Mapping[str, Any], key: str) -> datetime | FieldSentinel:
    """ISO-8601 datetime normalized to UTC; naive/garbage -> sentinel."""
    value = data.get(key)
    if value is None:
        return FieldSentinel.MISSING
    if not isinstance(value, str):
        return FieldSentinel.UNPARSEABLE
    normalized = value.replace("Z", "+00:00") if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return FieldSentinel.UNPARSEABLE
    if parsed.tzinfo is None:
        # A device timestamp without timezone cannot be trusted for event time.
        return FieldSentinel.UNPARSEABLE
    return parsed.astimezone(UTC)


# --- links ---------------------------------------------------------------


def resolve_odata_id(value: object) -> str | None:
    """``@odata.id`` string from a link member (dict or bare string)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        candidate = value.get("@odata.id")
        return candidate if isinstance(candidate, str) else None
    return None


class RedfishResource(dict[str, Any]):
    """A decoded Redfish resource: dict data + @odata metadata + sentinel helpers."""

    def __init__(self, payload: object) -> None:
        if not isinstance(payload, dict):
            raise _protocol_error("device returned a non-object resource payload")
        super().__init__(payload)

    @property
    def odata_id(self) -> str | None:
        candidate = self.get("@odata.id")
        return candidate if isinstance(candidate, str) else None

    @property
    def odata_type(self) -> str | None:
        candidate = self.get("@odata.type")
        return candidate if isinstance(candidate, str) else None

    @property
    def schema_family(self) -> str | None:
        return schema_family(self.odata_type)

    @property
    def schema_version(self) -> tuple[int, int, int] | None:
        return schema_version(self.odata_type)

    def get_text(self, key: str) -> str | FieldSentinel:
        return text_field(self, key)

    def get_number(self, key: str) -> int | float | FieldSentinel:
        return number_field(self, key)

    def get_bool(self, key: str) -> bool | FieldSentinel:
        return bool_field(self, key)

    def get_datetime(self, key: str) -> datetime | FieldSentinel:
        return datetime_field(self, key)


def member_links(payload: Mapping[str, Any]) -> list[str]:
    """Resolved member odata ids from a collection payload (tolerant)."""
    raw_members = payload.get("Members")
    if not isinstance(raw_members, list):
        return []
    links: list[str] = []
    for member in raw_members:
        link = resolve_odata_id(member)
        if link is not None:
            links.append(link)
    return links


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _absolute_url(client: Any, url: str) -> str:
    """Validate and normalize a request URL to a same-origin absolute path.

    Absolute URLs must share the client origin (SECURITY.md §7); the returned
    href is the path+query form so every request travels through the client's
    own base URL — a foreign host can never be reached.
    """
    if url.startswith(("http://", "https://")):
        if _origin_of(url) != client.base_origin:
            raise _protocol_error("device link points at a foreign origin")
        parts = urlsplit(url)
        return urlunsplit(("", "", parts.path, parts.query, parts.fragment))
    if url.startswith("/"):
        return url
    raise _protocol_error("odata link must be an absolute path")


def follow(client: Any, url: str) -> RedfishResource | None:
    """GET ``url`` following ``@odata.id``-only redirect chains with bounded depth.

    Returns None when the payload is not a resource object (e.g. an empty
    204). Raises ``protocol_error`` when the chain exceeds ``MAX_LINK_DEPTH``,
    repeats, or leaves the client origin.
    """
    current = _absolute_url(client, url)
    seen: set[str] = set()
    for _ in range(MAX_LINK_DEPTH + 1):
        if current in seen:
            raise _protocol_error("odata link chain repeated")
        seen.add(current)
        reply = client.request("GET", current)
        if reply.status_code == 204 or reply.payload is None:
            return None
        resource = RedfishResource(reply.payload)
        odata_id = resource.odata_id
        if odata_id is None or len(resource) > 1:
            return resource
        current = _absolute_url(client, odata_id)
    raise _protocol_error(f"odata link chain exceeded {MAX_LINK_DEPTH} hops")


def _count_of(payload: Mapping[str, Any]) -> int | None:
    raw = payload.get("Members@odata.count")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return None


def _with_skip(url: str, skip: int) -> str:
    parts = urlsplit(url)
    pairs = [
        f"{quote(key, safe='')}={quote(value, safe='')}"
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != "$skip"
    ]
    pairs.append(f"$skip={skip}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))


def walk_collection(
    client: Any,
    collection_url: str,
    *,
    allow_skip_pagination: bool = True,
) -> tuple[list[RedfishResource], bool]:
    """Walk a Redfish collection, yielding inline member resources.

    Follows ``@odata.nextLink`` when present; otherwise continues with
    ``$skip`` while the server advertised more members than it returned.
    Returns ``(resources, truncated)`` — ``truncated=True`` when the device
    stopped short and no continuation is possible, never a fabricated full
    result. Raises ``protocol_error`` on link loops and runaway pagination.
    """
    page_url = _absolute_url(client, collection_url)
    resources: list[RedfishResource] = []
    collected = 0
    seen_pages: set[str] = set()
    while True:
        if page_url in seen_pages:
            raise _protocol_error("collection pagination loop detected")
        seen_pages.add(page_url)
        if len(seen_pages) > MAX_COLLECTION_PAGES:
            raise _protocol_error("collection pagination exceeded page budget")
        reply = client.request("GET", page_url)
        payload = reply.payload
        if payload is None:
            raise _protocol_error("collection returned an empty body")
        page = RedfishResource(payload)
        raw_members = page.get("Members")
        if not isinstance(raw_members, list):
            break
        previous_collected = collected
        for member in raw_members:
            if isinstance(member, dict):
                resources.append(RedfishResource(member))
            elif isinstance(member, str):
                resources.append(RedfishResource({"@odata.id": member}))
        collected += len(raw_members)
        count = _count_of(page)
        next_link = page.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link:
            page_url = _absolute_url(client, urljoin(page_url, next_link))
            continue
        if count is not None and collected < count and allow_skip_pagination and collected > previous_collected:
            page_url = _with_skip(page_url, collected)
            continue
        truncated = count is not None and collected < count
        return resources, truncated
    return resources, False
