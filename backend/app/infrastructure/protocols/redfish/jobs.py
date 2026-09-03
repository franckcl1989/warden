"""Generic OEM vendor job polling shape (docs/DEVICE_ADAPTERS.md §4.2).

Vendor job URIs and their terminal predicates are vendor-specific; overlays
(M3T5: dell/inspur/xfusion/lenovo/huawei) supply ``is_terminal`` and, when
the vendor reports progress, ``percent_of``. This module only provides the
bounded polling skeleton: poll the vendor URI until the predicate is
terminal or ``timeout_at`` passes — a timeout is a timed-out outcome with
the last payload, never a fabricated failure, and never a replay trigger.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.infrastructure.protocols.redfish.parse import (
    FieldSentinel,
    RedfishResource,
)

ProgressSink = Callable[[int | None, str | None], None]
VendorJobPredicate = Callable[[RedfishResource, int], bool]
PercentExtractor = Callable[[RedfishResource], int | float | FieldSentinel | None]


@dataclass(frozen=True)
class VendorJobOutcome:
    """Result of a bounded vendor-job poll run."""

    uri: str
    attempts: int
    terminal: bool = False
    timed_out: bool = False
    payload: RedfishResource | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def poll_vendor_job(
    client: Any,
    job_uri: str,
    *,
    is_terminal: VendorJobPredicate,
    timeout_at: datetime,
    poll_interval: float = 2.0,
    percent_of: PercentExtractor | None = None,
    progress_sink: ProgressSink | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> VendorJobOutcome:
    """Poll ``job_uri`` until the vendor predicate is terminal or the deadline."""
    clock = now if now is not None else _utc_now
    snooze = sleep if sleep is not None else time.sleep
    attempts = 0
    last_payload: RedfishResource | None = None
    sink_seen: tuple[int | None, str | None] | None = None
    while True:
        current = clock()
        if current >= timeout_at:
            return VendorJobOutcome(
                uri=job_uri,
                attempts=attempts,
                terminal=False,
                timed_out=True,
                payload=last_payload,
            )
        attempts += 1
        reply = client.request("GET", job_uri)
        payload = RedfishResource(reply.payload) if reply.payload is not None else None
        if payload is not None:
            last_payload = payload
            if percent_of is not None:
                raw = percent_of(payload)
                percent: int | None = None
                if not isinstance(raw, FieldSentinel) and raw is not None:
                    percent = int(raw)  # floor: never fabricate a higher percent
                if progress_sink is not None:
                    current_sink = (percent, None)
                    if current_sink != sink_seen:
                        sink_seen = current_sink
                        progress_sink(percent, None)
        if payload is not None and is_terminal(payload, attempts):
            return VendorJobOutcome(
                uri=job_uri,
                attempts=attempts,
                terminal=True,
                payload=last_payload,
            )
        remaining = max(0.0, (timeout_at - current).total_seconds())
        snooze(min(poll_interval, remaining))
