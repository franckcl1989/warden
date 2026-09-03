"""Redfish TaskService poller (DSP2046 Task + TaskMonitor).

``poll_task`` reads a task resource (and its advertised ``TaskMonitor`` when
present) until a terminal state, feeding changed ``(percent, state)`` pairs
to the progress sink and bounded by ``timeout_at``:

- ``Completed`` -> success (``succeeded=True``);
- ``Exception``/``Killed`` -> ``operation_failed``;
- ``Interrupted``/``Cancelled`` -> ``ambiguous_result`` — the action may or
  may not have run, the caller must verify, never replay (DEVICE_ADAPTERS §9);
- a vanished task (404) -> ``ambiguous_result``;
- deadline reached while the task still runs -> ``timed_out`` with the last
  observed state (never fabricated success/failure);
- any unknown ``TaskState`` string -> ``protocol_error``.

Progress is taken from ``PercentComplete`` (tolerant float -> int, range
0..100; out-of-range or absent values are reported as None — never faked).
Device-supplied Messages text is never copied into outcomes or logs.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.infrastructure.protocols.redfish.errors import RedfishError, RedfishHttpError
from app.infrastructure.protocols.redfish.parse import (
    FieldSentinel,
    RedfishResource,
    number_field,
    text_field,
)

_TASK_STATE_FIELD = "TaskState"
_PERCENT_FIELDS = ("PercentComplete",)
_STATE_SUCCESS = "Completed"
_STATE_FAILURE = frozenset({"Exception", "Killed"})
_STATE_AMBIGUOUS = frozenset({"Interrupted", "Cancelled"})
_STATE_NONTERMINAL = frozenset(
    {
        "New",
        "Starting",
        "Running",
        "Suspended",
        "Pending",
        "Stopping",
        "Cancelling",
        "Resuming",
    }
)
_KNOWN_STATES = _STATE_FAILURE | _STATE_AMBIGUOUS | _STATE_NONTERMINAL | {_STATE_SUCCESS}

# Matches the domain OperationProgress shape (percent, optional state label).
ProgressSink = Callable[[int | None, str | None], None]


@dataclass(frozen=True)
class TaskOutcome:
    """Result of one bounded task poll run (never fabricated success/failure)."""

    uri: str
    state: str
    attempts: int
    succeeded: bool | None = None
    error_code: str | None = None
    percent: int | None = None
    timed_out: bool = False
    message_safe: str | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_task(client: Any, uri: str) -> RedfishResource:
    """GET a task/monitor resource; 404 raises nothing here (handled by caller)."""
    reply = client.request("GET", uri)
    if reply.payload is None:
        raise RedfishError(
            "protocol_error",
            "device task returned an empty body",
            stage="task",
        )
    return RedfishResource(reply.payload)


def _task_state(payload: RedfishResource) -> str:
    state = text_field(payload, _TASK_STATE_FIELD)
    if isinstance(state, FieldSentinel):
        raise RedfishError(
            "protocol_error",
            "device task is missing a TaskState",
            stage="task",
        )
    if state not in _KNOWN_STATES:
        raise RedfishError(
            "protocol_error",
            f"device task reported an unknown state {state!r}",
            stage="task",
        )
    return state


def _task_percent(payload: RedfishResource) -> int | None:
    for key in _PERCENT_FIELDS:
        value = number_field(payload, key)
        if isinstance(value, FieldSentinel):
            continue
        truncated = int(value)  # floor: never fabricate a higher percent
        if 0 <= truncated <= 100:
            return truncated
        return None  # out-of-range percent is suspect, never fabricated
    return None


def _deadline_exceeded(now: datetime, timeout_at: datetime) -> bool:
    return now >= timeout_at


def poll_task(
    client: Any,
    task_uri: str,
    *,
    timeout_at: datetime,
    progress_sink: ProgressSink | None = None,
    poll_interval: float = 2.0,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> TaskOutcome:
    """Poll the Redfish task until terminal, the deadline, or a protocol error."""
    clock = now if now is not None else _utc_now
    snooze = sleep if sleep is not None else time.sleep
    task_resource_uri: str | None = task_uri
    monitor_uri: str | None = None
    sink_progress: tuple[int | None, str | None] | None = None
    attempts = 0
    while True:
        attempts += 1
        current = clock()
        source_uri = monitor_uri if monitor_uri is not None else task_resource_uri
        if source_uri is None:
            raise RedfishError("protocol_error", "no task uri to poll", stage="task")
        try:
            reply = client.request("GET", source_uri)
        except RedfishHttpError as exc:
            if exc.status == 404:
                # The task vanished: outcome unprovable (ambiguous), never a replay.
                return TaskOutcome(
                    uri=task_uri,
                    state="Vanished",
                    attempts=attempts,
                    succeeded=None,
                    error_code="ambiguous_result",
                    timed_out=False,
                )
            raise exc
        payload = RedfishResource(reply.payload)
        if monitor_uri is None:
            advertised = payload.get_text("TaskMonitor")
            if not isinstance(advertised, FieldSentinel) and advertised:
                monitor_uri = advertised
                continue  # first poll reads the monitor from now on
        state = _task_state(payload)
        percent = _task_percent(payload)
        current_sink = (percent, state)
        if progress_sink is not None and current_sink != sink_progress:
            sink_progress = current_sink
            progress_sink(percent, state)
        if state == _STATE_SUCCESS:
            return TaskOutcome(
                uri=task_uri,
                state=state,
                attempts=attempts,
                succeeded=True,
                percent=percent,
            )
        if state in _STATE_FAILURE:
            return TaskOutcome(
                uri=task_uri,
                state=state,
                attempts=attempts,
                succeeded=False,
                error_code="operation_failed",
                percent=percent,
            )
        if state in _STATE_AMBIGUOUS:
            return TaskOutcome(
                uri=task_uri,
                state=state,
                attempts=attempts,
                succeeded=None,
                error_code="ambiguous_result",
                percent=percent,
            )
        if _deadline_exceeded(current, timeout_at):
            return TaskOutcome(
                uri=task_uri,
                state=state,
                attempts=attempts,
                succeeded=None,
                percent=percent,
                timed_out=True,
            )
        remaining = max(0.0, (timeout_at - current).total_seconds())
        snooze(min(poll_interval, remaining))
