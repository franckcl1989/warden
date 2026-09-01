"""Readiness probe interface and registry for ``/health/ready``.

No probes registered yet in M0T3 (the DB probe is wired in M0T4); an empty
registry reports ``ok`` — there are no required dependencies configured.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ProbeResult:
    name: str
    ok: bool
    detail: str = ""


@runtime_checkable
class ReadinessProbe(Protocol):
    name: str

    async def check(self) -> ProbeResult: ...


@dataclass(frozen=True)
class ReadinessSummary:
    status: str  # ok | degraded | unavailable
    probes: tuple[ProbeResult, ...] = ()


class ReadinessRegistry:
    """Collects readiness probes; empty registry means no required dependencies."""

    def __init__(self) -> None:
        self._probes: list[ReadinessProbe] = []

    def register(self, probe: ReadinessProbe) -> None:
        self._probes.append(probe)

    @property
    def probes(self) -> tuple[ReadinessProbe, ...]:
        return tuple(self._probes)

    async def summary(self) -> ReadinessSummary:
        """Run all probes and derive the overall status.

        Overall status: all ok (or no probes) -> ok; some ok -> degraded;
        none ok -> unavailable. A probe that raises or returns something else
        counts as failed.
        """
        results = await asyncio.gather(*(probe.check() for probe in self._probes), return_exceptions=True)
        probe_results: list[ProbeResult] = []
        for probe, result in zip(self._probes, results, strict=True):
            if isinstance(result, ProbeResult):
                probe_results.append(result)
            elif isinstance(result, BaseException):
                probe_results.append(ProbeResult(name=probe.name, ok=False, detail="probe failed"))
            else:
                probe_results.append(ProbeResult(name=probe.name, ok=False, detail="probe returned invalid result"))
        if not probe_results or all(result.ok for result in probe_results):
            status = "ok"
        elif any(result.ok for result in probe_results):
            status = "degraded"
        else:
            status = "unavailable"
        return ReadinessSummary(status=status, probes=tuple(probe_results))
