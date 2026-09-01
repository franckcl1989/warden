"""Unit tests for readiness registry aggregation (DB-free)."""

from __future__ import annotations

import pytest
from app.infrastructure.readiness import ProbeResult, ReadinessRegistry


class _FakeProbe:
    def __init__(self, name: str, ok: bool) -> None:
        self.name = name
        self._ok = ok

    async def check(self) -> ProbeResult:
        return ProbeResult(name=self.name, ok=self._ok)


class _RaisingProbe:
    name = "boom"

    async def check(self) -> ProbeResult:
        msg = "probe exploded"
        raise RuntimeError(msg)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_empty_registry_reports_ok() -> None:
    summary = await ReadinessRegistry().summary()
    assert summary.status == "ok"
    assert summary.probes == ()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_all_ok_reports_ok() -> None:
    registry = ReadinessRegistry()
    registry.register(_FakeProbe("a", ok=True))
    registry.register(_FakeProbe("b", ok=True))
    summary = await registry.summary()
    assert summary.status == "ok"
    assert summary.probes == (ProbeResult("a", True), ProbeResult("b", True))


@pytest.mark.asyncio
@pytest.mark.unit
async def test_partial_failure_reports_degraded() -> None:
    registry = ReadinessRegistry()
    registry.register(_FakeProbe("a", ok=True))
    registry.register(_FakeProbe("b", ok=False))
    summary = await registry.summary()
    assert summary.status == "degraded"
    assert summary.probes[1] == ProbeResult("b", False)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_all_failed_reports_unavailable() -> None:
    registry = ReadinessRegistry()
    registry.register(_FakeProbe("a", ok=False))
    summary = await registry.summary()
    assert summary.status == "unavailable"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_raising_probe_counts_as_failed() -> None:
    registry = ReadinessRegistry()
    registry.register(_RaisingProbe())
    summary = await registry.summary()
    assert summary.status == "unavailable"
    assert summary.probes == (ProbeResult("boom", False, "probe failed"),)
