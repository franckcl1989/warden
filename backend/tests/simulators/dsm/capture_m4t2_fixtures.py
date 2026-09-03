"""One-off M4T2 fixture capture (run manually; results committed).

Boots the DSM TEST SIMULATOR over real HTTP (uvicorn) and snapshots the
documented profile/knob payloads verbatim into tests/fixtures/dsm/ with the
exact request used. Provenance rows are recorded by hand in the fixtures
README (profile/knobs, date, simulator origin — never 真机).

Run:  .venv\\Scripts\\python.exe tests/simulators/dsm/capture_m4t2_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from tests.simulators.dsm.payloads import SimulatorConfig
from tests.simulators.dsm.serving import serve_simulator

USER = "admin"
PASSWORD = "sim-pass-1"
OUT = Path(__file__).resolve().parent.parent / "fixtures" / "dsm"


def _get(base: str, path: str, params: dict[str, str]) -> dict[str, object]:
    with httpx.Client(base_url=base, timeout=10.0) as client:
        response = client.get(path, params=params)
        response.raise_for_status()
        body = response.json()
        assert isinstance(body, dict)
        return body


def _capture(
    base: str, sid: str, filename: str, *, api: str, method: str, version: int, extra: dict[str, str] | None = None
) -> None:
    params: dict[str, str] = {
        "api": api,
        "version": str(version),
        "method": method,
        "_sid": sid,
    }
    if extra:
        params.update(extra)
    body = _get(base, "/webapi/entry.cgi", params)
    (OUT / filename).write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"captured {filename}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    # ds224plus profile snapshots.
    with serve_simulator(SimulatorConfig(profile="ds224plus")) as base:
        with httpx.Client(base_url=base, timeout=10.0) as client:
            login = client.get(
                "/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            login.raise_for_status()
            data = login.json()["data"]
            sid = data["sid"]
        _capture(base, sid, "info-query-ds224plus.json", api="SYNO.API.Info", method="query", version=1)
        _capture(base, sid, "system-info-ds224plus.json", api="SYNO.Core.System", method="info", version=2)
        _capture(
            base, sid, "storage-ds224plus-healthy.json", api="SYNO.Storage.CGI.Storage", method="load_info", version=1
        )
        _capture(base, sid, "share-list-ds224plus.json", api="SYNO.Core.Share", method="list", version=1)
        _capture(base, sid, "ups-normal-ds224plus.json", api="SYNO.Core.UPS", method="get", version=1)
        _capture(
            base,
            sid,
            "log-page1-ds224plus.json",
            api="SYNO.Core.System.Log",
            method="list",
            version=1,
            extra={"offset": "0", "limit": "5"},
        )
    # ds225plus identity snapshot.
    with serve_simulator(SimulatorConfig(profile="ds225plus")) as base:
        with httpx.Client(base_url=base, timeout=10.0) as client:
            login = client.get(
                "/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            login.raise_for_status()
            sid = login.json()["data"]["sid"]
        _capture(base, sid, "system-info-ds225plus.json", api="SYNO.Core.System", method="info", version=2)
    # Honest edge knobs over the ds224plus identity (profile base via knobs).
    with serve_simulator(SimulatorConfig(profile="ds224plus", pool_rebuilding=True)) as base:
        with httpx.Client(base_url=base, timeout=10.0) as client:
            login = client.get(
                "/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            login.raise_for_status()
            sid = login.json()["data"]["sid"]
        _capture(
            base, sid, "storage-pool-rebuilding.json", api="SYNO.Storage.CGI.Storage", method="load_info", version=1
        )
    with serve_simulator(SimulatorConfig(profile="ds224plus", share_no_quota=True)) as base:
        with httpx.Client(base_url=base, timeout=10.0) as client:
            login = client.get(
                "/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            login.raise_for_status()
            sid = login.json()["data"]["sid"]
        _capture(base, sid, "share-list-no-quota.json", api="SYNO.Core.Share", method="list", version=1)
    with serve_simulator(SimulatorConfig(profile="ds224plus", ups_on_battery=True)) as base:
        with httpx.Client(base_url=base, timeout=10.0) as client:
            login = client.get(
                "/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            login.raise_for_status()
            sid = login.json()["data"]["sid"]
        _capture(base, sid, "ups-on-battery.json", api="SYNO.Core.UPS", method="get", version=1)


if __name__ == "__main__":
    main()
