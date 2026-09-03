# Warden Redfish test-device simulator

**This is a TEST DEVICE SIMULATOR — a fake BMC for repeatable automated
tests. It is NOT evidence of hardware support.** Nothing served here may be
used to claim that Warden supports any real server/management card:
`contracts/hardware-targets.json` and the certification matrix stay
`not_started` until real-device runs exist (docs/HARDWARE_CERTIFICATION.md
§3, docs/TEST_STRATEGY.md §2.2). Fixtures captured from this simulator MUST
record their 模拟器来源 (profile, capture date) — never a 真机 claim.

## What it serves

`/redfish/v1` (DSP2046-shaped, driven by the M3 needs in
docs/DEVICE_ADAPTERS.md §4):

- ServiceRoot + collections;
- `Systems/1`: ComputerSystem (PowerState, Reset action), Memory DIMMs with
  OEM ECC counters, Storage/Drives/Volumes with OEM SMART/RAID state;
- `Chassis/1`: Thermal (temperatures + fans), Power (PSUs), PhysicalSecurity,
  IndicatorLED;
- `Managers/1`: Manager + Reset, LogServices/SEL with paginated Entries
  (fields per contracts/events.json: Created/severity/Message/Id),
  VirtualMedia with InsertMedia/EjectMedia;
- `UpdateService`: FirmwareInventory + SimpleUpdate;
- SessionService/AccountService (login -> `X-Auth-Token`);
- TaskService: actions return `202` + `Location`, tasks transition
  Running(50%) -> Completed (or Exception under failure injection), with
  TaskMonitor endpoints.

## Configuration

Constructor `SimulatorConfig` (see `app.py`) or the live control endpoint
(no auth): `GET /warden-sim/control` for state; `POST /warden-sim/control`
with `{"profile": ...}`, `{"vendor": ...}`, `{"pagination": ...}`,
`{"task_duration_seconds": ...}`, `{"sel_append": <int>}`, `{"failures": {...}}`.

- Profiles: `healthy` (default), `critical`, `auth_fail` (login 401),
  `slow_paginated` (150 SEL entries, page size 20).
- `sel_append`: appends extra SEL entries AFTER the profile's base count
  (continuing the Id/timestamp sequence — strictly newer than every base
  entry), for delta-collection tests growing a live SEL past a page
  boundary. `empty_sel` still wins (zero entries).
- Vendors: `generic` (default; neutral `Oem.Vendor` blocks) plus
  `dell`/`inspur`/`xfusion`/`lenovo`/`huawei` stubs returning
  vendor-namespaced odata types + OEM keys. These are STUBS — the real
  per-vendor shapes come from vendor overlays (M3T5) and certified
  sanitized fixtures.
- Failure injection: `login_401`, `reads_500`, `reads_429`,
  `reset_rejected_400`, `reset_forbidden_403`, `reset_task_fails`.
- Media image host allowlist: `media_hosts_required` + `media_hosts`
  (platform ticket URL fetch check — the simulator validates the host the
  "BMC" would fetch from; it never performs real fetches).

## Running

Served over ASGI (httpx `ASGITransport`, or boot uvicorn on localhost via
`tests/simulators/redfish/serving.py` for real-HTTP integration tests).
Credentials default: `admin` / `sim-pass-1` (test-only, simulator only).

OEM/vendor resource shapes are intentionally generic; overlays (M3T5)
define real shapes from certification fixtures.
