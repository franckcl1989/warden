# Warden DSM test-device simulator

**THIS IS A TEST DEVICE SIMULATOR — a fake Synology DSM for repeatable
automated tests. It is NOT evidence of hardware support.** Nothing served
here may be used to claim that Warden supports any real Synology NAS
(DS224+/DS225+ or otherwise): `contracts/hardware-targets.json` and the
certification matrix stay `not_started` until real-device runs exist
(docs/HARDWARE_CERTIFICATION.md §3, ADR-018). Fixtures captured from this
simulator MUST record their 模拟器来源 (profile, capture date) — never a 真机
claim.

## API-name basis (binding for fixture provenance)

The DSM Login Web API guide (official public PDF) documents exactly two APIs:
`SYNO.API.Info` (query.cgi, v1) and `SYNO.API.Auth` (auth.cgi, v6). DSM's
non-public management API families (`SYNO.Core.*`, `SYNO.Storage.CGI.*`) are
NOT covered by that guide; per ADR-018 every use of them is `vendor_private`
and requires target-DSM-version API-discovery + sanitized fixtures + real
behavior for certification evidence. The simulator therefore flags the basis
of every API name it advertises:

| API name (simulator map) | Path | maxVersion | Basis |
| --- | --- | --- | --- |
| `SYNO.API.Info` | query.cgi | 1 | DSM Login Web API guide (documented) |
| `SYNO.API.Auth` | auth.cgi | 6 | DSM Login Web API guide (documented) |
| `SYNO.Core.System` | entry.cgi | 2 | **simulator-invented** placeholder for the DSM Control-Panel system family (not in the Login guide; certification pending) |
| `SYNO.Storage.CGI.Storage` | entry.cgi | 1 | **simulator-invented** placeholder for the DSM Storage Manager family (not in the Login guide; certification pending) |
| `SYNO.Core.Share` | entry.cgi | 1 | **simulator-invented** placeholder for the DSM shared-folder quota family (M4T2; the Login guide's SYNO.FileStation.List sample lists shares with name/path only and documents no usage/quota members, so the usage/quota surface stays a simulator-DSL row pending certification) |
| `SYNO.Core.UPS` | entry.cgi | 1 | **simulator-invented** placeholder for the DSM UPS family (not in the Login guide; certification pending) |
| `SYNO.Core.System.Log` | entry.cgi | 1 | **simulator-invented** placeholder for the DSM Log Centre family (not in the Login guide; certification pending) |
| `SYNO.Core.Upgrade` | entry.cgi | 1 | **simulator-invented** placeholder for the DSM Update family (not in the Login guide; certification pending) |

The value vocabularies of the family payloads (disk statuses, pool statuses,
UPS states, fan statuses, log levels, task responses) are **simulator DSL**:
the M4 protocol parser's certified mapping tables are fixture-certified
against these exact literals, and real-DSM vocabulary certification happens
per target model in M4T2. The adapter's certified API/version list (M4T2)
must never call an API name that is not in that certified list.

Error codes served: the Login-guide common block (100..108; the simulator
uses 101 invalid parameter, 102 unknown API, 103 unknown method, 104
unsupported version, 106 session invalid/timeout) plus simulator DSL login
rows 401 (wrong credentials) and 403 (two-step/OTP required), and injectable
unmapped code 2100 (`error_unknown_2100` knob) — the client must preserve
unknown codes, never guess them into another stable code.

## What it serves

DSM WebAPI over `/webapi/` (ASGI; DSM parameters travel as query string on
GET or a form body on POST — both are accepted for every endpoint):

- `query.cgi` — `SYNO.API.Info` method=query query=all: configurable API map;
- `auth.cgi` — `SYNO.API.Auth` login/logout (`sid` sessions, `session`
  family `DiskStation`, sid parameter `_sid`);
- `entry.cgi` — authenticated family APIs:
  - `SYNO.Core.System`: info (identity/firmware/temperature/fan/uptime),
    shutdown, restart (side effects end the session);
  - `SYNO.Storage.CGI.Storage`: load_info (disks + SMART + bad sectors,
    storage pools with status + rebuild progress, volumes with used/total
    bytes), smart_test (async taskid: running -> success/failure),
    smart_task_status;
  - `SYNO.Core.Share`: list (shared folders with id/name/used_bytes/
    quota_bytes — quota 0 = 无配额, the missing usage-percent denominator);
  - `SYNO.Core.UPS`: get;
  - `SYNO.Core.System.Log`: list (offset/limit pages, `total` + `log`
    entries with id/time/level/message);
  - `SYNO.Core.Upgrade`: upgrade (async taskid), update_task_status.

## Configuration

Constructor `SimulatorConfig` or the live control endpoint (no auth):
`GET /warden-sim/control` for state; `POST /warden-sim/control` with
`{"profile": ...}`, `{"storage_degraded": bool}`,
`{"pool_rebuilding": bool}`, `{"ups_on_battery": bool}`,
`{"ups_absent": bool}`, `{"fan_broken": bool}`, `{"fan_zero_rpm": bool}`,
`{"share_no_quota": bool}`, `{"log_append": int}`,
`{"missing_apis": ["SYNO.Core.UPS", ...]}`,
`{"storage_max_version": 9}` (inflate the advertised Storage maxVersion to
prove the client never calls above its certified version),
`{"task_duration_seconds": ...}`, `{"failures": {...}}`,
`{"expire_sessions": true}`. Switching profile resets every knob to the
profile's preset (repeatable switches).

- Profiles: `healthy` (default), `ds224plus` and `ds225plus` (M4T2
  vendor-model profiles naming the hardware-targets units
  nas.synology_ds224plus/nas.synology_ds225plus: identity only — model/
  serial/DSM version differ, always marked `(simulated)`; the served API
  map is identical in this DSL), `degraded` (pool 1 Degraded, disk 2
  Broken/SMART Fail/bad sectors, UPS On Battery, fan 1 at 0 rpm Error,
  volume used/total near capacity — usage values are DATA), `auth_fail`
  (login always 401), `api_map_missing` (SYNO.Storage.CGI.Storage absent
  from the map — discovery must report the per-API gap, never guess a
  path), `slow_paginated` (150 log entries, page size 20).
- Volume/share usage: the payload carries `used_bytes`/`total_bytes` and
  share `used_bytes`/`quota_bytes` only — no invented thresholds anywhere;
  percentages are computed by the parser from the bytes
  (DEVICE_ADAPTERS.md §5.1) or reported missing. `share_no_quota` serves a
  share whose quota is 0 (无配额): the denominator is missing, so the
  adapter reports the gap instead of bytes-as-percent (ADR-016).
- Knob semantics (each exercises one honest adapter edge):
  `pool_rebuilding` serves pool status `Rebuilding` with a device-reported
  rebuild_progress (raid.rebuild_progress is only read while rebuilding);
  `ups_absent` answers `{"ups": null}` — no point and no component for a
  UPS-less unit; `fan_zero_rpm` reports 0 rpm with status Normal — 0 rpm
  is DEVICE-REPORTED data, never fabricated, and must not alert by itself;
  `log_append` appends strictly-newer entries after the base total
  (deterministic ids/timestamps continue) for delta log reads.
- Failure injection: `login_reject`, `login_otp`, `reads_500`,
  `error_unknown_2100`, `sessions_reject_106` (bounded re-login must fail
  honestly instead of looping), `smart_test_fails`, `update_fails`.

## Running

Served over ASGI (httpx `ASGITransport`, or boot uvicorn on localhost via
`tests/simulators/dsm/serving.py` for real-HTTP integration tests).
Credentials default: `admin` / `sim-pass-1` (test-only, simulator only).
