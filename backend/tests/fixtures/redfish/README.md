# Redfish fixture policy (tests/fixtures/redfish)

Fixture JSON files in this directory represent **canned Redfish responses**.
Their ONLY origin today is the Warden Redfish test-device simulator
(`tests/simulators/redfish/`) — they are **模拟器来源（TEST SIMULATOR）**, never
真机 evidence. Nothing in this directory may be cited as proof that Warden
supports any real server/management card; the hardware certification matrix
(`contracts/hardware-targets.json` + `tests/hardware-certification/`)
stays `not_started` until real-device runs exist.

## Files

| File | Represents | Origin | Captured |
| --- | --- | --- | --- |
| `service-root-healthy.json` | `GET /redfish/v1` (ServiceRoot) | simulator profile `healthy` | 2026-09-03 |
| `sel-entries-page1-healthy.json` | `GET /redfish/v1/Managers/1/LogServices/SEL/Entries` (first page, 4 entries, inline LogEntry members) | simulator profile `healthy` | 2026-09-03 |
| `computer-system-critical.json` | `GET /redfish/v1/Systems/1` | simulator profile `critical` | 2026-09-03 |

Capture provenance: the healthy files were captured over real HTTP
(uvicorn on 127.0.0.1, HTTP Basic) via `tests/simulators/redfish/serving.py`;
the critical file was captured from the same simulator over an ASGI
transport. All three come from `SimulatorConfig()` defaults except
`computer-system-critical.json` (`profile="critical"`). Synthetic data needs
no sanitization; it contains no credentials, tokens, serials or real device
identity.

## Rules for future fixtures (binding)

1. **Real-device fixtures (M6/later, or any vendor overlay work)** must record
   the actual device model, firmware version, capture date AND the sanitized
   evidence hash per docs/HARDWARE_CERTIFICATION.md §3 and
   docs/TEST_STRATEGY.md §2.2 (`厂商 fixture 必须来自脱敏真机响应或官方模拟器，
   保存来源型号/固件和采集日期`).
2. Sanitize before committing: credentials, cookies, tokens, raw serials,
   topology and sensitive support-bundle text must not enter the repo
   (docs/SECURITY.md §10, HARDWARE_CERTIFICATION.md §3).
3. Simulator captures must state the profile used and the capture date —
   this README table is the index; update it when adding a file.
4. A simulator capture is a contract snapshot: it is frozen at capture time
   and must not be silently regenerated when the simulator evolves — update
   the README provenance row when a capture is re-taken.
5. Never label a fixture as coming from a real device unless it does.
