# DSM fixture policy (tests/fixtures/dsm)

Fixture JSON files in this directory are **canned DSM WebAPI response
envelopes** captured verbatim over real HTTP from the Warden DSM test-device
simulator (`tests/simulators/dsm/`, booted with uvicorn via
`tests/simulators/dsm/serving.py`). They are **模拟器来源（TEST SIMULATOR）**,
never 真机 evidence: nothing here may be cited as proof that Warden supports
any real Synology NAS (DS224+/DS225+ or otherwise). The hardware
certification matrix (`contracts/hardware-targets.json` +
`tests/hardware-certification/`) stays `not_started` until real-device runs
exist (docs/HARDWARE_CERTIFICATION.md §3, ADR-018 — real DSM behavior
requires target-model certification). The payload vocabularies are the
simulator DSL documented in `tests/simulators/dsm/README.md`.

## Files

| File | Represents | Origin | Captured |
| --- | --- | --- | --- |
| `info-query-all-healthy.json` | `GET /webapi/query.cgi` (SYNO.API.Info.Query query=all API map incl. the M4T3 operation families SYNO.Core.Support/SYNO.Core.Backup/SYNO.Core.Network.SNMP) | simulator profile `healthy`, uvicorn 127.0.0.1 | 2026-09-03 (re-captured 2026-09-03 for M4T3) |
| `info-query-api-map-missing.json` | `GET /webapi/query.cgi` (API map WITHOUT SYNO.Storage.CGI.Storage) | simulator profile `api_map_missing`, uvicorn 127.0.0.1 | 2026-09-03 (re-captured 2026-09-03 for M4T3) |
| `info-query-ds224plus.json` | `GET /webapi/query.cgi` (SYNO.API.Info.Query query=all API map incl. SYNO.Core.Share and the M4T3 operation families) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 (re-captured 2026-09-03 for M4T3) |
| `login-otp-required.json` | `GET /webapi/auth.cgi` (SYNO.API.Auth login answer: two-step required, code 403) | simulator failures knob `login_otp`, uvicorn 127.0.0.1 | 2026-09-03 |
| `system-info-healthy.json` | `GET /webapi/entry.cgi` (SYNO.Core.System method=info, version 2) | simulator profile `healthy`, uvicorn 127.0.0.1 | 2026-09-03 |
| `system-info-ds224plus.json` | `GET /webapi/entry.cgi` (SYNO.Core.System info, version 2 — ds224plus identity) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 |
| `system-info-ds225plus.json` | `GET /webapi/entry.cgi` (SYNO.Core.System info, version 2 — ds225plus identity) | simulator profile `ds225plus`, uvicorn 127.0.0.1 | 2026-09-03 |
| `storage-degraded.json` | `GET /webapi/entry.cgi` (SYNO.Storage.CGI.Storage load_info: broken/failed disk, degraded pool, near-capacity volume usage bytes) | simulator profile `degraded`, uvicorn 127.0.0.1 | 2026-09-03 |
| `storage-ds224plus-healthy.json` | `GET /webapi/entry.cgi` (SYNO.Storage.CGI.Storage load_info — ds224plus healthy disks/pool/volume) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 |
| `storage-pool-rebuilding.json` | `GET /webapi/entry.cgi` (SYNO.Storage.CGI.Storage load_info — pool 1 Rebuilding with device-reported rebuild_progress 45) | simulator profile `ds224plus` + knob `pool_rebuilding`, uvicorn 127.0.0.1 | 2026-09-03 |
| `share-list-ds224plus.json` | `GET /webapi/entry.cgi` (SYNO.Core.Share list — homes share with used_bytes/quota_bytes) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 |
| `share-list-no-quota.json` | `GET /webapi/entry.cgi` (SYNO.Core.Share list — backup share with quota_bytes 0, the missing usage-percent denominator) | simulator profile `ds224plus` + knob `share_no_quota`, uvicorn 127.0.0.1 | 2026-09-03 |
| `ups-normal-ds224plus.json` | `GET /webapi/entry.cgi` (SYNO.Core.UPS get — Normal) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 |
| `ups-on-battery.json` | `GET /webapi/entry.cgi` (SYNO.Core.UPS get — On Battery) | simulator profile `ds224plus` + knob `ups_on_battery`, uvicorn 127.0.0.1 | 2026-09-03 |
| `log-page1-healthy.json` | `GET /webapi/entry.cgi` (SYNO.Core.System.Log list, offset 0 limit 5) | simulator profile `healthy`, uvicorn 127.0.0.1 | 2026-09-03 |
| `log-page1-ds224plus.json` | `GET /webapi/entry.cgi` (SYNO.Core.System.Log list, offset 0 limit 5 — ds224plus profile) | simulator profile `ds224plus`, uvicorn 127.0.0.1 | 2026-09-03 |

All files are synthetic simulator data — no credentials, tokens, serials of
real devices or other sensitive content (login envelopes are captured with
the test-only `admin`/`sim-pass-1` account and their sid-bearing bodies were
NOT snapshotted; only the failure answer without a sid was kept). The M4T2
rows were captured with `tests/simulators/dsm/capture_m4t2_fixtures.py`
(uvicorn 127.0.0.1, profiles/knobs in the table above).

## Rules for future fixtures (binding)

1. **Real-device fixtures (M4T2/later, or any certification work)** must
   record the actual device model, DSM firmware version, capture date AND
   the sanitized evidence hash per docs/HARDWARE_CERTIFICATION.md §3 and
   docs/TEST_STRATEGY.md §2.2.
2. Sanitize before committing: credentials, cookies, tokens, raw serials
   and sensitive text must not enter the repo (docs/SECURITY.md §10,
   HARDWARE_CERTIFICATION.md §3).
3. Simulator captures must state the profile/knobs used and the capture
   date — this README table is the index; update it when adding a file.
4. A simulator capture is a contract snapshot: it is frozen at capture time
   and must not be silently regenerated when the simulator evolves — update
   the README provenance row when a capture is re-taken.
5. Never label a fixture as coming from a real device unless it does.
