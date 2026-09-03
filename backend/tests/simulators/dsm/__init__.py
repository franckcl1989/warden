"""DSM simulator payload builders + profiles.

THIS IS A TEST DEVICE SIMULATOR — a fake Synology DSM for repeatable
automated tests. It is NOT evidence of hardware support for DS224+/DS225+ or
any real DSM: fixtures captured from it must state their 模拟器 origin, and
the hardware certification matrix (hardware-targets.json /
HARDWARE_CERTIFICATION.md §3) stays ``not_started`` until real-device runs
exist (ADR-018 — real DSM behavior requires target-model certification).

The DSM payload vocabulary served here is a documented SIMULATOR DSL:

- response envelopes follow the public DSM Login Web API guide
  (``{"success": true, "data": ...}`` / ``{"success": false,
  "error": {"code": N}}``; codes 100..108 are the guide's common error
  block);
- the API map advertises the platform API families the Warden NAS adapter
  needs; every API name's documentation basis is listed in the module
  README — SYNO.API.Auth/SYNO.API.Info are Login-guide documented, all
  SYNO.Core.* / SYNO.Storage.CGI.* families are NOT and are flagged as
  simulator-invented placeholders pending M4T2 certification;
- the value vocabularies of those family payloads (disk statuses, pool
  statuses, UPS states, log levels, ...) are simulator-authored and must
  only be treated as certified mapping rows by fixtures, never as real-DSM
  evidence.
"""
