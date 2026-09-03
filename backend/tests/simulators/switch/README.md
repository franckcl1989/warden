"""Warden Huawei-switch TEST-DEVICE SIMULATOR.

**THIS IS A TEST DEVICE SIMULATOR — a fake Huawei VRP switch for repeatable
automated tests. It is NOT evidence of hardware support.** Nothing served
here may be used to claim that Warden supports any real Huawei switch
(S5732-H48XUM2CC / S5731S-S48P4X-A / S5735-L48P4S-A1 or otherwise):
``contracts/hardware-targets.json`` and the certification matrix stay
``not_started`` until real-device runs exist (docs/HARDWARE_CERTIFICATION.md
§3, ADR-018, docs/DEVICE_ADAPTERS.md §6/§10).

## What it serves (M5T1)

- a real SNMP agent over UDP (pysnmp command responder): SNMPv1/v2c/v3 with
  USM auth+decryption emulation (exactly the configured credentials answer;
  wrong credentials get no response), GET/NEXT/BULK over the M5T1 seed tree
  (SNMPv2-MIB system group + IF-MIB ifTable — RFC 3418/2863 OIDs from
  ``app/infrastructure/protocols/snmp/oid.py``), ifInOctets/ifOutOctets
  counters that advance per read so rate tests observe monotonic growth;
- syslog/trap EMITTERS for tests: RFC3164/5424 syslog lines with knobs
  (port-flap down/up, device restart, auth failure, arbitrary lines) and
  RFC-standard traps (coldStart/warmStart/linkDown/linkUp/
  authenticationFailure) over v2c or v3 authPriv;
- three model profiles (``core_s5732`` / ``core_s5731s`` / ``access_s5735``)
  whose sysDescr carries the EXACT hardware-target model string and a
  simulator-declared VRP version (all [sim] DSL — see profiles.py).

## Basis discipline (binding)

- OIDs: only RFC-standard seeds are served (system group RFC 3418, ifTable
  RFC 2863). Huawei enterprise MIB trees (hwEntity/PoE/VRP traps) are NOT
  invented here: they arrive with the M5T2 MIB table and its citable basis
  ([huawei-doc-url] or [sim]) — ``SwitchAgent.register_oid`` is the
  extension point.
- Syslog wording is the fixture-DSL counterpart of the [sim] classification
  rows in ``app/infrastructure/ingest/dispatcher.py``; real VRP log wording
  must be archived from the target model's event catalog during hardware
  certification before any [huawei-doc-url] claim replaces a [sim] row.
- VRP versions and port layouts are simulator DSL, marked (simulated) in
  profiles.py; they prove protocol mechanics, never product facts.
- Fixture snapshots captured from this simulator MUST record their
  模拟器来源 (profile, capture date) — never a 真机 claim.

## v3 USM mechanics note

A v3 trap is stamped with the SENDER's engine id + boots/time (RFC 3414
§3.2 semantics as pysnmp implements them): the receiving platform must
register the device's USM user keys under the profile engine id (devices'
``connection_config["snmp_engine_id"]``) before authPriv traps decode. The
emitters use one long-lived engine per instance so boots/time advance like a
real switch.
"""
