"""Warden Huawei-switch TEST-DEVICE SIMULATOR.

**THIS IS A TEST DEVICE SIMULATOR — a fake Huawei VRP switch for repeatable
automated tests. It is NOT evidence of hardware support.** Nothing served
here may be used to claim that Warden supports any real Huawei switch
(S5732-H48XUM2CC / S5731S-S48P4X-A / S5735-L48P4S-A1 or otherwise):
``contracts/hardware-targets.json`` and the certification matrix stay
``not_started`` until real-device runs exist (docs/HARDWARE_CERTIFICATION.md
§3, ADR-018, docs/DEVICE_ADAPTERS.md §6/§10).

## What it serves

- a real SNMP agent over UDP (pysnmp command responder): SNMPv1/v2c/v3 with
  USM auth+decryption emulation (exactly the configured credentials answer;
  wrong credentials get no response), GET/NEXT/BULK over the M5T1 seed tree
  (SNMPv2-MIB system group + IF-MIB ifTable — RFC 3418/2863 OIDs from
  ``app/infrastructure/protocols/snmp/oid.py``), ifInOctets/ifOutOctets
  counters that advance per read so rate tests observe monotonic growth;
- M5T2 trees (mounted from the adapter ledger
  ``app/adapters/huawei/oids.py`` — see Basis discipline): the RFC-2863
  ifXTable 64-bit ifHCInOctets/ifHCOutOctets + ifTable discard counters the
  adapter rate derivation reads, and the [sim] Huawei subtree
  (1.3.6.1.4.1.2011.5.25.31.*): CPU/memory utilization scalars,
  hwEntityStateTable (PSU/fan/temperature slots — including an
  installed-but-absent PSU slot on the core_s5731s profile), the
  hwOpticalModuleInfoTable (one row per uplink port that HAS an optical
  module), hwPoEPortTable + device PoE scalars (access profile: 16 powered
  ports x 5 W = 80 W of a 400 W budget -> 20%), loop/broadcast scalars +
  hwStpPortTable (core profiles), hwPortCrcErrors counters;
- per-profile MIB variance (CPU/memory utilization, entity slots, optics/
  PoE layout) and KNOBS (``SwitchAgent`` methods): fan fault, PSU absent,
  PoE port state/power + budget leaf removal (``set_poe_budget_present``),
  device PoE alarm state, transceiver install/removal, HC counter rollover
  (``AgentConfig.hc_wrap_at``), per-port admin/oper/STP states,
  loop/broadcast detection, sysDescr override for cross-model rejection
  probes;
- syslog/trap EMITTERS for tests: RFC3164/5424 syslog lines with knobs
  (port-flap down/up, device restart, auth failure, arbitrary lines) and
  RFC-standard traps (coldStart/warmStart/linkDown/linkUp/
  authenticationFailure) over v2c or v3 authPriv;
- three model profiles (``core_s5732`` / ``core_s5731s`` / ``access_s5735``)
  whose sysDescr carries the EXACT hardware-target model string and a
  simulator-declared VRP version (all [sim] DSL — see profiles.py).

## Basis discipline (binding)

- OIDs: only RFC-standard seeds AND the rows of the M5T2 adapter ledger
  (``app/adapters/huawei/oids.py``) are served — every row carries its
  [basis] tag ([rfc-3418]/[rfc-2863]/[rfc-3411], the IANA-cited Huawei PEN
  prefix, or [sim] for the simulator-declared Huawei subtree). Nothing is
  invented here; the honesty tests pin the agent tree to the ledger, so the
  adapter and the simulator can never drift. Real Huawei MIB OIDs must be
  archived from the target model's MIB reference during hardware
  certification before any [huawei-doc-url] claim replaces a [sim] row.
- Syslog wording is the fixture-DSL counterpart of the [sim] classification
  rows in ``app/infrastructure/ingest/dispatcher.py``; real VRP log wording
  must be archived from the target model's event catalog during hardware
  certification before any [huawei-doc-url] claim replaces a [sim] row.
- VRP versions, port layouts, entity layouts, enum literals and the scaled
  optical/PoE values are simulator DSL (marked [sim]); they prove protocol
  mechanics, never product facts.
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
