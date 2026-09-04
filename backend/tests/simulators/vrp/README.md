# VRP SSH simulator (M5T3)

A stateful Huawei-VRP CLI + SFTP **test-device simulator** served over real
asyncssh on `127.0.0.1` with an OS-assigned port. It exists to prove the
platform's SSH/CLI transport MECHANICS (host-key pinning, prompts, paging,
error signatures, config mode, reboot flow, SFTP transfers, firmware boot
paths) against a real SSH server — it is **never hardware evidence**
(ADR-018, DEVICE_ADAPTERS.md §10).

## Honest framing

- Every CLI response and state semantic is the `[sim]` DSL declared in
  `device.py` (basis tag `[sim] vrp-cli-sim-1`, 2026-09-04). The Huawei
  command reference was unreachable from this environment (same outcome as
  M5T1/M5T2), so **no `[huawei-doc-url]` exists anywhere in this repo**;
  the adapter template registry (`app/infrastructure/protocols/vrp/
  templates.py`) implements the same DSL text VERBATIM.
- The model strings are the certified `contracts/hardware-targets.json`
  tokens (S5732-H48XUM2CC / S5731S-S48P4X-A / S5735-L48P4S-A1) but the VRP
  version tokens, serials, port layouts, config text and command behavior
  are simulator-declared fixtures. M5 hardware certification must replace
  the whole DSL with per-model/VRP CLI evidence before any real-device
  claim (the `hardware-targets.json` certification matrix stays
  `not_started`).
- The firmware image format is the warden-sim shape (`WARDEN-SIM-FW
  {json}` first line) — the same shape the platform-side image metadata
  parser reads (M3T3/M4T3 convention).

## What it serves

- password authentication (fixed simulator credential, `device.py`
  `SSH_USERNAME`/`SSH_PASSWORD`); wrong passwords are refused;
- one host key generated per boot; the canonical SHA-256 fingerprint is
  `SSHKey.get_fingerprint("sha256")` — the exact value the platform pins in
  `connection_config["ssh_host_fingerprint"]`;
- a CLI shell: banner, prompts (`<sysname>` / `[sysname]` /
  `[sysname-Interface]`), view enforcement, error signatures, paging
  (`-- More --` when `screen-length` is not 0; `q` cancels), reboot flow;
- an SFTP subsystem rooted at a real bounded flash directory (allowlisted
  file names, no overwrite of the pristine config/base image, flash budget,
  `sftp_fail` knob);
- failure/behavior knobs on `device.knobs` (see `device.py` docstring):
  `error_on_command`, `save_prompt`, `restart_blip_seconds`, `restart_long`,
  `sftp_fail`, `poe_delayed_seconds`, `config_inject_marker`.

## DSL highlights (full contract: `device.py` module docstring)

| Command | Behavior |
| --- | --- |
| `screen-length 0 temporary` | disables paging for the session |
| `system-view` / `interface {id}` / `quit` / `return` | view stack |
| `display version` | model + VRP token + serial + uptime seconds |
| `display interface {id}` | `up`/`down`/`Administratively down` forms |
| `display poe-power interface {id}` | `Power state : on/off` (access GE only) |
| `shutdown`/`undo shutdown`/`poe-power on/off` | apply + mark config dirty |
| `display current-configuration` | deterministic text of the device state |
| `compare configuration` | saved/dirty verdict (restart precondition) |
| `display diagnostic-information` | long paged output + end marker |
| `display logbuffer` | access-profile log text |
| `dir flash:` | listing + `Total {t} KB ({f} KB free)` |
| `display startup` | boot image + startup config file |
| `startup system-software` / `startup saved-configuration {name}` | boot bindings |
| `reboot` | save-prompt knob, continue prompt, close, blip, boot side effects |

## Layout

- `device.py` — profiles, state, the DSL contract docstring, flash area;
- `app.py` — asyncssh server (auth server + CLI process handler + SFTP);
- `hosting.py` — sync hosting on a private thread + event loop; yields the
  OS port and the host-key fingerprint;
- `test_vrp_simulator.py` — the simulator self-tests (paging, views, state,
  reboot, SFTP, firmware paths).

## Provenance

All content is original simulator work authored for M5 (2026-09-04);
model strings sourced from `contracts/hardware-targets.json`. No vendor
documentation, MIB, or CLI reference was reachable or used, and none is
claimed.
