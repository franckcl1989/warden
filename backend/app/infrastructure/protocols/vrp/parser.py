"""VRP CLI output parsing (prompts, errors, structured readbacks).

Everything here parses the [sim] CLI DSL of the M5T3 simulator
(tests/simulators/vrp) — the SAME output shapes the certified command
templates produce. Parsing is honest: an output that does not contain the
expected marker returns None/False — the caller never invents a value from
an unparseable response (AGENTS.md: 不得把不确定的结果伪装成成功).

Parsers are pure functions over decoded text (the transport layer already
strips ANSI/paging artifacts; ``clean_output`` normalizes CRLF and trailing
whitespace so hashes are deterministic across channels).
"""

from __future__ import annotations

import hashlib
import re

# ---------------------------------------------------------------------------
# generic text normalization

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*(\x07|\x1b\\)")


def clean_output(text: str) -> str:
    """Decode-level cleanup: ANSI escapes, CRLF and trailing spaces."""
    text = _ANSI_RE.sub("", text)
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(lines)


def normalize_config_text(text: str) -> str:
    """Deterministic config fingerprint text (config backup/restore).

    CRLF -> LF, per-line trailing whitespace stripped, blank lines dropped.
    The simulator derives ``display current-configuration`` deterministically
    from its state, so the normalized text of two identical states is
    byte-identical; the SHA-256 of this text is the config fingerprint.
    """
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.strip():
            lines.append(line)
    return "\n".join(lines) + "\n"


def config_fingerprint(text: str) -> str:
    """SHA-256 of the normalized config text (restore comparison value)."""
    return hashlib.sha256(normalize_config_text(text).encode("utf-8")).hexdigest()


def config_parse_ok(text: str) -> tuple[bool, str]:
    """Sanity parse of a running-config export ([sim] DSL shapes).

    (ok, reason): the text is non-empty, its first non-blank line is a ``#``
    section marker and a ``sysname`` line follows somewhere in the first
    lines — the documented sanity gate of the config.backup/restore
    profiles. Anything else is refused (no full VRP parser exists in 0.1.0;
    this is a sanity gate, not a syntax proof).
    """
    normalized = normalize_config_text(text)
    lines = normalized.splitlines()
    if not lines:
        return False, "配置内容为空"
    if not lines[0].startswith("#"):
        return False, "配置缺少 VRP 段标记（首行不是 #）"
    head = lines[1:6]
    if not any(line.startswith("sysname ") for line in head):
        return False, "配置缺少 sysname 行（不是可识别的运行配置）"
    return True, "ok"


def vrp_major_version(version_token: str) -> str | None:
    """The VRP major version prefix (restore precondition gate).

    [sim] DSL versions look like ``V200R021C10SPC600``; the major family is
    the ``V<d>R<d>C<d>`` prefix. A token without that shape (unknown real
    VRP naming) yields None — the caller must fail the gate, never guess.
    """
    match = re.match(r"^(V[0-9]+R[0-9]+C[0-9]+)", version_token.strip())
    return match.group(1) if match is not None else None


# ---------------------------------------------------------------------------
# prompt detection

_USER_PROMPT_RE = re.compile(r"<([^<>\s]+)>\s*$")
_CONFIG_PROMPT_RE = re.compile(r"\[([^\]]+)\]\s*$")


def user_prompt_match(text: str) -> str | None:
    """The sysname when ``text`` ends with a user-view prompt, else None."""
    cleaned = text.rstrip()
    if cleaned.endswith("\n"):
        cleaned = cleaned.rstrip()
    match = _USER_PROMPT_RE.search(cleaned)
    return match.group(1) if match is not None else None


def config_prompt_match(text: str, sysname: str | None = None) -> tuple[str, str | None] | None:
    """(sysname, interface_name) when ``text`` ends with a config/interface
    prompt ``[sysname]`` / ``[sysname-Interface]``; None otherwise.

    ``sysname`` restricts the match when known; an interface-view prompt
    carries the interface name after the first ``-``.
    """
    cleaned = text.rstrip()
    if cleaned.endswith("\n"):
        cleaned = cleaned.rstrip()
    match = _CONFIG_PROMPT_RE.search(cleaned)
    if match is None:
        return None
    inside = match.group(1).strip()
    if not inside or " " in inside:
        return None
    if sysname is not None:
        if inside == sysname:
            return (sysname, None)
        if inside.startswith(sysname + "-") and len(inside) > len(sysname) + 1:
            return (sysname, inside[len(sysname) + 1 :])
        return None
    if "-" in inside:
        name, _, rest = inside.partition("-")
        return (name, rest) if rest else None
    return (inside, None)


# ---------------------------------------------------------------------------
# error markers (VRP signatures of the [sim] DSL)

_ERROR_LINE_RE = re.compile(r"(?m)^\s*Error:.*$")
_VALIDATION_MARKER_WORDS = ("wrong parameter", "unrecognized command", "unknown command")


def find_error_markers(text: str) -> tuple[str, ...]:
    """Every ``Error:`` line in ``text`` (the DSL device failure signature).

    Caret lines (``^``) below an error are position hints and are NOT
    standalone markers.
    """
    return tuple(match.group(0).strip() for match in _ERROR_LINE_RE.finditer(text))


def classify_error_marker(marker: str) -> str:
    """Map one error marker to an error code: a parameter/command defect is
    ``validation_failed`` (the caller passed a bad value); anything else the
    device refused is ``operation_failed``."""
    lowered = marker.lower()
    if any(word in lowered for word in _VALIDATION_MARKER_WORDS):
        return "validation_failed"
    return "operation_failed"


# ---------------------------------------------------------------------------
# structured readbacks (DSL shapes)

_VERSION_LINE_RE = re.compile(r"VRP\s*\(\s*R\s*\)\s*software.*?Version\s+([0-9A-Za-z_.+-]+)", re.IGNORECASE)
_SERIAL_LINE_RE = re.compile(r"Device serial number\s*:\s*(\S+)", re.IGNORECASE)
_UPTIME_LINE_RE = re.compile(r"System uptime is (\d+) seconds", re.IGNORECASE)
_VERSION_MODEL_RE = re.compile(r"Version\s+[0-9A-Za-z_.+-]+\s*\(([^()]+)\)")


def parse_version(text: str) -> dict[str, str | int | None]:
    """display version -> model/vrp_version/serial/uptime_seconds.

    The model token comes from the DSL ``(...)`` suffix (first token);
    ``vrp_version`` is the token after ``Version``. Missing pieces are None
    — the caller treats an incomplete identity read as a protocol error.
    """
    cleaned = clean_output(text)
    version_match = _VERSION_LINE_RE.search(cleaned)
    serial_match = _SERIAL_LINE_RE.search(cleaned)
    uptime_match = _UPTIME_LINE_RE.search(cleaned)
    model: str | None = None
    if version_match is not None:
        suffix = _VERSION_MODEL_RE.search(cleaned)
        if suffix is not None:
            tokens = suffix.group(1).split()
            if tokens:
                model = tokens[0]
    uptime: int | None = None
    if uptime_match is not None:
        try:
            uptime = int(uptime_match.group(1))
        except ValueError:
            uptime = None
    return {
        "model": model,
        "vrp_version": version_match.group(1) if version_match is not None else None,
        "serial": serial_match.group(1) if serial_match is not None else None,
        "uptime_seconds": uptime,
    }


_CURRENT_STATE_RE = re.compile(r"(?m)^([A-Za-z0-9/.-]+)\s+current state\s*:\s*(.+)$")
_ADMIN_DOWN = "Administratively down"


def parse_interface_state(text: str) -> dict[str, str | bool | None]:
    """display interface -> {admin: up|down, oper: up|down, found: bool}.

    [sim] DSL forms (only three possible ``current state`` values):
    ``up`` (admin up, link up), ``down`` (admin up, link down) and
    ``Administratively down`` (admin down). ``Line protocol current state``
    mirrors the link state.
    """
    cleaned = clean_output(text)
    current = _CURRENT_STATE_RE.search(cleaned)
    if current is None:
        return {"admin": None, "oper": None, "found": False}
    state = current.group(2).strip()
    if state == _ADMIN_DOWN:
        return {"admin": "down", "oper": "down", "found": True}
    if state in ("up", "down"):
        return {"admin": "up", "oper": state, "found": True}
    return {"admin": None, "oper": None, "found": False}


_POE_STATE_RE = re.compile(r"Power state\s*:\s*(\w+)", re.IGNORECASE)


def parse_poe_state(text: str) -> str | None:
    """display poe-power interface -> ``on``/``off`` or None (unparseable)."""
    cleaned = clean_output(text)
    match = _POE_STATE_RE.search(cleaned)
    if match is None:
        return None
    value = match.group(1).strip().lower()
    return value if value in ("on", "off") else None


_COMPARE_DIRTY_MARKER = "different from the saved configuration"
_COMPARE_SAVED_MARKER = "same as the saved configuration"


def parse_compare_configuration(text: str) -> bool | None:
    """compare configuration -> True (dirty) / False (saved) / None."""
    cleaned = clean_output(text)
    if _COMPARE_DIRTY_MARKER in cleaned:
        return True
    if _COMPARE_SAVED_MARKER in cleaned:
        return False
    return None


_DIR_FREE_RE = re.compile(r"Total\s+\d+\s+KB\s*\(\s*(\d+)\s+KB free\)", re.IGNORECASE)


def parse_dir_free_kb(text: str) -> int | None:
    """dir flash: -> free KB (the space check of firmware transfers)."""
    cleaned = clean_output(text)
    match = _DIR_FREE_RE.search(cleaned)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


_STARTUP_SOFTWARE_RE = re.compile(r"System software\s*:\s*(\S+)", re.IGNORECASE)
_STARTUP_CONFIG_RE = re.compile(r"Startup saved-configuration file\s*:\s*(\S+)", re.IGNORECASE)


def parse_startup(text: str) -> dict[str, str | None]:
    """display startup -> {boot_image, startup_file}."""
    cleaned = clean_output(text)
    software = _STARTUP_SOFTWARE_RE.search(cleaned)
    config = _STARTUP_CONFIG_RE.search(cleaned)
    return {
        "boot_image": software.group(1) if software is not None else None,
        "startup_file": config.group(1) if config is not None else None,
    }
