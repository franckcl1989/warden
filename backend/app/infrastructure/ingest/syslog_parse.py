"""Syslog RFC3164/RFC5424 tolerant line parser (M5T1 event-ingest).

Tolerance rules (documented, tested):

- RFC5424 (``<PRI>1 TS HOST APP PROCID MSGID SD MSG``) with ISO-8601
  timestamps, and RFC3164 (``<PRI>Mmm dd hh:mm:ss HOST [TAG:] MSG``) with
  no-year timestamps; VRP-style ``Mmm dd yyyy hh:mm:ss`` timestamps are
  accepted as an RFC3164 variant.
- PRI is optional; a malformed PRI rejects the line (never mis-parsed).
- A year-less timestamp defaults to the CURRENT year (standard syslog
  receiver convention; the year is not part of RFC3164).
- The tag is the first space token ending with ``:``; everything after it is
  the message. Without a tag, the whole remaining text is the message (a
  hostname cannot be distinguished from the message start without a tag
  marker — the parser never guesses).
- ``parse_syslog_line`` returns None for lines that are not syslog at all
  (callers count and drop them; nothing is stored).
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_ISO_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)
_3164_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(20\d{2})\s+)?(\d{1,2}):(\d{2}):(\d{2})$"
)
_5424_RE = re.compile(
    r"^(\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", re.DOTALL
)
_5424_SD_RE = re.compile(r"^(\[[^\]]*\])(?: |$)(.*)$", re.DOTALL)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True)
class ParsedSyslogMessage:
    """One tolerant-parsed syslog line."""

    raw: str
    message: str
    priority: int | None = None
    facility: int | None = None
    severity: int | None = None
    version: int | None = None
    timestamp: datetime.datetime | None = None
    hostname: str | None = None
    app_name: str | None = None
    tag: str | None = None
    structured_data: str | None = None


def parse_syslog_timestamp(raw: str) -> datetime.datetime | None:
    """ISO-8601 (RFC5424) or RFC3164/VRP month-day timestamp -> aware datetime.

    A year-less RFC3164 timestamp defaults to the current UTC year; the
    result is always timezone-aware (naive input is treated as UTC — syslog
    has no local-time transport contract here and the platform stores UTC).
    """
    iso = _ISO_TS_RE.match(raw)
    if iso is not None:
        iso_year, iso_month, iso_day, iso_hour, iso_minute, iso_second = (
            int(part) for part in iso.groups()[:6]
        )
        fraction_raw = iso.group(7) or ""
        fraction = int(fraction_raw.ljust(6, "0")) if fraction_raw else 0
        zone_raw = iso.group(8)
        tzinfo: datetime.tzinfo
        if zone_raw == "Z":
            tzinfo = datetime.UTC
        else:
            sign = 1 if zone_raw[0] == "+" else -1
            zone_hour, zone_minute = (int(part) for part in zone_raw[1:].split(":"))
            tzinfo = datetime.timezone(sign * datetime.timedelta(hours=zone_hour, minutes=zone_minute))
        return datetime.datetime(
            iso_year, iso_month, iso_day, iso_hour, iso_minute, iso_second, fraction, tzinfo=tzinfo
        )
    legacy = _3164_TS_RE.match(raw)
    if legacy is not None:
        month_name, day, year, hour, minute, second = legacy.groups()
        month_number = _MONTHS.get(month_name)
        if month_number is None:
            return None
        year_value = int(year) if year is not None else datetime.datetime.now(datetime.UTC).year
        return datetime.datetime(
            year_value, month_number, int(day), int(hour), int(minute), int(second), tzinfo=datetime.UTC
        )
    return None


def parse_syslog_line(raw_line: str) -> ParsedSyslogMessage | None:
    """Parse one syslog datagram/stream line tolerantly; None = not syslog."""
    if not raw_line:
        return None
    if "\x00" in raw_line:
        return None
    line = raw_line.rstrip("\r\n")
    if not line:
        return None

    priority: int | None = None
    pri_match = _PRI_RE.match(line)
    body = line
    if pri_match is not None:
        priority = int(pri_match.group(1))
        if priority > 191:
            return None
        body = line[pri_match.end():]

    if not body:
        return ParsedSyslogMessage(raw=raw_line, message="", priority=priority,
                                   facility=priority // 8 if priority is not None else None,
                                   severity=priority % 8 if priority is not None else None)

    # RFC5424: version 1..999 followed by six space-delimited fields.
    if body[0].isdigit():
        first_space = body.find(" ")
        if first_space > 0 and body[:first_space].isdigit():
            version = int(body[:first_space])
            if 1 <= version <= 999:
                rest = body[first_space + 1 :]
                fields = _5424_RE.match(rest)
                if fields is not None:
                    timestamp_raw, hostname, app_name, _proc_id, _msg_id, structured, tail = fields.groups()
                    timestamp = parse_syslog_timestamp(timestamp_raw)
                    structured_data: str | None = None
                    message = tail
                    if structured.startswith("["):
                        sd_match = _5424_SD_RE.match(structured + " " + tail)
                        if sd_match is not None:
                            structured_data, message = sd_match.groups()
                    elif structured == "-":
                        structured_data = None
                    else:
                        message = structured + (" " + tail if tail else "")
                    return ParsedSyslogMessage(
                        raw=raw_line,
                        message=message.strip(),
                        priority=priority,
                        facility=priority // 8 if priority is not None else None,
                        severity=priority % 8 if priority is not None else None,
                        version=version,
                        timestamp=timestamp,
                        hostname=hostname if hostname != "-" else None,
                        app_name=app_name if app_name != "-" else None,
                        structured_data=structured_data,
                    )

    # RFC3164 / VRP variants: optional timestamp then hostname + [tag:] msg.
    header_timestamp: datetime.datetime | None = None
    remaining = body
    tokens = body.split()
    if tokens:
        consumed = 0
        if re.match(r"^[A-Z][a-z]{2}$", tokens[0]) or _ISO_TS_RE.match(tokens[0]):
            # A header timestamp spans up to four tokens
            # ("Mmm d hh:mm:ss" / "Mmm d yyyy hh:mm:ss" / one ISO token).
            for width in range(min(4, len(tokens)), 0, -1):
                candidate_ts = " ".join(tokens[:width])
                parsed_ts = parse_syslog_timestamp(candidate_ts)
                if parsed_ts is not None:
                    header_timestamp = parsed_ts
                    consumed = width
                    break
        remaining = " ".join(tokens[consumed:]).strip()

    header_hostname: str | None = None
    header_tag: str | None = None
    message = remaining
    if remaining:
        tokens = remaining.split(" ", 2)
        if len(tokens) >= 2 and tokens[1].endswith(":"):
            header_hostname = tokens[0]
            header_tag = tokens[1][:-1]
            message = tokens[2].strip() if len(tokens) == 3 else ""
        elif tokens[0].endswith(":"):
            header_tag = tokens[0][:-1]
            message = (tokens[1] if len(tokens) == 2 else tokens[2] if len(tokens) == 3 else "").strip()
    return ParsedSyslogMessage(
        raw=raw_line,
        message=message,
        priority=priority,
        facility=priority // 8 if priority is not None else None,
        severity=priority % 8 if priority is not None else None,
        timestamp=header_timestamp,
        hostname=header_hostname,
        tag=header_tag,
    )
