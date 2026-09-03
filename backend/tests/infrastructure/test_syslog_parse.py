"""Syslog RFC3164/RFC5424 tolerant parser unit tests (M5T1 ingest).

The parser must tolerate real-world syslog variants (RFC3164 no-year
timestamps, RFC5424 ISO timestamps, VRP-style year timestamps, missing PRI,
missing hostname/tag) without ever guessing a wrong timestamp.
"""

from __future__ import annotations

import datetime

import pytest
from app.infrastructure.ingest.syslog_parse import (
    ParsedSyslogMessage,
    parse_syslog_line,
    parse_syslog_timestamp,
)

UTC = datetime.UTC


def _message_with_timestamp(line: str) -> tuple[datetime.datetime | None, str | None, str | None, str]:
    parsed = parse_syslog_line(line)
    assert isinstance(parsed, ParsedSyslogMessage)
    return parsed.timestamp, parsed.hostname, parsed.tag, parsed.message


def test_rfc3164_with_priority_hostname_and_tag() -> None:
    parsed = parse_syslog_line("<190>Aug  4 14:22:01 s5732-1 %%01IFNET/4/LINK_STATE(l): down now")
    assert parsed is not None
    assert parsed.priority == 190
    assert parsed.facility == 23
    assert parsed.severity == 6
    assert parsed.hostname == "s5732-1"
    assert parsed.tag == "%%01IFNET/4/LINK_STATE(l)"
    assert parsed.message == "down now"


def test_rfc3164_single_space_day() -> None:
    parsed = parse_syslog_line("<14>Jan  5 09:00:00 host app: hello")
    assert parsed is not None
    assert parsed.tag == "app"
    assert parsed.message == "hello"


def test_vrp_year_timestamp_variant() -> None:
    parsed = parse_syslog_line("<190>Aug  4 2026 14:22:01 sw %%01SECE/4/AUTH_FAIL(l): login failed")
    assert parsed is not None
    assert parsed.timestamp == datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC)


def test_rfc5424_full_message() -> None:
    line = (
        "<165>1 2026-08-04T14:22:01.123Z s5732-1 warden-sim 1234 - - "
        "GigabitEthernet0/0/1 changed state to down"
    )
    parsed = parse_syslog_line(line)
    assert parsed is not None
    assert parsed.version == 1
    assert parsed.timestamp == datetime.datetime(2026, 8, 4, 14, 22, 1, 123000, tzinfo=UTC)
    assert parsed.hostname == "s5732-1"
    assert parsed.app_name == "warden-sim"
    assert parsed.message == "GigabitEthernet0/0/1 changed state to down"


def test_rfc5424_with_offset_timezone() -> None:
    line = "<34>1 2026-08-04T14:22:01+08:00 host app - - - text"
    parsed = parse_syslog_line(line)
    assert parsed is not None
    assert parsed.timestamp == datetime.datetime(
        2026, 8, 4, 14, 22, 1, tzinfo=datetime.timezone(datetime.timedelta(hours=8))
    )


def test_rfc5424_with_structured_data() -> None:
    line = '<165>1 2026-08-04T14:22:01Z host app 1 - [meta seq="1"] text here'
    parsed = parse_syslog_line(line)
    assert parsed is not None
    assert parsed.message == "text here"
    assert parsed.structured_data is not None
    assert 'seq="1"' in parsed.structured_data


def test_missing_priority_and_hostname() -> None:
    parsed = parse_syslog_line("Aug  4 14:22:01 the link changed")
    assert parsed is not None
    assert parsed.priority is None
    assert parsed.tag is None
    assert parsed.hostname is None
    assert parsed.message == "the link changed"


def test_missing_priority_no_timestamp_bare_message() -> None:
    parsed = parse_syslog_line("GigabitEthernet0/0/1 changed state to down")
    assert parsed is not None
    assert parsed.timestamp is None
    assert parsed.message == "GigabitEthernet0/0/1 changed state to down"


def test_priority_without_rest() -> None:
    parsed = parse_syslog_line("<14>")
    assert parsed is not None
    assert parsed.priority == 14
    assert parsed.message == ""


def test_invalid_priority_rejected() -> None:
    parsed = parse_syslog_line("<999>Aug  4 14:22:01 host msg")
    assert parsed is None


def test_garbage_rejected() -> None:
    assert parse_syslog_line("") is None
    assert parse_syslog_line("\x00\x01\x02") is None


def test_tag_without_colon_is_kept_in_message() -> None:
    parsed = parse_syslog_line("<14>Aug  4 14:22:01 hostname AUTH: login failed for user")
    assert parsed is not None
    assert parsed.hostname == "hostname"
    assert parsed.tag == "AUTH"
    assert parsed.message == "login failed for user"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-04T14:22:01.123Z", datetime.datetime(2026, 8, 4, 14, 22, 1, 123000, tzinfo=UTC)),
        (
            "2026-08-04T14:22:01+08:00",
            datetime.datetime(
                2026, 8, 4, 14, 22, 1, tzinfo=datetime.timezone(datetime.timedelta(hours=8))
            ),
        ),
        (
            "2026-08-04T14:22:01-05:30",
            datetime.datetime(
                2026, 8, 4, 14, 22, 1,
                tzinfo=datetime.timezone(datetime.timedelta(hours=-5, minutes=-30)),
            ),
        ),
    ],
)
def test_iso_timestamps(raw: str, expected: datetime.datetime) -> None:
    assert parse_syslog_timestamp(raw) == expected


def test_rfc3164_no_year_defaults_to_current_year() -> None:
    parsed = parse_syslog_timestamp("Aug  4 14:22:01")
    assert parsed is not None
    assert parsed.year == datetime.datetime.now(UTC).year
    assert parsed.tzinfo == UTC


def test_unparseable_timestamp_is_none() -> None:
    assert parse_syslog_timestamp("not a timestamp") is None


def test_trailing_newline_stripped() -> None:
    parsed = parse_syslog_line("<14>Aug  4 14:22:01 host tag: message\r\n")
    assert parsed is not None
    assert parsed.message == "message"
