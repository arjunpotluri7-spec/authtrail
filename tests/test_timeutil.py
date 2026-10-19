from datetime import UTC, datetime

import pytest

from authtrail.timeutil import fmt_duration, fmt_iso, load_timezone, parse_timestamp


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-10-14T02:14:09Z", datetime(2026, 10, 14, 2, 14, 9, tzinfo=UTC)),
        ("2026-10-14 02:17:31.402113+0000", datetime(2026, 10, 14, 2, 17, 31, 402113, tzinfo=UTC)),
        ("2026-10-14T09:20:03.4410000Z", datetime(2026, 10, 14, 9, 20, 3, 441000, tzinfo=UTC)),
        ("2026-10-13T22:14:09-04:00", datetime(2026, 10, 14, 2, 14, 9, tzinfo=UTC)),
        ("/Date(1791871200000)/", datetime(2026, 10, 13, 6, 0, 0, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_variants(text, expected):
    assert parse_timestamp(text) == expected


def test_parse_timestamp_naive_uses_default_zone():
    zone = load_timezone("America/New_York")
    assert parse_timestamp("2026-10-13T22:00:00", zone) == datetime(2026, 10, 14, 2, tzinfo=UTC)


@pytest.mark.parametrize("bad", ["", "yesterday", "2026-13-01T00:00:00Z"])
def test_parse_timestamp_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_timestamp(bad)


def test_load_timezone_unknown():
    with pytest.raises(ValueError, match="unknown time zone"):
        load_timezone("Mars/Olympus_Mons")


def test_formatting():
    assert fmt_iso(datetime(2026, 10, 14, 2, 14, 9, 999, tzinfo=UTC)) == "2026-10-14T02:14:09Z"
    assert fmt_duration(45) == "45s"
    assert fmt_duration(270) == "4m 30s"
    assert fmt_duration(5340) == "1h 29m"
    assert fmt_duration(2 * 86400 + 3 * 3600) == "2d 3h"
