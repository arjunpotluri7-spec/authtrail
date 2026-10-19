"""Timestamp parsing and formatting helpers."""

import re
from datetime import UTC, datetime, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# PowerShell's ConvertTo-Json (Windows PowerShell 5.1) writes dates as /Date(1697270460000)/.
_MS_DATE_RE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")
# Windows writes 7 fractional digits; datetime only keeps microseconds.
_LONG_FRACTION_RE = re.compile(r"(\.\d{6})\d+")
# macOS `log show` writes offsets as +0000; normalize to +00:00.
_COMPACT_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_timestamp(value: str, default_tz: tzinfo = UTC) -> datetime:
    """Parse an ISO-8601-ish timestamp and return it as timezone-aware UTC.

    Naive timestamps are interpreted in ``default_tz``. Raises ``ValueError`` on bad input.
    """
    text = value.strip()
    match = _MS_DATE_RE.fullmatch(text)
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=UTC)
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    text = _COMPACT_OFFSET_RE.sub(r"\1:\2", text)
    text = _LONG_FRACTION_RE.sub(r"\1", text, count=1)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=default_tz)
    return parsed.astimezone(UTC)


def load_timezone(name: str) -> tzinfo:
    """Return a tzinfo for an IANA name. ``UTC`` works even without a tz database."""
    if name.strip().upper() in ("UTC", "Z", "ETC/UTC"):
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"unknown time zone {name!r} (use an IANA name such as 'UTC' or 'America/New_York';"
            " on Windows install the 'tzdata' package)"
        ) from exc


def fmt_iso(value: datetime) -> str:
    """Format as ``2026-10-14T02:14:09Z`` (UTC, second precision)."""
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def fmt_human(value: datetime) -> str:
    """Format as ``2026-10-14 02:14:09 UTC``."""
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_clock(value: datetime) -> str:
    """Format as ``02:14:09 UTC``."""
    return value.astimezone(UTC).strftime("%H:%M:%S UTC")


def fmt_duration(seconds: float) -> str:
    """Human duration: ``45s``, ``4m 30s``, ``1h 29m``, ``2d 3h``."""
    total = round(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


def fmt_window(minutes: float) -> str:
    """Describe a rule window: ``10 minutes``, ``1 minute``, ``1.5 minutes``."""
    return f"{minutes:g} minute{'' if minutes == 1 else 's'}"
