"""Log parsers. Each one normalizes a source format into ``AuthEvent`` objects."""

from datetime import UTC, tzinfo
from pathlib import Path

from authtrail.errors import InputError
from authtrail.parsers.common import ParseResult, iter_json_records, read_text, split_lines
from authtrail.parsers.linux import looks_like_syslog, parse_linux
from authtrail.parsers.macos import parse_macos
from authtrail.parsers.windows import parse_windows

FORMATS = ("linux", "macos", "windows")
_DETECT_LINES = 50
_DETECT_RECORDS = 5

__all__ = ["FORMATS", "ParseResult", "detect_format", "parse_file", "parse_text"]


def detect_format(text: str) -> str | None:
    """Guess the format from content; ``None`` if it cannot be determined."""
    stripped = text.lstrip()
    if not stripped:
        return None
    if stripped[0] in "[{":
        for checked, record in enumerate(iter_json_records(text)):
            if checked >= _DETECT_RECORDS:
                break
            if not isinstance(record.value, dict):
                continue
            keys = record.value
            if "EventID" in keys or ("Id" in keys and "TimeCreated" in keys):
                return "windows"
            if "eventMessage" in keys:
                return "macos"
        return None
    seen = 0
    for line in split_lines(text):
        if not line.strip():
            continue
        if looks_like_syslog(line):
            return "linux"
        seen += 1
        if seen >= _DETECT_LINES:
            break
    return None


def parse_text(
    text: str, path: str, fmt: str, *, year: int, default_tz: tzinfo = UTC
) -> ParseResult:
    """Parse already-read text in a known format."""
    if fmt == "linux":
        return parse_linux(text, path, year=year, default_tz=default_tz)
    if fmt == "macos":
        return parse_macos(text, path)
    if fmt == "windows":
        return parse_windows(text, path)
    raise InputError(f"{path}: unknown input format {fmt!r}")


def parse_file(
    path: Path,
    *,
    format_in: str = "auto",
    year: int,
    default_tz: tzinfo = UTC,
    max_bytes: int,
) -> ParseResult:
    """Read and parse one file, auto-detecting the format unless ``format_in`` is given."""
    text = read_text(path, max_bytes)
    label = str(path)
    if not text.strip():
        return ParseResult(path=label, format="empty")
    fmt = format_in
    if fmt == "auto":
        detected = detect_format(text)
        if detected is None:
            raise InputError(
                f"{path}: could not detect the log format; pass --format-in linux|macos|windows"
            )
        fmt = detected
    return parse_text(text, label, fmt, year=year, default_tz=default_tz)
