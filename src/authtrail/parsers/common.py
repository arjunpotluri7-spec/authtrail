"""Shared parser plumbing: results, file reading, IP normalization, JSON record iteration."""

import codecs
import ipaddress
import json
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from authtrail.errors import InputError
from authtrail.models import AuthEvent, EvidenceRef

MAX_RAW_CHARS = 1000
_MAX_EXAMPLES = 5


@dataclass(slots=True)
class ParseResult:
    """Events and counters for one input file."""

    path: str
    format: str
    events: list[AuthEvent] = field(default_factory=list)
    skipped: int = 0  # well-formed but not authentication-relevant
    unparseable: int = 0  # malformed lines or records
    unparseable_lines: list[int] = field(default_factory=list)

    def mark_unparseable(self, line: int) -> None:
        """Count a malformed line and remember the first few line numbers."""
        self.unparseable += 1
        if len(self.unparseable_lines) < _MAX_EXAMPLES:
            self.unparseable_lines.append(line)


def evidence(path: str, line: int, raw: str) -> EvidenceRef:
    """Build an evidence reference, trimming absurdly long raw lines."""
    raw = raw.rstrip("\r\n")
    if len(raw) > MAX_RAW_CHARS:
        raw = raw[:MAX_RAW_CHARS] + "...[truncated]"
    return EvidenceRef(file=path, line=line, raw=raw)


def normalize_ip(value: object) -> str | None:
    """Return a canonical IP string, ``None`` for empty/placeholder values.

    Non-IP values (for example host names when sshd uses UseDNS) are kept as-is.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "-"):
        return None
    if text.lower().startswith("::ffff:") and "." in text:
        text = text[7:]  # IPv4-mapped IPv6, common in Windows logs
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return text


def read_text(path: Path, max_bytes: int) -> str:
    """Read a log file as text, enforcing a size limit and tolerating bad encodings."""
    try:
        info = path.stat()
    except FileNotFoundError:
        raise InputError(f"{path}: no such file") from None
    except OSError as exc:
        raise InputError(f"{path}: cannot access file ({exc.strerror})") from None
    if stat.S_ISDIR(info.st_mode):
        raise InputError(f"{path}: is a directory; pass log files explicitly")
    if not stat.S_ISREG(info.st_mode):
        raise InputError(f"{path}: not a regular file")
    if info.st_size > max_bytes:
        raise InputError(
            f"{path}: file is {info.st_size / 1_048_576:.1f} MB, over the "
            f"{max_bytes / 1_048_576:g} MB limit (raise limits.max_file_size_mb in the config)"
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path}: cannot read file ({exc.strerror})") from None
    # Windows PowerShell 5.1 redirects/Out-File write UTF-16 with a BOM.
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def split_lines(text: str) -> list[str]:
    """Split on newlines only, so line numbers match what editors show."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line.rstrip("\r") for line in lines]


@dataclass(frozen=True, slots=True)
class JsonRecord:
    """One record from a JSON array or NDJSON file. ``value`` is None when malformed."""

    line: int
    value: Any
    raw: str
    error: str | None = None


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def iter_json_records(text: str) -> Iterator[JsonRecord]:
    """Yield records from a JSON array (``[...]``) or newline-delimited JSON.

    Line numbers point at the line where each record starts.
    """
    start = _skip_ws(text, 0)
    if start < len(text) and text[start] == "[":
        yield from _iter_array(text, start)
    else:
        yield from _iter_ndjson(text)


def _iter_array(text: str, start: int) -> Iterator[JsonRecord]:
    decoder = json.JSONDecoder()
    pos = start + 1
    line = text.count("\n", 0, pos) + 1
    counted = pos
    while True:
        pos = _skip_ws(text, pos)
        if pos >= len(text):
            yield JsonRecord(line, None, "", "unexpected end of JSON array")
            return
        char = text[pos]
        if char == "]":
            return
        if char == ",":
            pos += 1
            continue
        line += text.count("\n", counted, pos)
        counted = pos
        try:
            value, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as exc:
            snippet = text[pos : pos + 200].split("\n", 1)[0]
            yield JsonRecord(line, None, snippet, f"invalid JSON: {exc.msg}")
            return  # cannot resynchronize inside an array
        chunk = text[pos:end]
        raw = chunk if "\n" not in chunk else json.dumps(value, ensure_ascii=False)
        yield JsonRecord(line, value, raw)
        pos = end


def _iter_ndjson(text: str) -> Iterator[JsonRecord]:
    for number, line in enumerate(split_lines(text), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as exc:
            yield JsonRecord(number, None, stripped, f"invalid JSON: {exc.msg}")
            continue
        yield JsonRecord(number, value, stripped)
