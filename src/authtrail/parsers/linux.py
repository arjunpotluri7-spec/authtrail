"""Linux ``auth.log`` / ``secure`` syslog parser (BSD syslog, rsyslog ISO, and RFC 5424)."""

import re
from datetime import UTC, datetime, tzinfo

from authtrail.models import AuthEvent
from authtrail.parsers.common import ParseResult, evidence, split_lines
from authtrail.parsers.messages import parse_program_message
from authtrail.timeutil import parse_timestamp

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_BSD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)? "
    r"(?P<host>\S+) (?P<rest>.*)$"
)
_ISO_RE = re.compile(
    r"^(?:<\d{1,3}>1 )?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<rest>.*)$"
)
_TAG_RE = re.compile(r"^(?P<tag>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
_RFC5424_RE = re.compile(
    r"^(?P<tag>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$"
)
# A month going backwards by at least this much means the log crossed New Year.
_ROLLOVER_MONTHS = 6


def looks_like_syslog(line: str) -> bool:
    """True if the line has a recognizable syslog header."""
    return bool(_BSD_RE.match(line) or _ISO_RE.match(line))


def _split_program(rest: str) -> tuple[str, str] | None:
    match = _TAG_RE.match(rest)
    if match:
        return match.group("tag"), match.group("msg")
    match = _RFC5424_RE.match(rest)
    if match:
        return match.group("tag"), match.group("msg").lstrip("\ufeff")
    return None


def parse_linux(text: str, path: str, *, year: int, default_tz: tzinfo = UTC) -> ParseResult:
    """Parse syslog text.

    BSD syslog timestamps have no year: ``year`` is the year of the first line, and the year
    is incremented when the month jumps backwards (for example Dec -> Jan). Timestamps
    without a zone are interpreted in ``default_tz``.
    """
    result = ParseResult(path=path, format="linux")
    current_year = year
    previous_month: int | None = None
    for number, line in enumerate(split_lines(text), start=1):
        if not line.strip():
            continue
        timestamp: datetime | None = None
        host = rest = None
        bsd = _BSD_RE.match(line)
        if bsd:
            month = _MONTHS.get(bsd.group("mon"))
            if month is None:
                result.mark_unparseable(number)
                continue
            if previous_month is not None and previous_month - month >= _ROLLOVER_MONTHS:
                current_year += 1
            previous_month = month
            try:
                naive = datetime.strptime(
                    f"{current_year} {month} {bsd.group('day')} {bsd.group('time')}",
                    "%Y %m %d %H:%M:%S",
                )
            except ValueError:
                result.mark_unparseable(number)
                continue
            timestamp = naive.replace(tzinfo=default_tz).astimezone(UTC)
            host, rest = bsd.group("host"), bsd.group("rest")
        else:
            iso = _ISO_RE.match(line)
            if not iso:
                result.mark_unparseable(number)
                continue
            try:
                timestamp = parse_timestamp(iso.group("ts"), default_tz)
            except ValueError:
                result.mark_unparseable(number)
                continue
            host, rest = iso.group("host"), iso.group("rest")
        program = _split_program(rest)
        if program is None:
            result.mark_unparseable(number)
            continue
        match, repeat = parse_program_message(*program)
        if match is None:
            result.skipped += 1
            continue
        ref = evidence(path, number, line)
        event = AuthEvent(
            timestamp=timestamp,
            source_format="linux",
            event_type=match.event_type,
            outcome=match.outcome,
            evidence=ref,
            host=host if host and host != "-" else None,
            user=match.user,
            src_ip=match.src_ip,
            method=match.method,
            detail=match.detail,
        )
        result.events.extend([event] * repeat)
    return result
