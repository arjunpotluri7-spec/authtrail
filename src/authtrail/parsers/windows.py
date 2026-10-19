"""Windows Security event parser for JSON exports (array or NDJSON).

Expected flat fields, as produced by common ``Get-WinEvent`` -> ``ConvertTo-Json`` pipelines
or SIEM exports: ``EventID`` (or ``Id``), ``TimeCreated``, ``TargetUserName``,
``IpAddress``, ``LogonType``, ``Computer``.
"""

from authtrail.models import (
    ACCOUNT_LOCKOUT,
    FAILURE,
    LOGIN,
    OTHER,
    SPECIAL_PRIVILEGES,
    SUCCESS,
    AuthEvent,
)
from authtrail.parsers.common import ParseResult, evidence, iter_json_records, normalize_ip
from authtrail.timeutil import parse_timestamp

LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}
# EventID -> (event_type, outcome)
_EVENT_MAP = {
    4624: (LOGIN, SUCCESS),
    4625: (LOGIN, FAILURE),
    4740: (ACCOUNT_LOCKOUT, OTHER),
    4672: (SPECIAL_PRIVILEGES, SUCCESS),
}


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def _logon_method(value: object) -> str | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return _text(value)
    return LOGON_TYPES.get(number, f"logon_type_{number}")


def parse_windows(text: str, path: str) -> ParseResult:
    """Parse 4624/4625/4740/4672 events; other event IDs are skipped."""
    result = ParseResult(path=path, format="windows")
    for record in iter_json_records(text):
        value = record.value
        if not isinstance(value, dict):
            result.mark_unparseable(record.line)
            continue
        raw_id = value.get("EventID", value.get("Id"))
        try:
            event_id = int(str(raw_id))
        except (TypeError, ValueError):
            result.mark_unparseable(record.line)
            continue
        mapping = _EVENT_MAP.get(event_id)
        if mapping is None:
            result.skipped += 1
            continue
        stamp = value.get("TimeCreated")
        try:
            timestamp = parse_timestamp(str(stamp)) if stamp is not None else None
        except ValueError:
            timestamp = None
        if timestamp is None:
            result.mark_unparseable(record.line)
            continue
        event_type, outcome = mapping
        user = _text(value.get("TargetUserName"))
        if event_id == 4672:
            user = _text(value.get("SubjectUserName")) or user
        detail = None
        if event_id == 4625:
            detail = _text(value.get("SubStatus")) or _text(value.get("Status"))
        elif event_id == 4740:
            caller = _text(value.get("CallerComputerName"))
            detail = f"caller {caller}" if caller else None
        result.events.append(
            AuthEvent(
                timestamp=timestamp,
                source_format="windows",
                event_type=event_type,
                outcome=outcome,
                evidence=evidence(path, record.line, record.raw),
                host=_text(value.get("Computer")),
                user=user,
                src_ip=normalize_ip(value.get("IpAddress")),
                method=_logon_method(value.get("LogonType")) if event_id in (4624, 4625) else None,
                detail=detail,
            )
        )
    return result
