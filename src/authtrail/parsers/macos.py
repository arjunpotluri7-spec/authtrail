"""macOS unified log parser for ``log show --style ndjson`` (or ``--style json``) exports."""

from pathlib import PurePosixPath

from authtrail.models import AuthEvent
from authtrail.parsers.common import ParseResult, evidence, iter_json_records
from authtrail.parsers.messages import parse_program_message
from authtrail.timeutil import parse_timestamp


def parse_macos(text: str, path: str) -> ParseResult:
    """Parse sshd and sudo authentication messages from ``eventMessage`` fields.

    Records without an ``eventMessage`` (for example trailing summary objects) are skipped.
    """
    result = ParseResult(path=path, format="macos")
    for record in iter_json_records(text):
        value = record.value
        if not isinstance(value, dict):
            result.mark_unparseable(record.line)
            continue
        message = value.get("eventMessage")
        if message is None:
            result.skipped += 1
            continue
        stamp = value.get("timestamp")
        if not isinstance(message, str) or not isinstance(stamp, str):
            result.mark_unparseable(record.line)
            continue
        try:
            timestamp = parse_timestamp(stamp)
        except ValueError:
            result.mark_unparseable(record.line)
            continue
        image = value.get("processImagePath") or value.get("process") or ""
        program = PurePosixPath(str(image)).name
        match, repeat = parse_program_message(program, message)
        if match is None:
            result.skipped += 1
            continue
        host = value.get("host") or value.get("hostname")
        event = AuthEvent(
            timestamp=timestamp,
            source_format="macos",
            event_type=match.event_type,
            outcome=match.outcome,
            evidence=evidence(path, record.line, record.raw),
            host=str(host) if host else None,
            user=match.user,
            src_ip=match.src_ip,
            method=match.method,
            detail=match.detail,
        )
        result.events.extend([event] * repeat)
    return result
