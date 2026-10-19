"""Parsers for sshd and sudo message text (shared by the Linux and macOS parsers)."""

import re
from dataclasses import dataclass

from authtrail.models import FAILURE, INVALID_USER, LOGIN, OTHER, SUCCESS, SUDO
from authtrail.parsers.common import normalize_ip

# OpenSSH 9.8+ splits the daemon into sshd, sshd-session and sshd-auth.
SSHD_PROGRAMS = frozenset({"sshd", "sshd-session", "sshd-auth"})
SUDO_PROGRAMS = frozenset({"sudo"})

_IP = r"(?P<ip>[0-9A-Za-z:.%_-]+)"
_FAILED_RE = re.compile(
    rf"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>\S*) from {_IP} port \d+"
)
_ACCEPTED_RE = re.compile(rf"^Accepted (?P<method>[\w-]+) for (?P<user>\S+) from {_IP} port \d+")
_INVALID_RE = re.compile(rf"^Invalid user (?P<user>\S*) from {_IP}")
_REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")
_SUDO_RE = re.compile(r"^\s*(?P<user>[^\s:]+) : (?P<body>.*)$")
_SUDO_TARGET_RE = re.compile(r"(?:^|; )USER=(?P<target>[^;]+?)\s*(?:;|$)")
_SUDO_FAILURE_MARKERS = (
    "incorrect password attempt",
    "NOT in sudoers",
    "authentication failure",
    "command not allowed",
)
MAX_REPEAT = 1000


@dataclass(frozen=True, slots=True)
class MessageMatch:
    """Fields extracted from one log message."""

    event_type: str
    outcome: str
    user: str | None = None
    src_ip: str | None = None
    method: str | None = None
    detail: str | None = None


def unwrap_repeated(message: str) -> tuple[str, int]:
    """Handle rsyslog's ``message repeated N times: [ ... ]`` compression."""
    match = _REPEATED_RE.match(message)
    if not match:
        return message, 1
    return match.group("msg"), max(1, min(int(match.group("n")), MAX_REPEAT))


def parse_sshd_message(message: str) -> MessageMatch | None:
    """Recognize sshd authentication messages; ``None`` if not relevant."""
    match = _FAILED_RE.match(message)
    if match:
        return MessageMatch(
            event_type=LOGIN,
            outcome=FAILURE,
            user=match.group("user") or None,
            src_ip=normalize_ip(match.group("ip")),
            method=match.group("method"),
            detail="invalid user" if match.group("invalid") else None,
        )
    match = _ACCEPTED_RE.match(message)
    if match:
        return MessageMatch(
            event_type=LOGIN,
            outcome=SUCCESS,
            user=match.group("user"),
            src_ip=normalize_ip(match.group("ip")),
            method=match.group("method"),
        )
    match = _INVALID_RE.match(message)
    if match:
        # Logged alongside "Failed ... for invalid user"; kept as context, not counted as a failure.
        return MessageMatch(
            event_type=INVALID_USER,
            outcome=OTHER,
            user=match.group("user") or None,
            src_ip=normalize_ip(match.group("ip")),
        )
    return None


def parse_sudo_message(message: str) -> MessageMatch | None:
    """Recognize ``user : TTY=... ; USER=root ; COMMAND=...`` sudo lines."""
    match = _SUDO_RE.match(message)
    if not match:
        return None
    body = match.group("body")
    index = body.find("COMMAND=")
    if index < 0:
        return None
    command = body[index + len("COMMAND=") :].strip()
    target = _SUDO_TARGET_RE.search(body[:index])
    outcome = FAILURE if any(m in body[:index] for m in _SUDO_FAILURE_MARKERS) else SUCCESS
    detail = command if not target else f"{command} (as {target.group('target').strip()})"
    return MessageMatch(
        event_type=SUDO, outcome=outcome, user=match.group("user"), method="sudo", detail=detail
    )


def parse_program_message(program: str, message: str) -> tuple[MessageMatch | None, int]:
    """Dispatch on the program name; returns (match, repeat count)."""
    message, repeat = unwrap_repeated(message)
    if program in SSHD_PROGRAMS:
        return parse_sshd_message(message), repeat
    if program in SUDO_PROGRAMS:
        return parse_sudo_message(message), repeat
    return None, repeat
