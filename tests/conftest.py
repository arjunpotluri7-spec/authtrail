"""Shared test helpers."""

from datetime import datetime
from pathlib import Path

import pytest

from authtrail.models import FAILURE, LOGIN, AuthEvent, EvidenceRef, Severity, Technique
from authtrail.rules import RULE_TYPES, Rule
from authtrail.timeutil import parse_timestamp

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"
EXAMPLE_CONFIG = REPO / "config.example.yaml"


def ts(text: str) -> datetime:
    """``ts("2026-10-14T02:00:00Z")`` -> aware UTC datetime."""
    return parse_timestamp(text)


_counter = {"line": 0}


def make_event(
    when: str,
    *,
    user: str | None = "bob",
    ip: str | None = "203.0.113.45",
    outcome: str = FAILURE,
    event_type: str = LOGIN,
    method: str | None = "password",
    host: str | None = "web-01",
    source_format: str = "linux",
    detail: str | None = None,
) -> AuthEvent:
    """Build an AuthEvent with a unique evidence line."""
    _counter["line"] += 1
    line = _counter["line"]
    return AuthEvent(
        timestamp=ts(when),
        source_format=source_format,
        event_type=event_type,
        outcome=outcome,
        evidence=EvidenceRef("test.log", line, f"synthetic line {line}"),
        host=host,
        user=user,
        src_ip=ip,
        method=method,
        detail=detail,
    )


def make_rule(rule_type: str, severity: str = "medium", **params: object) -> Rule:
    """A rule of ``rule_type`` with defaults overridden by ``params``."""
    merged = {name: spec.default for name, spec in RULE_TYPES[rule_type].items()}
    merged.update(params)
    return Rule(
        id=rule_type.replace("_", "-"),
        title=f"test {rule_type}",
        type=rule_type,
        severity=Severity.parse(severity),
        techniques=(Technique("T1110", "Brute Force"),),
        description="test rule",
        params=merged,
    )


@pytest.fixture
def sample_paths() -> list[Path]:
    return [
        SAMPLES / "linux_auth.log",
        SAMPLES / "macos_unified.ndjson",
        SAMPLES / "windows_security.json",
    ]
