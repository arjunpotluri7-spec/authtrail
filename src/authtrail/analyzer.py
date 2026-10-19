"""Orchestration: parse files -> filter -> detect -> correlate into a Report."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from authtrail import __version__
from authtrail.config import Config
from authtrail.detectors import run_rules
from authtrail.logsetup import get_logger
from authtrail.models import Alert, AuthEvent, Severity, Story
from authtrail.parsers import parse_file
from authtrail.rules import Rule
from authtrail.stories import build_stories

log = get_logger("analyze")


@dataclass(frozen=True, slots=True)
class InputSummary:
    """Per-file parse counters."""

    path: str
    format: str
    events: int
    skipped: int
    unparseable: int


@dataclass(slots=True)
class Report:
    """Everything a renderer needs."""

    inputs: list[InputSummary]
    events_analyzed: int
    first_event: datetime | None
    last_event: datetime | None
    rules: list[Rule]
    alerts: list[Alert]
    stories: list[Story]
    stories_enabled: bool
    since: datetime | None = None
    until: datetime | None = None
    version: str = __version__
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def max_severity(self) -> Severity | None:
        """Highest alert or story severity, or None if nothing fired."""
        levels = [a.severity for a in self.alerts] + [s.severity for s in self.stories]
        return max(levels) if levels else None


def analyze(
    paths: Sequence[Path],
    config: Config,
    rules: Sequence[Rule],
    *,
    year: int,
    format_in: str = "auto",
    since: datetime | None = None,
    until: datetime | None = None,
    stories: bool = True,
) -> Report:
    """Run the full pipeline over ``paths``."""
    events: list[AuthEvent] = []
    inputs = []
    for path in paths:
        result = parse_file(
            path,
            format_in=format_in,
            year=year,
            default_tz=config.syslog_timezone,
            max_bytes=config.max_file_size_bytes,
        )
        log.info(
            "file parsed",
            extra={
                "event": "file_parsed",
                "path": result.path,
                "format": result.format,
                "events": len(result.events),
                "skipped": result.skipped,
                "unparseable": result.unparseable,
            },
        )
        if result.unparseable:
            log.warning(
                "unparseable lines skipped",
                extra={
                    "event": "unparseable_lines",
                    "path": result.path,
                    "count": result.unparseable,
                    "first_lines": result.unparseable_lines,
                },
            )
        inputs.append(
            InputSummary(
                result.path, result.format, len(result.events), result.skipped, result.unparseable
            )
        )
        events.extend(result.events)
    if since is not None:
        events = [e for e in events if e.timestamp >= since]
    if until is not None:
        events = [e for e in events if e.timestamp <= until]
    enabled = [r for r in rules if r.enabled]
    alerts = run_rules(enabled, events, config)
    built = build_stories(alerts, config.story_gap) if stories else []
    log.info(
        "analysis complete",
        extra={
            "event": "analysis_complete",
            "events": len(events),
            "alerts": len(alerts),
            "stories": len(built),
        },
    )
    return Report(
        inputs=inputs,
        events_analyzed=len(events),
        first_event=min((e.timestamp for e in events), default=None),
        last_event=max((e.timestamp for e in events), default=None),
        rules=enabled,
        alerts=alerts,
        stories=built,
        stories_enabled=stories,
        since=since,
        until=until,
    )
