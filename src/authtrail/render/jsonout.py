"""Stable JSON output (schema documented in README, ``schema_version`` bumps on change)."""

import json
from typing import Any

from authtrail.analyzer import Report
from authtrail.models import SEVERITY_NAMES, Alert, Story
from authtrail.timeutil import fmt_iso

SCHEMA_VERSION = "1.0"


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """Serialize one alert."""
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_type": alert.rule_type,
        "title": alert.title,
        "severity": alert.severity.label,
        "techniques": [t.to_dict() for t in alert.techniques],
        "entity": {"users": list(alert.users), "ips": list(alert.ips), "hosts": list(alert.hosts)},
        "first_seen": fmt_iso(alert.first_seen),
        "last_seen": fmt_iso(alert.last_seen),
        "count": alert.count,
        "reason": alert.reason,
        "details": alert.facts,
        "evidence": [e.to_dict() for e in alert.evidence],
        "evidence_total": alert.evidence_total,
        "evidence_truncated": alert.evidence_total > len(alert.evidence),
    }


def story_to_dict(story: Story) -> dict[str, Any]:
    """Serialize one story."""
    return {
        "id": story.id,
        "title": story.title,
        "severity": story.severity.label,
        "base_severity": story.base_severity.label,
        "escalation": story.escalation,
        "first_seen": fmt_iso(story.first_seen),
        "last_seen": fmt_iso(story.last_seen),
        "users": list(story.users),
        "ips": list(story.ips),
        "hosts": list(story.hosts),
        "alert_ids": list(story.alert_ids),
        "techniques": [t.to_dict() for t in story.techniques],
        "timeline": [
            {
                "time": fmt_iso(step.time),
                "alert_id": step.alert_id,
                "severity": step.severity.label,
                "techniques": [t.to_dict() for t in step.techniques],
                "narrative": step.narrative,
                "evidence": [e.location for e in step.evidence],
                "evidence_total": step.evidence_total,
            }
            for step in story.steps
        ],
        "next_actions": list(story.actions),
    }


def _counts(items: list[Any]) -> dict[str, int]:
    counts = dict.fromkeys(reversed(SEVERITY_NAMES), 0)
    for item in items:
        counts[item.severity.label] += 1
    return counts


def report_to_dict(report: Report) -> dict[str, Any]:
    """Serialize the whole report."""
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "authtrail", "version": report.version},
        "generated_at": fmt_iso(report.generated_at),
        "inputs": [
            {
                "path": i.path,
                "format": i.format,
                "events": i.events,
                "skipped": i.skipped,
                "unparseable": i.unparseable,
            }
            for i in report.inputs
        ],
        "filters": {
            "since": fmt_iso(report.since) if report.since else None,
            "until": fmt_iso(report.until) if report.until else None,
        },
        "summary": {
            "events_analyzed": report.events_analyzed,
            "first_event": fmt_iso(report.first_event) if report.first_event else None,
            "last_event": fmt_iso(report.last_event) if report.last_event else None,
            "rules_enabled": [r.id for r in report.rules],
            "alerts": len(report.alerts),
            "stories": len(report.stories),
            "stories_enabled": report.stories_enabled,
            "alerts_by_severity": _counts(report.alerts),
            "stories_by_severity": _counts(report.stories),
            "max_severity": report.max_severity.label if report.max_severity else None,
        },
        "stories": [story_to_dict(s) for s in report.stories],
        "alerts": [alert_to_dict(a) for a in report.alerts],
    }


def render_json(report: Report) -> str:
    """Pretty-printed JSON document."""
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"
