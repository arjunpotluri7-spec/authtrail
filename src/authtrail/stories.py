"""Attack stories: correlate related alerts into one narrated, escalated incident."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from authtrail.models import Alert, Severity, Story, StoryStep, Technique
from authtrail.narrative import ATTACK_TYPES, narrate, next_actions, story_title

# (all of these rule types, plus at least one of these) -> at least this severity.
ESCALATIONS: tuple[tuple[frozenset[str], frozenset[str], Severity, str], ...] = (
    (
        frozenset({"success_after_failures"}),
        frozenset(ATTACK_TYPES),
        Severity.CRITICAL,
        "a password attack was followed by a successful login from the attacking source",
    ),
    (
        frozenset({"impossible_travel"}),
        frozenset({"success_after_failures"}),
        Severity.CRITICAL,
        "an account reached through repeated failures also shows impossible travel",
    ),
    (
        frozenset({"lockout_storm"}),
        frozenset(ATTACK_TYPES),
        Severity.HIGH,
        "the password attack also locked accounts out, so it is disrupting real users",
    ),
    (
        frozenset({"off_hours_privileged"}),
        frozenset({"new_source_for_user"}),
        Severity.HIGH,
        "a privileged account was used from a new source outside business hours",
    ),
)


def _keys(alert: Alert) -> set[tuple[str, str]]:
    return {("ip", ip) for ip in alert.ips} | {("user", u.casefold()) for u in alert.users}


def _close(a: Alert, b: Alert, gap: timedelta) -> bool:
    return a.first_seen <= b.last_seen + gap and b.first_seen <= a.last_seen + gap


def correlate(alerts: Sequence[Alert], gap: timedelta) -> list[list[Alert]]:
    """Union-find: alerts sharing a user or IP with time ranges within ``gap`` are merged."""
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    keys = [_keys(a) for a in alerts]
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            if keys[i] & keys[j] and _close(alerts[i], alerts[j], gap):
                parent[find(j)] = find(i)
    groups: dict[int, list[Alert]] = {}
    for index, alert in enumerate(alerts):
        groups.setdefault(find(index), []).append(alert)
    return [sorted(g, key=lambda a: (a.first_seen, a.last_seen, a.id)) for g in groups.values()]


def escalate(alerts: Sequence[Alert]) -> tuple[Severity, Severity, str | None]:
    """Return (final severity, base severity, escalation reason or None)."""
    base = max(a.severity for a in alerts)
    types = {a.rule_type for a in alerts}
    final, reason = base, None
    for required, any_of, target, why in ESCALATIONS:
        if required <= types and types & any_of and target > final:
            final, reason = target, why
    return final, base, reason


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    seen: dict[str, str] = {}
    for value in values:
        seen.setdefault(value.casefold(), value)
    return tuple(seen.values())


def step_time(alert: Alert) -> datetime:
    """When a step "happened": the success itself for success-after-failures, else the start."""
    return alert.last_seen if alert.rule_type == "success_after_failures" else alert.first_seen


def build_stories(alerts: Sequence[Alert], gap: timedelta) -> list[Story]:
    """Correlate alerts and build stories, most severe first (ids ``S-001``...)."""
    stories = []
    for group in correlate(alerts, gap):
        severity, base, reason = escalate(group)
        techniques: dict[str, Technique] = {}
        for alert in group:
            for technique in alert.techniques:
                techniques.setdefault(technique.id, technique)
        ordered = sorted(group, key=lambda a: (step_time(a), a.id))
        steps = tuple(
            StoryStep(
                time=step_time(alert),
                narrative=narrate(alert),
                techniques=alert.techniques,
                severity=alert.severity,
                alert_id=alert.id,
                evidence=alert.evidence,
                evidence_total=alert.evidence_total,
            )
            for alert in ordered
        )
        stories.append(
            Story(
                id="",
                title=story_title(group),
                severity=severity,
                base_severity=base,
                escalation=reason,
                first_seen=min(a.first_seen for a in group),
                last_seen=max(a.last_seen for a in group),
                users=_unique([u for a in group for u in a.users]),
                ips=_unique([ip for a in group for ip in a.ips]),
                hosts=_unique([h for a in group for h in a.hosts]),
                alert_ids=tuple(a.id for a in ordered),
                techniques=tuple(sorted(techniques.values(), key=lambda t: t.id)),
                steps=steps,
                actions=tuple(next_actions(ordered, severity)),
            )
        )
    stories.sort(key=lambda s: (-s.severity, s.first_seen, s.title))
    for number, story in enumerate(stories, start=1):
        story.id = f"S-{number:03d}"
    return stories
