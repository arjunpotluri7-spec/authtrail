"""Plain-text report for terminals: summary counts, then stories, then alerts."""

import textwrap

from authtrail.analyzer import Report
from authtrail.models import SEVERITY_NAMES, Severity
from authtrail.render.common import compact_refs
from authtrail.timeutil import fmt_duration, fmt_human

WIDTH = 100
RAW_LIMIT = 240  # full raw lines are always in --format json
_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def _sev(severity: Severity, color: bool, upper: bool = False, width: int = 0) -> str:
    text = (severity.label.upper() if upper else severity.label).ljust(width)
    return f"{_COLORS[severity]}{text}{_RESET}" if color else text


def _wrap(text: str, indent: str, first: str | None = None) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first if first is not None else indent,
        subsequent_indent=indent,
        break_on_hyphens=False,
    )


def render_table(report: Report, *, color: bool = False) -> str:
    """Render the human-readable report."""
    out: list[str] = []
    total_skipped = sum(i.skipped for i in report.inputs)
    total_bad = sum(i.unparseable for i in report.inputs)
    out.append(f"Authtrail {report.version} report")
    out.append(
        f"Inputs: {len(report.inputs)} file(s), {report.events_analyzed} events analyzed "
        f"({total_skipped} lines skipped as not auth-related, {total_bad} unparseable)"
    )
    for item in report.inputs:
        out.append(
            f"  - {item.path} [{item.format}]: {item.events} events, {item.skipped} skipped, "
            f"{item.unparseable} unparseable"
        )
    if report.first_event and report.last_event:
        out.append(f"Time range: {fmt_human(report.first_event)} -> {fmt_human(report.last_event)}")
    out.append(f"Rules: {len(report.rules)} enabled")
    out.append("")
    out.append("SUMMARY")
    out.append(f"  {'severity':<10}{'stories':>8}{'alerts':>8}")
    for name in reversed(SEVERITY_NAMES):
        level = Severity.parse(name)
        stories = sum(1 for s in report.stories if s.severity == level)
        alerts = sum(1 for a in report.alerts if a.severity == level)
        out.append(f"  {_sev(level, color, width=10)}{stories:>8}{alerts:>8}")
    out.append(f"  {'total':<10}{len(report.stories):>8}{len(report.alerts):>8}")

    if report.stories_enabled:
        out.append("")
        out.append("ATTACK STORIES")
        if not report.stories:
            out.append("  No stories: no alerts fired.")
        for story in report.stories:
            out.append("")
            out.append(f"[{story.id}] {_sev(story.severity, color, upper=True)}  {story.title}")
            span = (story.last_seen - story.first_seen).total_seconds()
            out.append(
                f"  When:      {fmt_human(story.first_seen)} -> {fmt_human(story.last_seen)} "
                f"({fmt_duration(span)})"
            )
            out.append(f"  Users:     {', '.join(story.users) or '-'}")
            out.append(f"  Sources:   {', '.join(story.ips) or '-'}")
            out.append(f"  Hosts:     {', '.join(story.hosts) or '-'}")
            out.append(f"  ATT&CK:    {', '.join(f'{t.id} {t.name}' for t in story.techniques)}")
            if story.escalation:
                out.extend(
                    _wrap(
                        f"{story.base_severity.label} -> {story.severity.label}: "
                        f"{story.escalation}",
                        " " * 13,
                        "  Escalated: ",
                    )
                )
            out.append("  Timeline:")
            for step in story.steps:
                ids = ",".join(t.id for t in step.techniques)
                head = f"    {step.time:%Y-%m-%d %H:%M:%S}  {ids:<15} "
                out.extend(_wrap(step.narrative, " " * len(head), head))
                out.extend(
                    _wrap(
                        compact_refs(step.evidence, step.evidence_total),
                        " " * (len(head) + 10),
                        " " * len(head) + "evidence: ",
                    )
                )
            out.append("  Next steps:")
            for number, action in enumerate(story.actions, start=1):
                out.extend(_wrap(action, "       ", f"    {number}. "))

    out.append("")
    out.append("ALERTS")
    if not report.alerts:
        out.append("  No alerts.")
    else:
        out.append(
            f"  {'ID':<7}{'SEVERITY':<10}{'RULE':<24}{'FIRST SEEN (UTC)':<21}{'COUNT':>6}  ENTITY"
        )
    for alert in report.alerts:
        out.append(
            f"  {alert.id:<7}{_sev(alert.severity, color, width=10)}{alert.rule_id:<24}"
            f"{alert.first_seen:%Y-%m-%d %H:%M:%S}  {alert.count:>6}  {alert.entity}"
        )
        out.extend(_wrap(alert.reason, " " * 14, "         Why: "))
        for ref in alert.evidence:
            # Evidence stays on one line so it can be copied and searched for verbatim.
            raw = ref.raw if len(ref.raw) <= RAW_LIMIT else ref.raw[: RAW_LIMIT - 3] + "..."
            out.append(f"           > {ref.location}  {raw}")
        hidden = alert.evidence_total - len(alert.evidence)
        if hidden > 0:
            out.append(f"           ({hidden} more evidence lines not shown)")
    return "\n".join(out) + "\n"
