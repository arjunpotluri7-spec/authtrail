"""Markdown incident report, suitable for a ticket, wiki page, or portfolio write-up."""

from authtrail.analyzer import Report
from authtrail.models import SEVERITY_NAMES, Severity
from authtrail.timeutil import fmt_duration, fmt_human


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    return "`" + text.replace("`", "'") + "`"


def render_markdown(report: Report) -> str:
    """Render the incident-report document."""
    lines: list[str] = []
    add = lines.append
    add("# Authentication incident report")
    add("")
    add(
        f"Produced by Authtrail {report.version} on {fmt_human(report.generated_at)} from "
        f"{len(report.inputs)} log file(s) and {report.events_analyzed} authentication events."
    )
    if report.first_event and report.last_event:
        add(f"Data covers {fmt_human(report.first_event)} to {fmt_human(report.last_event)}.")
    add("")
    add("## Executive summary")
    add("")
    if not report.alerts:
        add("No detection rules fired on the analyzed data.")
    else:
        by_sev = []
        for name in reversed(SEVERITY_NAMES):
            level = Severity.parse(name)
            count = sum(1 for s in report.stories if s.severity == level)
            if count:
                by_sev.append(f"{count} {name}")
        if report.stories_enabled:
            add(
                f"- **{len(report.stories)} attack stories** ({', '.join(by_sev)}) built from "
                f"**{len(report.alerts)} alerts**."
            )
        else:
            add(f"- **{len(report.alerts)} alerts** (story correlation disabled).")
        escalated = [s for s in report.stories if s.escalation]
        if escalated:
            noun = "story was" if len(escalated) == 1 else "stories were"
            add(f"- {len(escalated)} {noun} escalated because of how their alerts combine.")
        add("")
    if report.stories:
        add("| Story | Severity | What happened | Window (UTC) |")
        add("|---|---|---|---|")
        for story in report.stories:
            add(
                f"| [{story.id}](#{story.id.lower()}) | **{story.severity.label}** | "
                f"{_cell(story.title)} | {story.first_seen:%Y-%m-%d %H:%M} - "
                f"{story.last_seen:%H:%M} |"
            )
        add("")

    for story in report.stories:
        add(f'<a id="{story.id.lower()}"></a>')
        add("")
        add(f"## {story.id}: {story.title}")
        add("")
        severity = f"**{story.severity.label}**"
        if story.escalation:
            severity += f" (escalated from {story.base_severity.label}: {story.escalation})"
        span = (story.last_seen - story.first_seen).total_seconds()
        add(f"- **Severity:** {severity}")
        add(
            f"- **Window:** {fmt_human(story.first_seen)} to {fmt_human(story.last_seen)} "
            f"({fmt_duration(span)})"
        )
        add(f"- **Accounts:** {', '.join(_code(u) for u in story.users) or 'none'}")
        add(f"- **Source addresses:** {', '.join(_code(i) for i in story.ips) or 'none'}")
        add(f"- **Hosts:** {', '.join(_code(h) for h in story.hosts) or 'unknown'}")
        add(
            "- **ATT&CK:** "
            + ", ".join(
                f"[{t.id}](https://attack.mitre.org/techniques/{t.id.replace('.', '/')}/) {t.name}"
                for t in story.techniques
            )
        )
        add("")
        add("### Timeline")
        add("")
        add("| Time (UTC) | Technique | What happened | Alert |")
        add("|---|---|---|---|")
        for step in story.steps:
            add(
                f"| {step.time:%Y-%m-%d %H:%M:%S} | {', '.join(t.id for t in step.techniques)} | "
                f"{_cell(step.narrative)} | {step.alert_id} |"
            )
        add("")
        add("### Evidence")
        add("")
        for step in story.steps:
            hidden = step.evidence_total - len(step.evidence)
            note = f" (showing {len(step.evidence)} of {step.evidence_total})" if hidden else ""
            add(f"{step.alert_id}{note}:")
            add("")
            add("```text")
            for ref in step.evidence:
                add(f"{ref.location}  {ref.raw}")
            add("```")
            add("")
        add("### Recommended next steps")
        add("")
        for action in story.actions:
            add(f"- [ ] {action}")
        add("")

    if report.alerts:
        add("## All alerts")
        add("")
        add("| ID | Severity | Rule | Entity | First seen (UTC) | Count | Why it fired |")
        add("|---|---|---|---|---|---|---|")
        for alert in report.alerts:
            add(
                f"| {alert.id} | {alert.severity.label} | {_code(alert.rule_id)} | "
                f"{_cell(alert.entity)} | {alert.first_seen:%Y-%m-%d %H:%M:%S} | {alert.count} | "
                f"{_cell(alert.reason)} |"
            )
        add("")
    add("## Inputs")
    add("")
    add("| File | Format | Events | Skipped | Unparseable |")
    add("|---|---|---|---|---|")
    for item in report.inputs:
        add(
            f"| {_code(item.path)} | {item.format} | {item.events} | {item.skipped} | "
            f"{item.unparseable} |"
        )
    add("")
    add("## Method")
    add("")
    add(
        "Alerts come from deterministic, threshold-based rules (listed with "
        "`authtrail rules list`). Alerts that share an account or source address and occur "
        "within the configured gap of each other are merged into one story. Narratives and "
        "next steps are built from templates using the numbers in each alert; every "
        "step links back to the exact log lines that support it."
    )
    add("")
    add(f"Rules enabled: {', '.join(_code(r.id) for r in report.rules)}.")
    add("")
    return "\n".join(lines)
