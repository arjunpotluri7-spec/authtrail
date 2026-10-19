from datetime import timedelta

from conftest import make_event, make_rule

from authtrail.config import Config
from authtrail.detectors import run_rules
from authtrail.models import ACCOUNT_LOCKOUT, OTHER, SUCCESS, Severity
from authtrail.narrative import edge_block_range, is_internal, join_human
from authtrail.stories import build_stories, correlate

GAP = timedelta(hours=2)
RULES = [
    make_rule("password_spray", "medium"),
    make_rule("brute_force", "medium"),
    make_rule("success_after_failures", "high"),
    make_rule("lockout_storm", "medium"),
    make_rule("new_source_for_user", "low"),
]


def spray_then_success(ip="203.0.113.45", start_hour=2):
    users = ["admin", "test", "oracle", "guest", "bob", "bob"]
    events = [
        make_event(f"2026-10-14T{start_hour:02d}:{i:02d}:00Z", user=u, ip=ip)
        for i, u in enumerate(users)
    ]
    events.append(make_event(f"2026-10-14T{start_hour:02d}:14:09Z", ip=ip, outcome=SUCCESS))
    return events


def test_spray_followed_by_success_escalates_to_critical():
    alerts = run_rules(RULES, spray_then_success(), Config())
    stories = build_stories(alerts, GAP)
    assert len(stories) == 1
    story = stories[0]
    assert story.severity == Severity.CRITICAL and story.base_severity == Severity.HIGH
    assert story.escalation and "successful login" in story.escalation
    assert story.title == "Password spray from 203.0.113.45 led to a successful login as bob"
    assert story.id == "S-001"
    assert [s.alert_id for s in story.steps] == list(story.alert_ids)
    assert story.steps[0].time <= story.steps[-1].time
    assert story.actions[0].startswith("Open an incident and treat 'bob' as compromised")
    assert any("Consider blocking 203.0.113.0/24" in a for a in story.actions)
    assert any("Reset bob's credentials" in a for a in story.actions)


def test_spray_and_lockouts_merge_by_user_and_escalate_to_high():
    users = ["administrator", "helpdesk", "frank", "erin", "dave"]
    events = [
        make_event(f"2026-10-14T09:{i:02d}:00Z", user=u, ip="192.0.2.66", source_format="windows")
        for i, u in enumerate(users)
    ]
    events += [
        make_event(
            f"2026-10-14T09:1{i}:00Z", user=u, ip=None, outcome=OTHER, event_type=ACCOUNT_LOCKOUT
        )
        for i, u in enumerate(users[:3])
    ]
    stories = build_stories(run_rules(RULES, events, Config()), GAP)
    assert len(stories) == 1
    assert stories[0].severity == Severity.HIGH and stories[0].base_severity == Severity.MEDIUM
    assert stories[0].title == "Password spray from 192.0.2.66 caused 3 account lockouts"
    assert any("require MFA for them" in a for a in stories[0].actions)


def test_alerts_far_apart_or_unrelated_stay_separate():
    events = spray_then_success("203.0.113.45", 2) + spray_then_success("203.0.113.45", 9)
    alerts = run_rules(RULES, events, Config())
    groups = correlate(alerts, GAP)
    assert len(groups) == 2
    other = spray_then_success("198.51.100.7", 2)
    for event in other:
        object.__setattr__(event, "user", "zed" if event.user == "bob" else f"x{event.user}")
    alerts = run_rules(RULES, spray_then_success() + other, Config())
    assert len(correlate(alerts, GAP)) == 2


def test_correlation_is_transitive():
    # A (ip1, user u) -- B (ip2, user u) -- C (ip2, user v): all one story.
    rule = make_rule("brute_force", threshold=2)
    events = [
        make_event("2026-10-14T01:00:00Z", user="u", ip="192.0.2.1"),
        make_event("2026-10-14T01:00:05Z", user="u", ip="192.0.2.1"),
        make_event("2026-10-14T01:30:00Z", user="u", ip="192.0.2.2"),
        make_event("2026-10-14T01:30:05Z", user="u", ip="192.0.2.2"),
        make_event("2026-10-14T02:00:00Z", user="v", ip="192.0.2.2"),
        make_event("2026-10-14T02:00:05Z", user="v", ip="192.0.2.2"),
    ]
    stories = build_stories(run_rules([rule], events, Config()), GAP)
    assert len(stories) == 1
    assert stories[0].title == "Brute force against u and v from 2 sources"


def test_stories_sorted_by_severity():
    events = spray_then_success("203.0.113.45", 9)
    events += [
        make_event(f"2026-10-14T02:00:0{i}Z", user="root", ip="198.51.100.23") for i in range(6)
    ]
    stories = build_stories(run_rules(RULES, events, Config()), GAP)
    assert [s.severity for s in stories] == [Severity.CRITICAL, Severity.MEDIUM]
    assert [s.id for s in stories] == ["S-001", "S-002"]
    assert "Disable direct root login over SSH (PermitRootLogin no)." in stories[1].actions


def test_narrative_helpers():
    assert join_human(["a"]) == "a"
    assert join_human(["a", "b", "c"]) == "a, b and c"
    assert join_human(list("abcdefg"), limit=3) == "a, b, c and 4 more"
    assert is_internal("10.0.0.5") and not is_internal("203.0.113.45")
    assert edge_block_range("2001:db8::1") == "2001:db8::/64"
