from dataclasses import replace

from conftest import make_event, make_rule

from authtrail.config import Config, config_from_dict
from authtrail.detectors import (
    cap_evidence,
    detect_brute_force,
    detect_impossible_travel,
    detect_lockout_storm,
    detect_new_source_for_user,
    detect_off_hours_privileged,
    detect_password_spray,
    detect_success_after_failures,
    run_rules,
)
from authtrail.models import ACCOUNT_LOCKOUT, OTHER, SUCCESS, SUDO

CONFIG = Config()


def failures(times, **kw):
    return [make_event(f"2026-10-14T{t}Z", **kw) for t in times]


# brute_force -------------------------------------------------------------


def test_brute_force_fires_at_threshold_within_window():
    events = failures(["02:00:00", "02:02:00", "02:04:00", "02:06:00", "02:10:00"])
    alerts = detect_brute_force(
        make_rule("brute_force", threshold=5, window_minutes=10), events, CONFIG
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.count == 5 and alert.users == ("bob",) and alert.ips == ("203.0.113.45",)
    assert "5 failed logins for 'bob' from 203.0.113.45 within 10 minutes (threshold: 5)" in (
        alert.reason
    )


def test_brute_force_below_threshold_or_outside_window():
    rule = make_rule("brute_force", threshold=5, window_minutes=10)
    four = failures(["02:00:00", "02:01:00", "02:02:00", "02:03:00"])
    assert detect_brute_force(rule, four, CONFIG) == []
    spread = failures(["02:00:00", "02:02:00", "02:04:00", "02:06:00", "02:10:01"])
    assert detect_brute_force(rule, spread, CONFIG) == []


def test_brute_force_groups_by_user_and_ip_case_insensitively():
    events = failures(["02:00:00", "02:00:10"], user="Administrator") + failures(
        ["02:00:20", "02:00:30", "02:00:40"], user="administrator"
    )
    events += failures(["02:00:50"], user="administrator", ip="192.0.2.9")
    alerts = detect_brute_force(make_rule("brute_force", threshold=5), events, CONFIG)
    assert len(alerts) == 1 and alerts[0].count == 5


def test_brute_force_separate_bursts():
    events = failures(["01:00:00", "01:00:10", "01:00:20", "03:00:00", "03:00:10", "03:00:20"])
    alerts = detect_brute_force(make_rule("brute_force", threshold=3), events, CONFIG)
    assert [a.count for a in alerts] == [3, 3]


# password_spray -----------------------------------------------------------


def spray(users, start_minute=0):
    return [
        make_event(f"2026-10-14T02:{start_minute + i:02d}:00Z", user=u) for i, u in enumerate(users)
    ]


def test_password_spray_threshold_boundary():
    rule = make_rule("password_spray", min_users=5, window_minutes=30)
    assert detect_password_spray(rule, spray(["a", "b", "c", "d"]), CONFIG) == []
    alerts = detect_password_spray(rule, spray(["a", "b", "c", "d", "e"]), CONFIG)
    assert len(alerts) == 1
    assert alerts[0].facts["distinct_users"] == 5
    assert alerts[0].users == ("a", "b", "c", "d", "e")


def test_password_spray_repeated_user_does_not_count_twice():
    rule = make_rule("password_spray", min_users=3)
    assert detect_password_spray(rule, spray(["a", "a", "b", "b", "a"]), CONFIG) == []


# success_after_failures -----------------------------------------------------


def test_success_after_failures_from_same_ip_any_user():
    events = spray(["a", "b", "c", "d", "bob"])
    events.append(make_event("2026-10-14T02:10:00Z", outcome=SUCCESS))
    rule = make_rule("success_after_failures", "high", min_failures=5, window_minutes=30)
    alerts = detect_success_after_failures(rule, events, CONFIG)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.facts["failures"] == 5 and alert.facts["targeted_users"][-1] == "bob"
    assert alert.evidence[-1] == events[-1].evidence  # the success is always kept
    assert "targeted 5 accounts" in alert.reason


def test_success_after_failures_boundaries():
    rule = make_rule("success_after_failures", min_failures=5, window_minutes=30)
    four = [*spray(["a", "b", "c", "d"]), make_event("2026-10-14T02:10:00Z", outcome=SUCCESS)]
    assert detect_success_after_failures(rule, four, CONFIG) == []
    # The first failure (02:00) is 35 minutes old by the time of the success.
    old = [*spray(["a", "b", "c", "d", "e"]), make_event("2026-10-14T02:35:00Z", outcome=SUCCESS)]
    assert detect_success_after_failures(rule, old, CONFIG) == []


def test_success_after_failures_user_scope_and_no_double_alert():
    rule = make_rule("success_after_failures", min_failures=3, scope="user_and_ip")
    others = spray(["a", "b", "c"])
    success = make_event("2026-10-14T02:05:00Z", outcome=SUCCESS)
    assert detect_success_after_failures(rule, [*others, success], CONFIG) == []
    mine = failures(["02:00:00", "02:01:00", "02:02:00"])
    again = make_event("2026-10-14T02:06:00Z", outcome=SUCCESS)
    alerts = detect_success_after_failures(rule, [*mine, success, again], CONFIG)
    assert len(alerts) == 1


# impossible_travel ----------------------------------------------------------

TRAVEL_CONFIG = config_from_dict(
    {
        "ip_locations": {
            "10.20.0.0/16": {"name": "New York", "lat": 40.7128, "lon": -74.006},
            "10.40.0.0/16": {"name": "Singapore", "lat": 1.3521, "lon": 103.8198},
            "10.30.0.0/16": {"name": "Newark", "lat": 40.7357, "lon": -74.1724},
        }
    },
    "c",
)


def logins(*pairs):
    return [make_event(f"2026-10-14T{t}Z", user="carol", ip=ip, outcome=SUCCESS) for t, ip in pairs]


def test_impossible_travel_fires():
    events = logins(("13:00:00", "10.20.5.14"), ("14:30:00", "10.40.7.9"))
    alerts = detect_impossible_travel(make_rule("impossible_travel"), events, TRAVEL_CONFIG)
    assert len(alerts) == 1
    facts = alerts[0].facts
    assert facts["from_location"] == "New York" and facts["to_location"] == "Singapore"
    assert 15000 < facts["distance_km"] < 15600
    assert facts["speed_kmh"] > 900


def test_impossible_travel_does_not_fire_for_slow_short_or_unknown():
    rule = make_rule("impossible_travel", max_speed_kmh=900, min_distance_km=100)
    slow = logins(("00:00:00", "10.20.5.14"), ("23:59:00", "10.40.7.9"))
    assert detect_impossible_travel(rule, slow, TRAVEL_CONFIG) == []
    near = logins(("13:00:00", "10.20.5.14"), ("13:01:00", "10.30.1.1"))
    assert detect_impossible_travel(rule, near, TRAVEL_CONFIG) == []
    unknown = logins(("13:00:00", "10.20.5.14"), ("13:01:00", "203.0.113.9"))
    assert detect_impossible_travel(rule, unknown, TRAVEL_CONFIG) == []


def test_impossible_travel_same_moment():
    events = logins(("13:00:00", "10.20.5.14"), ("13:00:00", "10.40.7.9"))
    alerts = detect_impossible_travel(make_rule("impossible_travel"), events, TRAVEL_CONFIG)
    assert alerts[0].facts["speed_kmh"] is None
    assert "same moment" in alerts[0].reason


# off_hours_privileged ---------------------------------------------------------

HOURS = config_from_dict(
    {
        "business_hours": {"timezone": "America/New_York", "start": "08:00", "end": "18:00"},
        "privileged_users": ["deploy"],
    },
    "c",
)


def test_off_hours_privileged_groups_login_and_sudo():
    events = [
        make_event(
            "2026-10-14T03:09:58Z",
            user="deploy",
            ip="10.0.0.40",
            outcome=SUCCESS,
            method="publickey",
        ),
        make_event(
            "2026-10-14T03:10:22Z",
            user="deploy",
            ip=None,
            outcome=SUCCESS,
            event_type=SUDO,
            method="sudo",
            detail="/usr/bin/id",
        ),
    ]
    alerts = detect_off_hours_privileged(make_rule("off_hours_privileged"), events, HOURS)
    assert len(alerts) == 1
    assert alerts[0].facts["logins"] == 1 and alerts[0].facts["sudo_commands"] == 1
    assert "23:09" in alerts[0].reason and "America/New_York" in alerts[0].reason


def test_off_hours_privileged_respects_hours_list_and_sudo_flag():
    in_hours = make_event("2026-10-14T16:00:00Z", user="deploy", outcome=SUCCESS)  # 12:00 NY
    other = make_event("2026-10-14T03:00:00Z", user="alice", outcome=SUCCESS)
    failed = make_event("2026-10-14T03:00:00Z", user="deploy")
    rule = make_rule("off_hours_privileged")
    assert detect_off_hours_privileged(rule, [in_hours, other, failed], HOURS) == []
    sudo = make_event("2026-10-14T03:10:00Z", user="deploy", outcome=SUCCESS, event_type=SUDO)
    no_sudo = make_rule("off_hours_privileged", include_sudo=False)
    assert detect_off_hours_privileged(no_sudo, [sudo], HOURS) == []


# new_source_for_user ------------------------------------------------------------


def test_new_source_for_user():
    events = [
        make_event("2026-10-13T15:00:00Z", ip="10.0.0.34", outcome=SUCCESS),
        make_event("2026-10-13T16:00:00Z", ip="10.0.0.99", outcome=SUCCESS),  # same /24
        make_event("2026-10-14T02:14:09Z", ip="203.0.113.45", outcome=SUCCESS),
        make_event("2026-10-14T02:20:00Z", ip="203.0.113.46", outcome=SUCCESS),  # now known
    ]
    alerts = detect_new_source_for_user(make_rule("new_source_for_user"), events, CONFIG)
    assert len(alerts) == 1
    assert alerts[0].facts["network"] == "203.0.113.0/24"
    assert alerts[0].facts["prior_logins"] == 2


def test_new_source_first_login_and_loopback_do_not_fire():
    events = [
        make_event("2026-10-14T01:00:00Z", ip="10.0.0.34", outcome=SUCCESS),
        make_event("2026-10-14T01:05:00Z", ip="127.0.0.1", outcome=SUCCESS),
    ]
    assert detect_new_source_for_user(make_rule("new_source_for_user"), events, CONFIG) == []
    strict = make_rule("new_source_for_user", ipv4_prefix=32)
    events.append(make_event("2026-10-14T01:10:00Z", ip="10.0.0.35", outcome=SUCCESS))
    assert len(detect_new_source_for_user(strict, events, CONFIG)) == 1


# lockout_storm ----------------------------------------------------------------


def lockouts(times, users):
    return [
        make_event(f"2026-10-14T{t}Z", user=u, ip=None, outcome=OTHER, event_type=ACCOUNT_LOCKOUT)
        for t, u in zip(times, users, strict=True)
    ]


def test_lockout_storm_boundary():
    rule = make_rule("lockout_storm", threshold=3, window_minutes=15)
    two = lockouts(["09:25:00", "09:26:00"], ["a", "b"])
    assert detect_lockout_storm(rule, two, CONFIG) == []
    spread = lockouts(["09:00:00", "09:10:00", "09:15:01"], ["a", "b", "c"])
    assert detect_lockout_storm(rule, spread, CONFIG) == []
    three = lockouts(["09:00:00", "09:10:00", "09:15:00"], ["a", "b", "c"])
    alerts = detect_lockout_storm(rule, three, CONFIG)
    assert len(alerts) == 1 and alerts[0].users == ("a", "b", "c") and alerts[0].ips == ()


# shared helpers -----------------------------------------------------------------


def test_cap_evidence_keeps_last_and_dedupes():
    events = failures([f"02:00:{i:02d}" for i in range(10)])
    refs, total = cap_evidence([*events, events[-1]], 3)
    assert total == 10
    assert refs == (events[0].evidence, events[1].evidence, events[-1].evidence)


def test_run_rules_assigns_ids_and_skips_disabled():
    events = failures(["02:00:00", "02:00:10", "02:00:20", "02:00:30", "02:00:40"])
    enabled = make_rule("brute_force")
    alerts = run_rules([enabled], events, CONFIG)
    assert [a.id for a in alerts] == ["A-001"]
    assert run_rules([replace(enabled, enabled=False)], events, CONFIG) == []
