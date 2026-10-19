"""Detection rule types. Each takes a Rule (YAML parameters) and returns explained Alerts."""

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable, Hashable, Sequence
from datetime import timedelta
from itertools import pairwise

from authtrail.config import Config
from authtrail.geo import haversine_km
from authtrail.logsetup import get_logger
from authtrail.models import (
    ACCOUNT_LOCKOUT,
    FAILURE,
    LOGIN,
    SUCCESS,
    SUDO,
    Alert,
    AuthEvent,
    EvidenceRef,
)
from authtrail.rules import Rule
from authtrail.timeutil import fmt_clock, fmt_duration, fmt_iso, fmt_window

log = get_logger("detect")

Detector = Callable[[Rule, Sequence[AuthEvent], Config], list[Alert]]


def cap_evidence(events: Sequence[AuthEvent], cap: int) -> tuple[tuple[EvidenceRef, ...], int]:
    """Deduplicate evidence lines and keep at most ``cap``, always including the last one.

    The last event is usually the most important (for example the successful login).
    """
    seen: set[tuple[str, int]] = set()
    refs: list[EvidenceRef] = []
    for event in events:
        key = (event.evidence.file, event.evidence.line)
        if key not in seen:
            seen.add(key)
            refs.append(event.evidence)
    total = len(refs)
    if total <= cap:
        return tuple(refs), total
    if cap >= 2:
        return (*refs[: cap - 1], refs[-1]), total
    return tuple(refs[:cap]), total


def find_bursts(
    events: Sequence[AuthEvent],
    window: timedelta,
    minimum: int,
    key: Callable[[AuthEvent], Hashable] | None = None,
) -> list[tuple[list[AuthEvent], int]]:
    """Find maximal runs where some sliding window reaches ``minimum``.

    Without ``key`` the window metric is the event count; with ``key`` it is the number of
    distinct keys. Events must be sorted by time. Two events exactly ``window`` apart are in
    the same window. Returns ``(events_in_burst, peak_metric)`` pairs.
    """
    bursts: list[tuple[list[AuthEvent], int]] = []
    counts: Counter[Hashable] = Counter()
    left = 0
    start = end = -1
    peak = 0
    for right, event in enumerate(events):
        if key is not None:
            counts[key(event)] += 1
        while event.timestamp - events[left].timestamp > window:
            if key is not None:
                old = key(events[left])
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
            left += 1
        metric = len(counts) if key is not None else right - left + 1
        if metric < minimum:
            continue
        if start >= 0 and left <= end:
            end = right
            peak = max(peak, metric)
        else:
            if start >= 0:
                bursts.append((list(events[start : end + 1]), peak))
            start, end, peak = left, right, metric
    if start >= 0:
        bursts.append((list(events[start : end + 1]), peak))
    return bursts


def _distinct_users(events: Sequence[AuthEvent]) -> list[str]:
    seen: dict[str, str] = {}
    for event in events:
        if event.user and event.user_key not in seen:
            seen[event.user_key or ""] = event.user
    return list(seen.values())


def _alert(
    rule: Rule,
    events: Sequence[AuthEvent],
    config: Config,
    *,
    users: Sequence[str],
    ips: Sequence[str],
    reason: str,
    facts: dict[str, object],
) -> Alert:
    refs, total = cap_evidence(events, config.evidence_cap)
    return Alert(
        rule_id=rule.id,
        rule_type=rule.type,
        title=rule.title,
        severity=rule.severity,
        techniques=rule.techniques,
        users=tuple(users),
        ips=tuple(dict.fromkeys(ips)),
        hosts=tuple(sorted({e.host for e in events if e.host})),
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        count=len(events),
        reason=reason,
        evidence=refs,
        evidence_total=total,
        facts=facts,
    )


def _logins(events: Sequence[AuthEvent], outcome: str) -> list[AuthEvent]:
    return [e for e in events if e.event_type == LOGIN and e.outcome == outcome]


def _span(events: Sequence[AuthEvent]) -> float:
    return (events[-1].timestamp - events[0].timestamp).total_seconds()


def detect_brute_force(rule: Rule, events: Sequence[AuthEvent], config: Config) -> list[Alert]:
    """>= threshold failures for one user from one IP within the window."""
    threshold = rule.params["threshold"]
    minutes = rule.params["window_minutes"]
    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in _logins(events, FAILURE):
        if event.user_key and event.src_ip:
            groups[(event.user_key, event.src_ip)].append(event)
    alerts = []
    for group in groups.values():
        for burst, peak in find_bursts(group, timedelta(minutes=minutes), threshold):
            user, ip = burst[0].user or "", burst[0].src_ip or ""
            reason = (
                f"{peak} failed logins for '{user}' from {ip} within {fmt_window(minutes)} "
                f"(threshold: {threshold}); {len(burst)} failures in total over "
                f"{fmt_duration(_span(burst))}."
            )
            facts = {
                "user": user,
                "ip": ip,
                "failures": len(burst),
                "peak_in_window": peak,
                "threshold": threshold,
                "window_minutes": minutes,
                "duration_seconds": int(_span(burst)),
                "methods": sorted({e.method for e in burst if e.method}),
                "sources": sorted({e.source_format for e in burst}),
            }
            alerts.append(
                _alert(rule, burst, config, users=[user], ips=[ip], reason=reason, facts=facts)
            )
    return alerts


def detect_password_spray(rule: Rule, events: Sequence[AuthEvent], config: Config) -> list[Alert]:
    """One IP fails against >= min_users distinct users within the window."""
    minimum = rule.params["min_users"]
    minutes = rule.params["window_minutes"]
    groups: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in _logins(events, FAILURE):
        if event.user_key and event.src_ip:
            groups[event.src_ip].append(event)
    alerts = []
    for ip, group in groups.items():
        bursts = find_bursts(group, timedelta(minutes=minutes), minimum, key=lambda e: e.user_key)
        for burst, peak in bursts:
            users = _distinct_users(burst)
            reason = (
                f"{peak} different accounts failed to log in from {ip} within "
                f"{fmt_window(minutes)} (threshold: {minimum}); {len(burst)} failures against "
                f"{len(users)} accounts in total over {fmt_duration(_span(burst))}."
            )
            facts = {
                "ip": ip,
                "users": users,
                "distinct_users": len(users),
                "peak_users_in_window": peak,
                "failures": len(burst),
                "threshold": minimum,
                "window_minutes": minutes,
                "duration_seconds": int(_span(burst)),
                "sources": sorted({e.source_format for e in burst}),
            }
            alerts.append(
                _alert(rule, burst, config, users=users, ips=[ip], reason=reason, facts=facts)
            )
    return alerts


def detect_success_after_failures(
    rule: Rule, events: Sequence[AuthEvent], config: Config
) -> list[Alert]:
    """A success preceded by >= min_failures failures (same IP, or same user+IP)."""
    minimum = rule.params["min_failures"]
    minutes = rule.params["window_minutes"]
    by_user = rule.params["scope"] == "user_and_ip"
    window = timedelta(minutes=minutes)

    def key(event: AuthEvent) -> Hashable:
        return (event.user_key, event.src_ip) if by_user else event.src_ip

    failures: dict[Hashable, list[AuthEvent]] = defaultdict(list)
    for event in _logins(events, FAILURE):
        if event.src_ip and (event.user_key or not by_user):
            failures[key(event)].append(event)
    times = {k: [e.timestamp for e in v] for k, v in failures.items()}
    last_alerted: dict[Hashable, object] = {}
    alerts = []
    for success in _logins(events, SUCCESS):
        if not success.src_ip or not success.user:
            continue
        k = key(success)
        if k not in failures:
            continue
        stamps = times[k]
        low = bisect_left(stamps, success.timestamp - window)
        if k in last_alerted:
            low = max(low, bisect_right(stamps, last_alerted[k]))
        high = bisect_right(stamps, success.timestamp)
        prior = failures[k][low:high]
        if len(prior) < minimum:
            continue
        last_alerted[k] = success.timestamp
        targeted = _distinct_users(prior)
        source_text = (
            "against this account from the same source" if by_user else ("from the same source")
        )
        reason = (
            f"Successful {success.method or 'unknown-method'} login as '{success.user}' from "
            f"{success.src_ip} at {fmt_clock(success.timestamp)} after {len(prior)} failed "
            f"logins {source_text} in the preceding {fmt_window(minutes)} "
            f"(threshold: {minimum})"
        )
        if not by_user and len(targeted) > 1:
            reason += f"; the failures targeted {len(targeted)} accounts"
        facts = {
            "user": success.user,
            "ip": success.src_ip,
            "method": success.method,
            "host": success.host,
            "success_time": fmt_iso(success.timestamp),
            "failures": len(prior),
            "targeted_users": targeted,
            "threshold": minimum,
            "window_minutes": minutes,
            "scope": rule.params["scope"],
        }
        alerts.append(
            _alert(
                rule,
                [*prior, success],
                config,
                users=[success.user],
                ips=[success.src_ip],
                reason=reason + ".",
                facts=facts,
            )
        )
    return alerts


def detect_impossible_travel(
    rule: Rule, events: Sequence[AuthEvent], config: Config
) -> list[Alert]:
    """Consecutive located successes for a user that imply speed > max_speed_kmh."""
    max_speed = rule.params["max_speed_kmh"]
    min_distance = rule.params["min_distance_km"]
    per_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in _logins(events, SUCCESS):
        if event.user_key and config.locate(event.src_ip):
            per_user[event.user_key].append(event)
    alerts = []
    for located in per_user.values():
        for previous, current in pairwise(located):
            here, there = config.locate(previous.src_ip), config.locate(current.src_ip)
            if here is None or there is None or here == there:
                continue
            distance = haversine_km(here.lat, here.lon, there.lat, there.lon)
            if distance < min_distance:
                continue
            elapsed = (current.timestamp - previous.timestamp).total_seconds()
            speed = None if elapsed <= 0 else distance / (elapsed / 3600)
            if speed is not None and speed <= max_speed:
                continue
            speed_text = "at the same moment" if speed is None else f"about {speed:,.0f} km/h"
            reason = (
                f"'{current.user}' logged in from {here.name} ({previous.src_ip}) at "
                f"{fmt_clock(previous.timestamp)} and from {there.name} ({current.src_ip}) at "
                f"{fmt_clock(current.timestamp)}: {distance:,.0f} km in "
                f"{fmt_duration(max(elapsed, 0))}, {speed_text} (limit: {max_speed:,.0f} km/h)."
            )
            facts = {
                "user": current.user,
                "from_ip": previous.src_ip,
                "to_ip": current.src_ip,
                "from_location": here.name,
                "to_location": there.name,
                "distance_km": round(distance),
                "elapsed_seconds": int(max(elapsed, 0)),
                "speed_kmh": None if speed is None else round(speed),
                "max_speed_kmh": max_speed,
            }
            alerts.append(
                _alert(
                    rule,
                    [previous, current],
                    config,
                    users=[current.user or ""],
                    ips=[previous.src_ip or "", current.src_ip or ""],
                    reason=reason,
                    facts=facts,
                )
            )
    return alerts


def _describe_privileged(event: AuthEvent) -> str:
    if event.event_type == SUDO:
        return f"sudo {event.detail or ''}".strip()
    text = f"{event.method or 'unknown-method'} login"
    return f"{text} from {event.src_ip}" if event.src_ip else text


def detect_off_hours_privileged(
    rule: Rule, events: Sequence[AuthEvent], config: Config
) -> list[Alert]:
    """Successful login/sudo by a privileged user outside business hours."""
    privileged = config.privileged_keys
    if not privileged:
        return []
    hours = config.business_hours
    types = {LOGIN, SUDO} if rule.params["include_sudo"] else {LOGIN}
    gap = timedelta(minutes=rule.params["group_minutes"])
    per_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if (
            event.event_type in types
            and event.outcome == SUCCESS
            and event.user_key in privileged
            and not hours.contains(event.timestamp)
        ):
            per_user[event.user_key or ""].append(event)
    alerts = []
    for group_events in per_user.values():
        groups: list[list[AuthEvent]] = []
        for event in group_events:
            if groups and event.timestamp - groups[-1][-1].timestamp <= gap:
                groups[-1].append(event)
            else:
                groups.append([event])
        for group in groups:
            user = group[0].user or ""
            first_local = group[0].timestamp.astimezone(hours.tz)
            last_local = group[-1].timestamp.astimezone(hours.tz)
            logins = sum(1 for e in group if e.event_type == LOGIN)
            sudos = len(group) - logins
            parts = []
            if logins:
                parts.append(f"{logins} login{'s' if logins != 1 else ''}")
            if sudos:
                parts.append(f"{sudos} sudo command{'s' if sudos != 1 else ''}")
            when = f"{first_local:%a %Y-%m-%d %H:%M}"
            if last_local != first_local:
                when += f"-{last_local:%H:%M}"
            reason = (
                f"Privileged account '{user}' had {' and '.join(parts)} at {when} "
                f"{hours.tz_name}, outside business hours ({hours.describe()})."
            )
            facts = {
                "user": user,
                "logins": logins,
                "sudo_commands": sudos,
                "actions": [_describe_privileged(e) for e in group],
                "local_time": f"{first_local:%Y-%m-%d %H:%M}",
                "timezone": hours.tz_name,
                "business_hours": hours.describe(),
            }
            ips = [e.src_ip for e in group if e.src_ip]
            alerts.append(
                _alert(rule, group, config, users=[user], ips=ips, reason=reason, facts=facts)
            )
    return alerts


_LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


def _source_network(ip: str, v4_prefix: int, v6_prefix: int) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip  # host name or other non-IP source: compare literally
    if any(address in net for net in _LOOPBACK if net.version == address.version):
        return None
    prefix = v4_prefix if address.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def detect_new_source_for_user(
    rule: Rule, events: Sequence[AuthEvent], config: Config
) -> list[Alert]:
    """A success from a network not seen earlier for that user."""
    min_prior = rule.params["min_prior_logins"]
    v4, v6 = rule.params["ipv4_prefix"], rule.params["ipv6_prefix"]
    known: dict[str, list[str]] = defaultdict(list)
    prior_count: Counter[str] = Counter()
    alerts = []
    for event in _logins(events, SUCCESS):
        if not event.user_key or not event.src_ip:
            continue
        network = _source_network(event.src_ip, v4, v6)
        if network is None:
            continue
        user_key = event.user_key
        if network not in known[user_key] and prior_count[user_key] >= min_prior:
            shown = ", ".join(known[user_key][:3]) + (" ..." if len(known[user_key]) > 3 else "")
            reason = (
                f"'{event.user}' logged in from {event.src_ip} (network {network}), which was not "
                f"seen in {prior_count[user_key]} earlier successful "
                f"login{'s' if prior_count[user_key] != 1 else ''} for this account "
                f"(known: {shown})."
            )
            facts = {
                "user": event.user,
                "ip": event.src_ip,
                "network": network,
                "known_networks": list(known[user_key]),
                "prior_logins": prior_count[user_key],
                "method": event.method,
            }
            alerts.append(
                _alert(
                    rule,
                    [event],
                    config,
                    users=[event.user or ""],
                    ips=[event.src_ip],
                    reason=reason,
                    facts=facts,
                )
            )
        if network not in known[user_key]:
            known[user_key].append(network)
        prior_count[user_key] += 1
    return alerts


def detect_lockout_storm(rule: Rule, events: Sequence[AuthEvent], config: Config) -> list[Alert]:
    """>= threshold account lockouts within the window."""
    threshold = rule.params["threshold"]
    minutes = rule.params["window_minutes"]
    lockouts = [e for e in events if e.event_type == ACCOUNT_LOCKOUT]
    alerts = []
    for burst, peak in find_bursts(lockouts, timedelta(minutes=minutes), threshold):
        users = _distinct_users(burst)
        reason = (
            f"{peak} account lockouts within {fmt_window(minutes)} (threshold: {threshold}); "
            f"{len(burst)} lockouts affecting {len(users)} accounts over "
            f"{fmt_duration(_span(burst))}."
        )
        facts = {
            "lockouts": len(burst),
            "users": users,
            "peak_in_window": peak,
            "threshold": threshold,
            "window_minutes": minutes,
            "duration_seconds": int(_span(burst)),
        }
        alerts.append(_alert(rule, burst, config, users=users, ips=[], reason=reason, facts=facts))
    return alerts


DETECTORS: dict[str, Detector] = {
    "brute_force": detect_brute_force,
    "password_spray": detect_password_spray,
    "success_after_failures": detect_success_after_failures,
    "impossible_travel": detect_impossible_travel,
    "off_hours_privileged": detect_off_hours_privileged,
    "new_source_for_user": detect_new_source_for_user,
    "lockout_storm": detect_lockout_storm,
}


def run_rules(rules: Sequence[Rule], events: Sequence[AuthEvent], config: Config) -> list[Alert]:
    """Run every enabled rule, then sort alerts by time and assign ids ``A-001``..."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.evidence.file, e.evidence.line))
    alerts: list[Alert] = []
    for rule in rules:
        if not rule.enabled:
            continue
        found = DETECTORS[rule.type](rule, ordered, config)
        log.info(
            "rule evaluated",
            extra={"event": "rule_evaluated", "rule": rule.id, "alerts": len(found)},
        )
        alerts.extend(found)
    alerts.sort(key=lambda a: (a.first_seen, -a.severity, a.rule_id, a.entity))
    for number, alert in enumerate(alerts, start=1):
        alert.id = f"A-{number:03d}"
    return alerts
