"""Deterministic, template-based narration for story steps, titles, and next actions."""

import ipaddress
from collections.abc import Sequence

from authtrail.models import Alert, Severity
from authtrail.timeutil import fmt_clock, fmt_duration, fmt_window

_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)
ATTACK_TYPES = ("password_spray", "brute_force")


def join_human(items: Sequence[str], limit: int = 5) -> str:
    """``a``, ``a and b``, ``a, b and c``, ``a, b, c and 4 more``."""
    items = list(items)
    if not items:
        return "nobody"
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def _quoted(users: Sequence[str]) -> list[str]:
    return [f"'{u}'" for u in users]


def is_internal(ip: str) -> bool:
    """RFC 1918 / loopback / link-local / ULA. Documentation ranges count as external."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in _INTERNAL_NETS if net.version == address.version)


def edge_block_range(ip: str) -> str | None:
    """The /24 (IPv4) or /64 (IPv6) around an external address, for a block suggestion."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def narrate(alert: Alert) -> str:
    """One plain-language sentence describing what this alert means as a story step."""
    f = alert.facts
    hosts = f" on {join_human(list(alert.hosts))}" if alert.hosts else ""
    match alert.rule_type:
        case "password_spray":
            return (
                f"{f['ip']} tried passwords against {f['distinct_users']} different accounts "
                f"({join_human(_quoted(f['users']))}){hosts}, failing {f['failures']} times over "
                f"{fmt_duration(f['duration_seconds'])}."
            )
        case "brute_force":
            return (
                f"{f['ip']} made {f['failures']} failed login attempts against '{f['user']}'"
                f"{hosts} over {fmt_duration(f['duration_seconds'])} (up to "
                f"{f['peak_in_window']} within {fmt_window(f['window_minutes'])})."
            )
        case "success_after_failures":
            where = f" on {f['host']}" if f.get("host") else ""
            scope = "against this account" if f["scope"] == "user_and_ip" else "from that source"
            return (
                f"{f['ip']} logged in successfully as '{f['user']}'{where} with "
                f"{f['method'] or 'an unknown method'} at {fmt_clock(alert.last_seen)}, "
                f"right after {f['failures']} failed attempts {scope}."
            )
        case "impossible_travel":
            speed = (
                "at the same moment"
                if f["speed_kmh"] is None
                else f"which implies about {f['speed_kmh']:,} km/h"
            )
            return (
                f"'{f['user']}' logged in from {f['from_location']} ({f['from_ip']}) and then "
                f"from {f['to_location']} ({f['to_ip']}) {fmt_duration(f['elapsed_seconds'])} "
                f"later: {f['distance_km']:,} km apart, {speed}."
            )
        case "off_hours_privileged":
            return (
                f"Privileged account '{f['user']}' was used outside business hours "
                f"({f['local_time']} {f['timezone']}): {'; '.join(f['actions'])}."
            )
        case "new_source_for_user":
            return (
                f"'{f['user']}' logged in from {f['ip']}, a network ({f['network']}) not seen "
                f"for this account earlier in the data."
            )
        case "lockout_storm":
            return (
                f"{f['lockouts']} account lockouts hit {join_human(_quoted(f['users']))}{hosts} "
                f"within {fmt_duration(f['duration_seconds'])}."
            )
    return alert.reason


def _first(alerts: Sequence[Alert], rule_type: str) -> Alert | None:
    return next((a for a in alerts if a.rule_type == rule_type), None)


def _attack(alerts: Sequence[Alert]) -> tuple[str, Alert] | None:
    for rule_type, label in (("password_spray", "Password spray"), ("brute_force", "Brute force")):
        found = _first(alerts, rule_type)
        if found:
            return label, found
    return None


def story_title(alerts: Sequence[Alert]) -> str:
    """Pick the most informative title template that matches the story's alert types."""
    attack = _attack(alerts)
    success = _first(alerts, "success_after_failures")
    lockouts = [a for a in alerts if a.rule_type == "lockout_storm"]
    travel = _first(alerts, "impossible_travel")
    if attack and success:
        label, first = attack
        return f"{label} from {first.ips[0]} led to a successful login as {success.users[0]}"
    if success:
        return (
            f"Successful login as {success.users[0]} from {success.ips[0]} after repeated failures"
        )
    if attack and lockouts:
        label, first = attack
        locked = {u.casefold() for a in lockouts for u in a.users}
        return f"{label} from {first.ips[0]} caused {len(locked)} account lockouts"
    if travel:
        f = travel.facts
        return f"Impossible travel for {f['user']}: {f['from_location']} to {f['to_location']}"
    if attack and attack[0] == "Password spray":
        first = attack[1]
        return (
            f"Password spray from {first.ips[0]} against {first.facts['distinct_users']} accounts"
        )
    brutes = [a for a in alerts if a.rule_type == "brute_force"]
    if brutes:
        users = list(dict.fromkeys(u for a in brutes for u in a.users))
        ips = list(dict.fromkeys(ip for a in brutes for ip in a.ips))
        if len(ips) == 1:
            return f"Brute force from {ips[0]} against {join_human(users)}"
        return f"Brute force against {join_human(users)} from {len(ips)} sources"
    if lockouts:
        locked = {u.casefold() for a in lockouts for u in a.users}
        return f"Lockout storm: {len(locked)} accounts locked out"
    off_hours = _first(alerts, "off_hours_privileged")
    if off_hours:
        return f"Off-hours privileged activity by {off_hours.users[0]}"
    new_source = _first(alerts, "new_source_for_user")
    if new_source:
        return f"{new_source.users[0]} logged in from a new source {new_source.ips[0]}"
    return f"{len(alerts)} related alerts: {join_human([a.title for a in alerts])}"


def _block_action(ip: str) -> str:
    if is_internal(ip):
        return (
            f"{ip} is an internal address: find and investigate that host instead of blocking it."
        )
    block = edge_block_range(ip)
    if block and block != f"{ip}/32":
        return f"Consider blocking {block} at the edge (at minimum {ip})."
    return f"Consider blocking {ip} at the edge."


def next_actions(alerts: Sequence[Alert], severity: Severity) -> list[str]:
    """Ordered, de-duplicated defensive next steps for a story."""
    # (priority, text): containment first, then investigation, then hardening.
    actions: list[tuple[int, str]] = []
    success = _first(alerts, "success_after_failures")
    if success and severity >= Severity.CRITICAL:
        actions.append(
            (
                0,
                f"Open an incident and treat '{success.users[0]}' as compromised until proven "
                "otherwise.",
            )
        )
    for alert in alerts:
        f = alert.facts
        match alert.rule_type:
            case "success_after_failures":
                actions.append(
                    (
                        1,
                        f"Reset {f['user']}'s credentials and revoke their active sessions "
                        "and keys.",
                    )
                )
                actions.append(
                    (
                        2,
                        f"Review sessions from {f['ip']} after {alert.last_seen:%H:%M} UTC on "
                        f"{alert.last_seen:%Y-%m-%d} (commands run, sudo use, files changed).",
                    )
                )
                actions.append((3, _block_action(f["ip"])))
            case "password_spray":
                actions.append((3, _block_action(f["ip"])))
                hardening = (
                    "MFA or key-only SSH" if set(f["sources"]) & {"linux", "macos"} else "MFA"
                )
                actions.append(
                    (
                        4,
                        f"Check the {f['distinct_users']} targeted accounts for any successful "
                        f"login from {f['ip']}, and require {hardening} for them.",
                    )
                )
            case "brute_force":
                actions.append((3, _block_action(f["ip"])))
                if f["user"].casefold() == "root" and "linux" in f["sources"]:
                    actions.append((5, "Disable direct root login over SSH (PermitRootLogin no)."))
                else:
                    actions.append(
                        (
                            5,
                            f"Make sure '{f['user']}' has a strong unique password or key-only "
                            "access, and rate-limit authentication (for example fail2ban or an "
                            "account lockout policy).",
                        )
                    )
            case "lockout_storm":
                actions.append(
                    (
                        4,
                        f"Before unlocking {join_human(_quoted(f['users']))}, confirm with each "
                        "user and check that the lockouts are explained by the attack.",
                    )
                )
            case "impossible_travel":
                actions.append(
                    (
                        1,
                        f"Confirm with {f['user']} whether both logins ({f['from_location']} and "
                        f"{f['to_location']}) were theirs; if not, reset credentials and revoke "
                        "sessions.",
                    )
                )
                actions.append(
                    (
                        2,
                        f"Check whether {f['from_ip']} or {f['to_ip']} is a VPN, proxy, or shared "
                        "egress that would explain the jump, and update ip_locations if so.",
                    )
                )
            case "off_hours_privileged":
                actions.append(
                    (
                        2,
                        f"Confirm the activity by '{f['user']}' at {f['local_time']} "
                        f"{f['timezone']} was an approved change or scheduled job.",
                    )
                )
            case "new_source_for_user":
                actions.append(
                    (4, f"Verify that {f['ip']} is an expected source for '{f['user']}'.")
                )
    ordered = sorted(enumerate(actions), key=lambda item: (item[1][0], item[0]))
    return list(dict.fromkeys(text for _, (_, text) in ordered))
