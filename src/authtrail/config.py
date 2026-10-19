"""Configuration loading and validation (``config.example.yaml`` documents every key)."""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from datetime import time as dtime
from pathlib import Path
from typing import Any

import yaml

from authtrail.errors import ConfigError
from authtrail.models import Severity
from authtrail.timeutil import load_timezone

WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DEFAULT_PRIVILEGED = ("root", "administrator")
MAX_CONFIG_BYTES = 1_048_576
TOP_LEVEL_KEYS = (
    "version",
    "syslog_timezone",
    "business_hours",
    "privileged_users",
    "ip_locations",
    "stories",
    "evidence",
    "limits",
    "rules",
)

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class BusinessHours:
    """Working hours in a time zone. ``end < start`` means the window wraps past midnight."""

    tz_name: str = "UTC"
    tz: tzinfo = UTC
    start: dtime = dtime(8, 0)
    end: dtime = dtime(18, 0)
    days: frozenset[int] = frozenset(range(5))  # Monday=0

    def contains(self, moment: datetime) -> bool:
        """True if ``moment`` falls inside business hours."""
        local = moment.astimezone(self.tz)
        clock = local.time().replace(tzinfo=None)
        weekday = local.weekday()
        if self.start < self.end:
            return weekday in self.days and self.start <= clock < self.end
        if clock >= self.start:
            return weekday in self.days
        return clock < self.end and (weekday - 1) % 7 in self.days

    def describe(self) -> str:
        """``Mon-Fri 08:00-18:00 America/New_York``."""
        days = sorted(self.days)
        names = [WEEKDAYS[d].capitalize() for d in days]
        if len(days) > 2 and days == list(range(days[0], days[-1] + 1)):
            day_text = f"{names[0]}-{names[-1]}"
        else:
            day_text = ",".join(names) or "no days"
        return f"{day_text} {self.start:%H:%M}-{self.end:%H:%M} {self.tz_name}"


@dataclass(frozen=True, slots=True)
class IpLocation:
    """A user-supplied location for a network (no GeoIP lookups are ever made)."""

    network: IpNetwork
    name: str
    lat: float
    lon: float


@dataclass(frozen=True, slots=True)
class RuleOverride:
    """Per-rule settings from the ``rules:`` section of the config."""

    enabled: bool | None = None
    severity: Severity | None = None
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Config:
    """Validated configuration. ``Config()`` gives safe defaults."""

    source: str = "<defaults>"
    syslog_timezone_name: str = "UTC"
    syslog_timezone: tzinfo = UTC
    business_hours: BusinessHours = field(default_factory=BusinessHours)
    privileged_users: tuple[str, ...] = DEFAULT_PRIVILEGED
    ip_locations: tuple[IpLocation, ...] = ()
    story_gap_minutes: float = 120.0
    evidence_cap: int = 5
    max_file_size_mb: float = 200.0
    rule_overrides: Mapping[str, RuleOverride] = field(default_factory=dict)

    @property
    def story_gap(self) -> timedelta:
        """Maximum time between alerts that may still be correlated into one story."""
        return timedelta(minutes=self.story_gap_minutes)

    @property
    def max_file_size_bytes(self) -> int:
        """Input size limit in bytes."""
        return int(self.max_file_size_mb * 1_048_576)

    @property
    def privileged_keys(self) -> frozenset[str]:
        """Case-folded privileged user names."""
        return frozenset(u.casefold() for u in self.privileged_users)

    def locate(self, ip: str | None) -> IpLocation | None:
        """Most specific configured location containing ``ip``, if any."""
        if not ip or not self.ip_locations:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: IpLocation | None = None
        for location in self.ip_locations:
            if address.version != location.network.version or address not in location.network:
                continue
            if best is None or location.network.prefixlen > best.network.prefixlen:
                best = location
        return best


class _Validator:
    """Raises ConfigError messages that name the file, the key, and what was expected."""

    def __init__(self, source: str) -> None:
        self.source = source

    def fail(self, key: str, message: str) -> ConfigError:
        return ConfigError(f"{self.source}: '{key}': {message}")

    def mapping(self, value: Any, key: str, allowed: tuple[str, ...]) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise self.fail(key, f"expected a mapping, got {type(value).__name__}")
        unknown = sorted(str(k) for k in value if k not in allowed)
        if unknown:
            raise self.fail(
                key, f"unknown key(s) {', '.join(unknown)}; allowed: {', '.join(allowed)}"
            )
        return value

    def number(
        self, value: Any, key: str, *, minimum: float, maximum: float | None = None
    ) -> float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise self.fail(key, f"expected a number, got {value!r}")
        if value < minimum or (maximum is not None and value > maximum):
            bound = (
                f"between {minimum:g} and {maximum:g}"
                if maximum is not None
                else (f"at least {minimum:g}")
            )
            raise self.fail(key, f"expected a number {bound}, got {value!r}")
        return float(value)

    def integer(self, value: Any, key: str, *, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.fail(key, f"expected an integer, got {value!r}")
        if not minimum <= value <= maximum:
            raise self.fail(
                key, f"expected an integer between {minimum} and {maximum}, got {value}"
            )
        return value

    def string(self, value: Any, key: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise self.fail(key, f"expected a non-empty string, got {value!r}")
        return value.strip()

    def timezone(self, value: Any, key: str) -> tuple[str, tzinfo]:
        name = self.string(value, key)
        try:
            return name, load_timezone(name)
        except ValueError as exc:
            raise self.fail(key, str(exc)) from None

    def clock(self, value: Any, key: str) -> dtime:
        if isinstance(value, int) and not isinstance(value, bool):
            raise self.fail(
                key, 'expected a quoted time like "08:00" (YAML reads unquoted HH:MM as a number)'
            )
        text = self.string(value, key)
        try:
            return datetime.strptime(text, "%H:%M").time()
        except ValueError:
            raise self.fail(key, f'expected a time as "HH:MM" (24-hour), got {text!r}') from None


def _business_hours(v: _Validator, raw: Any) -> BusinessHours:
    data = v.mapping(raw, "business_hours", ("timezone", "start", "end", "days"))
    defaults = BusinessHours()
    tz_name, tz = (defaults.tz_name, defaults.tz)
    if "timezone" in data:
        tz_name, tz = v.timezone(data["timezone"], "business_hours.timezone")
    start = v.clock(data["start"], "business_hours.start") if "start" in data else defaults.start
    end = v.clock(data["end"], "business_hours.end") if "end" in data else defaults.end
    if start == end:
        raise v.fail("business_hours", "start and end must differ")
    days = defaults.days
    if "days" in data:
        raw_days = data["days"]
        if not isinstance(raw_days, list) or not raw_days:
            raise v.fail("business_hours.days", "expected a non-empty list such as [mon, tue]")
        parsed = set()
        for item in raw_days:
            name = str(item).strip().lower()[:3]
            if name not in WEEKDAYS:
                raise v.fail(
                    "business_hours.days", f"unknown day {item!r}; use {', '.join(WEEKDAYS)}"
                )
            parsed.add(WEEKDAYS.index(name))
        days = frozenset(parsed)
    return BusinessHours(tz_name=tz_name, tz=tz, start=start, end=end, days=days)


def _privileged(v: _Validator, raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise v.fail("privileged_users", "expected a list of user names")
    return tuple(v.string(item, f"privileged_users[{i}]") for i, item in enumerate(raw))


def _locations(v: _Validator, raw: Any) -> tuple[IpLocation, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise v.fail("ip_locations", "expected a mapping of CIDR -> {name, lat, lon}")
    locations = []
    for cidr, entry in raw.items():
        key = f"ip_locations.{cidr}"
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            raise v.fail(key, "expected a CIDR such as 203.0.113.0/24") from None
        data = v.mapping(entry, key, ("name", "lat", "lon"))
        for required in ("name", "lat", "lon"):
            if required not in data:
                raise v.fail(f"{key}.{required}", "missing required key")
        locations.append(
            IpLocation(
                network=network,
                name=v.string(data["name"], f"{key}.name"),
                lat=v.number(data["lat"], f"{key}.lat", minimum=-90, maximum=90),
                lon=v.number(data["lon"], f"{key}.lon", minimum=-180, maximum=180),
            )
        )
    return tuple(locations)


def _overrides(v: _Validator, raw: Any) -> dict[str, RuleOverride]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise v.fail("rules", "expected a mapping of rule id -> {enabled, severity, params}")
    overrides = {}
    for rule_id, entry in raw.items():
        key = f"rules.{rule_id}"
        data = v.mapping(entry, key, ("enabled", "severity", "params"))
        enabled = data.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise v.fail(f"{key}.enabled", f"expected true or false, got {enabled!r}")
        severity = None
        if "severity" in data:
            try:
                severity = Severity.parse(data["severity"])
            except ValueError as exc:
                raise v.fail(f"{key}.severity", str(exc)) from None
        params = data.get("params") or {}
        if not isinstance(params, dict):
            raise v.fail(f"{key}.params", "expected a mapping of parameter -> value")
        overrides[str(rule_id)] = RuleOverride(enabled=enabled, severity=severity, params=params)
    return overrides


def config_from_dict(data: Any, source: str) -> Config:
    """Validate a parsed YAML document and build a ``Config``."""
    v = _Validator(source)
    if data is None:
        return Config(source=source)
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a YAML mapping at the top level")
    data = v.mapping(data, "<top level>", TOP_LEVEL_KEYS)
    if "version" in data and data["version"] != 1:
        raise v.fail("version", f"unsupported config version {data['version']!r}; expected 1")
    tz_name, tz = ("UTC", UTC)
    if "syslog_timezone" in data:
        tz_name, tz = v.timezone(data["syslog_timezone"], "syslog_timezone")
    stories = v.mapping(data.get("stories"), "stories", ("gap_minutes",))
    evidence = v.mapping(data.get("evidence"), "evidence", ("max_per_alert",))
    limits = v.mapping(data.get("limits"), "limits", ("max_file_size_mb",))
    defaults = Config()
    return Config(
        source=source,
        syslog_timezone_name=tz_name,
        syslog_timezone=tz,
        business_hours=_business_hours(v, data.get("business_hours")),
        privileged_users=(
            _privileged(v, data["privileged_users"])
            if "privileged_users" in data
            else defaults.privileged_users
        ),
        ip_locations=_locations(v, data.get("ip_locations")),
        story_gap_minutes=(
            v.number(stories["gap_minutes"], "stories.gap_minutes", minimum=1, maximum=10080)
            if "gap_minutes" in stories
            else defaults.story_gap_minutes
        ),
        evidence_cap=(
            v.integer(evidence["max_per_alert"], "evidence.max_per_alert", minimum=1, maximum=1000)
            if "max_per_alert" in evidence
            else defaults.evidence_cap
        ),
        max_file_size_mb=(
            v.number(limits["max_file_size_mb"], "limits.max_file_size_mb", minimum=1, maximum=4096)
            if "max_file_size_mb" in limits
            else defaults.max_file_size_mb
        ),
        rule_overrides=_overrides(v, data.get("rules")),
    )


def load_config(path: Path) -> Config:
    """Read and validate a YAML config file (safe loader only)."""
    source = str(path)
    try:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{source}: config file is larger than 1 MB")
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise ConfigError(f"{source}: config file not found") from None
    except IsADirectoryError:
        raise ConfigError(f"{source}: is a directory, expected a YAML file") from None
    except OSError as exc:
        raise ConfigError(f"{source}: cannot read config ({exc.strerror})") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", None) or "syntax error"
        raise ConfigError(f"{source}: invalid YAML{where}: {problem}") from None
    return config_from_dict(data, source)
