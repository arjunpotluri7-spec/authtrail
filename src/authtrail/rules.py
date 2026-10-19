"""Rule definitions: YAML files parameterize the detection types implemented in Python."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from authtrail.config import Config
from authtrail.errors import ConfigError, RuleError
from authtrail.models import Severity, Technique

RULE_KEYS = (
    "id",
    "title",
    "type",
    "severity",
    "attack",
    "description",
    "params",
    "enabled",
    "references",
)
REQUIRED_KEYS = ("id", "title", "type", "severity", "attack", "description")
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MAX_RULE_BYTES = 262_144


@dataclass(frozen=True, slots=True)
class ParamSpec:
    """Type, default, and bounds for one tunable rule parameter."""

    kind: str  # int | float | bool | choice
    default: Any
    help: str
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()

    def coerce(self, value: Any) -> Any:
        """Validate ``value``; raise ValueError with a readable message."""
        if self.kind == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"expected true or false, got {value!r}")
            return value
        if self.kind == "choice":
            if value not in self.choices:
                raise ValueError(f"expected one of {', '.join(self.choices)}, got {value!r}")
            return value
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"expected a number, got {value!r}")
        if self.kind == "int" and not isinstance(value, int):
            raise ValueError(f"expected an integer, got {value!r}")
        if self.minimum is not None and value < self.minimum:
            raise ValueError(f"must be at least {self.minimum:g}, got {value!r}")
        if self.maximum is not None and value > self.maximum:
            raise ValueError(f"must be at most {self.maximum:g}, got {value!r}")
        return int(value) if self.kind == "int" else float(value)


_WINDOW = ParamSpec("float", 10, "Sliding window length in minutes.", minimum=0.1, maximum=10080)

RULE_TYPES: dict[str, dict[str, ParamSpec]] = {
    "brute_force": {
        "threshold": ParamSpec("int", 5, "Failures for one user from one IP.", minimum=2),
        "window_minutes": _WINDOW,
    },
    "password_spray": {
        "min_users": ParamSpec("int", 5, "Distinct users failing from one IP.", minimum=2),
        "window_minutes": replace(_WINDOW, default=30),
    },
    "success_after_failures": {
        "min_failures": ParamSpec("int", 5, "Failures before the success.", minimum=1),
        "window_minutes": replace(_WINDOW, default=30),
        "scope": ParamSpec(
            "choice",
            "source_ip",
            "source_ip: failures from the same IP against any account; "
            "user_and_ip: failures for the same user from the same IP.",
            choices=("source_ip", "user_and_ip"),
        ),
    },
    "impossible_travel": {
        "max_speed_kmh": ParamSpec("float", 900, "Fastest believable travel speed.", minimum=1),
        "min_distance_km": ParamSpec(
            "float", 100, "Ignore location changes shorter than this.", minimum=0
        ),
    },
    "off_hours_privileged": {
        "include_sudo": ParamSpec("bool", True, "Also flag successful sudo commands."),
        "group_minutes": ParamSpec(
            "float", 60, "Merge events by the same user closer than this.", minimum=0
        ),
    },
    "new_source_for_user": {
        "min_prior_logins": ParamSpec(
            "int", 1, "Earlier successes required before a source counts as new.", minimum=1
        ),
        "ipv4_prefix": ParamSpec(
            "int", 24, "Treat IPv4 sources in the same /N as one source.", minimum=8, maximum=32
        ),
        "ipv6_prefix": ParamSpec(
            "int", 64, "Treat IPv6 sources in the same /N as one source.", minimum=16, maximum=128
        ),
    },
    "lockout_storm": {
        "threshold": ParamSpec("int", 3, "Lockout events (Windows 4740).", minimum=2),
        "window_minutes": replace(_WINDOW, default=15),
    },
}


@dataclass(frozen=True, slots=True)
class Rule:
    """A loaded, validated rule."""

    id: str
    title: str
    type: str
    severity: Severity
    techniques: tuple[Technique, ...]
    description: str
    params: Mapping[str, Any]
    enabled: bool = True
    source: str = "built-in"
    references: tuple[str, ...] = field(default_factory=tuple)


def _fail(source: str, key: str, message: str) -> RuleError:
    return RuleError(f"{source}: '{key}': {message}")


def _coerce_params(rule_type: str, raw: Any, source: str, prefix: str) -> dict[str, Any]:
    specs = RULE_TYPES[rule_type]
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise _fail(source, prefix, "expected a mapping of parameter -> value")
    unknown = sorted(str(k) for k in raw if k not in specs)
    if unknown:
        raise _fail(
            source,
            prefix,
            f"unknown parameter(s) {', '.join(unknown)} for type {rule_type}; "
            f"allowed: {', '.join(specs)}",
        )
    params = {}
    for name, spec in specs.items():
        try:
            params[name] = spec.coerce(raw[name]) if name in raw else spec.default
        except ValueError as exc:
            raise _fail(source, f"{prefix}.{name}", str(exc)) from None
    return params


def parse_rule(data: Any, source: str) -> Rule:
    """Validate one rule document."""
    if not isinstance(data, dict):
        raise RuleError(f"{source}: expected a YAML mapping describing one rule")
    unknown = sorted(str(k) for k in data if k not in RULE_KEYS)
    if unknown:
        raise RuleError(f"{source}: unknown key(s) {', '.join(unknown)}")
    for key in REQUIRED_KEYS:
        if key not in data:
            raise _fail(source, key, "missing required key")
    rule_id = data["id"]
    if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
        raise _fail(source, "id", "expected lower-case letters, digits, '-', '_' or '.'")
    rule_type = data["type"]
    if rule_type not in RULE_TYPES:
        raise _fail(
            source, "type", f"unknown rule type {rule_type!r}; known: {', '.join(RULE_TYPES)}"
        )
    for key in ("title", "description"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise _fail(source, key, "expected a non-empty string")
    try:
        severity = Severity.parse(data["severity"])
    except ValueError as exc:
        raise _fail(source, "severity", str(exc)) from None
    attack = data["attack"]
    if not isinstance(attack, list) or not attack:
        raise _fail(source, "attack", "expected a non-empty list of {id, name}")
    techniques = []
    for index, item in enumerate(attack):
        if not isinstance(item, dict) or set(item) != {"id", "name"}:
            raise _fail(source, f"attack[{index}]", "expected a mapping with keys id and name")
        if not isinstance(item["id"], str) or not _TECHNIQUE_RE.match(item["id"]):
            raise _fail(source, f"attack[{index}].id", "expected an ATT&CK id such as T1110.001")
        if not isinstance(item["name"], str) or not item["name"].strip():
            raise _fail(source, f"attack[{index}].name", "expected a non-empty string")
        techniques.append(Technique(item["id"], item["name"].strip()))
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise _fail(source, "enabled", f"expected true or false, got {enabled!r}")
    references = data.get("references") or []
    if not isinstance(references, list) or not all(isinstance(r, str) for r in references):
        raise _fail(source, "references", "expected a list of strings")
    return Rule(
        id=rule_id,
        title=data["title"].strip(),
        type=rule_type,
        severity=severity,
        techniques=tuple(techniques),
        description=" ".join(data["description"].split()),
        params=_coerce_params(rule_type, data.get("params"), source, "params"),
        enabled=enabled,
        source=source,
        references=tuple(references),
    )


def _load_yaml(text: str, source: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        raise RuleError(f"{source}: invalid YAML{where}") from None


def _builtin_rules() -> list[Rule]:
    folder = resources.files("authtrail").joinpath("rules")
    rules = []
    for entry in sorted(folder.iterdir(), key=lambda item: item.name):
        if entry.name.endswith((".yaml", ".yml")):
            rules.append(
                parse_rule(_load_yaml(entry.read_text(encoding="utf-8"), entry.name), "built-in")
            )
    return rules


def _directory_rules(directory: Path) -> list[Rule]:
    if not directory.is_dir():
        raise RuleError(f"{directory}: rules directory not found")
    rules = []
    for path in sorted(directory.iterdir()):
        if path.suffix not in (".yaml", ".yml") or not path.is_file():
            continue
        if path.stat().st_size > MAX_RULE_BYTES:
            raise RuleError(f"{path}: rule file is larger than 256 KB")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RuleError(f"{path}: cannot read rule ({exc.strerror})") from None
        rules.append(parse_rule(_load_yaml(text, str(path)), str(path)))
    return rules


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Load built-in rules plus any ``*.yaml`` rules from ``rules_dir``. Ids must be unique."""
    rules = _builtin_rules()
    if rules_dir is not None:
        rules.extend(_directory_rules(rules_dir))
    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(
                f"duplicate rule id {rule.id!r} in {rule.source} (already defined in "
                f"{seen[rule.id]}); pick a new id or tune the existing rule in the config"
            )
        seen[rule.id] = rule.source
    return rules


def apply_overrides(rules: list[Rule], config: Config) -> list[Rule]:
    """Apply the config's ``rules:`` section (enable/disable, severity, params)."""
    by_id = {rule.id: rule for rule in rules}
    for rule_id in config.rule_overrides:
        if rule_id not in by_id:
            raise ConfigError(
                f"{config.source}: 'rules.{rule_id}': unknown rule id; known: "
                f"{', '.join(sorted(by_id))}"
            )
    result = []
    for rule in rules:
        override = config.rule_overrides.get(rule.id)
        if override is None:
            result.append(rule)
            continue
        merged = {**rule.params, **override.params}
        try:
            params = _coerce_params(rule.type, merged, config.source, f"rules.{rule.id}.params")
        except RuleError as exc:
            raise ConfigError(str(exc)) from None
        result.append(
            replace(
                rule,
                params=params,
                enabled=rule.enabled if override.enabled is None else override.enabled,
                severity=override.severity or rule.severity,
            )
        )
    return result
