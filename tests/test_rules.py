import pytest

from authtrail.config import config_from_dict
from authtrail.errors import ConfigError, RuleError
from authtrail.models import Severity
from authtrail.rules import RULE_TYPES, apply_overrides, load_rules, parse_rule

VALID = {
    "id": "root-guessing",
    "title": "Root guessing",
    "type": "brute_force",
    "severity": "high",
    "attack": [{"id": "T1110.001", "name": "Brute Force: Password Guessing"}],
    "description": "Tight brute force rule.",
    "params": {"threshold": 3},
}


def test_builtin_rules_cover_every_type():
    rules = load_rules()
    assert {r.type for r in rules} == set(RULE_TYPES)
    assert len({r.id for r in rules}) == len(rules)
    spray = next(r for r in rules if r.id == "password-spray")
    assert spray.techniques[0].id == "T1110.003"
    assert spray.params == {"min_users": 5, "window_minutes": 30.0}


def test_parse_rule_fills_defaults():
    rule = parse_rule(VALID, "x.yaml")
    assert rule.params == {"threshold": 3, "window_minutes": 10}
    assert rule.severity == Severity.HIGH


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"type": "telepathy"}, "unknown rule type"),
        ({"severity": "urgent"}, "unknown severity"),
        ({"attack": [{"id": "T99", "name": "x"}]}, "ATT&CK id"),
        ({"attack": []}, "non-empty list"),
        ({"params": {"thresh": 3}}, "unknown parameter"),
        ({"params": {"threshold": 1}}, "at least 2"),
        ({"params": {"threshold": 2.5}}, "expected an integer"),
        ({"id": "Bad Id!"}, "'id'"),
        ({"extra": 1}, "unknown key"),
        ({"enabled": "yes"}, "expected true or false"),
    ],
)
def test_parse_rule_errors(change, message):
    with pytest.raises(RuleError, match=message):
        parse_rule({**VALID, **change}, "x.yaml")


def test_missing_required_key():
    data = dict(VALID)
    del data["attack"]
    with pytest.raises(RuleError, match="'attack': missing"):
        parse_rule(data, "x.yaml")


def test_rules_dir_loading_and_duplicates(tmp_path):
    (tmp_path / "root.yaml").write_text(
        "id: root-guessing\ntitle: Root\ntype: brute_force\nseverity: high\n"
        "attack:\n  - {id: T1110.001, name: Guessing}\ndescription: d\nparams: {threshold: 3}\n"
    )
    (tmp_path / "notes.txt").write_text("ignored")
    rules = load_rules(tmp_path)
    assert rules[-1].id == "root-guessing" and rules[-1].source.endswith("root.yaml")
    (tmp_path / "dup.yaml").write_text(
        "id: brute-force\ntitle: Dup\ntype: brute_force\nseverity: low\n"
        "attack:\n  - {id: T1110, name: BF}\ndescription: d\n"
    )
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(tmp_path)
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "nope")


def test_apply_overrides():
    config = config_from_dict(
        {
            "rules": {
                "brute-force": {"severity": "high", "params": {"threshold": 8}},
                "lockout-storm": {"enabled": False},
            }
        },
        "c.yaml",
    )
    rules = {r.id: r for r in apply_overrides(load_rules(), config)}
    assert rules["brute-force"].severity == Severity.HIGH
    assert rules["brute-force"].params["threshold"] == 8
    assert rules["brute-force"].params["window_minutes"] == 10
    assert not rules["lockout-storm"].enabled


@pytest.mark.parametrize(
    ("rules", "message"),
    [
        ({"no-such-rule": {"enabled": False}}, "unknown rule id"),
        ({"brute-force": {"params": {"threshold": 0}}}, "rules.brute-force.params.threshold"),
        ({"success-after-failures": {"params": {"scope": "galaxy"}}}, "expected one of"),
    ],
)
def test_bad_overrides_are_config_errors(rules, message):
    config = config_from_dict({"rules": rules}, "c.yaml")
    with pytest.raises(ConfigError, match=message):
        apply_overrides(load_rules(), config)
