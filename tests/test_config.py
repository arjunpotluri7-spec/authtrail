from datetime import UTC, datetime

import pytest
from conftest import EXAMPLE_CONFIG

from authtrail.config import Config, config_from_dict, load_config
from authtrail.errors import ConfigError
from authtrail.models import Severity


def test_example_config_is_valid():
    config = load_config(EXAMPLE_CONFIG)
    assert config.business_hours.tz_name == "America/New_York"
    assert "deploy" in config.privileged_users
    assert len(config.ip_locations) == 3
    assert config.rule_overrides["success-after-failures"].severity == Severity.HIGH
    assert config.locate("10.40.7.9").name == "Singapore office"
    assert config.locate("10.0.0.5").name == "New York datacenter"
    assert config.locate("203.0.113.45") is None


def test_empty_file_gives_defaults(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("")
    config = load_config(path)
    assert config.privileged_users == Config().privileged_users
    assert config.source == str(path)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"colour": 1}, "unknown key"),
        ({"version": 2}, "unsupported config version"),
        ({"syslog_timezone": "Nowhere/City"}, "'syslog_timezone': unknown time zone"),
        ({"business_hours": {"start": 480}}, "quoted time"),
        ({"business_hours": {"start": "25:00"}}, "'business_hours.start'"),
        ({"business_hours": {"start": "09:00", "end": "09:00"}}, "must differ"),
        ({"business_hours": {"days": ["funday"]}}, "unknown day"),
        ({"privileged_users": "root"}, "expected a list"),
        ({"ip_locations": {"not-a-cidr": {"name": "x", "lat": 1, "lon": 1}}}, "expected a CIDR"),
        ({"ip_locations": {"10.0.0.0/8": {"name": "x", "lat": 91, "lon": 1}}}, ".lat'"),
        ({"ip_locations": {"10.0.0.0/8": {"lat": 1, "lon": 1}}}, ".name': missing"),
        ({"stories": {"gap_minutes": 0}}, "'stories.gap_minutes'"),
        ({"evidence": {"max_per_alert": "5"}}, "expected an integer"),
        ({"rules": {"brute-force": {"severity": "urgent"}}}, "unknown severity"),
        ({"rules": {"brute-force": {"enabled": "yes"}}}, "expected true or false"),
        ({"rules": {"brute-force": {"colour": 1}}}, "unknown key"),
        ([1, 2], "top level"),
    ],
)
def test_validation_errors_name_file_and_key(data, message):
    with pytest.raises(ConfigError, match=message) as info:
        config_from_dict(data, "my.yaml")
    assert str(info.value).startswith("my.yaml")


def test_invalid_yaml_and_missing_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("business_hours: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML at line"):
        load_config(bad)
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_business_hours_contains_and_overnight_wrap():
    day = config_from_dict({"business_hours": {"timezone": "UTC"}}, "c").business_hours
    assert day.contains(datetime(2026, 10, 14, 9, 0, tzinfo=UTC))  # Wednesday
    assert not day.contains(datetime(2026, 10, 14, 18, 0, tzinfo=UTC))  # end is exclusive
    assert not day.contains(datetime(2026, 10, 17, 10, 0, tzinfo=UTC))  # Saturday
    night = config_from_dict(
        {"business_hours": {"start": "22:00", "end": "06:00", "days": ["mon"]}}, "c"
    ).business_hours
    assert night.contains(datetime(2026, 10, 12, 23, 0, tzinfo=UTC))  # Monday night
    assert night.contains(datetime(2026, 10, 13, 5, 0, tzinfo=UTC))  # Tuesday early, Monday shift
    assert not night.contains(datetime(2026, 10, 13, 23, 0, tzinfo=UTC))  # Tuesday night
    assert day.describe() == "Mon-Fri 08:00-18:00 UTC"
