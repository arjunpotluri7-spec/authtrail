import json
import os
import stat

import pytest
from conftest import EXAMPLE_CONFIG

from authtrail import __version__
from authtrail.cli import main

LINUX_SPRAY = "\n".join(
    [
        f"Oct 14 02:{i:02d}:00 web-01 sshd[1]: Failed password for invalid user {u} from "
        f"203.0.113.45 port {5000 + i} ssh2"
        for i, u in enumerate(["admin", "test", "oracle", "guest", "ubuntu", "bob"])
    ]
    + ["Oct 14 02:14:09 web-01 sshd[2]: Accepted password for bob from 203.0.113.45 port 1 ssh2"]
)
QUIET = "Oct 14 13:02:11 web-01 sshd[1]: Accepted publickey for alice from 10.0.0.21 port 1 ssh2\n"


@pytest.fixture
def spray_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(LINUX_SPRAY + "\n")
    return path


@pytest.fixture
def quiet_log(tmp_path):
    path = tmp_path / "quiet.log"
    path.write_text(QUIET)
    return path


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_version_and_help(capsys):
    code, out, _ = run(capsys, "--version")
    assert code == 0 and __version__ in out
    code, out, _ = run(capsys, "analyze", "--help")
    assert code == 0 and "--fail-on" in out and "exit codes" in out


def test_exit_0_when_no_findings(capsys, quiet_log):
    code, out, _ = run(capsys, "analyze", quiet_log, "--year", "2026")
    assert code == 0
    assert "No alerts." in out


def test_exit_1_with_findings_and_fail_on_threshold(capsys, spray_log):
    code, out, _ = run(capsys, "analyze", spray_log, "--year", "2026")
    assert code == 1
    assert (
        "[S-001] CRITICAL  Password spray from 203.0.113.45 led to a successful login as bob" in out
    )
    code, _, _ = run(capsys, "analyze", spray_log, "--year", "2026", "--fail-on", "none")
    assert code == 0
    code, _, _ = run(
        capsys, "analyze", spray_log, "--year", "2026", "--no-stories", "--fail-on", "critical"
    )
    assert code == 0  # without stories nothing escalates to critical
    code, _, _ = run(capsys, "analyze", spray_log, "--year", "2026", "--fail-on", "critical")
    assert code == 1


def test_exit_2_on_usage_input_and_config_errors(capsys, tmp_path, spray_log):
    code, _, err = run(capsys, "analyze", tmp_path / "missing.log")
    assert code == 2 and "authtrail: error:" in err and "no such file" in err
    assert "Traceback" not in err
    code, _, _ = run(capsys, "analyze")
    assert code == 2
    code, _, err = run(capsys, "analyze", spray_log, "--since", "last tuesday")
    assert code == 2 and "invalid timestamp" in err
    bad = tmp_path / "bad.yaml"
    bad.write_text("business_hours:\n  start: 8am\n")
    code, _, err = run(capsys, "analyze", spray_log, "--config", bad)
    assert code == 2 and "'business_hours.start'" in err
    code, _, err = run(capsys, "analyze", tmp_path, "--year", "2026")
    assert code == 2 and "is a directory" in err


def test_json_schema(capsys, spray_log):
    code, out, _ = run(capsys, "analyze", spray_log, "--year", "2026", "--format", "json")
    assert code == 1
    doc = json.loads(out)
    assert set(doc) == {
        "schema_version",
        "tool",
        "generated_at",
        "inputs",
        "filters",
        "summary",
        "stories",
        "alerts",
    }
    assert doc["schema_version"] == "1.0"
    assert set(doc["summary"]) >= {
        "events_analyzed",
        "alerts",
        "stories",
        "alerts_by_severity",
        "stories_by_severity",
        "max_severity",
        "rules_enabled",
    }
    assert doc["summary"]["max_severity"] == "critical"
    alert = doc["alerts"][0]
    assert set(alert) == {
        "id",
        "rule_id",
        "rule_type",
        "title",
        "severity",
        "techniques",
        "entity",
        "first_seen",
        "last_seen",
        "count",
        "reason",
        "details",
        "evidence",
        "evidence_total",
        "evidence_truncated",
    }
    assert set(alert["evidence"][0]) == {"ref", "file", "line", "raw"}
    story = doc["stories"][0]
    assert set(story) == {
        "id",
        "title",
        "severity",
        "base_severity",
        "escalation",
        "first_seen",
        "last_seen",
        "users",
        "ips",
        "hosts",
        "alert_ids",
        "techniques",
        "timeline",
        "next_actions",
    }
    assert set(story["timeline"][0]) == {
        "time",
        "alert_id",
        "severity",
        "techniques",
        "narrative",
        "evidence",
        "evidence_total",
    }


def test_output_file_permissions_and_overwrite_refusal(capsys, tmp_path, spray_log):
    target = tmp_path / "report.md"
    code, out, err = run(
        capsys, "analyze", spray_log, "--year", "2026", "--format", "markdown", "-o", target
    )
    assert code == 1 and out == "" and "wrote markdown report" in err
    text = target.read_text()
    assert text.startswith("# Authentication incident report")
    assert "## S-001: Password spray from 203.0.113.45 led to a successful login as bob" in text
    assert "### Recommended next steps" in text and "- [ ] " in text
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    code, _, err = run(capsys, "analyze", spray_log, "--year", "2026", "-o", target)
    assert code == 2 and "already exists" in err
    assert target.read_text() == text
    code, _, _ = run(capsys, "analyze", spray_log, "--year", "2026", "-o", target, "--force")
    assert code == 1 and target.read_text().startswith("Authtrail")


def test_refuses_to_write_over_an_input(capsys, spray_log):
    before = spray_log.read_text()
    code, _, err = run(capsys, "analyze", spray_log, "-o", spray_log, "--force")
    assert code == 2 and "also an input" in err
    assert spray_log.read_text() == before


def test_since_until_filter(capsys, spray_log):
    code, out, _ = run(
        capsys,
        "analyze",
        spray_log,
        "--year",
        "2026",
        "--since",
        "2026-10-14T02:10:00Z",
        "--format",
        "json",
    )
    assert code == 0
    assert json.loads(out)["summary"]["events_analyzed"] == 1
    code, _, err = run(
        capsys,
        "analyze",
        spray_log,
        "--since",
        "2026-10-15T00:00:00Z",
        "--until",
        "2026-10-14T00:00:00Z",
    )
    assert code == 2 and "later than" in err


def test_json_logs_on_stderr(capsys, spray_log):
    code, out, err = run(
        capsys,
        "analyze",
        spray_log,
        "--year",
        "2026",
        "--log-level",
        "INFO",
        "--log-format",
        "json",
        "--format",
        "json",
    )
    assert code == 1
    json.loads(out)
    records = [json.loads(line) for line in err.splitlines()]
    assert any(r.get("event") == "file_parsed" and r["events"] == 7 for r in records)
    assert all(r["level"] in {"info", "warning"} for r in records)


def test_rules_list_and_show(capsys):
    code, out, _ = run(capsys, "rules", "list")
    assert code == 0 and "password-spray" in out and "T1110.003" in out
    code, out, _ = run(capsys, "rules", "show", "impossible-travel")
    assert code == 0 and "max_speed_kmh = 900" in out
    code, out, _ = run(capsys, "rules", "show", "brute-force", "--config", EXAMPLE_CONFIG)
    assert code == 0 and "threshold = 5" in out
    code, _, err = run(capsys, "rules", "show", "nope")
    assert code == 2 and "unknown rule id" in err


def test_validate_config(capsys, tmp_path):
    code, out, _ = run(capsys, "validate-config", EXAMPLE_CONFIG)
    assert code == 0 and out.startswith("OK:") and "3 ip_locations" in out
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  not-a-rule:\n    enabled: false\n")
    code, _, err = run(capsys, "validate-config", bad)
    assert code == 2 and "'rules.not-a-rule': unknown rule id" in err
