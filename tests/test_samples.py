"""Regression test: the shipped samples must keep telling the same stories."""

import json

from conftest import EXAMPLE_CONFIG

from authtrail.cli import main


def analyze_samples(capsys, sample_paths, *extra):
    argv = [
        "analyze",
        *map(str, sample_paths),
        "--config",
        str(EXAMPLE_CONFIG),
        "--year",
        "2026",
        "--format",
        "json",
        *extra,
    ]
    code = main(argv)
    out, _ = capsys.readouterr()
    return code, json.loads(out)


def test_sample_stories(capsys, sample_paths):
    code, doc = analyze_samples(capsys, sample_paths)
    assert code == 1
    stories = {s["title"]: s for s in doc["stories"]}
    assert [s["severity"] for s in doc["stories"]] == [
        "critical",
        "high",
        "high",
        "medium",
        "medium",
        "low",
    ]
    spray = stories["Password spray from 203.0.113.45 led to a successful login as bob"]
    assert spray["severity"] == "critical" and spray["base_severity"] == "high"
    assert spray["ips"] == ["203.0.113.45"]
    assert {"bob", "admin", "jenkins"} <= set(spray["users"])
    assert any(a.startswith("Reset bob's credentials") for a in spray["next_actions"])
    assert any("203.0.113.0/24" in a for a in spray["next_actions"])
    refs = [r for step in spray["timeline"] for r in step["evidence"]]
    assert "samples/linux_auth.log:46" in " ".join(refs)  # the successful login line
    assert any("macos_unified.ndjson" in r for r in refs)  # cross-source correlation

    lockouts = stories["Password spray from 192.0.2.66 caused 4 account lockouts"]
    assert lockouts["severity"] == "high" and lockouts["base_severity"] == "medium"
    travel = stories["Impossible travel for carol: New York office to Singapore office"]
    assert travel["severity"] == "high"
    brute = stories["Brute force from 198.51.100.23 against root and administrator"]
    assert set(brute["hosts"]) == {"web-01", "DC01.corp.example.com"}
    assert "Off-hours privileged activity by deploy" in stories
    assert "svc-backup logged in from a new source 198.51.100.77" in stories


def test_sample_counts(capsys, sample_paths):
    _, doc = analyze_samples(capsys, sample_paths)
    by_rule = {}
    for alert in doc["alerts"]:
        by_rule[alert["rule_id"]] = by_rule.get(alert["rule_id"], 0) + 1
    assert by_rule == {
        "success-after-failures": 1,
        "password-spray": 2,
        "new-source-for-user": 3,
        "off-hours-privileged": 1,
        "brute-force": 2,
        "lockout-storm": 1,
        "impossible-travel": 1,
    }
    assert [i["unparseable"] for i in doc["inputs"]] == [2, 1, 1]
    assert [i["format"] for i in doc["inputs"]] == ["linux", "macos", "windows"]
    for alert in doc["alerts"]:
        for ref in alert["evidence"]:
            assert ref["raw"]  # every alert points at real lines


def test_samples_are_not_modified(capsys, sample_paths):
    before = [p.read_bytes() for p in sample_paths]
    analyze_samples(capsys, sample_paths)
    assert [p.read_bytes() for p in sample_paths] == before
