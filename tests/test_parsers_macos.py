import json

from authtrail.models import FAILURE, SUCCESS, SUDO
from authtrail.parsers.macos import parse_macos


def record(message, image="/usr/sbin/sshd", stamp="2026-10-14 02:17:31.402113+0000", **extra):
    data = {"timestamp": stamp, "processImagePath": image, "eventMessage": message, **extra}
    return json.dumps(data)


def test_ndjson_sshd_and_sudo():
    text = "\n".join(
        [
            record("Failed password for admin from 203.0.113.45 port 53980 ssh2"),
            record(
                "Accepted publickey for alice from 10.0.0.21 port 50877 ssh2",
                image="/usr/libexec/sshd-session",
            ),
            record(
                "   alice : TTY=ttys001 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/true",
                image="/usr/bin/sudo",
            ),
        ]
    )
    result = parse_macos(text, "mac.ndjson")
    failure, success, sudo = result.events
    assert failure.outcome == FAILURE and failure.user == "admin"
    assert failure.source_format == "macos" and failure.host is None
    assert success.outcome == SUCCESS and success.evidence.line == 2
    assert sudo.event_type == SUDO and sudo.user == "alice"


def test_json_array_export_and_hostname_field():
    text = json.dumps(
        [
            {
                "timestamp": "2026-10-14 02:17:31.000000+0000",
                "processImagePath": "/usr/sbin/sshd",
                "eventMessage": "Failed password for bob from 192.0.2.4 port 1 ssh2",
                "hostname": "mac-07",
            }
        ],
        indent=2,
    )
    result = parse_macos(text, "mac.json")
    assert len(result.events) == 1
    assert result.events[0].host == "mac-07"
    assert result.events[0].evidence.line == 2


def test_noise_malformed_and_bad_timestamps():
    text = "\n".join(
        [
            record("Session 100004 created", image="/usr/libexec/securityd"),
            '{"timestamp":"2026-10-14 14:2',
            record("Failed password for bob from 192.0.2.4 port 1 ssh2", stamp="not a time"),
            json.dumps({"count": 3, "finished": 1}),
            "[1, 2]",
        ]
    )
    result = parse_macos(text, "mac.ndjson")
    assert result.events == []
    assert result.skipped == 2  # securityd message + summary record without eventMessage
    assert result.unparseable == 3
    assert result.unparseable_lines == [2, 3, 5]
