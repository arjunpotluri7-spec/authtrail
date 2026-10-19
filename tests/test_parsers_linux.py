from datetime import UTC, datetime

from authtrail.models import FAILURE, INVALID_USER, LOGIN, OTHER, SUCCESS, SUDO
from authtrail.parsers.linux import parse_linux
from authtrail.timeutil import load_timezone


def parse(text, year=2026, **kw):
    return parse_linux(text, "auth.log", year=year, **kw)


def test_failed_and_accepted_logins():
    result = parse(
        "Oct 14 02:09:02 web-01 sshd[4188]: Failed password for bob from 203.0.113.45 "
        "port 52011 ssh2\n"
        "Oct 14 02:14:09 web-01 sshd[4222]: Accepted publickey for bob from 203.0.113.45 "
        "port 53122 ssh2\n"
    )
    failed, accepted = result.events
    assert (failed.event_type, failed.outcome, failed.user, failed.src_ip, failed.method) == (
        LOGIN,
        FAILURE,
        "bob",
        "203.0.113.45",
        "password",
    )
    assert failed.timestamp == datetime(2026, 10, 14, 2, 9, 2, tzinfo=UTC)
    assert failed.host == "web-01"
    assert failed.evidence.location == "auth.log:1"
    assert accepted.outcome == SUCCESS and accepted.method == "publickey"
    assert accepted.evidence.line == 2


def test_invalid_user_lines():
    result = parse(
        "Oct 14 01:58:03 web-01 sshd[1]: Invalid user admin from 203.0.113.45 port 50122\n"
        "Oct 14 01:58:05 web-01 sshd[1]: Failed password for invalid user admin from "
        "203.0.113.45 port 50122 ssh2\n"
    )
    info, failure = result.events
    assert info.event_type == INVALID_USER and info.outcome == OTHER
    assert failure.outcome == FAILURE and failure.user == "admin"
    assert failure.detail == "invalid user"


def test_sudo_success_and_failure():
    result = parse(
        "Oct 14 03:10:22 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart app.service\n"
        "Oct 14 02:16:51 web-01 sudo:      bob : 3 incorrect password attempts ; TTY=pts/2 ; "
        "PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n"
    )
    ok, bad = result.events
    assert ok.event_type == SUDO and ok.outcome == SUCCESS and ok.user == "deploy"
    assert ok.detail == "/usr/bin/systemctl restart app.service (as root)"
    assert bad.outcome == FAILURE and bad.user == "bob"


def test_noise_is_skipped_and_garbage_is_unparseable():
    result = parse(
        "Oct 14 01:17:01 web-01 CRON[4011]: pam_unix(cron:session): session opened for user root\n"
        "\n"
        "Oct 14 04:4\n"
        "@@@@ partial write @@@@\n"
        "Oct 14 04:44:32 web-01 sshd[4625]: Disconnecting authenticating user root 198.51.100.23\n"
    )
    assert result.events == []
    assert result.skipped == 2
    assert result.unparseable == 2
    assert result.unparseable_lines == [3, 4]


def test_message_repeated_expands_events():
    result = parse(
        "Oct 14 04:42:08 web-01 sshd[4618]: message repeated 3 times: "
        "[ Failed password for root from 198.51.100.23 port 41190 ssh2]\n"
    )
    assert len(result.events) == 3
    assert {e.evidence.line for e in result.events} == {1}


def test_year_rollover_from_december_to_january():
    result = parse(
        "Dec 31 23:59:58 web-01 sshd[1]: Failed password for bob from 192.0.2.10 port 1 ssh2\n"
        "Jan  1 00:00:03 web-01 sshd[1]: Failed password for bob from 192.0.2.10 port 2 ssh2\n",
        year=2025,
    )
    first, second = result.events
    assert first.timestamp.year == 2025
    assert second.timestamp == datetime(2026, 1, 1, 0, 0, 3, tzinfo=UTC)


def test_small_backwards_jump_does_not_roll_year():
    result = parse(
        "Mar  2 10:00:00 h sshd[1]: Failed password for bob from 192.0.2.10 port 1 ssh2\n"
        "Feb 28 10:00:00 h sshd[1]: Failed password for bob from 192.0.2.10 port 1 ssh2\n"
    )
    assert {e.timestamp.year for e in result.events} == {2026}


def test_invalid_calendar_date_is_unparseable():
    result = parse("Feb 29 10:00:00 h sshd[1]: Failed password for bob from 192.0.2.10 port 1 ssh2")
    assert result.unparseable == 1


def test_default_timezone_converts_to_utc():
    result = parse(
        "Oct 13 22:00:00 h sshd[1]: Accepted password for bob from 192.0.2.10 port 1 ssh2",
        default_tz=load_timezone("America/New_York"),
    )
    assert result.events[0].timestamp == datetime(2026, 10, 14, 2, 0, tzinfo=UTC)


def test_iso_rsyslog_and_rfc5424_lines():
    result = parse(
        "2026-10-14T04:14:09.123456+02:00 web-01 sshd[9]: Accepted password for bob from "
        "2001:db8::5 port 22 ssh2\n"
        "<38>1 2026-10-14T02:20:00Z web-02 sshd 811 - - Failed password for root from "
        "198.51.100.23 port 4100 ssh2\n"
        '<38>1 2026-10-14T02:21:00Z web-02 sshd-session 812 ID47 [meta x="1"] Failed password '
        "for root from 198.51.100.23 port 4101 ssh2\n"
    )
    first, second, third = result.events
    assert first.timestamp == datetime(2026, 10, 14, 2, 14, 9, 123456, tzinfo=UTC)
    assert first.src_ip == "2001:db8::5"
    assert second.host == "web-02" and second.user == "root" and second.outcome == FAILURE
    assert third.timestamp.minute == 21
