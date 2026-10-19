import pytest

from authtrail.errors import InputError
from authtrail.parsers import detect_format, parse_file


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Oct 14 02:09:02 web-01 sshd[1]: Failed password for bob from 192.0.2.1 port 1 ssh2",
            "linux",
        ),
        ("2026-10-14T02:09:02Z web-01 sshd[1]: hello", "linux"),
        ('{"timestamp": "2026-10-14 02:17:31+0000", "eventMessage": "x"}', "macos"),
        ('[{"EventID": 4625, "TimeCreated": "2026-10-14T00:00:00Z"}]', "windows"),
        ('{"Id": 4624, "TimeCreated": "2026-10-14T00:00:00Z"}', "windows"),
        ('{"some": "json"}', None),
        ("just some text\nwith no syslog header", None),
        ("   \n", None),
    ],
)
def test_detect_format(text, expected):
    assert detect_format(text) == expected


def test_parse_file_errors(tmp_path):
    with pytest.raises(InputError, match="no such file"):
        parse_file(tmp_path / "missing.log", year=2026, max_bytes=100)
    with pytest.raises(InputError, match="is a directory"):
        parse_file(tmp_path, year=2026, max_bytes=100)
    big = tmp_path / "big.log"
    big.write_text("x" * 200)
    with pytest.raises(InputError, match="over the"):
        parse_file(big, year=2026, max_bytes=100)
    unknown = tmp_path / "notes.txt"
    unknown.write_text("hello world\n")
    with pytest.raises(InputError, match="could not detect"):
        parse_file(unknown, year=2026, max_bytes=1000)


def test_empty_file_and_format_override(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert parse_file(empty, year=2026, max_bytes=100).format == "empty"
    odd = tmp_path / "odd.txt"
    odd.write_text(
        "Oct 14 02:09:02 h sshd[1]: Accepted password for bob from 192.0.2.1 port 1 ssh2\n"
    )
    result = parse_file(odd, format_in="linux", year=2026, max_bytes=1000)
    assert len(result.events) == 1


def test_invalid_utf8_is_replaced_not_fatal(tmp_path):
    path = tmp_path / "auth.log"
    path.write_bytes(
        b"Oct 14 02:09:02 h sshd[1]: Failed password for b\xffb from 192.0.2.1 port 1 ssh2\n"
    )
    result = parse_file(path, year=2026, max_bytes=1000)
    assert result.events[0].user == "b�b"
