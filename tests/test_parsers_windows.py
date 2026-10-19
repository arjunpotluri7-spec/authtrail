import codecs
import json
from datetime import UTC, datetime

from authtrail.models import ACCOUNT_LOCKOUT, FAILURE, LOGIN, OTHER, SPECIAL_PRIVILEGES, SUCCESS
from authtrail.parsers import parse_file
from authtrail.parsers.windows import parse_windows


def event(eid, **fields):
    base = {"EventID": eid, "TimeCreated": "2026-10-14T09:20:03.4410000Z", "Computer": "DC01"}
    base.update(fields)
    return base


def test_event_id_mapping():
    records = [
        event(4624, TargetUserName="carol", IpAddress="10.20.5.14", LogonType=10),
        event(
            4625,
            TargetUserName="frank",
            IpAddress="192.0.2.66",
            LogonType="3",
            SubStatus="0xc000006a",
        ),
        event(4740, TargetUserName="frank", CallerComputerName="WS01"),
        event(4672, SubjectUserName="svc-backup"),
    ]
    result = parse_windows(json.dumps(records), "sec.json")
    ok, bad, lock, priv = result.events
    assert (ok.event_type, ok.outcome, ok.method, ok.src_ip) == (
        LOGIN,
        SUCCESS,
        "remote_interactive",
        "10.20.5.14",
    )
    assert (bad.outcome, bad.method, bad.detail) == (FAILURE, "network", "0xc000006a")
    assert (lock.event_type, lock.outcome, lock.src_ip, lock.detail) == (
        ACCOUNT_LOCKOUT,
        OTHER,
        None,
        "caller WS01",
    )
    assert priv.event_type == SPECIAL_PRIVILEGES and priv.user == "svc-backup"
    assert ok.timestamp == datetime(2026, 10, 14, 9, 20, 3, 441000, tzinfo=UTC)
    assert ok.host == "DC01"


def test_placeholder_and_mapped_addresses():
    records = [
        event(4624, TargetUserName="SYSTEM", IpAddress="-", LogonType=5),
        event(4624, TargetUserName="alice", IpAddress="::ffff:10.0.0.21", LogonType=3),
        event(4624, Id=4624, TargetUserName="x", IpAddress="", LogonType=99),
    ]
    result = parse_windows(json.dumps(records), "sec.json")
    assert [e.src_ip for e in result.events] == [None, "10.0.0.21", None]
    assert result.events[0].method == "service"
    assert result.events[2].method == "logon_type_99"


def test_ndjson_line_numbers_skips_and_malformed():
    lines = [
        json.dumps(event(4634, TargetUserName="carol")),
        json.dumps({"EventID": 4625, "TargetUserName": "dave"}),
        json.dumps(event("not-a-number")),
        "{broken",
        json.dumps({"Id": 4625, "TimeCreated": "/Date(1791871200000)/", "TargetUserName": "d"}),
    ]
    result = parse_windows("\n".join(lines), "sec.ndjson")
    assert result.skipped == 1
    assert result.unparseable == 3
    assert result.unparseable_lines == [2, 3, 4]
    assert result.events[0].evidence.line == 5
    assert result.events[0].timestamp == datetime(2026, 10, 13, 6, tzinfo=UTC)


def test_pretty_printed_array_line_numbers_and_truncation():
    text = "[\n" + json.dumps(event(4625, TargetUserName="a"), indent=2) + ',\n  {"EventID": 46'
    result = parse_windows(text, "sec.json")
    assert len(result.events) == 1
    assert result.events[0].evidence.line == 2
    assert result.unparseable == 1


def test_utf16_powershell_export(tmp_path):
    path = tmp_path / "sec.json"
    payload = json.dumps([event(4625, TargetUserName="erin", IpAddress="192.0.2.66")])
    path.write_bytes(codecs.BOM_UTF16_LE + payload.encode("utf-16-le"))
    result = parse_file(path, year=2026, max_bytes=10_000_000)
    assert result.format == "windows"
    assert result.events[0].user == "erin"
