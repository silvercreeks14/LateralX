from backend.ingest.parser import (
    parse_plaso_csv,
    parse_timesketch_jsonl,
    parse_generic_csv,
    detect_and_parse,
)

PLASO_SAMPLE = """datetime,timestamp_desc,source,source_long,message,parser,display_name,tag,hostname,username
2024-03-15 08:23:11,Creation Time,EVT,Windows Event Log,Event ID: 4624 logon,winevt,Security.evtx,,WORKSTATION-01,jdoe
2024-03-15 08:24:05,Creation Time,EVT,Windows Event Log,certutil.exe download,winevt,Security.evtx,,WORKSTATION-01,jdoe"""

JSONL_SAMPLE = """{"datetime": "2024-03-15T08:23:11", "timestamp_desc": "Logon", "hostname": "HOST-01", "username": "alice", "message": "logon event"}
{"datetime": "2024-03-15T08:25:00", "timestamp_desc": "Process", "hostname": "HOST-01", "username": "alice", "message": "cmd.exe launched"}"""

GENERIC_SAMPLE = """timestamp,description,source_host,user
2024-03-15 08:23:11,test event,HOST-01,bob
2024-03-15 08:25:00,another event,HOST-02,bob"""


def test_plaso_parse():
    events = parse_plaso_csv(PLASO_SAMPLE)
    assert len(events) == 2
    assert events[0].source_host == "WORKSTATION-01"
    assert events[0].user == "jdoe"
    assert events[0].event_id == "4624"
    assert events[1].event_id is None


def test_timesketch_parse():
    events = parse_timesketch_jsonl(JSONL_SAMPLE)
    assert len(events) == 2
    assert events[0].source_host == "HOST-01"
    assert events[0].user == "alice"


def test_generic_parse():
    events = parse_generic_csv(GENERIC_SAMPLE)
    assert len(events) == 2
    assert events[0].source_host == "HOST-01"
    assert events[0].user == "bob"


def test_detect_plaso():
    events = detect_and_parse("test.csv", PLASO_SAMPLE)
    assert len(events) == 2
    assert events[0].raw_source.value == "plaso"


def test_detect_jsonl():
    events = detect_and_parse("test.jsonl", JSONL_SAMPLE)
    assert len(events) == 2
    assert events[0].raw_source.value == "timesketch"
