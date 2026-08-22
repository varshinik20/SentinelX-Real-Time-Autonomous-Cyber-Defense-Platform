from datetime import datetime, timezone
import pytest

from app.collectors.windows_events import parse_windows_event
from app.core.events import EventType, Severity


class MockPywintypesTime:
    def __init__(self, dt):
        self._dt = dt

    def timestamp(self):
        return self._dt.timestamp()


class MockEventRecord:
    def __init__(
        self,
        event_id: int,
        source_name: str,
        record_number: int,
        computer_name: str,
        time_generated: datetime,
        string_inserts: list[str],
        sid=None,
    ):
        self.EventID = event_id
        self.SourceName = source_name
        self.RecordNumber = record_number
        self.ComputerName = computer_name
        self.TimeGenerated = MockPywintypesTime(time_generated)
        self.StringInserts = string_inserts
        self.Sid = sid


def test_parse_logon_success_4624():
    # Mocking StringInserts for Logon Success (4624)
    # inserts[5]: TargetUserName, inserts[6]: TargetDomainName, inserts[18]: IpAddress
    inserts = [""] * 20
    inserts[5] = "testuser"
    inserts[6] = "TESTDOMAIN"
    inserts[18] = "192.168.1.100"

    record = MockEventRecord(
        event_id=4624,
        source_name="Microsoft-Windows-Security-Auditing",
        record_number=1001,
        computer_name="WIN-SOC-NODE",
        time_generated=datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc),
        string_inserts=inserts,
    )

    event = parse_windows_event(record, "Security")

    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS
    assert event.severity == Severity.LOW
    assert event.user == "TESTDOMAIN\\testuser"
    assert event.source_ip == "192.168.1.100"
    assert event.host == "WIN-SOC-NODE"
    assert event.metadata["win_event_id"] == 4624


def test_parse_process_created_4688():
    # Mocking StringInserts for Process Creation (4688)
    # inserts[1]: SubjectUserName, inserts[2]: SubjectDomainName
    # inserts[5]: NewProcessName, inserts[8]: CommandLine, inserts[13]: ParentProcessName
    inserts = [""] * 15
    inserts[1] = "Administrator"
    inserts[2] = "TESTDOMAIN"
    inserts[4] = "0x1a4"
    inserts[5] = "C:\\Windows\\System32\\cmd.exe"
    inserts[8] = "cmd.exe /c whoami"
    inserts[13] = "C:\\Windows\\explorer.exe"

    record = MockEventRecord(
        event_id=4688,
        source_name="Microsoft-Windows-Security-Auditing",
        record_number=1002,
        computer_name="WIN-SOC-NODE",
        time_generated=datetime(2026, 8, 22, 12, 1, 0, tzinfo=timezone.utc),
        string_inserts=inserts,
    )

    event = parse_windows_event(record, "Security")

    assert event is not None
    assert event.event_type == EventType.PROCESS_CREATED
    assert event.severity == Severity.LOW
    assert event.user == "TESTDOMAIN\\Administrator"
    assert event.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert event.parent_process == "C:\\Windows\\explorer.exe"
    assert event.metadata["command_line"] == "cmd.exe /c whoami"
    assert event.metadata["new_process_id"] == "0x1a4"


def test_parse_ignored_event_id():
    record = MockEventRecord(
        event_id=9999,  # Some irrelevant event ID
        source_name="Microsoft-Windows-Security-Auditing",
        record_number=1003,
        computer_name="WIN-SOC-NODE",
        time_generated=datetime(2026, 8, 22, 12, 2, 0, tzinfo=timezone.utc),
        string_inserts=[],
    )

    event = parse_windows_event(record, "Security")
    assert event is None
