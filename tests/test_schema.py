from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.core.events import SecurityEvent, EventType, Severity


def test_valid_security_event():
    event = SecurityEvent(
        event_id="test-123",
        event_type=EventType.PROCESS_CREATED,
        severity=Severity.LOW,
        host="SENTINELX-LAB",
        user="SYSTEM",
        process_name="cmd.exe",
        parent_process="explorer.exe",
        message="Process created successfully",
        metadata={"cmd_line": "cmd.exe /c whoami"},
    )

    assert event.event_id == "test-123"
    assert event.event_type == EventType.PROCESS_CREATED
    assert event.severity == Severity.LOW
    assert event.host == "SENTINELX-LAB"
    assert event.user == "SYSTEM"
    assert event.process_name == "cmd.exe"
    assert event.parent_process == "explorer.exe"
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo == timezone.utc


def test_invalid_event_type():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="test-124",
            event_type="INVALID_TYPE",  # Should raise validation error
            severity=Severity.LOW,
        )
