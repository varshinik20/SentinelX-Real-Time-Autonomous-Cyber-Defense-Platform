from datetime import datetime, timezone, timedelta
import pytest

from app.core.events import SecurityEvent, EventType, Severity
from app.detection.rules import (
    Rule001_BruteForce,
    Rule002_FailedThenSuccess,
    Rule005_CredentialAccessProcess,
    Rule008_SuspiciousProcessChain,
)


def test_rule_001_brute_force():
    rule = Rule001_BruteForce()
    history = []
    base_time = datetime.now(timezone.utc)

    # 4 failures in history
    for i in range(4):
        history.append(
            SecurityEvent(
                event_id=f"fail-{i}",
                timestamp=base_time - timedelta(seconds=10 * (4 - i)),
                event_type=EventType.LOGIN_FAILURE,
                host="SENTINELX-LAB",
                user="target-user",
                source_ip="192.168.1.100",
            )
        )

    # Current event (5th failure)
    current_event = SecurityEvent(
        event_id="fail-current",
        timestamp=base_time,
        event_type=EventType.LOGIN_FAILURE,
        host="SENTINELX-LAB",
        user="target-user",
        source_ip="192.168.1.100",
    )

    alert = rule.evaluate(current_event, history)

    assert alert is not None
    assert alert.rule_id == "RULE-001"
    assert alert.matched is True
    assert alert.evidence["failed_login_count"] == 5
    assert alert.user == "target-user"


def test_rule_002_failed_then_success():
    rule = Rule002_FailedThenSuccess()
    history = []
    base_time = datetime.now(timezone.utc)

    # 3 failures in history
    for i in range(3):
        history.append(
            SecurityEvent(
                event_id=f"fail-{i}",
                timestamp=base_time - timedelta(seconds=15 * (3 - i)),
                event_type=EventType.LOGIN_FAILURE,
                host="SENTINELX-LAB",
                user="target-user",
                source_ip="192.168.1.100",
            )
        )

    # Current event is a successful login
    current_event = SecurityEvent(
        event_id="success-current",
        timestamp=base_time,
        event_type=EventType.LOGIN_SUCCESS,
        host="SENTINELX-LAB",
        user="target-user",
        source_ip="192.168.1.100",
    )

    alert = rule.evaluate(current_event, history)

    assert alert is not None
    assert alert.rule_id == "RULE-002"
    assert alert.evidence["failed_login_count"] == 3


def test_rule_005_credential_access_correlation():
    rule = Rule005_CredentialAccessProcess()
    history = []
    base_time = datetime.now(timezone.utc)

    # Suspect process created in history (e.g. cmd.exe)
    history.append(
        SecurityEvent(
            event_id="proc-1",
            timestamp=base_time - timedelta(seconds=30),
            event_type=EventType.PROCESS_CREATED,
            host="SENTINELX-LAB",
            user="Administrator",
            process_name="C:\\Windows\\System32\\cmd.exe",
        )
    )

    # Current event: credential access (5379)
    current_event = SecurityEvent(
        event_id="cred-access",
        timestamp=base_time,
        event_type=EventType.CREDENTIAL_ACCESS,
        host="SENTINELX-LAB",
        user="Administrator",
        metadata={"target_name": "git:github.com"},
    )

    alert = rule.evaluate(current_event, history)

    assert alert is not None
    assert alert.rule_id == "RULE-005"
    assert alert.evidence["credential_read"] == "git:github.com"


def test_rule_008_suspicious_process_chain():
    rule = Rule008_SuspiciousProcessChain()
    history = []
    base_time = datetime.now(timezone.utc)

    # w3wp.exe (IIS Web Server) spawning powershell.exe
    event = SecurityEvent(
        event_id="proc-chain-1",
        timestamp=base_time,
        event_type=EventType.PROCESS_CREATED,
        host="SENTINELX-LAB",
        user="IIS_IUSRS",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        metadata={"command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\backdoor.ps1"},
    )

    alert = rule.evaluate(event, history)

    assert alert is not None
    assert alert.rule_id == "RULE-008"
    assert alert.evidence["scenario"] == "server_spawning_shell"
