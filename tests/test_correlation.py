from datetime import datetime, timezone, timedelta
import pytest

from app.core.events import SecurityEvent, DetectionAlert, EventType
from app.correlation.engine import CorrelationEngine


@pytest.mark.asyncio
async def test_alert_correlation_and_promotion():
    engine = CorrelationEngine()
    base_time = datetime.now(timezone.utc)

    # Mock history of events on a host
    event_history = [
        SecurityEvent(
            event_id="ev-101",
            timestamp=base_time - timedelta(seconds=30),
            event_type=EventType.LOGIN_FAILURE,
            host="HOST-CORR",
            user="user-alpha",
            source_ip="192.168.10.10",
        ),
        SecurityEvent(
            event_id="ev-102",
            timestamp=base_time,
            event_type=EventType.PROCESS_CREATED,
            host="HOST-CORR",
            user="user-alpha",
            process_name="cmd.exe",
        ),
    ]

    # Alert 1: Brute Force (risk contribution 25)
    alert1 = DetectionAlert(
        alert_id="a-101",
        rule_id="RULE-001",
        rule_name="Brute Force Authentication",
        matched=True,
        confidence=0.8,
        risk_contribution=25,
        timestamp=base_time,
        host="HOST-CORR",
        user="user-alpha",
    )

    # Correlation 1: Should create a new incident
    inc1 = await engine.correlate_alert(alert1, event_history)

    assert inc1 is not None
    assert inc1.risk_score == 25
    assert len(inc1.related_alerts) == 1
    assert inc1.host == "HOST-CORR"
    assert inc1.user == "user-alpha"

    # Alert 2: Suspicious Process Chain on same host (risk contribution 45)
    alert2 = DetectionAlert(
        alert_id="a-102",
        rule_id="RULE-008",
        rule_name="Suspicious Process Execution Chain",
        matched=True,
        confidence=0.9,
        risk_contribution=45,
        timestamp=base_time + timedelta(seconds=5),
        host="HOST-CORR",
        user="user-alpha",
    )

    # Correlation 2: Should update the existing incident
    inc2 = await engine.correlate_alert(alert2, event_history)

    assert inc2.incident_id == inc1.incident_id  # Should group into same incident!
    assert len(inc2.related_alerts) == 2
    # Combined risk: 25 + 45 = 70 (ELEVATED)
    assert inc2.risk_score == 70
    assert inc2.severity == "ELEVATED"
    assert inc2.ai_summary is not None
    assert len(inc2.recommendations) > 0
