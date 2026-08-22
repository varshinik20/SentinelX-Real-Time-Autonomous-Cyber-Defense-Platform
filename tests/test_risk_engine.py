from datetime import datetime, timezone
import pytest

from app.core.events import DetectionAlert
from app.risk.risk_engine import risk_engine


def test_calculate_risk_deterministic_alerts():
    # Scenario: 2 alerts with risk contributions 25 and 20
    alerts = [
        DetectionAlert(
            alert_id="a1",
            rule_id="RULE-001",
            rule_name="Brute Force Authentication",
            matched=True,
            confidence=0.8,
            risk_contribution=25,
            timestamp=datetime.now(timezone.utc),
        ),
        DetectionAlert(
            alert_id="a2",
            rule_id="RULE-003",
            rule_name="Special Privilege Assignment",
            matched=True,
            confidence=0.7,
            risk_contribution=20,
            timestamp=datetime.now(timezone.utc),
        )
    ]

    res = risk_engine.calculate_incident_risk(alerts, max_anomaly_score=0.0)

    assert res["risk_score"] == 45
    assert res["risk_band"] == "MEDIUM"
    assert len(res["contributors"]) == 2
    assert "RULE-001" in res["contributors"][0]


def test_calculate_risk_with_ml_anomaly():
    alerts = [
        DetectionAlert(
            alert_id="a1",
            rule_id="RULE-001",
            rule_name="Brute Force Authentication",
            matched=True,
            confidence=0.8,
            risk_contribution=25,
            timestamp=datetime.now(timezone.utc),
        )
    ]

    # Max ML anomaly score of 80 (should contribute 80 * 0.35 = 28 points)
    res = risk_engine.calculate_incident_risk(alerts, max_anomaly_score=80.0)

    # 25 + 28 = 53 (ELEVATED)
    assert res["risk_score"] == 53
    assert res["risk_band"] == "ELEVATED"
    assert "Anomaly Profile (Score 80.0): +28" in res["contributors"][1]
