from datetime import datetime, timezone
import pytest

from app.core.events import SecurityEvent, DetectionAlert, EventType, Severity
from app.correlation.attack_graph import attack_graph_generator


def test_attack_graph_generation():
    # 1. Mock raw events representing a process execution chain
    events = [
        SecurityEvent(
            event_id="ev-1",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.PROCESS_CREATED,
            host="SENTINELX-LAB",
            user="Administrator",
            process_name="C:\\Windows\\System32\\cmd.exe",
            parent_process="C:\\Windows\\explorer.exe",
        ),
        SecurityEvent(
            event_id="ev-2",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.NETWORK_CONNECTION,
            host="SENTINELX-LAB",
            user="Administrator",
            process_name="C:\\Windows\\System32\\cmd.exe",
            destination_ip="8.8.8.8",
        )
    ]

    # 2. Mock alerts
    alerts = [
        DetectionAlert(
            alert_id="al-1",
            rule_id="RULE-008",
            rule_name="Suspicious Process Execution Chain",
            matched=True,
            confidence=0.9,
            risk_contribution=45,
            timestamp=datetime.now(timezone.utc),
            host="SENTINELX-LAB",
            user="Administrator",
        )
    ]

    graph = attack_graph_generator.generate_graph(alerts, events)

    # 3. Check graph schema structure
    assert "nodes" in graph
    assert "edges" in graph

    node_ids = [n["id"] for n in graph["nodes"]]
    assert "SENTINELX-LAB" in node_ids
    assert "Administrator" in node_ids
    assert "C:\\Windows\\System32\\cmd.exe" in node_ids
    assert "8.8.8.8" in node_ids
    assert "Alert: Suspicious Process Execution Chain" in node_ids

    # Check edges
    relations = [(e["source"], e["target"], e["relation"]) for e in graph["edges"]]
    assert ("Administrator", "SENTINELX-LAB", "logged_into") in relations
    assert ("Administrator", "C:\\Windows\\System32\\cmd.exe", "executed") in relations
    assert ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe", "spawned") in relations
    assert ("C:\\Windows\\System32\\cmd.exe", "8.8.8.8", "communicated_with") in relations
