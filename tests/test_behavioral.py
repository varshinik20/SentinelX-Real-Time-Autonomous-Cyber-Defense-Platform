from datetime import datetime, timezone, timedelta
import pytest

from app.core.events import SecurityEvent, EventType
from app.detection.behavioral import EntityProfile, BehavioralEngine


def test_entity_profile_updates():
    profile = EntityProfile(entity_id="test-host", entity_type="host")
    base_time = datetime.now(timezone.utc)

    # 1. Update with a login success
    event1 = SecurityEvent(
        event_id="e1",
        timestamp=base_time,
        event_type=EventType.LOGIN_SUCCESS,
        host="test-host",
        source_ip="192.168.1.100",
    )
    profile.update(event1)
    
    # 2. Update with process creation
    event2 = SecurityEvent(
        event_id="e2",
        timestamp=base_time + timedelta(seconds=10),
        event_type=EventType.PROCESS_CREATED,
        host="test-host",
    )
    profile.update(event2)

    # Calculate features at current reference time
    features = profile.get_features(base_time + timedelta(seconds=30))

    assert features["successful_logins_5m"] == 1.0
    assert features["process_count_5m"] == 1.0
    assert features["unique_source_ips"] == 1.0
    assert features["new_source_ip"] == 0.0


def test_behavioral_engine_routing():
    engine = BehavioralEngine()
    base_time = datetime.now(timezone.utc)

    event = SecurityEvent(
        event_id="e-routing",
        timestamp=base_time,
        event_type=EventType.LOGIN_FAILURE,
        host="host-alpha",
        user="analyst-john",
        source_ip="10.0.0.5",
    )

    feature_maps = engine.update_profiles(event)

    # Profiles should be created and updated for user, host, and IP
    assert "host:host-alpha" in feature_maps
    assert "user:analyst-john" in feature_maps
    assert "ip:10.0.0.5" in feature_maps

    assert feature_maps["host:host-alpha"]["failed_logins_5m"] == 1.0
    assert feature_maps["user:analyst-john"]["failed_logins_5m"] == 1.0
