from datetime import datetime, timezone, timedelta
from typing import Any
import logging

from app.core.events import SecurityEvent, EventType

logger = logging.getLogger("sentinelx.behavioral")


class EntityProfile:
    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.created_at = datetime.now(timezone.utc)
        self.last_seen = self.created_at

        # Sliding window timestamp lists for feature calculation
        self.login_failures: list[datetime] = []
        self.login_successes: list[datetime] = []
        self.source_ips: set[str] = set()
        self.processes: list[datetime] = []
        self.credential_accesses: list[datetime] = []
        self.privilege_events: list[datetime] = []
        self.service_installs: list[datetime] = []
        self.network_events: list[datetime] = []

        # Totals for historical frequency baselines
        self.total_logins = 0
        self.total_events = 0
        self.login_hours: list[int] = []

    def update(self, event: SecurityEvent) -> bool:
        """
        Updates the profile with a new event.
        Returns True if a new source IP is seen for this entity.
        """
        self.last_seen = event.timestamp
        self.total_events += 1

        is_new_ip = False

        if event.event_type == EventType.LOGIN_FAILURE:
            self.login_failures.append(event.timestamp)
            if event.source_ip:
                if event.source_ip not in self.source_ips:
                    is_new_ip = True
                self.source_ips.add(event.source_ip)

        elif event.event_type == EventType.LOGIN_SUCCESS:
            self.login_successes.append(event.timestamp)
            self.total_logins += 1
            self.login_hours.append(event.timestamp.hour)
            if event.source_ip:
                if event.source_ip not in self.source_ips:
                    is_new_ip = True
                self.source_ips.add(event.source_ip)

        elif event.event_type == EventType.PROCESS_CREATED:
            self.processes.append(event.timestamp)

        elif event.event_type == EventType.CREDENTIAL_ACCESS:
            self.credential_accesses.append(event.timestamp)

        elif event.event_type == EventType.SPECIAL_PRIVILEGES:
            self.privilege_events.append(event.timestamp)

        elif event.event_type == EventType.SERVICE_INSTALLED:
            self.service_installs.append(event.timestamp)

        elif event.event_type == EventType.NETWORK_CONNECTION:
            self.network_events.append(event.timestamp)

        # Periodically prune timestamps older than 1 hour to prevent memory growth
        self._prune_old_timestamps(event.timestamp)
        
        return is_new_ip

    def _prune_old_timestamps(self, current_time: datetime):
        cutoff = current_time - timedelta(hours=1)
        self.login_failures = [t for t in self.login_failures if t >= cutoff]
        self.login_successes = [t for t in self.login_successes if t >= cutoff]
        self.processes = [t for t in self.processes if t >= cutoff]
        self.credential_accesses = [t for t in self.credential_accesses if t >= cutoff]
        self.privilege_events = [t for t in self.privilege_events if t >= cutoff]
        self.service_installs = [t for t in self.service_installs if t >= cutoff]
        self.network_events = [t for t in self.network_events if t >= cutoff]

    def get_features(self, reference_time: datetime, source_ip: str | None = None) -> dict[str, Any]:
        """
        Calculates and returns rolling behavior feature counts relative to a reference time.
        """
        cutoff_5m = reference_time - timedelta(minutes=5)
        
        failed_logins_5m = len([t for t in self.login_failures if t >= cutoff_5m])
        successful_logins_5m = len([t for t in self.login_successes if t >= cutoff_5m])
        process_count_5m = len([t for t in self.processes if t >= cutoff_5m])
        credential_access_count = len([t for t in self.credential_accesses if t >= cutoff_5m])
        privilege_event_count = len([t for t in self.privilege_events if t >= cutoff_5m])
        service_install_count = len([t for t in self.service_installs if t >= cutoff_5m])
        network_event_count = len([t for t in self.network_events if t >= cutoff_5m])

        # Calculate frequency metrics (per hour or total counts)
        lifetime_hours = max((reference_time - self.created_at).total_seconds() / 3600.0, 0.1)
        login_frequency = self.total_logins / lifetime_hours
        event_frequency = self.total_events / lifetime_hours

        # Check if IP is new
        is_new_ip = 0.0
        if source_ip and source_ip not in self.source_ips:
            is_new_ip = 1.0

        return {
            "failed_logins_5m": float(failed_logins_5m),
            "successful_logins_5m": float(successful_logins_5m),
            "unique_source_ips": float(len(self.source_ips)),
            "new_source_ip": is_new_ip,
            "process_count_5m": float(process_count_5m),
            "credential_access_count": float(credential_access_count),
            "privilege_event_count": float(privilege_event_count),
            "service_install_count": float(service_install_count),
            "network_event_count": float(network_event_count),
            "login_hour": float(reference_time.hour),
            "login_frequency": float(login_frequency),
            "event_frequency": float(event_frequency),
        }


class BehavioralEngine:
    def __init__(self):
        # Store profiles by entity key: e.g. "host:<host_name>", "user:<user_name>"
        self.profiles: dict[str, EntityProfile] = {}

    def update_profiles(self, event: SecurityEvent) -> dict[str, dict[str, Any]]:
        """
        Updates relevant user and host profiles for the event.
        Returns a dictionary of the updated feature vectors.
        """
        keys = []
        if event.host and event.host != "unknown":
            keys.append((f"host:{event.host}", "host"))
        if event.user:
            keys.append((f"user:{event.user}", "user"))
        if event.source_ip:
            keys.append((f"ip:{event.source_ip}", "ip"))

        features = {}

        for key, entity_type in keys:
            if key not in self.profiles:
                self.profiles[key] = EntityProfile(entity_id=key.split(":", 1)[1], entity_type=entity_type)
            
            profile = self.profiles[key]
            profile.update(event)
            features[key] = profile.get_features(event.timestamp, event.source_ip)

        return features

    def get_profile(self, entity_id: str, entity_type: str) -> EntityProfile | None:
        return self.profiles.get(f"{entity_type}:{entity_id}")


behavioral_engine = BehavioralEngine()
