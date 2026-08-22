from typing import Any

# Standard feature order for classifier consistency
FEATURE_KEYS = [
    "failed_logins_5m",
    "successful_logins_5m",
    "unique_source_ips",
    "new_source_ip",
    "process_count_5m",
    "credential_access_count",
    "privilege_event_count",
    "service_install_count",
    "network_event_count",
    "login_hour",
    "login_frequency",
    "event_frequency",
]


def extract_feature_vector(features: dict[str, Any]) -> list[float]:
    """
    Normalizes a dictionary of entity features into a sorted float list.
    """
    return [float(features.get(key, 0.0)) for key in FEATURE_KEYS]
