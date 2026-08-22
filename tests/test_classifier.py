import pytest
from app.detection.classifier import supervised_classifier


def test_supervised_classifier_predictions():
    # Model should boot and train on bootstrap
    assert supervised_classifier.is_loaded is True

    # Test normal/benign features
    benign_features = {
        "failed_logins_5m": 0.0,
        "successful_logins_5m": 1.0,
        "unique_source_ips": 1.0,
        "new_source_ip": 0.0,
        "process_count_5m": 2.0,
        "credential_access_count": 0.0,
        "privilege_event_count": 0.0,
        "service_install_count": 0.0,
        "network_event_count": 0.0,
        "login_hour": 12.0,
        "login_frequency": 0.1,
        "event_frequency": 0.5,
    }

    benign_prob = supervised_classifier.predict_maliciousness(benign_features)
    assert benign_prob < 0.2  # Should be very low probability of being malicious

    # Test malicious brute force features
    brute_force_features = {
        "failed_logins_5m": 15.0,
        "successful_logins_5m": 0.0,
        "unique_source_ips": 2.0,
        "new_source_ip": 1.0,
        "process_count_5m": 1.0,
        "credential_access_count": 0.0,
        "privilege_event_count": 0.0,
        "service_install_count": 0.0,
        "network_event_count": 0.0,
        "login_hour": 23.0,
        "login_frequency": 2.0,
        "event_frequency": 10.0,
    }

    brute_prob = supervised_classifier.predict_maliciousness(brute_force_features)
    assert brute_prob > 0.7  # Should be high probability of being malicious
