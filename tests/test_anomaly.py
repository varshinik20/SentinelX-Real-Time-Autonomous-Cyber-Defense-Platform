import pytest
from app.detection.anomaly import IsolationForestAnomalyDetector, FEATURE_KEYS


def test_anomaly_detector_training_and_explainability():
    detector = IsolationForestAnomalyDetector()
    
    # Assert model is trained on bootstrapped data
    assert detector.is_trained is True

    # 1. Test normal feature vector (representing standard usage)
    normal_features = {
        "failed_logins_5m": 0.0,
        "successful_logins_5m": 1.0,
        "unique_source_ips": 1.0,
        "new_source_ip": 0.0,
        "process_count_5m": 2.0,
        "credential_access_count": 0.0,
        "privilege_event_count": 0.0,
        "service_install_count": 0.0,
        "network_event_count": 1.0,
        "login_hour": 10.0,
        "login_frequency": 0.2,
        "event_frequency": 1.0,
    }

    anomaly_score, normality_score, explanations = detector.predict_anomaly(normal_features)

    # Normal score should be low anomaly (< 55)
    assert anomaly_score < 55.0
    assert normality_score > 45.0
    assert normality_score + anomaly_score == pytest.approx(100.0)

    # 2. Test anomalous feature vector (representing credential brute force + service install + heavy processes)
    anomalous_features = {
        "failed_logins_5m": 25.0,  # Highly anomalous!
        "successful_logins_5m": 0.0,
        "unique_source_ips": 10.0, # Highly anomalous!
        "new_source_ip": 1.0,
        "process_count_5m": 45.0,  # Highly anomalous!
        "credential_access_count": 5.0,
        "privilege_event_count": 3.0,
        "service_install_count": 4.0,  # Highly anomalous!
        "network_event_count": 30.0,
        "login_hour": 3.0,          # Middle of night
        "login_frequency": 2.0,
        "event_frequency": 50.0,
    }

    anom_score, norm_score, anom_explanations = detector.predict_anomaly(anomalous_features)

    # Anomalous score should be significantly higher
    assert anom_score > 50.0
    assert len(anom_explanations) > 0
    # The top explanation should mention one of the highly anomalous features (like failed_logins_5m or process_count_5m)
    explanation_str = "".join(anom_explanations)
    assert "failed_logins_5m" in explanation_str or "process_count_5m" in explanation_str or "service_install_count" in explanation_str or "unique_source_ips" in explanation_str
