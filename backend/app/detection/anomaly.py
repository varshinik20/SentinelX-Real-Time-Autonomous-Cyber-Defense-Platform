import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import threading
from typing import Any

logger = logging.getLogger("sentinelx.anomaly")

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


class IsolationForestAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.training_data: list[list[float]] = []
        self.lock = threading.Lock()
        self.is_trained = False
        
        # Means and Standard Deviations for explainability (Z-score calculation)
        self.means = np.zeros(len(FEATURE_KEYS))
        self.stds = np.ones(len(FEATURE_KEYS))

        # Bootstrap training data with typical normal activity patterns for cold start
        self._bootstrap_normal_data()
        self.train()

    def _bootstrap_normal_data(self):
        """
        Pre-populates training database with synthetic "normal" behavior vectors
        so the Isolation Forest model has a baseline to train on from start.
        """
        bootstrap_vectors = []
        
        # 1. Perfectly quiet baseline (no events)
        for _ in range(30):
            vector = [0.0] * len(FEATURE_KEYS)
            vector[9] = 12.0  # hour of day
            vector[10] = 0.1  # low login frequency
            vector[11] = 0.5  # low event frequency
            bootstrap_vectors.append(vector)
            
        # 2. Typical benign activity (few successes, processes, network calls)
        for _ in range(50):
            vector = [
                0.0,                   # failed logins
                float(np.random.randint(1, 3)),  # successful logins (1-2)
                1.0,                   # 1 unique source IP
                0.0,                   # not new source IP
                float(np.random.randint(2, 8)),  # process count
                0.0,                   # credential access
                0.0,                   # privilege events
                0.0,                   # service installations
                float(np.random.randint(0, 5)),  # network calls
                float(np.random.randint(8, 18)), # working hours
                0.5,                   # login frequency
                1.5                    # event frequency
            ]
            bootstrap_vectors.append(vector)

        self.training_data.extend(bootstrap_vectors)
        logger.info(f"[ANOMALY] Bootstrapped anomaly detector with {len(self.training_data)} normal vectors.")

    def add_training_sample(self, features: dict[str, float]):
        """
        Adds a new observed feature vector to the training pool.
        """
        vector = [features.get(k, 0.0) for k in FEATURE_KEYS]
        with self.lock:
            self.training_data.append(vector)
            # Limit memory of training samples to last 5000 observations
            if len(self.training_data) > 5000:
                self.training_data.pop(0)

    def train(self):
        """
        Trains the Isolation Forest model on the accumulated training data.
        """
        with self.lock:
            if len(self.training_data) < 10:
                logger.warning("[ANOMALY] Insufficient data to train Isolation Forest.")
                return

            try:
                X = np.array(self.training_data)
                self.model.fit(X)
                
                # Update means and stds for explaining predictions
                self.means = np.mean(X, axis=0)
                self.stds = np.std(X, axis=0) + 1e-6  # Add small constant to avoid divide by zero
                
                self.is_trained = True
                logger.info(f"[ANOMALY] isolation Forest successfully trained on {len(X)} samples.")
            except Exception as e:
                logger.error(f"[ANOMALY] Failed to train Isolation Forest: {e}", exc_info=True)

    def predict_anomaly(self, features: dict[str, float]) -> tuple[float, float, list[str]]:
        """
        Computes anomaly score, normality score, and top contributing features.
        Returns:
            anomaly_score (float): Range [0, 100] where higher is more anomalous.
            normality_score (float): Range [0, 100] where higher is more normal.
            top_features (list[str]): Explanation list of top contributing anomaly features.
        """
        if not self.is_trained:
            return 0.0, 100.0, []

        vector = np.array([[features.get(k, 0.0) for k in FEATURE_KEYS]])
        
        try:
            # decision_function output is in [-0.5, 0.5]
            # lower values are more anomalous
            d = self.model.decision_function(vector)[0]
            
            # Map decision output to [0, 100] scale
            # If d >= 0.15 (very normal) -> anomaly_score close to 0
            # If d <= -0.15 (very anomalous) -> anomaly_score close to 100
            raw_score = (0.15 - d) / 0.3 * 100.0
            anomaly_score = float(max(0.0, min(100.0, raw_score)))
            normality_score = 100.0 - anomaly_score

            # Explain anomaly using Z-score contributions (deviation from mean)
            v_flat = vector[0]
            z_scores = np.abs((v_flat - self.means) / self.stds)
            
            # Sort indices by deviation value
            sorted_indices = np.argsort(z_scores)[::-1]
            
            top_features = []
            for idx in sorted_indices:
                # Include features where the Z-score > 1.5 (significant deviation) and count is not zero
                if z_scores[idx] > 1.5 and v_flat[idx] > 0.0:
                    top_features.append(f"{FEATURE_KEYS[idx]} (val: {v_flat[idx]:.1f}, deviation: {z_scores[idx]:.1f}σ)")

            # Return at least the single highest feature if anomaly is elevated but Z-score is low
            if anomaly_score > 40.0 and not top_features:
                highest_idx = sorted_indices[0]
                top_features.append(f"{FEATURE_KEYS[highest_idx]} (val: {v_flat[highest_idx]:.1f})")

            return anomaly_score, normality_score, top_features
            
        except Exception as e:
            logger.error(f"[ANOMALY] Error predicting anomaly: {e}")
            return 0.0, 100.0, []


anomaly_detector = IsolationForestAnomalyDetector()
