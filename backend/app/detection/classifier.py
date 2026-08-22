import os
import logging
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from app.core.config import settings
from app.detection.features import FEATURE_KEYS, extract_feature_vector

logger = logging.getLogger("sentinelx.classifier")

MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models", "ml"
)
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")


class SupervisedSecurityClassifier:
    def __init__(self):
        self.model = None
        self.is_loaded = False
        self._initialize_model()

    def _initialize_model(self):
        # Ensure directories exist
        os.makedirs(MODEL_DIR, exist_ok=True)

        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.is_loaded = True
                logger.info(f"[ML CLASSIFIER] Loaded pre-trained model from {MODEL_PATH}")
            except Exception as e:
                logger.error(f"[ML CLASSIFIER] Failed to load model: {e}")

        if not self.is_loaded:
            logger.info("[ML CLASSIFIER] No saved model found. Training boot-strapped model...")
            self._train_bootstrap_model()

    def _train_bootstrap_model(self):
        """
        Trains and saves a bootstrapping Random Forest classifier on basic threat vectors.
        """
        X = []
        y = []

        # 1. Normal/Benign training data (label 0)
        # Low activity, no login failures, daytime work
        for _ in range(60):
            vector = [
                0.0,                   # failed logins
                float(np.random.randint(1, 4)),  # successful logins
                1.0,                   # unique IPs
                0.0,                   # new IP
                float(np.random.randint(2, 6)),  # process count
                0.0,                   # credential access
                0.0,                   # privilege events
                0.0,                   # service installations
                float(np.random.randint(0, 3)),  # network events
                float(np.random.randint(8, 18)), # work hours
                0.2,                   # login frequency
                1.0                    # event frequency
            ]
            X.append(vector)
            y.append(0)

        # 2. Malicious Brute Force vectors (label 1)
        for _ in range(20):
            vector = [
                float(np.random.randint(8, 30)), # high failed logins
                0.0,                   # successful logins
                float(np.random.randint(1, 4)),  # unique IPs
                1.0,                   # new IP
                1.0,                   # process count
                0.0,                   # credential access
                0.0,                   # privilege events
                0.0,                   # service installations
                0.0,                   # network events
                float(np.random.randint(0, 24)), # any hour
                2.0,                   # login frequency
                10.0                   # event frequency
            ]
            X.append(vector)
            y.append(1)

        # 3. Malicious Process/Web Shell vectors (label 1)
        for _ in range(20):
            vector = [
                0.0,                   # failed logins
                1.0,                   # successful logins
                1.0,                   # unique IPs
                0.0,                   # new IP
                float(np.random.randint(30, 80)), # extremely high process counts (recon loop)
                1.0,                   # credential access (e.g. read credentials)
                0.0,                   # privilege events
                0.0,                   # service installations
                float(np.random.randint(5, 30)),  # network exfil calls
                float(np.random.randint(0, 24)), # any hour
                0.5,                   # login frequency
                25.0                   # event frequency
            ]
            X.append(vector)
            y.append(1)

        # Train Random Forest Classifier
        try:
            self.model = RandomForestClassifier(n_estimators=50, random_state=42)
            self.model.fit(np.array(X), np.array(y))
            joblib.dump(self.model, MODEL_PATH)
            self.is_loaded = True
            logger.info(f"[ML CLASSIFIER] Bootstrapped model successfully trained and saved to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"[ML CLASSIFIER] Failed to train bootstrap model: {e}", exc_info=True)

    def predict_maliciousness(self, features: dict[str, Any]) -> float:
        """
        Predicts probability of featureset being malicious (0.0 to 1.0).
        """
        if not self.is_loaded:
            return 0.05

        try:
            vector = np.array([extract_feature_vector(features)])
            probs = self.model.predict_proba(vector)[0]
            # Label 1 is malicious probability
            return float(probs[1])
        except Exception as e:
            logger.error(f"[ML CLASSIFIER] Inference error: {e}")
            return 0.05


supervised_classifier = SupervisedSecurityClassifier()
