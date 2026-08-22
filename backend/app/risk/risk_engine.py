from typing import Any

from app.core.events import DetectionAlert


class RiskEngine:
    @staticmethod
    def calculate_incident_risk(
        alerts: list[DetectionAlert], max_anomaly_score: float = 0.0
    ) -> dict[str, Any]:
        """
        Computes dynamic 0-100 risk score and categorizes into severity bands.
        Returns:
            risk_score (int): 0-100 capped value.
            risk_band (str): LOW, MEDIUM, ELEVATED, HIGH, CRITICAL.
            contributors (list[str]): Text explanations for risk factors.
        """
        total_score = 0
        contributors = []
        seen_rules = set()

        # Aggregate risk from deterministic rule matches (avoid double-counting the same rule)
        for alert in alerts:
            if alert.rule_id not in seen_rules:
                seen_rules.add(alert.rule_id)
                total_score += alert.risk_contribution
                contributors.append(f"{alert.rule_name} ({alert.rule_id}): +{alert.risk_contribution}")

        # Integrate unsupervised ML anomaly score contributions (weighted at 35%)
        if max_anomaly_score > 0:
            anomaly_contrib = int(max_anomaly_score * 0.35)
            if anomaly_contrib > 0:
                total_score += anomaly_contrib
                contributors.append(
                    f"Machine Learning Anomaly Profile (Score {max_anomaly_score:.1f}): +{anomaly_contrib}"
                )

        risk_score = min(100, total_score)

        # Categorize into standard cybersecurity risk bands
        if risk_score <= 30:
            risk_band = "LOW"
        elif risk_score <= 50:
            risk_band = "MEDIUM"
        elif risk_score <= 70:
            risk_band = "ELEVATED"
        elif risk_score <= 85:
            risk_band = "HIGH"
        else:
            risk_band = "CRITICAL"

        return {
            "risk_score": risk_score,
            "risk_band": risk_band,
            "contributors": contributors,
        }


risk_engine = RiskEngine()
