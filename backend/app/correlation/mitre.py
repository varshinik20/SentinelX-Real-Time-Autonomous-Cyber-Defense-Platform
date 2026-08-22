from typing import Any

from app.core.events import DetectionAlert


class MitreMapper:
    # Mapping Rule IDs to MITRE ATT&CK techniques
    MITRE_MAP = {
        "RULE-001": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "confidence": 0.9,
        },
        "RULE-002": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access / Persistence",
            "confidence": 0.85,
        },
        "RULE-003": {
            "technique_id": "T1078.002",
            "technique_name": "Domain Accounts (Special Privilege logon)",
            "tactic": "Privilege Escalation",
            "confidence": 0.8,
        },
        "RULE-004": {
            "technique_id": "T1543.003",
            "technique_name": "Windows Service",
            "tactic": "Persistence / Privilege Escalation",
            "confidence": 0.9,
        },
        "RULE-005": {
            "technique_id": "T1555",
            "technique_name": "Credentials from Password Stores (Credential Manager read)",
            "tactic": "Credential Access",
            "confidence": 0.9,
        },
        "RULE-006": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access",
            "confidence": 0.7,
        },
        "RULE-007": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts (Multi-Anomaly Activity)",
            "tactic": "Defense Evasion",
            "confidence": 0.6,
        },
        "RULE-008": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "confidence": 0.95,
        },
        "ML-001": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts (Behavioral Anomaly)",
            "tactic": "Initial Access / Execution",
            "confidence": 0.75,
        },
    }

    @classmethod
    def map_alert(cls, alert: DetectionAlert) -> dict[str, Any] | None:
        """
        Maps a DetectionAlert to a MITRE ATT&CK technique with tactic and confidence score.
        """
        mapping = cls.MITRE_MAP.get(alert.rule_id)
        if not mapping:
            return None
        
        return {
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "tactic": mapping["tactic"],
            "confidence": mapping["confidence"],
            "evidence": alert.message,
        }


mitre_mapper = MitreMapper()
