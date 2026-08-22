import logging
from datetime import datetime, timezone
import uuid
from typing import Any

from app.core.config import settings
from app.incidents.models import Incident

logger = logging.getLogger("sentinelx.response")


class ResponseEngine:
    def __init__(self):
        self.audit_log: list[dict[str, Any]] = []

    def evaluate_response_policy(self, incident: Incident) -> list[dict[str, Any]]:
        """
        Determines and executes simulated mitigation actions based on incident risk scores.
        Every action is executed in DRY_RUN mode, creating a secure audit trail.
        """
        risk = incident.risk_score
        actions = []

        # Map risk thresholds to response levels
        if risk >= 86:
            actions.append({
                "action": "SIMULATE_ISOLATE_HOST",
                "target": incident.host,
                "reason": f"Critical risk score ({risk}/100) requires immediate containment."
            })
            if incident.user:
                actions.append({
                    "action": "SIMULATE_DISABLE_ACCOUNT",
                    "target": incident.user,
                    "reason": f"Critical risk score ({risk}/100) indicates user credentials compromise."
                })
        elif risk >= 71:
            actions.append({
                "action": "SIMULATE_TERMINATE_PROCESS",
                "target": "Suspicious Terminal Process",
                "reason": f"High risk score ({risk}/100) indicates active command execution."
            })
            if incident.source_ips:
                for ip in incident.source_ips:
                    actions.append({
                        "action": "SIMULATE_BLOCK_IP",
                        "target": ip,
                        "reason": f"High risk score ({risk}/100) indicates authentication brute-force."
                    })
        elif risk >= 51:
            actions.append({
                "action": "REQUIRE_HUMAN_REVIEW",
                "target": "incident-analyst-queue",
                "reason": "Elevated risk profile. Analyst intervention recommended."
            })
        else:
            actions.append({
                "action": "ALLOW_AND_LOG",
                "target": "sentinelx-syslog",
                "reason": "Low/Medium risk profile. Regular monitoring."
            })

        # Process and audit response actions
        audited_actions = []
        for act in actions:
            action_id = str(uuid.uuid4())
            audit_entry = {
                "action_id": action_id,
                "incident_id": incident.incident_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action_type": act["action"],
                "target": act["target"],
                "reason": act["reason"],
                "mode": settings.RESPONSE_MODE,
                "status": "SIMULATED_SUCCESS" if settings.RESPONSE_MODE == "DRY_RUN" else "EXECUTED"
            }
            audited_actions.append(audit_entry)
            self.audit_log.append(audit_entry)
            logger.info(
                f"[RESPONSE] [{settings.RESPONSE_MODE}] {act['action']} for {act['target']}: {act['reason']}"
            )

        return audited_actions


response_engine = ResponseEngine()
