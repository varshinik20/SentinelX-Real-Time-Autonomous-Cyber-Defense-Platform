import logging
from typing import Any

from app.incidents.models import Incident

logger = logging.getLogger("sentinelx.ai_investigator")


class AIInvestigator:
    @staticmethod
    def investigate_incident(incident: Incident) -> tuple[str, list[str]]:
        """
        Analyzes an incident's alerts and MITRE techniques to formulate:
        1. An AI summary explaining the security impact.
        2. A list of analyst investigation playbooks and containment recommendations.
        """
        alerts = incident.related_alerts
        techniques = [t.get("technique_name", "") for t in incident.attack_techniques]

        # Base templates for different alert types
        summary = ""
        recommendations = []

        is_brute_force = any(a.rule_id == "RULE-001" for a in alerts)
        is_success_after_fail = any(a.rule_id == "RULE-002" for a in alerts)
        is_service_installed = any(a.rule_id == "RULE-004" for a in alerts)
        is_cred_access = any(a.rule_id == "RULE-005" for a in alerts)
        is_proc_chain = any(a.rule_id == "RULE-008" for a in alerts)
        is_ml_anomaly = any(a.rule_id == "ML-001" for a in alerts)

        # Build evidence text
        evidence_summary = ", ".join([a.rule_name for a in alerts])

        if is_proc_chain or is_service_installed:
            summary = (
                f"AI ANALYSIS: Critical execution activity detected on host {incident.host}. "
                f"Correlated evidence ({evidence_summary}) indicates a multi-stage attack involving "
                f"suspicious process spawning or service registration. The technique(s) involved "
                f"({', '.join(techniques)}) are commonly used by threat actors to establish persistence "
                f"or run local shell discovery commands."
            )
            recommendations.extend([
                "Inspect the parent process execution paths and look for anomalous script/command arguments.",
                "Verify the checksum of the newly created service binary or process image.",
                "Isolate the host immediately to prevent lateral movement.",
                "Harvest memory logs from the host to check for active web shell threads."
            ])

        elif is_brute_force or is_success_after_fail:
            summary = (
                f"AI ANALYSIS: High-volume authentication anomalies detected targeting user account '{incident.user}' "
                f"on host {incident.host}. Evidence suggests active brute-force or credential stuffing "
                f"originating from {', '.join(incident.source_ips)}. The subsequent login success "
                f"points to a high-probability account compromise."
            )
            recommendations.extend([
                "Audit the user's active session logs and terminate all existing connections.",
                "Force an immediate password reset for account " + str(incident.user) + ".",
                "Review other endpoints for successful logons from the same source IP addresses.",
                "Check for modifications to security group memberships or credentials."
            ])
            
        elif is_ml_anomaly:
            summary = (
                f"AI ANALYSIS: Unsupervised machine learning flag raised on host {incident.host}. "
                f"Entity profile behavior has significantly drifted from established normal baselines. "
                f"Key deviations include elevated event frequencies and non-standard processes."
            )
            recommendations.extend([
                "Analyze the top anomalous features identified by the Isolation Forest model.",
                "Confirm if the activity aligns with scheduled administration window tasks.",
                "Correlate IP connection graphs with other hosts on the same network subnet."
            ])

        else:
            summary = (
                f"AI ANALYSIS: Suspicious activity correlated on host {incident.host} involving "
                f"{evidence_summary}. Risk calculations indicate an elevated risk profile."
            )
            recommendations.extend([
                "Review the incident event list for unusual registry or file system changes.",
                "Enable enhanced audit logging on host " + str(incident.host) + ".",
                "Correlate the timeline with firewall access logs."
            ])

        return summary, recommendations


ai_investigator = AIInvestigator()
