import logging
from datetime import datetime, timezone, timedelta
import uuid

from app.core.config import settings
from app.core.events import SecurityEvent, DetectionAlert
from app.core.enums import WebSocketMessageType
from app.correlation.attack_graph import attack_graph_generator
from app.correlation.mitre import mitre_mapper
from app.risk.risk_engine import risk_engine
from app.ai.investigator import ai_investigator
from app.response.engine import response_engine
from app.incidents.models import Incident
from app.streaming.event_manager import event_manager
from app.database.session import AsyncSessionLocal
from app.database.models import IncidentModel

logger = logging.getLogger("sentinelx.correlation")


class CorrelationEngine:
    def __init__(self, session_window_minutes: int = 15):
        self.incidents: dict[str, Incident] = {}
        self.session_window_minutes = session_window_minutes

    async def correlate_alert(
        self, alert: DetectionAlert, event_history: list[SecurityEvent]
    ) -> Incident:
        """
        Receives an alert, checks if it correlates with an active incident,
        updates risk, maps MITRE ATT&CK, updates the attack graph, triggers AI,
        evaluates response controls, saves to DB, and broadcasts incident updates.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.session_window_minutes)

        target_incident = None
        for inc in self.incidents.values():
            if inc.updated_at >= cutoff:
                match_host = inc.host == alert.host and alert.host is not None
                match_user = inc.user == alert.user and alert.user is not None and alert.user != "unknown"
                match_ip = any(ip in inc.source_ips for ip in ([alert.host] if alert.host else []))
                
                if match_host or match_user or match_ip:
                    target_incident = inc
                    break

        associated_events = [
            e for e in event_history
            if e.host == alert.host
            or (e.user == alert.user and alert.user is not None)
            or (e.source_ip == alert.host and alert.host is not None)
        ]
        
        event_ids = [e.event_id for e in associated_events]

        max_anomaly_score = 0.0
        if alert.rule_id == "ML-001":
            max_anomaly_score = alert.evidence.get("anomaly_score", 0.0)

        if target_incident:
            logger.info(f"[CORRELATION] Correlating alert {alert.rule_id} into existing incident {target_incident.incident_id}")
            
            if not any(a.alert_id == alert.alert_id for a in target_incident.related_alerts):
                target_incident.related_alerts.append(alert)

            for eid in event_ids:
                if eid not in target_incident.related_event_ids:
                    target_incident.related_event_ids.append(eid)

            if alert.user and not target_incident.user:
                target_incident.user = alert.user
            if alert.host and alert.host not in target_incident.source_ips:
                if "." in alert.host or ":" in alert.host:
                    target_incident.source_ips.append(alert.host)

            for a in target_incident.related_alerts:
                if a.rule_id == "ML-001":
                    max_anomaly_score = max(max_anomaly_score, a.evidence.get("anomaly_score", 0.0))

            risk_res = risk_engine.calculate_incident_risk(target_incident.related_alerts, max_anomaly_score)
            target_incident.risk_score = risk_res["risk_score"]
            target_incident.severity = risk_res["risk_band"]
            
            mitre_tag = mitre_mapper.map_alert(alert)
            if mitre_tag and not any(t["technique_id"] == mitre_tag["technique_id"] for t in target_incident.attack_techniques):
                target_incident.attack_techniques.append(mitre_tag)

            target_incident.attack_graph = attack_graph_generator.generate_graph(
                target_incident.related_alerts, associated_events
            )

            summary, recs = ai_investigator.investigate_incident(target_incident)
            target_incident.ai_summary = summary
            target_incident.recommendations = recs

            response_engine.evaluate_response_policy(target_incident)

            target_incident.updated_at = now
            incident = target_incident

        else:
            incident_id = str(uuid.uuid4())
            logger.info(f"[CORRELATION] Creating new incident {incident_id} for alert {alert.rule_id}")

            mitre_tags = []
            mitre_tag = mitre_mapper.map_alert(alert)
            if mitre_tag:
                mitre_tags.append(mitre_tag)

            risk_res = risk_engine.calculate_incident_risk([alert], max_anomaly_score)

            incident = Incident(
                incident_id=incident_id,
                severity=risk_res["risk_band"],
                risk_score=risk_res["risk_score"],
                host=alert.host or "unknown",
                user=alert.user,
                source_ips=[alert.host] if alert.host and ("." in alert.host or ":" in alert.host) else [],
                related_event_ids=event_ids,
                related_alerts=[alert],
                attack_techniques=mitre_tags,
                evidence=[alert.message],
                recommendations=[],
                attack_graph={},
                ai_summary=None
            )

            incident.attack_graph = attack_graph_generator.generate_graph([alert], associated_events)
            summary, recs = ai_investigator.investigate_incident(incident)
            incident.ai_summary = summary
            incident.recommendations = recs
            response_engine.evaluate_response_policy(incident)

            self.incidents[incident_id] = incident

        # Save Incident to Persistent Database
        await self._persist_incident(incident)

        # Broadcast incident updates
        await event_manager.publish(incident)

        return incident

    async def _persist_incident(self, incident: Incident):
        try:
            async with AsyncSessionLocal() as db:
                db_inc = await db.get(IncidentModel, incident.incident_id)
                if db_inc:
                    db_inc.updated_at = incident.updated_at
                    db_inc.severity = incident.severity
                    db_inc.risk_score = incident.risk_score
                    db_inc.status = incident.status
                    db_inc.user = incident.user
                    db_inc.source_ips = incident.source_ips
                    db_inc.related_event_ids = incident.related_event_ids
                    db_inc.related_alerts = [a.model_dump(mode="json") for a in incident.related_alerts]
                    db_inc.attack_techniques = incident.attack_techniques
                    db_inc.evidence = incident.evidence
                    db_inc.recommendations = incident.recommendations
                    db_inc.attack_graph = incident.attack_graph
                    db_inc.ai_summary = incident.ai_summary
                else:
                    db_inc = IncidentModel(
                        incident_id=incident.incident_id,
                        created_at=incident.created_at,
                        updated_at=incident.updated_at,
                        severity=incident.severity,
                        risk_score=incident.risk_score,
                        status=incident.status,
                        host=incident.host,
                        user=incident.user,
                        source_ips=incident.source_ips,
                        related_event_ids=incident.related_event_ids,
                        related_alerts=[a.model_dump(mode="json") for a in incident.related_alerts],
                        attack_techniques=incident.attack_techniques,
                        evidence=incident.evidence,
                        recommendations=incident.recommendations,
                        attack_graph=incident.attack_graph,
                        ai_summary=incident.ai_summary,
                    )
                    db.add(db_inc)
                await db.commit()
        except Exception as e:
            logger.error(f"[DATABASE] Failed to persist incident {incident.incident_id}: {e}")


correlation_engine = CorrelationEngine()
