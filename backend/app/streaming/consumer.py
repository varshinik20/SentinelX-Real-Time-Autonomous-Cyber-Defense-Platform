import asyncio
import logging
from typing import Union

from app.core.events import SecurityEvent, DetectionAlert, Severity
from app.core.status import system_status
from app.correlation.engine import correlation_engine
from app.detection.anomaly import anomaly_detector
from app.detection.behavioral import behavioral_engine
from app.detection.rule_engine import rule_engine
from app.streaming.event_manager import event_manager
from app.database.session import AsyncSessionLocal
from app.database.models import EventModel, AlertModel

logger = logging.getLogger("sentinelx.consumer")


class DetectionConsumer:
    def __init__(self):
        self.is_running = False
        self._task = None
        self.event_counter = 0

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._consume_loop())
        system_status.detection_engine = "RUNNING"
        system_status.correlation_engine = "RUNNING"
        logger.info("[DETECTION] Detection engine consumer task started.")

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        system_status.detection_engine = "STOPPED"
        system_status.correlation_engine = "STOPPED"
        logger.info("[DETECTION] Detection engine consumer task stopped.")

    async def _consume_loop(self):
        queue = event_manager.subscribe()

        while self.is_running:
            try:
                event = await queue.get()

                # Guard: Only evaluate raw SecurityEvents (ignore already-generated alerts and incidents)
                if not isinstance(event, SecurityEvent):
                    queue.task_done()
                    continue

                # Async task to write event to SQLite DB in background
                asyncio.create_task(self._persist_event(event))

                # 1. Update behavioral profiles & fetch rolling features
                profile_features = behavioral_engine.update_profiles(event)
                
                # Check anomaly score for each updated entity profile (host/user/ip)
                for entity_key, features in profile_features.items():
                    anomaly_detector.add_training_sample(features)
                    
                    anomaly_score, normality_score, top_features = anomaly_detector.predict_anomaly(features)
                    
                    # If anomaly score crosses threshold (e.g. 65), generate an anomaly alert
                    if anomaly_score > 65.0:
                        entity_type, entity_id = entity_key.split(":", 1)
                        alert = DetectionAlert(
                            alert_id=f"ML-{entity_id}-{int(event.timestamp.timestamp())}",
                            rule_id="ML-001",
                            rule_name="Machine Learning Behavioral Anomaly",
                            matched=True,
                            confidence=anomaly_score / 100.0,
                            evidence={
                                "entity_key": entity_key,
                                "entity_type": entity_type,
                                "anomaly_score": anomaly_score,
                                "normality_score": normality_score,
                                "contributing_features": top_features,
                                "feature_vector": features,
                            },
                            risk_contribution=int(anomaly_score * 0.4),
                            host=event.host if entity_type == "host" else None,
                            user=event.user if entity_type == "user" else None,
                            message=f"ML Anomaly detected on {entity_key}: Score {anomaly_score:.1f}/100. Contributing factors: {', '.join(top_features[:2])}"
                        )
                        # Publish, Persist & Correlate alert
                        await event_manager.publish(alert)
                        asyncio.create_task(self._persist_alert(alert))
                        await correlation_engine.correlate_alert(alert, rule_engine.history)

                # 2. Run deterministic rule engine
                alerts = rule_engine.evaluate_event(event)
                for alert in alerts:
                    await event_manager.publish(alert)
                    asyncio.create_task(self._persist_alert(alert))
                    await correlation_engine.correlate_alert(alert, rule_engine.history)

                # 3. Increment counter and periodically train Isolation Forest in background
                self.event_counter += 1
                if self.event_counter % 50 == 0:
                    logger.info("[DETECTION] Triggering background retraining of Isolation Forest...")
                    await asyncio.to_thread(anomaly_detector.train)

                queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[DETECTION] Error processing event in consumer: {e}", exc_info=True)

    async def _persist_event(self, event: SecurityEvent):
        try:
            async with AsyncSessionLocal() as db:
                db_event = EventModel(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    event_type=event.event_type.value,
                    source=event.source,
                    host=event.host,
                    user=event.user,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    process_name=event.process_name,
                    parent_process=event.parent_process,
                    severity=event.severity.value,
                    message=event.message,
                    metadata_json=event.metadata,
                )
                db.add(db_event)
                await db.commit()
        except Exception as e:
            logger.error(f"[DATABASE] Failed to persist event {event.event_id}: {e}")

    async def _persist_alert(self, alert: DetectionAlert):
        try:
            async with AsyncSessionLocal() as db:
                db_alert = AlertModel(
                    alert_id=alert.alert_id,
                    rule_id=alert.rule_id,
                    rule_name=alert.rule_name,
                    matched=alert.matched,
                    confidence=alert.confidence,
                    risk_contribution=alert.risk_contribution,
                    timestamp=alert.timestamp,
                    host=alert.host,
                    user=alert.user,
                    message=alert.message,
                    evidence=alert.evidence,
                )
                db.add(db_alert)
                await db.commit()
        except Exception as e:
            logger.error(f"[DATABASE] Failed to persist alert {alert.alert_id}: {e}")


detection_consumer = DetectionConsumer()
