from datetime import datetime, timezone, timedelta
import logging

from app.core.events import SecurityEvent, DetectionAlert
from app.detection.rules import ALL_RULES

logger = logging.getLogger("sentinelx.rule_engine")


class RuleEngine:
    def __init__(self, max_history_size: int = 2000, history_window_minutes: int = 15):
        self.history: list[SecurityEvent] = []
        self.max_history_size = max_history_size
        self.history_window_minutes = history_window_minutes

    def evaluate_event(self, event: SecurityEvent) -> list[DetectionAlert]:
        alerts = []

        # Evaluate rules against the current event and historical context
        for rule in ALL_RULES:
            try:
                alert = rule.evaluate(event, self.history)
                if alert:
                    alerts.append(alert)
                    logger.info(
                        f"[RULE MATCH] {rule.rule_id} ({rule.rule_name}) on host '{event.host}': {alert.message}"
                    )
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}", exc_info=True)

        # Append current event to the historical window
        self.history.append(event)

        # Prune older history to bound memory and enforce sliding time-window limits
        self._prune_history(event.timestamp)

        return alerts

    def _prune_history(self, current_time: datetime):
        cutoff = current_time - timedelta(minutes=self.history_window_minutes)
        # Keep events newer than the cutoff, and within size limits
        self.history = [e for e in self.history if e.timestamp >= cutoff]
        
        if len(self.history) > self.max_history_size:
            self.history = self.history[-self.max_history_size:]


rule_engine = RuleEngine()
