from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field

from app.core.events import DetectionAlert


class Incident(BaseModel):
    incident_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str  # LOW, MEDIUM, ELEVATED, HIGH, CRITICAL
    risk_score: int  # 0-100
    status: str = "OPEN"  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    host: str
    user: str | None = None
    source_ips: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    related_alerts: list[DetectionAlert] = Field(default_factory=list)
    attack_techniques: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    attack_graph: dict[str, Any] = Field(default_factory=dict)
    ai_summary: str | None = None
