from datetime import datetime, timezone
from typing import Any
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.database.session import engine


class Base(DeclarativeBase):
    pass


class EventModel(Base):
    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, default="sentinelx")
    host: Mapped[str] = mapped_column(String, default="unknown")
    user: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_process: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="LOW")
    message: Mapped[str] = mapped_column(String, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AlertModel(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    rule_name: Mapped[str] = mapped_column(String, nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[float] = mapped_column(Integer, default=0.0)
    risk_contribution: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    user: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str] = mapped_column(String, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String, default="OPEN")
    host: Mapped[str] = mapped_column(String, default="unknown")
    user: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_alerts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    attack_graph: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ai_summary: Mapped[str | None] = mapped_column(String, nullable=True)


async def init_db():
    """
    Initializes SQL tables asynchronously.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
