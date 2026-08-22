from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    EXPLICIT_CREDENTIAL_LOGIN = "EXPLICIT_CREDENTIAL_LOGIN"
    SPECIAL_PRIVILEGES = "SPECIAL_PRIVILEGES"
    PROCESS_CREATED = "PROCESS_CREATED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    SERVICE_INSTALLED = "SERVICE_INSTALLED"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    REGISTRY_CHANGE = "REGISTRY_CHANGE"
    SCRIPT_EXECUTION = "SCRIPT_EXECUTION"
    DATA_TRANSFER = "DATA_TRANSFER"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    event_type: EventType
    source: str = "sentinelx"
    host: str = "unknown"
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    severity: Severity = Severity.LOW
    message: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    matched: bool
    confidence: float
    evidence: dict[str, Any] = Field(default_factory=dict)
    risk_contribution: int
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    host: str | None = None
    user: str | None = None
    message: str = ""