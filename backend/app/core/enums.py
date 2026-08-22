from enum import Enum


class WebSocketMessageType(str, Enum):
    EVENT = "EVENT"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    RISK_UPDATE = "RISK_UPDATE"
    RESPONSE = "RESPONSE"
    STATUS = "STATUS"
