import asyncio
import random
import uuid

from app.core.events import (
    EventType,
    SecurityEvent,
    Severity,
)
from app.streaming.event_manager import event_manager


EVENT_TEMPLATES = [
    {
        "event_type": EventType.LOGIN_FAILURE,
        "severity": Severity.MEDIUM,
        "message": "Failed authentication attempt",
    },
    {
        "event_type": EventType.LOGIN_SUCCESS,
        "severity": Severity.LOW,
        "message": "Successful user authentication",
    },
    {
        "event_type": EventType.PROCESS_CREATED,
        "severity": Severity.LOW,
        "message": "New process created",
    },
    {
        "event_type": EventType.NETWORK_CONNECTION,
        "severity": Severity.LOW,
        "message": "Outbound network connection detected",
    },
    {
        "event_type": EventType.FILE_ACCESS,
        "severity": Severity.MEDIUM,
        "message": "File access detected",
    },
    {
        "event_type": EventType.DATA_TRANSFER,
        "severity": Severity.HIGH,
        "message": "Large outbound data transfer detected",
    },
]


async def generate_events():

    while True:

        template = random.choice(EVENT_TEMPLATES)

        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=template["event_type"],
            severity=template["severity"],
            host="SENTINELX-LAB",
            user="test-user",
            source_ip="192.168.1.50",
            message=template["message"],
            metadata={
                "generator": "development",
                "bytes": random.randint(1000, 10_000_000),
            },
        )

        await event_manager.publish(event)

        print(
            f"[EVENT] "
            f"{event.timestamp.isoformat()} | "
            f"{event.event_type.value} | "
            f"{event.severity.value}"
        )

        await asyncio.sleep(2)