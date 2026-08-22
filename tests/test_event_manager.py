import asyncio
import pytest

from app.core.events import SecurityEvent, EventType, Severity
from app.streaming.event_manager import EventManager


@pytest.mark.asyncio
async def test_event_manager_pub_sub():
    mgr = EventManager()
    queue = mgr.subscribe()

    event = SecurityEvent(
        event_id="test-1",
        event_type=EventType.LOGIN_SUCCESS,
        severity=Severity.LOW,
        message="Login successful",
    )

    await mgr.publish(event)

    # Verify event is received by subscription queue
    received = await queue.get()
    assert received.event_id == "test-1"

    mgr.unsubscribe(queue)


@pytest.mark.asyncio
async def test_event_manager_multiple_subscribers():
    mgr = EventManager()
    q1 = mgr.subscribe()
    q2 = mgr.subscribe()

    event = SecurityEvent(
        event_id="test-2",
        event_type=EventType.LOGIN_FAILURE,
        severity=Severity.HIGH,
        message="Login failed",
    )

    await mgr.publish(event)

    r1 = await q1.get()
    r2 = await q2.get()

    assert r1.event_id == "test-2"
    assert r2.event_id == "test-2"

    mgr.unsubscribe(q1)
    mgr.unsubscribe(q2)


@pytest.mark.asyncio
async def test_event_manager_slow_client_isolation():
    mgr = EventManager()
    # Subscribe queue with small maxsize
    queue = asyncio.Queue(maxsize=1)
    mgr.clients.add(queue)

    event = SecurityEvent(
        event_id="test-3",
        event_type=EventType.PROCESS_CREATED,
        severity=Severity.LOW,
    )

    # First event fills the queue
    await mgr.publish(event)
    assert queue.qsize() == 1

    # Second event should trigger QueueFull exception internally,
    # causing the manager to discard/unsubscribe this client
    await mgr.publish(event)

    assert queue not in mgr.clients
