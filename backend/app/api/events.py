from fastapi import APIRouter

from app.core.events import SecurityEvent
from app.streaming.event_manager import event_manager

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[SecurityEvent])
async def get_events():
    """
    Returns the sliding cache of raw security events.
    """
    # Filter for raw SecurityEvents only
    return [e for e in event_manager.events if isinstance(e, SecurityEvent)]
