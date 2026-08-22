from fastapi import APIRouter

from app.core.events import DetectionAlert
from app.streaming.event_manager import event_manager

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("", response_model=list[DetectionAlert])
async def get_threats():
    """
    Returns the sliding cache of generated alerts/threats.
    """
    # Filter for DetectionAlerts only
    return [e for e in event_manager.events if isinstance(e, DetectionAlert)]
