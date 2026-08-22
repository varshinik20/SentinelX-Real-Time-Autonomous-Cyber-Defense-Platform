from fastapi import APIRouter, HTTPException

from app.incidents.models import Incident
from app.correlation.engine import correlation_engine

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[Incident])
async def get_incidents():
    """
    Returns all active correlated security incidents.
    """
    return list(correlation_engine.incidents.values())


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    """
    Returns details for a specific incident.
    """
    incident = correlation_engine.incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
