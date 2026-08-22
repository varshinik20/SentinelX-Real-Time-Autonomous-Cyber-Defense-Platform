from fastapi import APIRouter, HTTPException

from app.correlation.engine import correlation_engine

router = APIRouter(prefix="/api/attack-graph", tags=["attack-graph"])


@router.get("/{incident_id}")
async def get_attack_graph(incident_id: str):
    """
    Returns nodes and edges mapping the attack path for an incident.
    """
    incident = correlation_engine.incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.attack_graph
