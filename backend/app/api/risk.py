from fastapi import APIRouter

from app.correlation.engine import correlation_engine

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("")
async def get_risk_status():
    """
    Returns general risk analytics for the platform.
    """
    incidents = list(correlation_engine.incidents.values())
    if not incidents:
        return {
            "highest_risk_score": 0,
            "incident_count": 0,
            "critical_count": 0,
            "high_count": 0,
        }

    highest = max(incidents, key=lambda x: x.risk_score)
    critical_count = sum(1 for i in incidents if i.severity == "CRITICAL")
    high_count = sum(1 for i in incidents if i.severity == "HIGH")

    return {
        "highest_risk_score": highest.risk_score,
        "highest_risk_incident_id": highest.incident_id,
        "incident_count": len(incidents),
        "critical_count": critical_count,
        "high_count": high_count,
    }
