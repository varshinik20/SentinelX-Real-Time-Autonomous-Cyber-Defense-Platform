from fastapi import APIRouter

from app.response.engine import response_engine

router = APIRouter(prefix="/api/response/actions", tags=["response"])


@router.get("")
async def get_response_actions():
    """
    Returns the list of audited/simulated response actions.
    """
    return response_engine.audit_log
