from fastapi import APIRouter
from datetime import datetime, timezone
router = APIRouter()
@router.get("/threats")
async def threats():
    return [{"id":"SIM-001","type":"BRUTE_FORCE","severity":"CRITICAL","status":"BLOCKED","source":"SIMULATION","timestamp":datetime.now(timezone.utc).isoformat()}]
