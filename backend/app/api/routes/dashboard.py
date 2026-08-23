from fastapi import APIRouter
router = APIRouter()
@router.get("/dashboard")
async def dashboard():
    return {"mode":"live-intelligence + simulation","active_incidents":3,"critical":1,"high":2,"medium":5,"simulated_events":12}
