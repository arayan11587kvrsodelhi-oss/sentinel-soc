from fastapi import APIRouter
from pydantic import BaseModel
from app.services.ai_service import analyze_incident
router = APIRouter()
class AnalysisRequest(BaseModel):
    event_type: str
    severity: str
    details: str
@router.post("/ai/analyze")
async def analyze(payload: AnalysisRequest):
    return await analyze_incident(payload.model_dump())
