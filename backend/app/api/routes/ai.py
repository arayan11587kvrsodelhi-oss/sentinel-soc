from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.models.schemas import AnalysisRequest, AnalysisResponse
from app.services.ai_service import analyze_incident

router = APIRouter()


@router.post("/ai/analyze", response_model=Dict[str, Any])
async def analyze_security_event(payload: AnalysisRequest):
    """
    Sentinel AI Defensive Triage Endpoint.
    Analyzes telemetry or incidents, produces MITRE mappings, risk scoring,
    fact-inference breakdown, and actionable defensive response steps.
    """
    try:
        result = await analyze_incident(payload.model_dump())
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI Analysis error: {str(exc)}")

