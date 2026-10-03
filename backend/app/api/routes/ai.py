from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any
import logging

from app.models.schemas import AnalysisRequest, AnalysisResponse
from app.core.logging import get_request_id
from app.services.ai_service import (
    AICallError,
    analyze_incident,
    client_disconnect_signal,
    safe_http_detail,
)

logger = logging.getLogger("sentinel.ai.route")

router = APIRouter()


@router.post("/ai/analyze", response_model=Dict[str, Any])
async def analyze_security_event(payload: AnalysisRequest, request: Request):
    """
    Sentinel AI Defensive Triage Endpoint.
    Analyzes telemetry or incidents, produces MITRE mappings, risk scoring,
    fact-inference breakdown, and actionable defensive response steps.

    Failures are reported as a structured, user-safe category. The raw upstream
    provider/gateway payload — which can contain internal routing metadata — is
    logged server-side only and is never echoed to the caller.
    """
    cancel_event, watcher = client_disconnect_signal(request)
    try:
        return await analyze_incident(
            payload.model_dump(), cancel_event=cancel_event
        )
    except AICallError as exc:
        status_code, detail = safe_http_detail(exc)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        status_code, detail = safe_http_detail(exc)
        logger.exception(
            "Unhandled AI analysis error",
            extra={"request_id": get_request_id(), "status_code": status_code},
        )
        raise HTTPException(status_code=status_code, detail=detail)
    finally:
        watcher.cancel()

