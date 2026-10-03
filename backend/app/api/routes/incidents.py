from fastapi import APIRouter, HTTPException, Query, Path, Request
from typing import List, Optional, Dict, Any
import logging

from app.models.schemas import Incident, IncidentStatusUpdate
from app.services.correlation_service import correlation_engine
from app.core.logging import get_request_id
from app.services.ai_service import (
    AICallError,
    analyze_incident,
    client_disconnect_signal,
    safe_http_detail,
)

logger = logging.getLogger("sentinel.route.incidents")

router = APIRouter()


@router.get("/incidents", response_model=List[Incident])
async def get_all_incidents(
    status: Optional[str] = Query(None, description="Filter by status: OPEN, INVESTIGATING, CONTAINED, RESOLVED"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    search: Optional[str] = Query(None, description="Search in title, ID, source, target, or summary")
):
    """Retrieve active and correlated security incidents."""
    return correlation_engine.get_incidents(status=status, severity=severity, search=search)


@router.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str = Path(..., description="The Incident ID")):
    """Get complete investigation details for a specific incident."""
    inc = correlation_engine.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc


@router.patch("/incidents/{incident_id}/status", response_model=Incident)
async def update_incident_status(
    incident_id: str = Path(..., description="The Incident ID"),
    payload: IncidentStatusUpdate = ...
):
    """Update the investigation/remediation status of an incident."""
    updated = correlation_engine.update_incident_status(incident_id, payload.status)
    if not updated:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Allowed: OPEN, INVESTIGATING, CONTAINED, RESOLVED"
        )
    return updated


@router.post("/incidents/{incident_id}/ai-triage", response_model=Dict[str, Any])
async def ai_triage_incident(
    request: Request,
    incident_id: str = Path(..., description="The Incident ID"),
):
    """Run Sentinel AI Defensive Triage directly on an active incident."""
    inc = correlation_engine.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    cancel_event, watcher = client_disconnect_signal(request)
    try:
        analysis = await analyze_incident(
            {
                "incident_id": inc.incident_id,
                "event_type": inc.category,
                "severity": inc.severity,
                "source_ip": inc.source_ip,
                "target": inc.target,
                "details": inc.summary,
                "context": {
                    "title": inc.title,
                    "events_count": inc.events_count,
                    "related_cves": inc.related_cves,
                },
            },
            cancel_event=cancel_event,
        )
    except AICallError as exc:
        status_code, detail = safe_http_detail(exc)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        status_code, detail = safe_http_detail(exc)
        logger.exception(
            "Unhandled AI triage error",
            extra={"incident_id": incident_id, "request_id": get_request_id()},
        )
        raise HTTPException(status_code=status_code, detail=detail)
    finally:
        watcher.cancel()

    inc.ai_analysis = analysis
    return analysis

