from fastapi import APIRouter, HTTPException, Query, Path
from typing import List, Optional, Dict, Any
from app.models.schemas import Incident, IncidentStatusUpdate
from app.services.correlation_service import correlation_engine
from app.services.ai_service import analyze_incident

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
async def ai_triage_incident(incident_id: str = Path(..., description="The Incident ID")):
    """Run Sentinel AI Defensive Triage directly on an active incident."""
    inc = correlation_engine.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    analysis = await analyze_incident({
        "incident_id": inc.incident_id,
        "event_type": inc.category,
        "severity": inc.severity,
        "source_ip": inc.source_ip,
        "target": inc.target,
        "details": inc.summary,
        "context": {
            "title": inc.title,
            "events_count": inc.events_count,
            "related_cves": inc.related_cves
        }
    })

    inc.ai_analysis = analysis
    return analysis

