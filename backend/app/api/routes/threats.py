from fastapi import APIRouter, Query
from typing import List, Optional
from app.models.schemas import SecurityEvent
from app.services.correlation_service import correlation_engine

router = APIRouter()


@router.get("/threats", response_model=List[SecurityEvent])
async def get_threats(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=200, description="Max events to return")
):
    """Retrieve recent simulated security telemetry events."""
    events = correlation_engine.get_recent_events(limit=limit)

    if severity:
        events = [e for e in events if e.severity.upper() == severity.upper()]

    if event_type:
        events = [e for e in events if e.event_type.upper() == event_type.upper()]

    return events

