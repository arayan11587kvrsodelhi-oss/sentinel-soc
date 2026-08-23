from fastapi import APIRouter
from datetime import datetime, timezone
from app.services.correlation_service import correlation_engine
from app.services.nvd_service import fetch_recent_cves, _nvd_cache
from app.services.cisa_service import refresh_kev_cache, _kev_cache

router = APIRouter()


@router.get("/dashboard")
async def get_dashboard_summary():
    """Retrieve dynamic aggregated SOC metrics across events, incidents, NVD, and CISA KEV."""
    # Ensure intelligence caches are primed
    kev_cache = await refresh_kev_cache()
    nvd_data = await fetch_recent_cves(limit=1)

    recent_events = correlation_engine.get_recent_events(limit=100)
    incidents = correlation_engine.get_incidents()

    critical_events = sum(1 for e in recent_events if e.severity == "CRITICAL")
    high_events = sum(1 for e in recent_events if e.severity == "HIGH")
    medium_events = sum(1 for e in recent_events if e.severity == "MEDIUM")
    low_events = sum(1 for e in recent_events if e.severity == "LOW")

    open_incidents = sum(1 for i in incidents if i.status in ("OPEN", "INVESTIGATING"))

    nvd_total = nvd_data.get("total", len(_nvd_cache.get("items", [])))
    kev_total = kev_cache.get("total", len(kev_cache.get("dict", {})))

    return {
        "status": "operational",
        "mode": "live-intelligence + controlled-simulation",
        "active_incidents": open_incidents,
        "total_incidents": len(incidents),
        "critical_events": critical_events,
        "high_events": high_events,
        "medium_events": medium_events,
        "low_events": low_events,
        "total_events_streamed": len(recent_events),
        "nvd_records_total": nvd_total,
        "nvd_records_cached": nvd_total,
        "nvd_data_source": nvd_data.get("data_source", "CACHED_NVD"),
        "kev_catalog_total": kev_total,
        "kev_records_cached": kev_total,
        "kev_data_source": kev_cache.get("data_source", "CACHED_CISA_KEV"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


