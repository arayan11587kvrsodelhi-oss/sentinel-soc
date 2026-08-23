from fastapi import APIRouter, Query
from typing import Optional, List, Dict, Any
from app.services.nvd_service import fetch_recent_cves
from app.services.cisa_service import fetch_kev_catalog

router = APIRouter()


@router.get("/vulnerabilities")
async def get_vulnerabilities(
    search: Optional[str] = Query(None, description="Search term in CVE ID, description, or affected products"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    kev_only: bool = Query(False, description="Filter only CVEs confirmed in CISA KEV"),
    limit: int = Query(30, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    force_refresh: bool = Query(False, description="Bypass cache and force refresh from NVD/CISA")
):
    """Retrieve enriched NVD vulnerabilities cross-referenced with CISA KEV catalog."""
    return await fetch_recent_cves(
        force=force_refresh,
        search=search,
        severity=severity,
        kev_only=kev_only,
        limit=limit,
        offset=offset
    )


@router.get("/vulnerabilities/kev")
async def get_kev_catalog(
    search: Optional[str] = Query(None, description="Search in CVE ID, vendor, product, or vulnerability name"),
    ransomware_only: bool = Query(False, description="Filter only vulnerabilities used in ransomware campaigns"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    force_refresh: bool = Query(False, description="Force refresh CISA feed")
):
    """Retrieve official CISA Known Exploited Vulnerabilities catalog with search and filtering."""
    return await fetch_kev_catalog(
        search=search,
        ransomware_only=ransomware_only,
        limit=limit,
        offset=offset
    )

