from typing import Optional

from fastapi import APIRouter, Query

from app.services.cisa_service import fetch_kev_catalog
from app.services.nvd_service import fetch_recent_cves

router = APIRouter()


@router.get("/vulnerabilities")
async def get_vulnerabilities(
    search: Optional[str] = Query(
        default=None,
        description="Search term in CVE ID, description, or affected products",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW",
    ),
    kev_only: bool = Query(
        default=False,
        description="Filter only CVEs confirmed in CISA KEV",
    ),
    limit: int = Query(
        default=30,
        ge=1,
        le=100,
        description="Page size",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Pagination offset",
    ),
    force_refresh: bool = Query(
        default=False,
        description="Bypass cache and force refresh from NVD/CISA",
    ),
):
    """
    Retrieve enriched NVD vulnerability intelligence.

    The NVD service is responsible for:
    - NIST NVD 2.0 retrieval
    - CVSS parsing
    - CWE / CPE extraction
    - CISA KEV cross-referencing
    - caching / fallback handling
    - search / filtering / pagination
    - data_source metadata
    """

    return await fetch_recent_cves(
        force=force_refresh,
        search=search,
        severity=severity,
        kev_only=kev_only,
        limit=limit,
        offset=offset,
    )


@router.get("/vulnerabilities/kev")
async def get_kev_catalog(
    search: Optional[str] = Query(
        default=None,
        description="Search in CVE ID, vendor, product, or vulnerability name",
    ),
    ransomware_only: bool = Query(
        default=False,
        description="Filter only vulnerabilities used in ransomware campaigns",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
        description="Page size",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Pagination offset",
    ),
    force_refresh: bool = Query(
        default=False,
        description="Force refresh CISA KEV feed",
    ),
):
    """
    Retrieve the official CISA Known Exploited Vulnerabilities catalog.

    The CISA service is responsible for:
    - official CISA KEV retrieval
    - caching
    - fallback handling
    - search
    - ransomware filtering
    - pagination
    - data_source metadata
    """

    return await fetch_kev_catalog(
        search=search,
        ransomware_only=ransomware_only,
        limit=limit,
        offset=offset,
        force=force_refresh,
    )