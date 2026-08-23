from fastapi import APIRouter
from app.services.nvd_service import fetch_recent_cves
from app.services.cisa_service import fetch_kev_catalog
router = APIRouter()
@router.get("/vulnerabilities")
async def vulnerabilities(): return await fetch_recent_cves()
@router.get("/vulnerabilities/kev")
async def kev(): return await fetch_kev_catalog()
