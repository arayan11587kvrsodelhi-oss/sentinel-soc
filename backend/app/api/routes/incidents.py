from fastapi import APIRouter
router = APIRouter()
@router.get("/incidents")
async def incidents():
    return [
      {"id":"INC-001","type":"Brute Force","severity":"CRITICAL","status":"OPEN","source":"simulation"},
      {"id":"INC-002","type":"Port Scan","severity":"HIGH","status":"INVESTIGATING","source":"simulation"}
    ]
