import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.threats import router as threats_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.api.routes.ai import router as ai_router
from app.api.websocket import router as websocket_router, background_simulation_loop, manager
from app.services.cisa_service import refresh_kev_cache
from app.services.nvd_service import fetch_recent_cves

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background simulation & prime cache
    logger.info("Initializing SentinelSOC services and telemetry simulation...")
    sim_task = asyncio.create_task(background_simulation_loop())

    # Pre-warm KEV and NVD caches asynchronously
    asyncio.create_task(refresh_kev_cache())
    asyncio.create_task(fetch_recent_cves(limit=25))

    yield

    # Shutdown: Cancel background tasks
    logger.info("Stopping SentinelSOC background simulation tasks...")
    sim_task.cancel()
    try:
        await sim_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="SENTINEL SOC API",
    version="2.0.0",
    description="Educational Security Operations Center (SOC) API — Public Intelligence + Real-Time Telemetry Simulation + AI Defensive Analysis",
    lifespan=lifespan
)

# Configurable CORS
cors_origins_env = os.getenv("CORS_ORIGINS", "")
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "https://sentinel-soc1.vercel.app",
    "https://sentinel-soc-gamma.vercel.app",
    "https://sentinel-soc.vercel.app"
]
if cors_origins_env:
    allowed_origins.extend([orig.strip() for orig in cors_origins_env.split(",") if orig.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


app.include_router(dashboard_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(ai_router, prefix="/api")
app.include_router(websocket_router)


@app.get("/")
async def root():
    return {
        "service": "SENTINEL SOC API",
        "version": "2.0.0",
        "status": "online",
        "mode": "educational-live-intelligence-and-simulation",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "SENTINEL SOC API",
        "active_ws_clients": len(manager.active_connections),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
