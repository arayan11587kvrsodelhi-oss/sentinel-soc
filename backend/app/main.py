"""
Sentinel SOC v2.2 — FastAPI application entry point.

Configures structured logging, request ID tracing, rate limiting,
hardened CORS, security headers, and the WebSocket event pipeline.
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Callable, Dict, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime, timezone

from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.threats import router as threats_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.api.routes.ai import router as ai_router
from app.api.routes.response import router as response_router
from app.api.websocket import router as websocket_router, background_simulation_loop, manager
from app.core.config import get_settings
from app.core.logging import configure_logging, generate_request_id, get_request_id, set_request_id
from app.services.cisa_service import refresh_kev_cache
from app.services.nvd_service import fetch_recent_cves

configure_logging()
logger = logging.getLogger("sentinel.main")
settings = get_settings()

# In-memory rate-limiting store. Keys are "client_ip:method:path".
_rate_limit_store: Dict[str, list] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: start background tasks, stop gracefully on shutdown."""
    logger.info(
        "Initializing SentinelSOC services and telemetry simulation",
        extra={"environment": settings.app_environment, "version": settings.app_version},
    )

    # Track background tasks so we can cancel and await them cleanly.
    tasks = [
        asyncio.create_task(background_simulation_loop(), name="sentinel-simulation-loop"),
        asyncio.create_task(refresh_kev_cache(), name="sentinel-kev-cache-warmup"),
        asyncio.create_task(fetch_recent_cves(limit=25), name="sentinel-nvd-cache-warmup"),
    ]

    # Give startup tasks a moment to begin before accepting traffic.
    await asyncio.sleep(0.1)

    yield

    # Shutdown: cancel all background tasks and wait for them to finish.
    logger.info("Stopping SentinelSOC background tasks...")
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass
    logger.info("SentinelSOC background tasks stopped.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Educational Security Operations Center (SOC) API — Public Intelligence + Real-Time Telemetry Simulation + AI Defensive Analysis",
    lifespan=lifespan,
    docs_url="/docs" if settings.app_environment != "production" else None,
    redoc_url="/redoc" if settings.app_environment != "production" else None,
)


# ---------------------------------------------------------------------------
# Request ID middleware — attaches a trace ID to every request/response.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_id_middleware(request: Request, call_next: Callable):
    request_id = request.headers.get(settings.request_id_header.lower().replace("-", "_")) or request.headers.get(settings.request_id_header)
    if not request_id:
        request_id = generate_request_id()
    set_request_id(request_id)
    response = await call_next(request)
    response.headers[settings.request_id_header] = request_id
    return response


# ---------------------------------------------------------------------------
# Rate limiting middleware — simple in-memory sliding window.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Callable):
    # Skip rate limiting for WebSocket upgrade requests and health checks.
    if request.url.path in ("/health", "/") or request.url.path.startswith("/ws"):
        return await call_next(request)

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    key = f"{client_ip}:{request.method}:{request.url.path}"
    now = time.time()
    window = settings.rate_limit_window_seconds
    limit = settings.rate_limit_requests

    timestamps = _rate_limit_store.get(key, [])
    # Keep only requests inside the current window.
    timestamps = [t for t in timestamps if now - t < window]

    if len(timestamps) >= limit:
        logger.warning("Rate limit exceeded", extra={"client_ip": client_ip, "path": request.url.path})
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded. Please slow down.",
                "retry_after": window,
            },
            headers={"Retry-After": str(window)},
        )

    timestamps.append(now)
    _rate_limit_store[key] = timestamps

    return await call_next(request)


# ---------------------------------------------------------------------------
# CORS — explicit origins, restricted methods/headers, no regex wildcard.
# ---------------------------------------------------------------------------
allowed_origins = settings.parsed_cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", settings.request_id_header],
    expose_headers=[settings.request_id_header],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Security headers middleware.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next: Callable):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src 'self' fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


app.include_router(dashboard_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(ai_router, prefix="/api")
app.include_router(response_router, prefix="/api")
app.include_router(websocket_router)


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "online",
        "mode": "educational-live-intelligence-and-simulation",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
async def health():
    """Real-time system health check for API, Database, AI Engine, and Event Pipeline."""
    db_status = "OPERATIONAL"
    try:
        from app.services.correlation_service import DB_PATH
        import sqlite3
        with sqlite3.connect(DB_PATH, timeout=2.0) as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        logger.warning("Database health check failed", extra={"error": str(exc)})
        db_status = "DEGRADED"

    ai_mode = "READY (LLM)" if settings.ai_api_key and settings.ai_api_base_url else "READY (EXPERT_ENGINE)"

    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subsystems": {
            "api": "OPERATIONAL",
            "websocket": "OPERATIONAL" if manager else "DEGRADED",
            "database": db_status,
            "ai_engine": ai_mode,
            "event_pipeline": "ACTIVE",
        },
        "active_ws_clients": len(manager.active_connections),
        "request_id": get_request_id(),
    }
