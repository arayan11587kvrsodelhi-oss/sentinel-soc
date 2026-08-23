from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.threats import router as threats_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.api.routes.ai import router as ai_router
from app.api.websocket import router as websocket_router


app = FastAPI(
    title="SENTINEL SOC API",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "https://sentinel-soc.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    dashboard_router,
    prefix="/api"
)

app.include_router(
    incidents_router,
    prefix="/api"
)

app.include_router(
    threats_router,
    prefix="/api"
)

app.include_router(
    vulnerabilities_router,
    prefix="/api"
)

app.include_router(
    ai_router,
    prefix="/api"
)

app.include_router(
    websocket_router
)


@app.get("/")
async def root():
    return {
        "service": "SENTINEL SOC API",
        "status": "online",
        "docs": "/docs",
        "health": "/health"
    }