import asyncio
import json
import random

from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

EVENTS = [
    ("LOGIN_FAILURE", "MEDIUM"),
    ("PORT_SCAN", "HIGH"),
    ("SUSPICIOUS_LOGIN", "HIGH"),
    ("BRUTE_FORCE", "CRITICAL"),
    ("MALWARE_ALERT", "CRITICAL"),
]


@router.websocket("/ws/events")
async def events(websocket: WebSocket):
    await websocket.accept()

    print("✅ WebSocket client connected")

    try:
        while True:
            event_type, severity = random.choice(EVENTS)

            event = {
                "id": f"SIM-{random.randint(1000, 9999)}",
                "type": event_type,
                "severity": severity,
                "source": "SIMULATION",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            await websocket.send_text(json.dumps(event))

            await asyncio.sleep(5)

    except WebSocketDisconnect:
        print("🔌 WebSocket client disconnected")

    except Exception as e:
        print(f"❌ WebSocket error: {e}")