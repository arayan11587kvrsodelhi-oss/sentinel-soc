"""
SentinelSOC Real-Time WebSocket Event Bus & Telemetry Broadcaster
Streams correlated synthetic security events and live incident updates to all connected SOC clients.
"""
import asyncio
import json
import logging
from typing import Set, Dict, Any, List
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.simulation_service import simulation_engine
from app.services.correlation_service import correlation_engine
from app.models.schemas import SecurityEvent

logger = logging.getLogger("sentinel.ws")
router = APIRouter()


class WebSocketConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._background_task: asyncio.Task = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Client connected. Active clients: {len(self.active_connections)}")

        # Send initial snapshot to newly connected client
        try:
            recent = correlation_engine.get_recent_events(limit=10)
            snapshot = {
                "type": "INITIAL_STATE",
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "recent_events": [e.model_dump() for e in recent],
                "active_incidents": [i.model_dump() for i in correlation_engine.get_incidents(status="OPEN")]
            }
            await websocket.send_text(json.dumps(snapshot))
        except Exception as e:
            logger.warning(f"Error sending initial state: {e}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"Client disconnected. Remaining clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return

        text = json.dumps(message)
        dead_connections = set()

        for conn in list(self.active_connections):
            try:
                await conn.send_text(text)
            except Exception as e:
                logger.warning(f"Failed to send to client: {e}")
                dead_connections.add(conn)

        for dead in dead_connections:
            self.disconnect(dead)


manager = WebSocketConnectionManager()


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            # Receive client actions / heartbeats
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get("type", "").upper()

                if msg_type == "PING":
                    await websocket.send_text(json.dumps({
                        "type": "PONG",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))

                elif msg_type == "TRIGGER_SCENARIO":
                    scenario_id = msg.get("scenario_id", "scenario_credential_brute_force")
                    events = simulation_engine.trigger_scenario(scenario_id)
                    if events:
                        for ev in events:
                            inc = correlation_engine.process_event(ev)
                            payload = ev.model_dump()
                            payload["type"] = "EVENT"
                            await manager.broadcast(payload)
                            if inc:
                                await manager.broadcast({
                                    "type": "INCIDENT_UPDATE",
                                    "incident": inc.model_dump()
                                })
                            await asyncio.sleep(0.3)

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket connection exception: {e}")
        manager.disconnect(websocket)


async def background_simulation_loop():
    """Continuously generates correlated security telemetry and broadcasts to clients."""
    # Pre-populate some baseline events on startup
    for _ in range(6):
        ev = simulation_engine.generate_next_event()
        correlation_engine.process_event(ev)

    while True:
        try:
            # Generate next correlated attack chain step
            event: SecurityEvent = simulation_engine.generate_next_event()

            # Pass through correlation engine
            incident = correlation_engine.process_event(event)

            # Broadcast event to all connected SOC dashboards
            event_payload = event.model_dump()
            # Retain backward compatibility: top level type is also event_type
            event_payload["event_msg_type"] = "SECURITY_EVENT"
            await manager.broadcast(event_payload)

            # If an incident was generated or updated, broadcast incident alert
            if incident:
                await manager.broadcast({
                    "type": "INCIDENT_UPDATE",
                    "incident": incident.model_dump()
                })

        except Exception as e:
            logger.error(f"Error in background simulation loop: {e}")

        # Sleep between 3.5 to 5.5 seconds for realistic cadence
        await asyncio.sleep(4.0)
