"""
SentinelSOC Real-Time WebSocket Event Bus & Telemetry Broadcaster
Streams correlated synthetic security events and live incident updates to all connected SOC clients.
"""
import asyncio
import json
import random
import logging
from typing import Set, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.simulation_service import simulation_engine
from app.services.correlation_service import correlation_engine
from app.models.schemas import SecurityEvent

logger = logging.getLogger("sentinel.ws")
router = APIRouter()


class WebSocketConnectionManager:
    """Manages active WebSocket connections and broadcasts events safely."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._shutdown_event = asyncio.Event()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            "Client connected",
            extra={"active_clients": len(self.active_connections)},
        )

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
            logger.warning("Error sending initial state", extra={"error": str(e)})

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(
            "Client disconnected",
            extra={"remaining_clients": len(self.active_connections)},
        )

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients with backpressure handling."""
        if not self.active_connections:
            return

        text = json.dumps(message)
        dead_connections: Set[WebSocket] = set()
        pending_tasks: Set[asyncio.Task] = set()

        for conn in list(self.active_connections):
            try:
                # Use wait_for to avoid slow clients blocking the broadcast.
                task = asyncio.create_task(
                    asyncio.wait_for(conn.send_text(text), timeout=2.0)
                )
                pending_tasks.add(task)
            except Exception as e:
                logger.warning("Failed to schedule send to client", extra={"error": str(e)})
                dead_connections.add(conn)

        if pending_tasks:
            done, _ = await asyncio.wait(pending_tasks, timeout=2.5, return_when=asyncio.ALL_COMPLETED)
            for task in done:
                try:
                    task.result()
                except Exception as e:
                    logger.warning("Send to client failed", extra={"error": str(e)})

        for dead in dead_connections:
            self.disconnect(dead)

    def shutdown(self):
        """Signal the manager to stop accepting new broadcasts."""
        self._shutdown_event.set()


manager = WebSocketConnectionManager()


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    last_pong = datetime.now(timezone.utc)

    try:
        while True:
            # Receive client actions / heartbeats with a timeout to detect stale connections.
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=35.0)
            except asyncio.TimeoutError:
                # Connection may be stale; send a ping and wait briefly for a pong.
                try:
                    await websocket.send_text(json.dumps({
                        "type": "PING",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))
                    pong_data = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
                    pong_msg = json.loads(pong_data)
                    if pong_msg.get("type", "").upper() == "PONG":
                        last_pong = datetime.now(timezone.utc)
                        continue
                except Exception:
                    logger.info("WebSocket connection stale, closing")
                    break
                continue

            try:
                msg = json.loads(data)
                msg_type = msg.get("type", "").upper()

                if msg_type == "PING":
                    await websocket.send_text(json.dumps({
                        "type": "PONG",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))

                elif msg_type == "PONG":
                    last_pong = datetime.now(timezone.utc)

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
                            await asyncio.sleep(0.7)

            except json.JSONDecodeError:
                # Ignore malformed messages.
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WebSocket connection exception", extra={"error": str(e)})
    finally:
        manager.disconnect(websocket)


async def background_simulation_loop():
    """Continuously generates correlated security telemetry and broadcasts to clients."""
    # Pre-populate some baseline events on startup
    for _ in range(6):
        try:
            ev = simulation_engine.generate_next_event()
            correlation_engine.process_event(ev)
        except Exception as e:
            logger.error("Error during simulation startup", extra={"error": str(e)})

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

        except asyncio.CancelledError:
            logger.info("Background simulation loop cancelled")
            raise
        except Exception as e:
            logger.error("Error in background simulation loop", extra={"error": str(e)})

        # Varied, realistic SOC cadence (5.0s to 10.0s interval)
        await asyncio.sleep(random.uniform(5.0, 10.0))
