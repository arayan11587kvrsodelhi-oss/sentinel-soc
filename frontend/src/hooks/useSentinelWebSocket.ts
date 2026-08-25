import { useEffect, useRef, useState, useCallback } from "react";
import { SecurityEvent, Incident, WebSocketStatus } from "../types";
import { getWebSocketUrl } from "../services/api";

const MAX_RECONNECT_ATTEMPTS = 8;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 16000;

interface UseSentinelWebSocketReturn {
  status: WebSocketStatus;
  events: SecurityEvent[];
  incidents: Incident[];
  latencyMs: number | null;
  reconnectCount: number;
  maxReconnectAttempts: number;
  lastEventAt: Date | null;
  triggerScenario: (scenarioId: string) => void;
  setIncidents: React.Dispatch<React.SetStateAction<Incident[]>>;
  clearEvents: () => void;
  reconnect: () => void;
}

export function useSentinelWebSocket(): UseSentinelWebSocketReturn {
  const [status, setStatus] = useState<WebSocketStatus>("CONNECTING");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [reconnectCount, setReconnectCount] = useState<number>(0);
  const [lastEventAt, setLastEventAt] = useState<Date | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pingTimestampRef = useRef<number | null>(null);
  const disposedRef = useRef<boolean>(false);
  const backoffDelayRef = useRef<number>(INITIAL_BACKOFF_MS);
  const reconnectAttemptsRef = useRef<number>(0);

  const cleanupSocket = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onopen = null;
      wsRef.current.onmessage = null;
      wsRef.current.onerror = null;
      wsRef.current.onclose = null;
      if (
        wsRef.current.readyState === WebSocket.OPEN ||
        wsRef.current.readyState === WebSocket.CONNECTING
      ) {
        wsRef.current.close();
      }
      wsRef.current = null;
    }
  }, []);

  const sendPing = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      pingTimestampRef.current = performance.now();
      try {
        wsRef.current.send(JSON.stringify({ type: "PING" }));
      } catch {
        // Ignore send errors during socket transitions
      }
    }
  }, []);

  const connect = useCallback(() => {
    if (disposedRef.current) return;

    // Clean up any existing connection to prevent duplicates
    cleanupSocket();

    const wsUrl = getWebSocketUrl();
    setStatus((prev) => (prev === "ONLINE" ? "RECONNECTING" : prev));

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (disposedRef.current) {
          ws.close();
          return;
        }
        setStatus("ONLINE");
        setReconnectCount(0);
        reconnectAttemptsRef.current = 0;
        backoffDelayRef.current = INITIAL_BACKOFF_MS;

        // Immediately measure latency upon connection
        sendPing();

        // Start periodic ping for ongoing latency measurement and keepalive
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          sendPing();
        }, 15000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "PONG") {
            if (pingTimestampRef.current) {
              const latency = Math.max(
                1,
                Math.round(performance.now() - pingTimestampRef.current)
              );
              setLatencyMs(latency);
            }
            return;
          }

          if (data.type === "INITIAL_STATE") {
            if (Array.isArray(data.recent_events)) {
              setEvents((prev) => {
                const combined = [...data.recent_events, ...prev];
                const seen = new Set<string>();
                return combined
                  .filter((e) => {
                    const key = String(e.event_id || e.id || "");
                    if (!key || seen.has(key)) return false;
                    seen.add(key);
                    return true;
                  })
                  .slice(0, 150);
              });
              setLastEventAt(new Date());
            }
            if (Array.isArray(data.active_incidents)) {
              setIncidents((prev) => {
                const map = new Map<string, Incident>();
                // Keep local updates while merging initial state
                prev.forEach((inc) => {
                  const key = String(inc.incident_id || inc.id || "");
                  if (key) map.set(key, inc);
                });
                data.active_incidents.forEach((inc: Incident) => {
                  const key = String(inc.incident_id || inc.id || "");
                  if (key && !map.has(key)) {
                    map.set(key, inc);
                  }
                });
                return Array.from(map.values()).slice(0, 50);
              });
            }
            return;
          }

          if (data.type === "INCIDENT_UPDATE" && data.incident) {
            setIncidents((prev) => {
              const updated = data.incident;
              const updateKey = String(updated.incident_id || updated.id || "");
              const idx = prev.findIndex(
                (i) => String(i.incident_id || i.id || "") === updateKey
              );
              if (idx >= 0) {
                const copy = [...prev];
                copy[idx] = updated;
                return copy;
              }
              return [updated, ...prev].slice(0, 50);
            });
            setLastEventAt(new Date());
            return;
          }

          // Regular Security Event
          const parsedEvent: SecurityEvent = {
            event_id: data.event_id || data.id || `EVT-${Date.now()}`,
            id: data.id || data.event_id,
            timestamp: data.timestamp || new Date().toISOString(),
            event_type: data.event_type || data.type || "SECURITY_ALERT",
            type: data.type || data.event_type || "SECURITY_ALERT",
            severity: data.severity || "MEDIUM",
            source_ip: data.source_ip || data.source || "192.168.1.100",
            destination_ip: data.destination_ip || "10.0.1.50",
            destination_port: data.destination_port || 443,
            protocol: data.protocol || "HTTPS",
            target: data.target || "internal-host",
            message:
              data.message ||
              `Simulated ${data.type || data.event_type || "Event"} detected`,
            simulation: data.simulation ?? true,
            source: data.source || "SIMULATION",
            mitre_technique: data.mitre_technique,
            scenario_id: data.scenario_id,
            metadata: data.metadata || {},
          };

          const eventKey = String(parsedEvent.event_id || parsedEvent.id || "");
          setEvents((prev) => {
            if (eventKey && prev.some((e) => String(e.event_id || e.id || "") === eventKey)) {
              return prev;
            }
            return [parsedEvent, ...prev].slice(0, 150);
          });
          setLastEventAt(new Date());
        } catch (err) {
          console.error("[Sentinel WS] Failed to parse message:", err);
        }
      };

      ws.onerror = (err) => {
        console.warn("[Sentinel WS] Connection error:", err);
      };

      ws.onclose = () => {
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        if (disposedRef.current) return;

        reconnectAttemptsRef.current += 1;
        const currentAttempt = reconnectAttemptsRef.current;
        setReconnectCount(currentAttempt);

        if (currentAttempt > MAX_RECONNECT_ATTEMPTS) {
          setStatus("OFFLINE");
          return;
        }

        setStatus("RECONNECTING");

        const delay = backoffDelayRef.current;
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        backoffDelayRef.current = Math.min(delay * 2, MAX_BACKOFF_MS);

        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (e) {
      console.error("[Sentinel WS] Init error:", e);
      setStatus("OFFLINE");
    }
  }, [cleanupSocket, sendPing]);

  const reconnect = useCallback(() => {
    reconnectAttemptsRef.current = 0;
    setReconnectCount(0);
    backoffDelayRef.current = INITIAL_BACKOFF_MS;
    setStatus("CONNECTING");
    connect();
  }, [connect]);

  useEffect(() => {
    disposedRef.current = false;
    connect();

    return () => {
      disposedRef.current = true;
      cleanupSocket();
    };
  }, [connect, cleanupSocket]);

  const triggerScenario = useCallback((scenarioId: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: "TRIGGER_SCENARIO",
          scenario_id: scenarioId,
        })
      );
    }
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    status,
    events,
    incidents,
    latencyMs,
    reconnectCount,
    maxReconnectAttempts: MAX_RECONNECT_ATTEMPTS,
    lastEventAt,
    triggerScenario,
    setIncidents,
    clearEvents,
    reconnect,
  };
}
