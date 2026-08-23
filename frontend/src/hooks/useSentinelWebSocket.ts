import { useEffect, useRef, useState, useCallback } from "react";
import { SecurityEvent, Incident, WebSocketStatus } from "../types";
import { getWebSocketUrl } from "../services/api";

interface UseSentinelWebSocketReturn {
  status: WebSocketStatus;
  events: SecurityEvent[];
  incidents: Incident[];
  latencyMs: number | null;
  reconnectCount: number;
  triggerScenario: (scenarioId: string) => void;
  setIncidents: React.Dispatch<React.SetStateAction<Incident[]>>;
  clearEvents: () => void;
}

export function useSentinelWebSocket(): UseSentinelWebSocketReturn {
  const [status, setStatus] = useState<WebSocketStatus>("CONNECTING");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [reconnectCount, setReconnectCount] = useState<number>(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pingTimestampRef = useRef<number | null>(null);
  const disposedRef = useRef<boolean>(false);
  const backoffDelayRef = useRef<number>(1000);

  const connect = useCallback(() => {
    if (disposedRef.current) return;

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
        backoffDelayRef.current = 1000;

        // Start periodic ping for latency measurement and keeping connection alive
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            pingTimestampRef.current = performance.now();
            ws.send(JSON.stringify({ type: "PING" }));
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "PONG") {
            if (pingTimestampRef.current) {
              const latency = Math.round(performance.now() - pingTimestampRef.current);
              setLatencyMs(latency);
            }
            return;
          }

          if (data.type === "INITIAL_STATE") {
            if (Array.isArray(data.recent_events)) {
              setEvents((prev) => {
                const combined = [...data.recent_events, ...prev];
                const seen = new Set();
                return combined.filter((e) => {
                  const key = e.event_id || e.id;
                  if (!key || seen.has(key)) return false;
                  seen.add(key);
                  return true;
                }).slice(0, 150);
              });
            }
            if (Array.isArray(data.active_incidents)) {
              setIncidents(data.active_incidents);
            }
            return;
          }

          if (data.type === "INCIDENT_UPDATE" && data.incident) {
            setIncidents((prev) => {
              const updated = data.incident;
              const idx = prev.findIndex((i) => (i.incident_id || i.id) === (updated.incident_id || updated.id));
              if (idx >= 0) {
                const copy = [...prev];
                copy[idx] = updated;
                return copy;
              }
              return [updated, ...prev].slice(0, 50);
            });
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
            message: data.message || `Simulated ${data.type || data.event_type || "Event"} detected`,
            simulation: data.simulation ?? true,
            source: data.source || "SIMULATION",
            mitre_technique: data.mitre_technique,
            scenario_id: data.scenario_id,
            metadata: data.metadata || {},
          };

          setEvents((prev) => [parsedEvent, ...prev].slice(0, 150));
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

        setStatus("RECONNECTING");
        setReconnectCount((c) => c + 1);

        const delay = backoffDelayRef.current;
        backoffDelayRef.current = Math.min(delay * 1.5, 10000);

        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (e) {
      console.error("[Sentinel WS] Init error:", e);
      setStatus("OFFLINE");
    }
  }, []);

  useEffect(() => {
    disposedRef.current = false;
    connect();

    return () => {
      disposedRef.current = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.onerror = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  const triggerScenario = useCallback((scenarioId: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: "TRIGGER_SCENARIO",
        scenario_id: scenarioId,
      }));
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
    triggerScenario,
    setIncidents,
    clearEvents,
  };
}
