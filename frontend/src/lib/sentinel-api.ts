export const SENTINEL_API = import.meta.env.VITE_SENTINEL_API_URL || "https://sentinel-soc-api-qpzg.onrender.com";
export const SENTINEL_WS = import.meta.env.VITE_SENTINEL_WS_URL || "wss://sentinel-soc-api-qpzg.onrender.com/ws/events";

export async function sentinelFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${SENTINEL_API}${path}`, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers || {}) },
  });
  if (!response.ok) throw new Error(`Sentinel API ${response.status}: ${response.statusText}`);
  return response.json() as Promise<T>;
}

export interface SentinelHealth {
  status: string;
  service: string;
  timestamp: string;
  subsystems: {
    api: string;
    websocket: string;
    database: string;
    ai_engine: string;
    event_pipeline: string;
  };
  active_ws_clients: number;
}

export const getHealth = () => sentinelFetch<SentinelHealth>("/health");
