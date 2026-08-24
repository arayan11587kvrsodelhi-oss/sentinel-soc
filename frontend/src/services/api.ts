import {
  VulnerabilityResponse,
  KevResponse,
  Incident,
  IncidentStatus,
  AiAnalysisResult,
  DashboardMetrics,
  SecurityEvent,
} from "../types";

/**
 * =========================================================
 * API / WEBSOCKET BASE URL
 * =========================================================
 *
 * Local development:
 *   VITE_API_BASE_URL=http://localhost:8000
 *   VITE_WS_BASE_URL=ws://localhost:8000/ws/events
 *
 * Production:
 *   VITE_API_BASE_URL=https://sentinel-soc-api-qpzg.onrender.com
 *   VITE_WS_BASE_URL=wss://sentinel-soc-api-qpzg.onrender.com/ws/events
 *
 * If environment variables are missing, sensible fallbacks
 * are used automatically.
 */

/**
 * Production backend endpoints (Render)
 */
const PRODUCTION_API_URL = "https://sentinel-soc-api-qpzg.onrender.com";
const PRODUCTION_WS_URL = "wss://sentinel-soc-api-qpzg.onrender.com/ws/events";

/**
 * Returns true if running in a real browser on a non-localhost domain.
 */
function isProductionDomain(): boolean {
  if (typeof window === "undefined" || !window.location) {
    return !import.meta.env.DEV;
  }
  const host = window.location.hostname.toLowerCase();
  return host !== "localhost" && host !== "127.0.0.1" && host !== "0.0.0.0";
}

/**
 * Returns the backend API base URL.
 */
export function getApiBaseUrl(): string {
  const configuredUrl = import.meta.env.VITE_API_BASE_URL?.trim();

  // If on a remote production domain (e.g. Vercel), NEVER use localhost even if misconfigured in env
  if (isProductionDomain()) {
    if (configuredUrl && !configuredUrl.includes("localhost") && !configuredUrl.includes("127.0.0.1")) {
      return configuredUrl.replace(/\/+$/, "");
    }
    return PRODUCTION_API_URL;
  }

  // Local development
  if (configuredUrl) {
    return configuredUrl.replace(/\/+$/, "");
  }

  if (import.meta.env.DEV) {
    return "http://localhost:8000";
  }

  return PRODUCTION_API_URL;
}

/**
 * Returns the WebSocket endpoint used by the live telemetry stream.
 */
export function getWebSocketUrl(): string {
  const configuredWsUrl = import.meta.env.VITE_WS_BASE_URL?.trim();

  // If on a remote production domain (e.g. Vercel), NEVER use localhost
  if (isProductionDomain()) {
    if (configuredWsUrl && !configuredWsUrl.includes("localhost") && !configuredWsUrl.includes("127.0.0.1")) {
      return configuredWsUrl.replace(/\/+$/, "");
    }
    return PRODUCTION_WS_URL;
  }

  // Local development
  if (configuredWsUrl) {
    return configuredWsUrl.replace(/\/+$/, "");
  }

  const apiBase = getApiBaseUrl();

  if (apiBase.startsWith("https://")) {
    return `${apiBase.replace(/^https:\/\//, "wss://")}/ws/events`;
  }

  if (apiBase.startsWith("http://")) {
    return `${apiBase.replace(/^http:\/\//, "ws://")}/ws/events`;
  }

  return PRODUCTION_WS_URL;
}

/**
 * API base used by all API requests.
 */
const API_BASE = getApiBaseUrl();

/**
 * =========================================================
 * RESPONSE HANDLER
 * =========================================================
 */

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text().catch(() => res.statusText);

    throw new Error(`API Error (${res.status}): ${errorText}`);
  }

  return res.json();
}

/**
 * =========================================================
 * API
 * =========================================================
 */

export const api = {
  /**
   * -------------------------------------------------------
   * DASHBOARD
   * -------------------------------------------------------
   */

  async getDashboardMetrics(): Promise<DashboardMetrics> {
    const res = await fetch(`${API_BASE}/api/dashboard`);

    return handleResponse<DashboardMetrics>(res);
  },

  /**
   * -------------------------------------------------------
   * VULNERABILITIES
   * -------------------------------------------------------
   */

  async getVulnerabilities(params?: {
    search?: string;
    severity?: string;
    kev_only?: boolean;
    limit?: number;
    offset?: number;
    force_refresh?: boolean;
  }): Promise<VulnerabilityResponse> {
    const query = new URLSearchParams();

    if (params?.search) {
      query.set("search", params.search);
    }

    if (params?.severity) {
      query.set("severity", params.severity);
    }

    if (params?.kev_only) {
      query.set("kev_only", "true");
    }

    if (params?.limit !== undefined) {
      query.set("limit", params.limit.toString());
    }

    if (params?.offset !== undefined) {
      query.set("offset", params.offset.toString());
    }

    if (params?.force_refresh) {
      query.set("force_refresh", "true");
    }

    const qs = query.toString();

    const url = `${API_BASE}/api/vulnerabilities${qs ? `?${qs}` : ""
      }`;

    const res = await fetch(url);

    const data = await handleResponse<
      VulnerabilityResponse | any[]
    >(res);

    /**
     * Backward compatibility:
     *
     * Older backend versions may return a raw array.
     * Newer versions return VulnerabilityResponse.
     */
    if (Array.isArray(data)) {
      return {
        source: "NVD Intelligence",
        total: data.length,
        cached: true,
        last_updated: new Date().toISOString(),
        vulnerabilities: data,
      };
    }

    return data as VulnerabilityResponse;
  },

  /**
   * -------------------------------------------------------
   * CISA KEV CATALOG
   * -------------------------------------------------------
   */

  async getKevCatalog(params?: {
    search?: string;
    ransomware_only?: boolean;
    limit?: number;
    offset?: number;
    force_refresh?: boolean;
  }): Promise<KevResponse> {
    const query = new URLSearchParams();

    if (params?.search) {
      query.set("search", params.search);
    }

    if (params?.ransomware_only) {
      query.set("ransomware_only", "true");
    }

    if (params?.limit !== undefined) {
      query.set("limit", params.limit.toString());
    }

    if (params?.offset !== undefined) {
      query.set("offset", params.offset.toString());
    }

    if (params?.force_refresh) {
      query.set("force_refresh", "true");
    }

    const qs = query.toString();

    const url = `${API_BASE}/api/vulnerabilities/kev${qs ? `?${qs}` : ""
      }`;

    const res = await fetch(url);

    return handleResponse<KevResponse>(res);
  },

  /**
   * -------------------------------------------------------
   * INCIDENTS
   * -------------------------------------------------------
   */

  async getIncidents(params?: {
    status?: string;
    severity?: string;
    search?: string;
  }): Promise<Incident[]> {
    const query = new URLSearchParams();

    if (params?.status) {
      query.set("status", params.status);
    }

    if (params?.severity) {
      query.set("severity", params.severity);
    }

    if (params?.search) {
      query.set("search", params.search);
    }

    const qs = query.toString();

    const url = `${API_BASE}/api/incidents${qs ? `?${qs}` : ""
      }`;

    const res = await fetch(url);

    return handleResponse<Incident[]>(res);
  },

  /**
   * Get a single incident.
   */
  async getIncidentById(
    incidentId: string
  ): Promise<Incident> {
    const res = await fetch(
      `${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}`
    );

    return handleResponse<Incident>(res);
  },

  /**
   * Update incident status.
   */
  async updateIncidentStatus(
    incidentId: string,
    status: IncidentStatus
  ): Promise<Incident> {
    const res = await fetch(
      `${API_BASE}/api/incidents/${encodeURIComponent(
        incidentId
      )}/status`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          status,
        }),
      }
    );

    return handleResponse<Incident>(res);
  },

  /**
   * -------------------------------------------------------
   * AI TRIAGE
   * -------------------------------------------------------
   */

  async aiTriageIncident(
    incidentId: string
  ): Promise<AiAnalysisResult> {
    const res = await fetch(
      `${API_BASE}/api/incidents/${encodeURIComponent(
        incidentId
      )}/ai-triage`,
      {
        method: "POST",
      }
    );

    return handleResponse<AiAnalysisResult>(res);
  },

  /**
   * Analyze telemetry with Sentinel AI.
   */
  async analyzeTelemetry(payload: {
    event_id?: string;
    event_type?: string;
    severity?: string;
    source_ip?: string;
    target?: string;
    details?: string;
    context?: Record<string, any>;
  }): Promise<AiAnalysisResult> {
    const res = await fetch(
      `${API_BASE}/api/ai/analyze`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }
    );

    return handleResponse<AiAnalysisResult>(res);
  },

  /**
   * -------------------------------------------------------
   * THREAT EVENTS
   * -------------------------------------------------------
   */

  async getThreatEvents(params?: {
    severity?: string;
    event_type?: string;
    limit?: number;
  }): Promise<SecurityEvent[]> {
    const query = new URLSearchParams();

    if (params?.severity) {
      query.set("severity", params.severity);
    }

    if (params?.event_type) {
      query.set("event_type", params.event_type);
    }

    if (params?.limit !== undefined) {
      query.set("limit", params.limit.toString());
    }

    const qs = query.toString();

    const url = `${API_BASE}/api/threats${qs ? `?${qs}` : ""
      }`;

    const res = await fetch(url);

    return handleResponse<SecurityEvent[]>(res);
  },
};

/**
 * =========================================================
 * OPTIONAL DEBUG HELPERS
 * =========================================================
 *
 * These make it easy to verify which backend the frontend
 * is actually using. They do not make network requests.
 */

if (import.meta.env.DEV) {
  console.info(
    "[Sentinel SOC] API:",
    API_BASE
  );

  console.info(
    "[Sentinel SOC] WebSocket:",
    getWebSocketUrl()
  );
}