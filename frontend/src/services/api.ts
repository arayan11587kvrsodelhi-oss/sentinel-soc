import {
  VulnerabilityResponse,
  KevResponse,
  Incident,
  IncidentStatus,
  AiAnalysisResult,
  DashboardMetrics,
  SecurityEvent,
} from "../types";

export function getApiBaseUrl(): string {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL.replace(/\/$/, "");
  }
  if (import.meta.env.DEV) {
    return "http://localhost:8000";
  }
  // Production fallback
  return "https://sentinel-soc-api-qpzg.onrender.com";
}

export function getWebSocketUrl(): string {
  if (import.meta.env.VITE_WS_BASE_URL) {
    return import.meta.env.VITE_WS_BASE_URL;
  }
  const apiBase = getApiBaseUrl();
  if (apiBase.startsWith("https://")) {
    return `${apiBase.replace("https://", "wss://")}/ws/events`;
  }
  return `${apiBase.replace("http://", "ws://")}/ws/events`;
}

const API_BASE = getApiBaseUrl();

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text().catch(() => res.statusText);
    throw new Error(`API Error (${res.status}): ${errorText}`);
  }
  return res.json();
}

export const api = {
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    const res = await fetch(`${API_BASE}/api/dashboard`);
    return handleResponse<DashboardMetrics>(res);
  },

  async getVulnerabilities(params?: {
    search?: string;
    severity?: string;
    kev_only?: boolean;
    limit?: number;
    offset?: number;
    force_refresh?: boolean;
  }): Promise<VulnerabilityResponse> {
    const query = new URLSearchParams();
    if (params?.search) query.set("search", params.search);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.kev_only) query.set("kev_only", "true");
    if (params?.limit) query.set("limit", params.limit.toString());
    if (params?.offset) query.set("offset", params.offset.toString());
    if (params?.force_refresh) query.set("force_refresh", "true");

    const qs = query.toString();
    const url = `${API_BASE}/api/vulnerabilities${qs ? `?${qs}` : ""}`;
    const res = await fetch(url);
    const data = await handleResponse<any>(res);

    // Handle backward-compatible array or new object envelope
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

  async getKevCatalog(params?: {
    search?: string;
    ransomware_only?: boolean;
    limit?: number;
    offset?: number;
    force_refresh?: boolean;
  }): Promise<KevResponse> {
    const query = new URLSearchParams();
    if (params?.search) query.set("search", params.search);
    if (params?.ransomware_only) query.set("ransomware_only", "true");
    if (params?.limit) query.set("limit", params.limit.toString());
    if (params?.offset) query.set("offset", params.offset.toString());
    if (params?.force_refresh) query.set("force_refresh", "true");

    const qs = query.toString();
    const url = `${API_BASE}/api/vulnerabilities/kev${qs ? `?${qs}` : ""}`;
    const res = await fetch(url);
    return handleResponse<KevResponse>(res);
  },

  async getIncidents(params?: {
    status?: string;
    severity?: string;
    search?: string;
  }): Promise<Incident[]> {
    const query = new URLSearchParams();
    if (params?.status) query.set("status", params.status);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.search) query.set("search", params.search);

    const qs = query.toString();
    const url = `${API_BASE}/api/incidents${qs ? `?${qs}` : ""}`;
    const res = await fetch(url);
    return handleResponse<Incident[]>(res);
  },

  async getIncidentById(incidentId: string): Promise<Incident> {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}`);
    return handleResponse<Incident>(res);
  },

  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<Incident> {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    return handleResponse<Incident>(res);
  },

  async aiTriageIncident(incidentId: string): Promise<AiAnalysisResult> {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/ai-triage`, {
      method: "POST",
    });
    return handleResponse<AiAnalysisResult>(res);
  },

  async analyzeTelemetry(payload: {
    event_id?: string;
    event_type?: string;
    severity?: string;
    source_ip?: string;
    target?: string;
    details?: string;
    context?: Record<string, any>;
  }): Promise<AiAnalysisResult> {
    const res = await fetch(`${API_BASE}/api/ai/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return handleResponse<AiAnalysisResult>(res);
  },

  async getThreatEvents(params?: {
    severity?: string;
    event_type?: string;
    limit?: number;
  }): Promise<SecurityEvent[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set("severity", params.severity);
    if (params?.event_type) query.set("event_type", params.event_type);
    if (params?.limit) query.set("limit", params.limit.toString());

    const qs = query.toString();
    const url = `${API_BASE}/api/threats${qs ? `?${qs}` : ""}`;
    const res = await fetch(url);
    return handleResponse<SecurityEvent[]>(res);
  },
};
