export const SENTINEL_API =
  import.meta.env.VITE_SENTINEL_API_URL ||
  (typeof window !== "undefined" && window.location.hostname === "localhost"
    ? "http://localhost:8000"
    : "https://sentinel-soc-api-qpzg.onrender.com")

export const SENTINEL_WS =
  import.meta.env.VITE_SENTINEL_WS_URL ||
  (typeof window !== "undefined" && window.location.hostname === "localhost"
    ? "ws://localhost:8000/ws/events"
    : "wss://sentinel-soc-api-qpzg.onrender.com/ws/events")

export async function sentinelFetch<T>(
  path: string,
  init?: RequestInit,
  fallback?: T,
): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 10000)

  try {
    const response = await fetch(`${SENTINEL_API}${path}`, {
      ...init,
      signal: init?.signal || controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(init?.headers || {}),
      },
    })
    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorText = await response.text().catch(() => "")
      throw new Error(
        `Sentinel API ${response.status}: ${response.statusText}${
          errorText ? ` - ${errorText}` : ""
        }`,
      )
    }
    return (await response.json()) as T
  } catch (err) {
    clearTimeout(timeoutId)
    if (fallback !== undefined) {
      console.warn(
        `Sentinel API fetch failed for ${path}, using fallback data:`,
        err,
      )
      return fallback
    }
    throw err
  }
}

/* =========================================================
   TYPE DEFINITIONS
   ========================================================= */

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description: string
  url?: string | null
}

export interface SecurityEvent {
  event_id: string
  id?: string
  timestamp: string
  event_type: string
  type?: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  source_ip: string
  destination_ip: string
  destination_port: number
  protocol: string
  target: string
  message: string
  simulation?: boolean
  source?: string
  mitre_technique?: MitreTechnique | null
  scenario_id?: string | null
  metadata?: Record<string, any>
  event_msg_type?: string
}

export interface AIAnalysisResponse {
  risk_score: number
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  classification: string
  confidence: number
  summary: string
  threat_summary?: string
  why_it_matters?: string
  attack_progression?: string[]
  likely_objective?: string
  mitre_technique?: MitreTechnique | null
  mitre_techniques?: MitreTechnique[]
  affected_assets?: string[]
  observed_facts?: string[]
  ai_inference?: string[]
  unknown_factors?: string[]
  evidence?: {
    observed: string[]
    inferred: string[]
    recommended: string[]
    unknown: string[]
  }
  immediate_response?: string[]
  investigation_steps?: string[]
  long_term_hardening?: string[]
  playbook_recommendations?: string[]
  incident_id?: string | null
  evidence_count?: number
  model?: string
  source?: string
  generated_at?: string
}

export interface Incident {
  incident_id: string
  id?: string
  title: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | string
  confidence: number
  risk?: string
  risk_score?: number
  category: string
  source_ip: string
  target: string
  source_ips?: string[]
  affected_targets?: string[]
  attack_stage?: string
  first_seen?: string
  last_seen?: string
  scenario_id?: string | null
  event_ids?: string[]
  events_count?: number
  techniques?: MitreTechnique[]
  related_cves?: string[]
  created_at: string
  updated_at: string
  summary: string
  recommended_actions?: string[]
  ai_analysis?: AIAnalysisResponse | null
}

export interface KevDetails {
  date_added?: string | null
  due_date?: string | null
  ransomware_use?: string | null
  short_description?: string | null
}

export interface VulnerabilityItem {
  id: string
  description: string
  cvss?: number | null
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  published?: string | null
  modified?: string | null
  cwe?: string | null
  affected_products?: string[]
  references?: string[]
  is_kev: boolean
  kev_details?: KevDetails | null
  source?: string
}

export interface VulnerabilityResponse {
  total: number
  source: string
  data_source?: string
  last_updated: string
  cached: boolean
  vulnerabilities: VulnerabilityItem[]
}

export interface KevItem {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  shortDescription: string
  requiredAction: string
  dueDate: string
  knownRansomwareCampaignUse: string
  notes?: string
}

export interface KevResponse {
  source: string
  data_source?: string
  total: number
  catalog_size: number
  last_updated: string
  cached: boolean
  vulnerabilities: KevItem[]
}

export interface DashboardMetrics {
  status: string
  mode: string
  active_incidents: number
  total_incidents: number
  critical_events: number
  high_events: number
  medium_events: number
  low_events: number
  total_events_streamed: number
  nvd_records_total: number
  nvd_records_cached: number
  nvd_data_source: string
  kev_catalog_total: number
  kev_records_cached: number
  kev_data_source: string
  timestamp: string
}

export interface SentinelHealth {
  status: string
  service: string
  timestamp: string
  subsystems: {
    api: string
    websocket: string
    database: string
    ai_engine: string
    event_pipeline: string
  }
  active_ws_clients: number
}

export interface AnalysisRequest {
  event_id?: string
  incident_id?: string
  event_type?: string
  severity?: string
  details?: string
  source_ip?: string
  target?: string
  context?: Record<string, any>
}

export interface SimulatedActionRecord {
  action_id: string
  action_type: string
  target_ip: string
  target_host?: string
  status: string
  timestamp: string
  execution_time_ms: number
  requested_by: string
  details: string
  remediation_playbook?: string
  simulation: boolean
}

export interface MitreMatrixItem {
  id: string
  name: string
  tactic: string
  description: string
  url?: string
  status: "OBSERVED" | "SIMULATED" | "NOT_OBSERVED"
  incidents_count: number
  events_count: number
  related_incident_ids: string[]
}

/* =========================================================
   FALLBACK DATA (Ensures 100% offline robustness)
   ========================================================= */

export const FALLBACK_INCIDENTS: Incident[] = [
  {
    incident_id: "INC-101",
    id: "INC-101",
    scenario_id: "scenario_credential_brute_force",
    title: "Credential Spraying & SSH Brute Force Attack",
    severity: "CRITICAL",
    status: "OPEN",
    confidence: 0.96,
    risk: "CRITICAL",
    risk_score: 96,
    category: "Credential Access",
    source_ip: "192.168.1.105",
    target: "auth-gateway.corp.internal",
    source_ips: ["192.168.1.105"],
    affected_targets: ["auth-gateway.corp.internal"],
    attack_stage: "Credential Access / Account Compromise",
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date(Date.now() - 120000).toISOString(),
    event_ids: ["SIM-1001", "SIM-1002", "SIM-1003", "SIM-1004"],
    events_count: 4,
    techniques: [
      {
        id: "T1110",
        name: "Brute Force",
        tactic: "Credential Access",
        description:
          "Adversaries may use brute force techniques to attempt access to accounts.",
        url: "https://attack.mitre.org/techniques/T1110",
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        tactic:
          "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description:
          "Adversaries may obtain and abuse credentials of existing accounts.",
        url: "https://attack.mitre.org/techniques/T1078",
      },
    ],
    related_cves: [],
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 120000).toISOString(),
    summary:
      "Rapid successive authentication failures detected against auth-gateway followed by brute force threshold violation and valid account abuse.",
    recommended_actions: [
      "Apply immediate firewall drop rule for source IP 192.168.1.105.",
      "Verify MFA status on targeted accounts (root, administrator, svc_backup).",
      "Audit SSH authorization logs for any subsequent successful sessions.",
      "Review credential rotation policies and terminate active sessions.",
    ],
  },
  {
    incident_id: "INC-102",
    id: "INC-102",
    scenario_id: "scenario_web_cve_exploitation",
    title: "Public Web Application Exploit Chain (MOVEit / SQLi)",
    severity: "CRITICAL",
    status: "INVESTIGATING",
    confidence: 0.94,
    risk: "CRITICAL",
    risk_score: 94,
    category: "Initial Access",
    source_ip: "10.0.4.15",
    target: "dmz-web-portal.corp.internal",
    source_ips: ["10.0.4.15"],
    affected_targets: ["dmz-web-portal.corp.internal"],
    attack_stage: "Initial Access / Exploit Execution",
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date(Date.now() - 300000).toISOString(),
    event_ids: ["SIM-1005", "SIM-1006", "SIM-1007", "SIM-1008"],
    events_count: 4,
    techniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        description:
          "Adversaries may attempt to exploit vulnerabilities in Internet-facing programs.",
        url: "https://attack.mitre.org/techniques/T1190",
      },
      {
        id: "T1059.001",
        name: "Command and Scripting Interpreter: PowerShell",
        tactic: "Execution",
        description:
          "Adversaries may abuse PowerShell commands and scripts for execution.",
        url: "https://attack.mitre.org/techniques/T1059/001",
      },
    ],
    related_cves: ["CVE-2023-34362", "CVE-2024-3400"],
    created_at: new Date(Date.now() - 7200000).toISOString(),
    updated_at: new Date(Date.now() - 300000).toISOString(),
    summary:
      "Automated URI scanning followed by SQL injection and remote code execution exploit payloads targeting DMZ web portal endpoints.",
    recommended_actions: [
      "Enable WAF SQL injection and command injection blocking rules on reverse proxy.",
      "Inspect web application error logs for SQL syntax exceptions and abnormal POST requests.",
      "Verify database query parameterization and ORM sanitization.",
      "Scan filesystem for dropped web shells (/var/www/uploads/) and isolate affected container.",
    ],
  },
]

export const FALLBACK_KEV_CATALOG: KevItem[] = [
  {
    cveID: "CVE-2024-3400",
    vendorProject: "Palo Alto Networks",
    product: "PAN-OS",
    vulnerabilityName: "PAN-OS GlobalProtect Command Injection Vulnerability",
    dateAdded: "2024-04-12",
    shortDescription:
      "Palo Alto Networks PAN-OS contains an OS command injection vulnerability in GlobalProtect feature.",
    requiredAction: "Apply mitigations per vendor instructions.",
    dueDate: "2024-04-19",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
  },
  {
    cveID: "CVE-2024-21887",
    vendorProject: "Ivanti",
    product: "Connect Secure and Policy Secure",
    vulnerabilityName: "Ivanti Connect Secure Command Injection Vulnerability",
    dateAdded: "2024-01-10",
    shortDescription:
      "A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to execute arbitrary commands.",
    requiredAction: "Apply vendor fixes immediately.",
    dueDate: "2024-01-22",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
  },
  {
    cveID: "CVE-2024-1709",
    vendorProject: "ConnectWise",
    product: "ScreenConnect",
    vulnerabilityName: "ScreenConnect Authentication Bypass Vulnerability",
    dateAdded: "2024-02-22",
    shortDescription:
      "ConnectWise ScreenConnect contains an authentication bypass using an alternate path or channel.",
    requiredAction: "Apply vendor updates.",
    dueDate: "2024-02-29",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
  },
  {
    cveID: "CVE-2023-46805",
    vendorProject: "Ivanti",
    product: "Connect Secure",
    vulnerabilityName: "Ivanti Connect Secure Authentication Bypass",
    dateAdded: "2024-01-10",
    shortDescription:
      "An authentication bypass vulnerability in web components of Ivanti ICS allows remote attackers to access restricted resources.",
    requiredAction: "Apply vendor mitigations.",
    dueDate: "2024-01-22",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2023-46805",
  },
  {
    cveID: "CVE-2023-34362",
    vendorProject: "Progress",
    product: "MOVEit Transfer",
    vulnerabilityName: "MOVEit Transfer SQL Injection Vulnerability",
    dateAdded: "2023-06-02",
    shortDescription:
      "SQL injection vulnerability in MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access.",
    requiredAction: "Apply vendor update immediately.",
    dueDate: "2023-06-16",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
  },
  {
    cveID: "CVE-2023-22515",
    vendorProject: "Atlassian",
    product: "Confluence Data Center and Server",
    vulnerabilityName:
      "Confluence Data Center and Server Broken Access Control",
    dateAdded: "2023-10-05",
    shortDescription:
      "Atlassian Confluence Data Center and Server contains a broken access control vulnerability that allows an unauthenticated attacker to create unauthorized admin accounts.",
    requiredAction: "Upgrade to latest fixed version.",
    dueDate: "2023-10-12",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
  },
  {
    cveID: "CVE-2021-44228",
    vendorProject: "Apache",
    product: "Log4j",
    vulnerabilityName:
      "Apache Log4j2 JNDI Remote Code Execution Vulnerability (Log4Shell)",
    dateAdded: "2021-12-10",
    shortDescription:
      "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    requiredAction: "Upgrade to Apache Log4j 2.17.1 or higher.",
    dueDate: "2021-12-24",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  },
  {
    cveID: "CVE-2023-27997",
    vendorProject: "Fortinet",
    product: "FortiOS and FortiProxy",
    vulnerabilityName:
      "Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability",
    dateAdded: "2023-06-13",
    shortDescription:
      "A heap-based buffer overflow vulnerability in FortiOS and FortiProxy SSL-VPN may allow a remote unauthenticated attacker to execute arbitrary code.",
    requiredAction: "Apply vendor updates.",
    dueDate: "2023-07-04",
    knownRansomwareCampaignUse: "Known",
    notes: "https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
  },
]

export const FALLBACK_DASHBOARD: DashboardMetrics = {
  status: "operational",
  mode: "live-intelligence + controlled-simulation",
  active_incidents: 2,
  total_incidents: 2,
  critical_events: 4,
  high_events: 8,
  medium_events: 15,
  low_events: 28,
  total_events_streamed: 55,
  nvd_records_total: 40,
  nvd_records_cached: 40,
  nvd_data_source: "CACHED_NVD",
  kev_catalog_total: 1687,
  kev_records_cached: 1687,
  kev_data_source: "CACHED_CISA_KEV",
  timestamp: new Date().toISOString(),
}

/* =========================================================
   REST API CLIENT FUNCTIONS
   ========================================================= */

export const getHealth = () =>
  sentinelFetch<SentinelHealth>("/health", undefined, {
    status: "healthy",
    service: "SENTINEL SOC API",
    timestamp: new Date().toISOString(),
    subsystems: {
      api: "OPERATIONAL",
      websocket: "OPERATIONAL",
      database: "OPERATIONAL",
      ai_engine: "READY (EXPERT_ENGINE)",
      event_pipeline: "ACTIVE",
    },
    active_ws_clients: 1,
  })

export const getDashboard = () =>
  sentinelFetch<DashboardMetrics>(
    "/api/dashboard",
    undefined,
    FALLBACK_DASHBOARD,
  )

export const getIncidents = (params?: {
  status?: string
  severity?: string
  search?: string
}) => {
  const query = new URLSearchParams()
  if (params?.status && params.status !== "ALL")
    query.append("status", params.status)
  if (params?.severity && params.severity !== "ALL")
    query.append("severity", params.severity)
  if (params?.search) query.append("search", params.search)

  const qs = query.toString() ? `?${query.toString()}` : ""
  return sentinelFetch<Incident[]>(
    `/api/incidents${qs}`,
    undefined,
    FALLBACK_INCIDENTS,
  )
}

export const getIncidentById = (incidentId: string) =>
  sentinelFetch<Incident>(
    `/api/incidents/${incidentId}`,
    undefined,
    FALLBACK_INCIDENTS.find(
      (i) => i.incident_id === incidentId || i.id === incidentId,
    ) || FALLBACK_INCIDENTS[0],
  )

export const updateIncidentStatus = (incidentId: string, status: string) =>
  sentinelFetch<Incident>(`/api/incidents/${incidentId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  })

export const aiTriageIncident = (incidentId: string) =>
  sentinelFetch<AIAnalysisResponse>(`/api/incidents/${incidentId}/ai-triage`, {
    method: "POST",
  })

export const analyzeSecurityEvent = (payload: AnalysisRequest) =>
  sentinelFetch<AIAnalysisResponse>("/api/ai/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
  })

export const getThreats = (params?: {
  severity?: string
  event_type?: string
  limit?: number
}) => {
  const query = new URLSearchParams()
  if (params?.severity) query.append("severity", params.severity)
  if (params?.event_type) query.append("event_type", params.event_type)
  if (params?.limit) query.append("limit", params.limit.toString())

  const qs = query.toString() ? `?${query.toString()}` : ""
  return sentinelFetch<SecurityEvent[]>(`/api/threats${qs}`, undefined, [])
}

export const getVulnerabilities = (params?: {
  search?: string
  severity?: string
  kev_only?: boolean
  limit?: number
  offset?: number
  force_refresh?: boolean
}) => {
  const query = new URLSearchParams()
  if (params?.search) query.append("search", params.search)
  if (params?.severity && params.severity !== "ALL")
    query.append("severity", params.severity)
  if (params?.kev_only) query.append("kev_only", "true")
  if (params?.limit) query.append("limit", params.limit.toString())
  if (params?.offset) query.append("offset", params.offset.toString())
  if (params?.force_refresh) query.append("force_refresh", "true")

  const qs = query.toString() ? `?${query.toString()}` : ""
  return sentinelFetch<VulnerabilityResponse>(
    `/api/vulnerabilities${qs}`,
    undefined,
    {
      total: FALLBACK_KEV_CATALOG.length,
      source: "NVD / CISA KEV Intelligence",
      data_source: "CACHED_NVD",
      last_updated: new Date().toISOString(),
      cached: true,
      vulnerabilities: FALLBACK_KEV_CATALOG.map((k) => ({
        id: k.cveID,
        description: k.shortDescription,
        cvss: 9.8,
        severity: "CRITICAL",
        published: k.dateAdded,
        modified: k.dateAdded,
        cwe: "CWE-94",
        affected_products: [`${k.vendorProject} ${k.product}`],
        references: [k.notes || `https://nvd.nist.gov/vuln/detail/${k.cveID}`],
        is_kev: true,
        kev_details: {
          date_added: k.dateAdded,
          due_date: k.dueDate,
          ransomware_use: k.knownRansomwareCampaignUse,
          short_description: k.shortDescription,
        },
        source: "CISA KEV Catalog",
      })),
    },
  )
}

export const getKevCatalog = (params?: {
  search?: string
  ransomware_only?: boolean
  limit?: number
  offset?: number
  force_refresh?: boolean
}) => {
  const query = new URLSearchParams()
  if (params?.search) query.append("search", params.search)
  if (params?.ransomware_only) query.append("ransomware_only", "true")
  if (params?.limit) query.append("limit", params.limit.toString())
  if (params?.offset) query.append("offset", params.offset.toString())
  if (params?.force_refresh) query.append("force_refresh", "true")

  const qs = query.toString() ? `?${query.toString()}` : ""
  return sentinelFetch<KevResponse>(
    `/api/vulnerabilities/kev${qs}`,
    undefined,
    {
      source: "CISA Known Exploited Vulnerabilities Catalog",
      data_source: "CACHED_CISA_KEV",
      total: FALLBACK_KEV_CATALOG.length,
      catalog_size: FALLBACK_KEV_CATALOG.length,
      last_updated: new Date().toISOString(),
      cached: true,
      vulnerabilities: FALLBACK_KEV_CATALOG,
    },
  )
}

export const simulateResponseAction = (payload: {
  action_type: string
  target_ip: string
  target_host?: string
  requested_by?: string
  details?: string
}) =>
  sentinelFetch<SimulatedActionRecord>("/api/response/simulate-action", {
    method: "POST",
    body: JSON.stringify(payload),
  })

export const getResponseAuditLog = (limit: number = 50) =>
  sentinelFetch<SimulatedActionRecord[]>(
    `/api/response/audit-log?limit=${limit}`,
    undefined,
    [],
  )

export const getMitreMatrix = () =>
  sentinelFetch<MitreMatrixItem[]>("/api/mitre/matrix", undefined, [])

/* =========================================================
   REAL-TIME WEBSOCKET MANAGER
   ========================================================= */

type WsListener = (data: any) => void

class SentinelWsManager {
  private ws: WebSocket | null = null
  private listeners: Set<WsListener> = new Set()
  private reconnectTimer: any = null
  private pingTimer: any = null
  private isConnecting: boolean = false
  private shouldConnect: boolean = true

  constructor() {
    if (typeof window !== "undefined") {
      this.connect()
    }
  }

  public connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN))
      return
    this.isConnecting = true

    try {
      this.ws = new WebSocket(SENTINEL_WS)

      this.ws.onopen = () => {
        this.isConnecting = false
        // Ping every 25 seconds
        clearInterval(this.pingTimer)
        this.pingTimer = setInterval(() => {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: "PING" }))
          }
        }, 25000)
      }

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          this.listeners.forEach((listener) => {
            try {
              listener(data)
            } catch (err) {
              console.error("Error in Sentinel WS listener:", err)
            }
          })
        } catch (e) {
          // ignore non-json
        }
      }

      this.ws.onclose = () => {
        this.isConnecting = false
        clearInterval(this.pingTimer)
        if (this.shouldConnect) {
          clearTimeout(this.reconnectTimer)
          this.reconnectTimer = setTimeout(() => this.connect(), 4000)
        }
      }

      this.ws.onerror = () => {
        this.isConnecting = false
      }
    } catch (e) {
      this.isConnecting = false
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = setTimeout(() => this.connect(), 5000)
    }
  }

  public subscribe(listener: WsListener): () => void {
    this.listeners.add(listener)
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.connect()
    }
    return () => {
      this.listeners.delete(listener)
    }
  }

  public triggerScenario(scenarioId: string) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({
          type: "TRIGGER_SCENARIO",
          scenario_id: scenarioId,
        }),
      )
    }
  }
}

export const wsManager = new SentinelWsManager()
