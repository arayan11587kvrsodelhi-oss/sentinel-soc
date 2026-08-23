export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED";

export type WebSocketStatus = "ONLINE" | "CONNECTING" | "RECONNECTING" | "OFFLINE";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url?: string;
}

export interface SecurityEvent {
  event_id: string;
  id?: string;
  timestamp: string;
  event_type: string;
  type?: string;
  severity: Severity;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  target: string;
  message: string;
  simulation: boolean;
  source?: string;
  mitre_technique?: MitreTechnique;
  scenario_id?: string;
  metadata?: Record<string, any>;
}

export interface Incident {
  incident_id: string;
  id?: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  confidence: number;
  category: string;
  source_ip: string;
  target: string;
  event_ids: string[];
  events_count: number;
  techniques: MitreTechnique[];
  related_cves: string[];
  created_at: string;
  updated_at: string;
  summary: string;
  recommended_actions: string[];
  ai_analysis?: AiAnalysisResult;
}

export interface KevDetails {
  date_added?: string;
  due_date?: string;
  ransomware_use?: string;
  short_description?: string;
}

export interface Vulnerability {
  id: string;
  description: string;
  cvss?: number;
  severity: Severity;
  published?: string;
  modified?: string;
  cwe?: string;
  affected_products?: string[];
  references?: string[];
  is_kev: boolean;
  kev_details?: KevDetails;
  source: string;
}

export interface VulnerabilityResponse {
  source: string;
  data_source?: string;
  total: number;
  cached: boolean;
  last_updated: string;
  vulnerabilities: Vulnerability[];
}

export interface KevResponse {
  source: string;
  data_source?: string;
  total: number;
  catalog_size: number;
  cached: boolean;
  last_updated: string;
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
    notes?: string;
  }>;
}

export interface AiAnalysisResult {
  risk_score: number;
  risk_level: Severity;
  classification: string;
  confidence: number;
  summary: string;
  observed_facts: string[];
  ai_inference: string[];
  mitre_technique?: MitreTechnique;
  affected_assets?: string[];
  immediate_response: string[];
  investigation_steps: string[];
  long_term_hardening: string[];
  source: string;
  generated_at?: string;
}

export interface DashboardMetrics {
  status: string;
  mode: string;
  active_incidents: number;
  total_incidents: number;
  critical_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  total_events_streamed: number;
  nvd_records_total: number;
  nvd_data_source?: string;
  kev_catalog_total: number;
  kev_data_source?: string;
  nvd_records_cached?: number;
  kev_records_cached?: number;
  timestamp: string;
}
