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
  source_ips?: string[];
  affected_targets?: string[];
  attack_stage?: string;
  first_seen?: string;
  last_seen?: string;
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

export interface EvidenceBreakdown {
  observed: string[];
  inferred: string[];
  recommended: string[];
  unknown: string[];
}

export interface AiAnalysisResult {
  risk_score: number;
  risk_level: Severity;
  classification: string;
  confidence: number;
  summary: string;
  threat_summary?: string;
  why_it_matters?: string;
  attack_progression?: string[];
  likely_objective?: string;
  observed_facts: string[];
  ai_inference: string[];
  unknown_factors?: string[];
  evidence?: EvidenceBreakdown;
  mitre_technique?: MitreTechnique;
  mitre_techniques?: MitreTechnique[];
  affected_assets?: string[];
  immediate_response: string[];
  investigation_steps: string[];
  long_term_hardening: string[];
  playbook_recommendations?: string[];
  incident_id?: string;
  evidence_count?: number;
  model?: string;
  source: string;
  generated_at?: string;
}

export interface SimulatedActionRecord {
  action_id: string;
  action_type: string;
  action_label: string;
  target: string;
  incident_id?: string;
  timestamp: string;
  triggered_by: string;
  reason: string;
  status: string;
  details: string;
  simulation: boolean;
}

export interface SimulatedActionRequest {
  action_type: string;
  target: string;
  incident_id?: string;
  reason?: string;
  triggered_by?: string;
}

export interface MitreMatrixItem {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url?: string;
  status: "OBSERVED" | "SIMULATED" | "NOT_OBSERVED";
  incidents_count: number;
  events_count: number;
  related_incident_ids: string[];
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
