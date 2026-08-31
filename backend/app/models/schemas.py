"""
SentinelSOC Data Models & Schemas
Typed Pydantic definitions for events, incidents, vulnerabilities, and AI analysis.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    description: str
    url: Optional[str] = None


class SecurityEvent(BaseModel):
    event_id: str
    id: Optional[str] = None
    timestamp: str
    event_type: str
    type: Optional[str] = None
    severity: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    target: str
    message: str
    simulation: bool = True
    source: str = "SIMULATION"
    mitre_technique: Optional[MitreTechnique] = None
    scenario_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.event_id
        if not self.type:
            self.type = self.event_type


SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10,
}


def calculate_risk_score(severity: Optional[str], confidence: Optional[float] = 1.0) -> int:
    """
    Calculate deterministic integer risk score (0-100) from severity weight and confidence.
    Severity weights:
      CRITICAL = 100
      HIGH = 75
      MEDIUM = 50
      LOW = 25
      INFO = 10
    Formula: risk_score = severity_weight * confidence (rounded to nearest integer, clamped 0-100)
    """
    if confidence is None:
        conf = 1.0
    else:
        try:
            conf = float(confidence)
        except (ValueError, TypeError):
            conf = 1.0

    sev_key = (severity or "INFO").upper().strip()
    weight = SEVERITY_WEIGHTS.get(sev_key, 10)
    score = int(round(weight * conf))
    return max(0, min(100, score))


def derive_risk_level(risk_score: int) -> str:
    """
    Convert risk_score (0-100) into a categorical risk level:
      90-100 -> CRITICAL
      70-89  -> HIGH
      40-69  -> MEDIUM
      20-39  -> LOW
      0-19   -> INFO
    """
    if risk_score >= 90:
        return "CRITICAL"
    elif risk_score >= 70:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFO"


def calculate_risk(severity: Optional[str], confidence: Optional[float] = 1.0) -> tuple[str, int]:
    """
    Derive (risk_level, risk_score) from incident severity and confidence.
    """
    score = calculate_risk_score(severity, confidence)
    level = derive_risk_level(score)
    return level, score


class Incident(BaseModel):
    incident_id: str
    id: Optional[str] = None
    title: str
    severity: str
    status: str = "OPEN"
    confidence: float
    risk: Optional[str] = None
    risk_score: Optional[int] = None
    category: str
    source_ip: str
    target: str
    source_ips: List[str] = Field(default_factory=list)
    affected_targets: List[str] = Field(default_factory=list)
    attack_stage: Optional[str] = "Initial Access"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    scenario_id: Optional[str] = None
    event_ids: List[str] = Field(default_factory=list)
    events_count: int = 0
    techniques: List[MitreTechnique] = Field(default_factory=list)
    related_cves: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    summary: str
    recommended_actions: List[str] = Field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.incident_id
        if self.risk_score is None:
            self.risk_score = calculate_risk_score(self.severity, self.confidence)
        if not self.risk:
            self.risk = derive_risk_level(self.risk_score)
        if not self.source_ips:
            self.source_ips = [self.source_ip] if self.source_ip else []
        elif self.source_ip and self.source_ip not in self.source_ips:
            self.source_ips.append(self.source_ip)
        if not self.affected_targets:
            self.affected_targets = [self.target] if self.target else []
        elif self.target and self.target not in self.affected_targets:
            self.affected_targets.append(self.target)
        if not self.first_seen:
            self.first_seen = self.created_at
        if not self.last_seen:
            self.last_seen = self.updated_at


class KevDetails(BaseModel):
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    ransomware_use: Optional[str] = "Known"
    short_description: Optional[str] = None


class VulnerabilityItem(BaseModel):
    id: str
    description: str
    cvss: Optional[float] = None
    severity: str = "MEDIUM"
    published: Optional[str] = None
    modified: Optional[str] = None
    cwe: Optional[str] = None
    affected_products: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    is_kev: bool = False
    kev_details: Optional[KevDetails] = None
    source: str = "NVD"


class VulnerabilityResponse(BaseModel):
    total: int
    source: str
    last_updated: str
    cached: bool
    vulnerabilities: List[VulnerabilityItem]


class KevResponse(BaseModel):
    total: int
    source: str
    last_updated: str
    cached: bool
    vulnerabilities: List[Dict[str, Any]]


class AnalysisRequest(BaseModel):
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = "HIGH"
    details: Optional[str] = None
    source_ip: Optional[str] = None
    target: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class EvidenceBreakdown(BaseModel):
    observed: List[str] = Field(default_factory=list)
    inferred: List[str] = Field(default_factory=list)
    recommended: List[str] = Field(default_factory=list)
    unknown: List[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    risk_score: int
    risk_level: str
    classification: str
    confidence: float
    summary: str
    threat_summary: Optional[str] = None
    why_it_matters: Optional[str] = None
    attack_progression: List[str] = Field(default_factory=list)
    likely_objective: Optional[str] = None
    mitre_technique: Optional[MitreTechnique] = None
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    observed_facts: List[str] = Field(default_factory=list)
    ai_inference: List[str] = Field(default_factory=list)
    unknown_factors: List[str] = Field(default_factory=list)
    evidence: Optional[EvidenceBreakdown] = None
    immediate_response: List[str] = Field(default_factory=list)
    investigation_steps: List[str] = Field(default_factory=list)
    long_term_hardening: List[str] = Field(default_factory=list)
    playbook_recommendations: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    evidence_count: int = 0
    model: str = "Sentinel AI Expert Defensive Engine"
    source: str = "Sentinel AI Defensive Engine"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.threat_summary:
            self.threat_summary = self.summary
        if not self.mitre_techniques and self.mitre_technique:
            self.mitre_techniques = [self.mitre_technique]
        if not self.evidence:
            self.evidence = EvidenceBreakdown(
                observed=self.observed_facts,
                inferred=self.ai_inference,
                recommended=self.immediate_response,
                unknown=self.unknown_factors
            )
        if not self.evidence_count:
            self.evidence_count = len(self.observed_facts) + len(self.ai_inference)


class IncidentStatusUpdate(BaseModel):
    status: str
