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


class Incident(BaseModel):
    incident_id: str
    id: Optional[str] = None
    title: str
    severity: str
    status: str = "OPEN"
    confidence: float
    category: str
    source_ip: str
    target: str
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


class AnalysisResponse(BaseModel):
    risk_score: int
    risk_level: str
    classification: str
    confidence: float
    summary: str
    observed_facts: List[str] = Field(default_factory=list)
    ai_inference: List[str] = Field(default_factory=list)
    mitre_technique: Optional[MitreTechnique] = None
    affected_assets: List[str] = Field(default_factory=list)
    immediate_response: List[str] = Field(default_factory=list)
    investigation_steps: List[str] = Field(default_factory=list)
    long_term_hardening: List[str] = Field(default_factory=list)
    source: str = "Sentinel AI Defensive Engine"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IncidentStatusUpdate(BaseModel):
    status: str
