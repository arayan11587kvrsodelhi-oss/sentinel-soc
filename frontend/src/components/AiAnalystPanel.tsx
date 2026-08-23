import React from "react";
import {
  Brain,
  ShieldCheck,
  Sparkles,
  CheckSquare,
  Search,
  Wrench,
  ExternalLink,
  Zap,
  Info,
} from "lucide-react";
import { AiAnalysisResult, Incident, SecurityEvent } from "../types";

interface AiAnalystPanelProps {
  analysis: AiAnalysisResult | null;
  loading: boolean;
  selectedContext: {
    type: "EVENT" | "INCIDENT" | "MANUAL" | null;
    event?: SecurityEvent | null;
    incident?: Incident | null;
  };
  onRunLiveTriage: () => void;
}

export const AiAnalystPanel: React.FC<AiAnalystPanelProps> = ({
  analysis,
  loading,
  selectedContext,
  onRunLiveTriage,
}) => {
  const getRiskColor = (score: number, level: string) => {
    if (score >= 90 || level === "CRITICAL") return "text-rose-400 border-rose-500/40 bg-rose-950/20";
    if (score >= 70 || level === "HIGH") return "text-amber-400 border-amber-500/40 bg-amber-950/20";
    if (score >= 40 || level === "MEDIUM") return "text-yellow-400 border-yellow-500/40 bg-yellow-950/20";
    return "text-emerald-400 border-emerald-500/40 bg-emerald-950/20";
  };

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-head">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-emerald-400" />
          <h2>SENTINEL AI DEFENSIVE ANALYST</h2>
          <span className="pill-ai">SOC TRIAGE ENGINE</span>
        </div>

        <div className="flex items-center gap-2">
          {analysis && (
            <span className="text-[10px] text-slate-400 font-mono">
              {analysis.source}
            </span>
          )}
        </div>
      </div>

      {/* Context Banner */}
      <div className="ai-context-bar">
        <div className="flex items-center gap-2">
          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-xs text-slate-300">
            {selectedContext.type === "INCIDENT" && selectedContext.incident
              ? `Target: Incident ${selectedContext.incident.incident_id || selectedContext.incident.id} (${selectedContext.incident.title})`
              : selectedContext.type === "EVENT" && selectedContext.event
                ? `Target: Event ${selectedContext.event.event_id || selectedContext.event.id} (${selectedContext.event.event_type})`
                : "Target: Live Telemetry Stream Triage"}
          </span>
        </div>

        <button
          className="btn btn-primary text-xs flex items-center gap-1.5"
          onClick={onRunLiveTriage}
          disabled={loading}
        >
          <Brain className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>{loading ? "Analyzing Telemetry..." : "Run AI Triage"}</span>
        </button>
      </div>

      {/* Main Analysis Content */}
      <div className="ai-content-scroll">
        {!analysis && !loading && (
          <div className="empty-state">
            <Brain className="w-10 h-10 text-slate-600 mb-3" />
            <h3 className="text-sm font-bold text-slate-300">Sentinel AI is standby ready.</h3>
            <p className="text-xs text-slate-400 max-w-sm text-center mt-1">
              Select any event from the Live Stream or an Incident from the list, then click{" "}
              <strong>AI Triage</strong> to compute structured risk scores, MITRE mappings, and containment playbooks.
            </p>
          </div>
        )}

        {loading && (
          <div className="loading-state">
            <div className="cyber-spinner" />
            <p className="text-xs text-emerald-400 font-mono tracking-wider animate-pulse mt-3">
              PROCESSING TELEMETRY & CORRELATING ATTACK VECTORS...
            </p>
          </div>
        )}

        {analysis && !loading && (
          <div className="ai-analysis-results">
            {/* Top Score Banner */}
            <div className={`risk-banner border ${getRiskColor(analysis.risk_score, analysis.risk_level)}`}>
              <div className="risk-score-circle">
                <span className="risk-num">{analysis.risk_score}</span>
                <span className="risk-sub">/ 100</span>
              </div>
              <div className="risk-info">
                <div className="flex items-center gap-2">
                  <span className="badge badge-critical">{analysis.risk_level} RISK</span>
                  <span className="text-xs text-slate-400 font-mono">
                    {Math.round(analysis.confidence * 100)}% Confidence
                  </span>
                </div>
                <h3 className="classification-title">{analysis.classification}</h3>
              </div>
            </div>

            {/* Summary */}
            <div className="ai-section">
              <h4 className="section-title">
                <Info className="w-3.5 h-3.5 text-emerald-400" />
                EXECUTIVE DEFENSIVE SUMMARY
              </h4>
              <p className="summary-text">{analysis.summary}</p>
            </div>

            {/* Facts vs Inference */}
            <div className="facts-inference-grid">
              <div className="facts-card">
                <h5 className="sub-title text-cyan-400">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  OBSERVED FACTS (GROUND TRUTH)
                </h5>
                <ul>
                  {analysis.observed_facts?.map((fact, idx) => (
                    <li key={idx} className="fact-item">
                      <span className="bullet">✓</span>
                      <span>{fact}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="inference-card">
                <h5 className="sub-title text-amber-400">
                  <Zap className="w-3.5 h-3.5" />
                  AI INFERENCE (PROBABILISTIC)
                </h5>
                <ul>
                  {analysis.ai_inference?.map((inf, idx) => (
                    <li key={idx} className="inference-item">
                      <span className="bullet">⚡</span>
                      <span>{inf}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* MITRE Technique */}
            {analysis.mitre_technique && (
              <div className="ai-section">
                <h4 className="section-title">
                  <Search className="w-3.5 h-3.5 text-emerald-400" />
                  MITRE ATT&CK ALIGNMENT
                </h4>
                <div className="mitre-box">
                  <div className="mitre-box-header">
                    <span className="font-mono text-emerald-400 font-bold">
                      {analysis.mitre_technique.id}
                    </span>
                    <span className="text-slate-200 font-semibold">
                      {analysis.mitre_technique.name}
                    </span>
                    <span className="tactic-pill">
                      Tactic: {analysis.mitre_technique.tactic}
                    </span>
                    {analysis.mitre_technique.url && (
                      <a
                        href={analysis.mitre_technique.url}
                        target="_blank"
                        rel="noreferrer"
                        className="ml-auto text-slate-400 hover:text-emerald-400"
                        title="View MITRE Technique Reference"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    {analysis.mitre_technique.description}
                  </p>
                </div>
              </div>
            )}

            {/* Playbooks */}
            <div className="ai-section">
              <h4 className="section-title text-rose-400">
                <CheckSquare className="w-3.5 h-3.5" />
                IMMEDIATE CONTAINMENT RESPONSE
              </h4>
              <div className="playbook-list">
                {analysis.immediate_response?.map((step, idx) => (
                  <label key={idx} className="playbook-item">
                    <input type="checkbox" className="cyber-check" />
                    <span>{step}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="ai-section">
              <h4 className="section-title text-cyan-400">
                <Search className="w-3.5 h-3.5" />
                FORENSIC INVESTIGATION STEPS
              </h4>
              <ol className="investigation-list">
                {analysis.investigation_steps?.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ol>
            </div>

            <div className="ai-section">
              <h4 className="section-title text-emerald-400">
                <Wrench className="w-3.5 h-3.5" />
                LONG-TERM SYSTEM HARDENING
              </h4>
              <ul className="hardening-list">
                {analysis.long_term_hardening?.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
