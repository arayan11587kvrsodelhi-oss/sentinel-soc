import React, { useState } from "react";
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
  HelpCircle,
  Crosshair,
  ShieldAlert,
  Terminal,
  Activity,
  CheckCircle2,
} from "lucide-react";
import { AiAnalysisResult, Incident, SecurityEvent, SimulatedActionRecord } from "../types";
import { api } from "../services/api";

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
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [lastActionRecord, setLastActionRecord] = useState<SimulatedActionRecord | null>(null);

  const handleSimulateAction = async (actionType: string) => {
    const target =
      selectedContext.incident?.source_ip ||
      selectedContext.incident?.target ||
      selectedContext.event?.source_ip ||
      selectedContext.event?.target ||
      "192.168.1.105";

    const incidentId = selectedContext.incident?.incident_id || selectedContext.incident?.id;

    setExecutingAction(actionType);
    try {
      const record = await api.simulateResponseAction({
        action_type: actionType,
        target,
        incident_id: incidentId,
        reason: `AI Copilot recommended containment for ${selectedContext.incident?.title || "active anomaly"}`,
      });
      setLastActionRecord(record);
    } catch (err) {
      console.error("Failed to execute simulated action:", err);
    } finally {
      setExecutingAction(null);
    }
  };

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

            {/* Summary & Impact */}
            <div className="ai-section">
              <h4 className="section-title">
                <Info className="w-3.5 h-3.5 text-emerald-400" />
                THREAT SUMMARY & IMPACT
              </h4>
              <p className="summary-text">{analysis.threat_summary || analysis.summary}</p>
              {analysis.why_it_matters && (
                <div className="mt-2 text-xs text-slate-300 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                  <strong className="text-cyan-400 block mb-0.5">Why It Matters:</strong>
                  <span>{analysis.why_it_matters}</span>
                </div>
              )}
            </div>

            {/* Attack Progression & Likely Objective */}
            {analysis.attack_progression && analysis.attack_progression.length > 0 && (
              <div className="ai-section">
                <h4 className="section-title text-cyan-400">
                  <Crosshair className="w-3.5 h-3.5" />
                  ATTACK PROGRESSION & LIKELY OBJECTIVE
                </h4>
                {analysis.likely_objective && (
                  <div className="text-xs text-amber-300 font-mono mb-2 bg-amber-950/20 p-2 rounded border border-amber-800/40">
                    <strong>Adversary Objective:</strong> {analysis.likely_objective}
                  </div>
                )}
                <div className="space-y-1 font-mono text-xs text-slate-300">
                  {analysis.attack_progression.map((step, idx) => (
                    <div key={idx} className="bg-slate-900/40 p-1.5 rounded border border-slate-800 flex items-center gap-2">
                      <span className="text-emerald-400 font-bold">›</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Structured Evidence: Observed vs Inferred vs Unknown */}
            <div className="ai-section">
              <h4 className="section-title text-slate-200">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                GROUNDED EVIDENCE CONTRACT
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-2">
                {/* Observed Facts */}
                <div className="facts-card">
                  <h5 className="sub-title text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    OBSERVED (FACTS)
                  </h5>
                  <ul className="text-xs space-y-1 mt-1 text-slate-300">
                    {(analysis.evidence?.observed || analysis.observed_facts)?.map((fact, idx) => (
                      <li key={idx} className="fact-item">
                        <span className="bullet text-emerald-400">✓</span>
                        <span>{fact}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* AI Inferences */}
                <div className="inference-card">
                  <h5 className="sub-title text-amber-400 flex items-center gap-1">
                    <Zap className="w-3 h-3" />
                    INFERRED (PROBABILISTIC)
                  </h5>
                  <ul className="text-xs space-y-1 mt-1 text-slate-300">
                    {(analysis.evidence?.inferred || analysis.ai_inference)?.map((inf, idx) => (
                      <li key={idx} className="inference-item">
                        <span className="bullet text-amber-400">⚡</span>
                        <span>{inf}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Unknown Factors */}
                <div className="bg-slate-900/40 p-2.5 rounded border border-slate-800">
                  <h5 className="sub-title text-slate-400 flex items-center gap-1">
                    <HelpCircle className="w-3 h-3" />
                    UNKNOWN (BLIND SPOTS)
                  </h5>
                  <ul className="text-xs space-y-1 mt-1 text-slate-400">
                    {(analysis.evidence?.unknown || analysis.unknown_factors || [
                      "External actor geography and ASN attribution.",
                      "Whether credentials were leaked on public paste sites."
                    ])?.map((unk, idx) => (
                      <li key={idx} className="flex items-start gap-1">
                        <span className="text-slate-500">?</span>
                        <span>{unk}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>

            {/* Automated Simulated Response Actions */}
            <div className="ai-section bg-rose-950/10 p-3 rounded-lg border border-rose-900/30">
              <div className="flex items-center justify-between mb-2">
                <h4 className="section-title text-rose-400 m-0">
                  <Terminal className="w-3.5 h-3.5" />
                  SIMULATED AUTOMATED RESPONSE PLAYBOOK
                </h4>
                <span className="pill-sim">SIMULATION ONLY</span>
              </div>
              <p className="text-xs text-slate-400 mb-3">
                Execute safe, auditable containment procedures for this incident. Zero modifications are made to real infrastructure.
              </p>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <button
                  className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-rose-950/30 hover:bg-rose-900/40 border-rose-800/50 text-rose-300 flex items-center justify-center gap-1"
                  onClick={() => handleSimulateAction("IP_BAN")}
                  disabled={executingAction !== null}
                >
                  <span>{executingAction === "IP_BAN" ? "Executing..." : "[ SIMULATE IP BAN ]"}</span>
                </button>

                <button
                  className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-amber-950/30 hover:bg-amber-900/40 border-amber-800/50 text-amber-300 flex items-center justify-center gap-1"
                  onClick={() => handleSimulateAction("FIREWALL_BLOCK")}
                  disabled={executingAction !== null}
                >
                  <span>{executingAction === "FIREWALL_BLOCK" ? "Executing..." : "[ SIMULATE FIREWALL BLOCK ]"}</span>
                </button>

                <button
                  className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-cyan-950/30 hover:bg-cyan-900/40 border-cyan-800/50 text-cyan-300 flex items-center justify-center gap-1"
                  onClick={() => handleSimulateAction("CREDENTIAL_REVOCATION")}
                  disabled={executingAction !== null}
                >
                  <span>{executingAction === "CREDENTIAL_REVOCATION" ? "Executing..." : "[ SIMULATE CREDENTIAL REVOCATION ]"}</span>
                </button>

                <button
                  className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-purple-950/30 hover:bg-purple-900/40 border-purple-800/50 text-purple-300 flex items-center justify-center gap-1"
                  onClick={() => handleSimulateAction("HOST_ISOLATION")}
                  disabled={executingAction !== null}
                >
                  <span>{executingAction === "HOST_ISOLATION" ? "Executing..." : "[ SIMULATE HOST ISOLATION ]"}</span>
                </button>
              </div>

              {/* Execution Feedback */}
              {lastActionRecord && (
                <div className="mt-3 bg-emerald-950/30 border border-emerald-500/40 p-2.5 rounded text-xs">
                  <div className="flex items-center justify-between text-emerald-400 font-mono font-bold mb-1">
                    <span>{lastActionRecord.action_label} · {lastActionRecord.status}</span>
                    <span className="text-[10px] text-slate-400">{new Date(lastActionRecord.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-slate-300 m-0">{lastActionRecord.details}</p>
                </div>
              )}
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
            {/* Auditability Footer */}
            <div className="ai-section mt-4 pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex flex-wrap items-center justify-between gap-2">
              <span>Engine: <strong>{analysis.model || analysis.source}</strong></span>
              <span>Generated At: <strong>{analysis.generated_at ? new Date(analysis.generated_at).toLocaleTimeString() : "Just now"}</strong></span>
              <span>Evidence Items: <strong>{analysis.evidence_count || (analysis.observed_facts?.length + analysis.ai_inference?.length) || 4}</strong></span>
              {analysis.incident_id && <span>Target Incident: <strong>{analysis.incident_id}</strong></span>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
