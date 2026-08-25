import React, { useEffect, useState } from "react";
import {
  X,
  Brain,
  ShieldAlert,
  Clock,
  CheckCircle2,
  Target,
  Zap,
  HelpCircle,
  Terminal,
  ShieldCheck,
  ExternalLink,
} from "lucide-react";
import { Incident, IncidentStatus, SecurityEvent, SimulatedActionRecord } from "../types";
import { api } from "../services/api";

interface IncidentDetailDrawerProps {
  incident: Incident | null;
  recentEvents: SecurityEvent[];
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
  onAiTriageIncident: (incident: Incident) => void;
  onSelectEvent?: (event: SecurityEvent) => void;
}

export const IncidentDetailDrawer: React.FC<IncidentDetailDrawerProps> = ({
  incident,
  recentEvents,
  onClose,
  onUpdateStatus,
  onAiTriageIncident,
  onSelectEvent,
}) => {
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [lastActionRecord, setLastActionRecord] = useState<SimulatedActionRecord | null>(null);

  const handleSimulateAction = async (actionType: string) => {
    if (!incident) return;
    const target = incident.source_ip || incident.target || "192.168.1.105";
    setExecutingAction(actionType);
    try {
      const record = await api.simulateResponseAction({
        action_type: actionType,
        target,
        incident_id: incident.incident_id || incident.id,
        reason: `Manual containment execution from Incident ${incident.incident_id || incident.id}`,
      });
      setLastActionRecord(record);
    } catch (err) {
      console.error("Failed to execute simulated action:", err);
    } finally {
      setExecutingAction(null);
    }
  };
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (incident) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [incident, onClose]);

  if (!incident) return null;

  const confPct = Math.round((incident.confidence || 0.9) * 100);

  // Find actual event objects matching incident.event_ids
  const correlatedEvents = (incident.event_ids || []).map((eid) => {
    const found = recentEvents.find((e) => (e.event_id || e.id) === eid);
    if (found) return found;
    return {
      event_id: eid,
      id: eid,
      timestamp: incident.created_at,
      event_type: incident.category || "SECURITY_ALERT",
      severity: incident.severity,
      source_ip: incident.source_ip,
      destination_ip: "10.0.1.50",
      destination_port: 443,
      protocol: "HTTPS",
      target: incident.target,
      message: `Correlated telemetry step for ${eid}`,
      simulation: true,
      source: "SIMULATION",
    } as SecurityEvent;
  });

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel drawer-panel-wide" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <h3 className="drawer-title">INCIDENT INVESTIGATION & TIMELINE</h3>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="drawer-body">
          {/* Header Card */}
          <div className="drawer-card">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="badge badge-critical">{incident.severity}</span>
                <span className="font-mono text-sm text-slate-300 font-bold">
                  {incident.incident_id || incident.id}
                </span>
                <span className="pill-engine">CORRELATED INCIDENT</span>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Status:</span>
                <select
                  className="status-select bg-slate-900 border-slate-700 text-slate-200"
                  value={incident.status}
                  onChange={(e) =>
                    onUpdateStatus(incident.incident_id || incident.id || "", e.target.value as IncidentStatus)
                  }
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>
            </div>

            <h2 className="text-lg font-bold text-slate-100 mb-2">{incident.title}</h2>
            <p className="text-sm text-slate-300 leading-relaxed mb-4">{incident.summary}</p>

            {/* Metrics Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 border-t border-slate-800 pt-3">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">ATTACK STAGE</span>
                <strong className="text-xs text-cyan-400 font-mono">{incident.attack_stage || "Initial Access"}</strong>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">ATTACK SOURCES</span>
                <strong className="text-xs text-amber-400 font-mono">
                  {(incident.source_ips && incident.source_ips.length > 0) ? incident.source_ips.join(", ") : incident.source_ip}
                </strong>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">TARGET ASSETS</span>
                <strong className="text-xs text-cyan-300 font-mono">
                  {(incident.affected_targets && incident.affected_targets.length > 0) ? incident.affected_targets.join(", ") : incident.target}
                </strong>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">CONFIDENCE</span>
                <strong className="text-xs text-emerald-400 font-mono">{confPct}% Match</strong>
              </div>
            </div>

            {/* Attack Window Info */}
            <div className="mt-3 pt-2 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-400">
              <span>First Seen: {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : new Date(incident.created_at).toLocaleString()}</span>
              <span>Last Activity: {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : new Date(incident.updated_at).toLocaleString()}</span>
            </div>
          </div>

          {/* Visual Event Timeline */}
          <div className="drawer-section">
            <h4 className="section-label">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              CORRELATED ATTACK CHAIN TIMELINE ({correlatedEvents.length} Events)
            </h4>

            <div className="timeline-container">
              {correlatedEvents.map((ev, idx) => (
                <div
                  key={ev.event_id || idx}
                  className="timeline-item"
                  onClick={() => onSelectEvent && onSelectEvent(ev)}
                >
                  <div className="timeline-marker">
                    <span className="marker-num">{idx + 1}</span>
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-head">
                      <strong className="text-xs text-slate-200 font-mono">{ev.event_type || ev.type}</strong>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="timeline-msg">{ev.message}</p>
                    <div className="timeline-meta">
                      <span>{ev.source_ip} → {ev.target} ({ev.protocol}:{ev.destination_port})</span>
                      {ev.mitre_technique && (
                        <span className="mitre-tag-sm ml-auto">{ev.mitre_technique.id}</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE ATT&CK Mappings */}
          {incident.techniques && incident.techniques.length > 0 && (
            <div className="drawer-section">
              <h4 className="section-label">
                <Target className="w-3.5 h-3.5 text-emerald-400" />
                MAPPED MITRE ATT&CK TECHNIQUES
              </h4>
              <div className="flex flex-col gap-2">
                {incident.techniques.map((tech) => (
                  <div key={tech.id} className="mitre-box">
                    <div className="mitre-box-header">
                      <a
                        href={tech.url || `https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-mono font-bold text-emerald-400 hover:underline"
                        title="View technique on attack.mitre.org"
                      >
                        {tech.id}
                      </a>
                      <span className="text-slate-200 font-semibold">{tech.name}</span>
                      <span className="tactic-pill">Tactic: {tech.tactic}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{tech.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Related CVEs */}
          {incident.related_cves && incident.related_cves.length > 0 && (
            <div className="drawer-section">
              <h4 className="section-label">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                ASSOCIATED CVE INTELLIGENCE
              </h4>
              <div className="flex flex-wrap gap-2">
                {incident.related_cves.map((cve) => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noreferrer"
                    className="cve-tag-sm hover:brightness-125 transition-all text-xs"
                    title={`View ${cve} on NIST NVD`}
                  >
                    {cve} ↗
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* AI Defensive Analysis Section (if present) */}
          {incident.ai_analysis && (
            <div className="drawer-section bg-slate-900/60 p-3 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between mb-2">
                <h4 className="section-label text-emerald-400 m-0">
                  <Brain className="w-3.5 h-3.5" />
                  AI DEFENSIVE COPILOT ASSESSMENT
                </h4>
                <span className="text-[10px] text-slate-400 font-mono">
                  {incident.ai_analysis.model || incident.ai_analysis.source}
                </span>
              </div>

              <p className="text-xs text-slate-200 leading-relaxed mb-2">
                {incident.ai_analysis.threat_summary || incident.ai_analysis.summary}
              </p>

              {incident.ai_analysis.why_it_matters && (
                <div className="text-xs text-slate-300 bg-slate-950/40 p-2 rounded border border-slate-800 mb-3">
                  <strong className="text-cyan-400 block mb-0.5">Why It Matters:</strong>
                  <span>{incident.ai_analysis.why_it_matters}</span>
                </div>
              )}

              {/* Evidence Contract: Observed vs Inferred vs Unknown */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-2">
                <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
                  <span className="text-[10px] text-emerald-400 font-bold uppercase block mb-1">
                    ✓ Observed (Facts)
                  </span>
                  <ul className="text-[11px] text-slate-300 space-y-0.5">
                    {(incident.ai_analysis.evidence?.observed || incident.ai_analysis.observed_facts)?.slice(0, 3).map((f, i) => (
                      <li key={i}>• {f}</li>
                    ))}
                  </ul>
                </div>

                <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
                  <span className="text-[10px] text-amber-400 font-bold uppercase block mb-1">
                    ⚡ Inferred (Analysis)
                  </span>
                  <ul className="text-[11px] text-slate-300 space-y-0.5">
                    {(incident.ai_analysis.evidence?.inferred || incident.ai_analysis.ai_inference)?.slice(0, 3).map((f, i) => (
                      <li key={i}>• {f}</li>
                    ))}
                  </ul>
                </div>

                <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">
                    ? Unknown (Blind Spots)
                  </span>
                  <ul className="text-[11px] text-slate-400 space-y-0.5">
                    {(incident.ai_analysis.evidence?.unknown || incident.ai_analysis.unknown_factors || ["External adversary staging location unknown."])?.slice(0, 2).map((f, i) => (
                      <li key={i}>• {f}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Simulated Automated Response Playbook */}
          <div className="drawer-section bg-rose-950/10 p-3 rounded-lg border border-rose-900/30">
            <div className="flex items-center justify-between mb-2">
              <h4 className="section-label text-rose-400 m-0">
                <Terminal className="w-3.5 h-3.5" />
                SIMULATED RESPONSE PLAYBOOK
              </h4>
              <span className="pill-sim">SIMULATION</span>
            </div>

            <div className="grid grid-cols-2 gap-2 mt-2">
              <button
                className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-rose-950/30 hover:bg-rose-900/40 border-rose-800/50 text-rose-300"
                onClick={() => handleSimulateAction("IP_BAN")}
                disabled={executingAction !== null}
              >
                {executingAction === "IP_BAN" ? "Executing..." : "[ SIMULATE IP BAN ]"}
              </button>

              <button
                className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-amber-950/30 hover:bg-amber-900/40 border-amber-800/50 text-amber-300"
                onClick={() => handleSimulateAction("FIREWALL_BLOCK")}
                disabled={executingAction !== null}
              >
                {executingAction === "FIREWALL_BLOCK" ? "Executing..." : "[ SIMULATE FIREWALL BLOCK ]"}
              </button>

              <button
                className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-cyan-950/30 hover:bg-cyan-900/40 border-cyan-800/50 text-cyan-300"
                onClick={() => handleSimulateAction("CREDENTIAL_REVOCATION")}
                disabled={executingAction !== null}
              >
                {executingAction === "CREDENTIAL_REVOCATION" ? "Executing..." : "[ SIMULATE CREDENTIAL REVOCATION ]"}
              </button>

              <button
                className="btn btn-secondary text-xs font-mono py-1.5 px-2 bg-purple-950/30 hover:bg-purple-900/40 border-purple-800/50 text-purple-300"
                onClick={() => handleSimulateAction("HOST_ISOLATION")}
                disabled={executingAction !== null}
              >
                {executingAction === "HOST_ISOLATION" ? "Executing..." : "[ SIMULATE HOST ISOLATION ]"}
              </button>
            </div>

            {lastActionRecord && (
              <div className="mt-2.5 bg-emerald-950/30 border border-emerald-500/40 p-2 rounded text-xs">
                <div className="flex items-center justify-between text-emerald-400 font-mono font-bold mb-0.5">
                  <span>{lastActionRecord.action_label} · {lastActionRecord.status}</span>
                  <span className="text-[10px] text-slate-400">{new Date(lastActionRecord.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="text-slate-300 m-0">{lastActionRecord.details}</p>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="drawer-footer">
          <button
            className="btn btn-primary w-full flex items-center justify-center gap-2"
            onClick={() => {
              onAiTriageIncident(incident);
              onClose();
            }}
          >
            <Brain className="w-4 h-4" />
            <span>Launch Sentinel AI Defensive Triage</span>
          </button>
        </div>
      </div>
    </div>
  );
};
