import React, { useEffect } from "react";
import {
  X,
  Brain,
  ShieldAlert,
  Clock,
  CheckCircle2,
  Target,
} from "lucide-react";
import { Incident, IncidentStatus, SecurityEvent } from "../types";

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
            <div className="grid grid-cols-3 gap-3 border-t border-slate-800 pt-3">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">ATTACK SOURCE</span>
                <strong className="text-xs text-amber-400 font-mono">{incident.source_ip}</strong>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">TARGET ASSET</span>
                <strong className="text-xs text-cyan-400 font-mono">{incident.target}</strong>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">CORRELATION CONFIDENCE</span>
                <strong className="text-xs text-emerald-400 font-mono">{confPct}% Match</strong>
              </div>
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
                      <span className="font-mono font-bold text-emerald-400">{tech.id}</span>
                      <span className="text-slate-200 font-semibold">{tech.name}</span>
                      <span className="tactic-pill">Tactic: {tech.tactic}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{tech.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Playbook Actions */}
          {incident.recommended_actions && incident.recommended_actions.length > 0 && (
            <div className="drawer-section">
              <h4 className="section-label text-rose-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                RECOMMENDED CONTAINMENT PLAYBOOK
              </h4>
              <div className="playbook-list">
                {incident.recommended_actions.map((act, idx) => (
                  <label key={idx} className="playbook-item">
                    <input type="checkbox" className="cyber-check" />
                    <span>{act}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
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
