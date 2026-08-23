import React, { useEffect } from "react";
import { X, Brain, Shield, ExternalLink, Terminal, ArrowRight, Network } from "lucide-react";
import { SecurityEvent } from "../types";

interface EventDetailDrawerProps {
  event: SecurityEvent | null;
  onClose: () => void;
  onAnalyzeEvent: (event: SecurityEvent) => void;
}

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({
  event,
  onClose,
  onAnalyzeEvent,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (event) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [event, onClose]);

  if (!event) return null;

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "badge-critical";
      case "HIGH":
        return "badge-high";
      case "MEDIUM":
        return "badge-medium";
      default:
        return "badge-low";
    }
  };

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <h3 className="drawer-title">SECURITY EVENT FORENSICS</h3>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="drawer-body">
          {/* Top Metadata */}
          <div className="drawer-card">
            <div className="flex items-center justify-between mb-3">
              <span className={`badge ${getSeverityBadge(event.severity)}`}>
                {event.severity}
              </span>
              <span className="pill-sim">SIMULATION TELEMETRY</span>
            </div>

            <h4 className="font-mono text-lg text-slate-100 font-bold mb-1">
              {event.event_type || event.type}
            </h4>
            <div className="text-xs text-slate-400 font-mono">
              Event ID: <strong>{event.event_id || event.id}</strong>
            </div>
            <div className="text-xs text-slate-400 font-mono">
              Observed At: {new Date(event.timestamp).toLocaleString()}
            </div>
          </div>

          {/* Network Flow */}
          <div className="drawer-section">
            <h5 className="section-label">
              <Network className="w-3.5 h-3.5 text-cyan-400" />
              NETWORK TELEMETRY & ATTACK PATH
            </h5>
            <div className="network-flow-box">
              <div className="flow-node">
                <span className="flow-label">SOURCE IP</span>
                <strong className="flow-val text-amber-300">{event.source_ip}</strong>
              </div>
              <div className="flow-arrow">
                <ArrowRight className="w-4 h-4 text-emerald-400" />
                <span className="flow-proto">{event.protocol}:{event.destination_port}</span>
              </div>
              <div className="flow-node">
                <span className="flow-label">TARGET ASSET</span>
                <strong className="flow-val text-cyan-300">{event.target}</strong>
                <span className="text-[10px] text-slate-500 font-mono">({event.destination_ip})</span>
              </div>
            </div>
          </div>

          {/* Message / Payload */}
          <div className="drawer-section">
            <h5 className="section-label">RAW LOG MESSAGE</h5>
            <div className="raw-log-box">
              <code>{event.message}</code>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          {event.mitre_technique && (
            <div className="drawer-section">
              <h5 className="section-label">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                MITRE ATT&CK CONTEXT
              </h5>
              <div className="mitre-box">
                <div className="mitre-box-header">
                  <span className="font-mono font-bold text-emerald-400">
                    {event.mitre_technique.id}
                  </span>
                  <span className="text-slate-100 font-semibold">
                    {event.mitre_technique.name}
                  </span>
                  <span className="tactic-pill">
                    Tactic: {event.mitre_technique.tactic}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  {event.mitre_technique.description}
                </p>
                {event.mitre_technique.url && (
                  <a
                    href={event.mitre_technique.url}
                    target="_blank"
                    rel="noreferrer"
                    className="ref-link mt-2 inline-flex items-center gap-1 text-xs"
                  >
                    <span>View MITRE ATT&CK Technique</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          )}

          {/* Scenario Context */}
          {event.metadata?.scenario_name && (
            <div className="drawer-section">
              <h5 className="section-label">ATTACK SCENARIO CONTEXT</h5>
              <div className="scenario-meta-box">
                <span className="text-xs text-slate-300 font-medium">
                  {event.metadata.scenario_name}
                </span>
                <div className="text-[11px] text-slate-400 mt-1">
                  Step {event.metadata.step_index} of {event.metadata.total_steps} · Attacker: {event.metadata.attacker_label}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="drawer-footer">
          <button
            className="btn btn-primary w-full flex items-center justify-center gap-2"
            onClick={() => {
              onAnalyzeEvent(event);
              onClose();
            }}
          >
            <Brain className="w-4 h-4" />
            <span>Send to Sentinel AI Analyst</span>
          </button>
        </div>
      </div>
    </div>
  );
};
