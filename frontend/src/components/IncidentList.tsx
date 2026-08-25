import React, { useState, useMemo } from "react";
import { ShieldAlert, Brain, ChevronRight, Layers, ArrowRight, CheckCircle2, Search, Crosshair, Clock } from "lucide-react";
import { Incident, IncidentStatus } from "../types";

interface IncidentListProps {
  incidents: Incident[];
  selectedIncidentId?: string;
  onSelectIncident: (incident: Incident) => void;
  onAiTriageIncident: (incident: Incident) => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
}

export const IncidentList: React.FC<IncidentListProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onAiTriageIncident,
  onUpdateStatus,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesStatus =
        statusFilter === "ALL" ||
        inc.status.toUpperCase() === statusFilter.toUpperCase();

      if (!matchesStatus) return false;

      if (!searchTerm.trim()) return true;

      const s = searchTerm.toLowerCase();
      const incId = (inc.incident_id || inc.id || "").toLowerCase();
      const title = (inc.title || "").toLowerCase();
      const summary = (inc.summary || "").toLowerCase();
      const src = (inc.source_ip || "").toLowerCase();
      const tgt = (inc.target || "").toLowerCase();
      const stage = (inc.attack_stage || "").toLowerCase();
      const tech = (inc.techniques || []).some(
        (t) => t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s)
      );

      return (
        incId.includes(s) ||
        title.includes(s) ||
        summary.includes(s) ||
        src.includes(s) ||
        tgt.includes(s) ||
        stage.includes(s) ||
        tech
      );
    });
  }, [incidents, statusFilter, searchTerm]);

  const getStatusBadge = (status: IncidentStatus) => {
    switch (status) {
      case "OPEN":
        return "badge-status-open";
      case "INVESTIGATING":
        return "badge-status-investigating";
      case "CONTAINED":
        return "badge-status-contained";
      case "RESOLVED":
        return "badge-status-resolved";
      default:
        return "badge-status-open";
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "badge-critical";
      case "HIGH":
        return "badge-high";
      default:
        return "badge-medium";
    }
  };

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-head">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <h2>ACTIVE CORRELATED INCIDENTS</h2>
          <span className="pill-engine">CORRELATION ENGINE</span>
        </div>
        <span className="text-xs text-slate-400">
          {incidents.filter((i) => i.status === "OPEN" || i.status === "INVESTIGATING").length} Active
        </span>
      </div>

      {/* Filter Tabs & Search */}
      <div className="incident-tabs flex flex-wrap gap-1 items-center justify-between">
        <div className="flex gap-1 flex-wrap">
          {["ALL", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"].map((st) => (
            <button
              key={st}
              className={`tab-btn ${statusFilter === st ? "active" : ""}`}
              onClick={() => setStatusFilter(st)}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      <div className="search-box my-2">
        <Search className="w-3.5 h-3.5 text-slate-400 search-icon" />
        <input
          type="text"
          placeholder="Filter incidents by title, IP, target, technique..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
      </div>

      {/* Incidents List */}
      <div className="incident-cards-list">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/50 mb-2" />
            <p className="text-sm text-slate-400 font-medium">No incidents in this status.</p>
            <span className="text-xs text-slate-500">
              The correlation engine clusters real-time telemetry into actionable incidents.
            </span>
          </div>
        ) : (
          filtered.map((inc) => {
            const isSelected = selectedIncidentId === (inc.incident_id || inc.id);
            const confPct = Math.round((inc.confidence || 0.9) * 100);

            return (
              <div
                key={inc.incident_id || inc.id}
                className={`incident-card ${isSelected ? "selected" : ""}`}
                onClick={() => onSelectIncident(inc)}
              >
                <div className="incident-card-top">
                  <div className="flex items-center gap-2">
                    <span className={`badge ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                    <span className="font-mono text-xs text-slate-400 font-bold">
                      {inc.incident_id || inc.id}
                    </span>
                  </div>

                  <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                    <select
                      className={`status-select ${getStatusBadge(inc.status)}`}
                      value={inc.status}
                      onChange={(e) =>
                        onUpdateStatus(inc.incident_id || inc.id || "", e.target.value as IncidentStatus)
                      }
                      title="Update incident lifecycle status"
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="CONTAINED">CONTAINED</option>
                      <option value="RESOLVED">RESOLVED</option>
                    </select>
                  </div>
                </div>

                  <h3 className="incident-title">{inc.title}</h3>

                  {/* Attack Stage Indicator */}
                  {inc.attack_stage && (
                    <div className="flex items-center gap-1.5 my-1.5 text-[11px] font-mono text-cyan-400 bg-cyan-950/30 border border-cyan-800/40 px-2 py-0.5 rounded w-fit">
                      <Crosshair className="w-3 h-3 text-cyan-400" />
                      <span>Stage: {inc.attack_stage}</span>
                    </div>
                  )}

                  <p className="incident-summary">{inc.summary}</p>

                {/* Confidence Bar */}
                <div className="confidence-row">
                  <div className="confidence-label">
                    <span>Correlation Confidence</span>
                    <strong>{confPct}%</strong>
                  </div>
                  <div className="confidence-track">
                    <div className="confidence-fill" style={{ width: `${confPct}%` }} />
                  </div>
                </div>

                {/* Meta details */}
                <div className="incident-meta-tags">
                  <div className="meta-pill">
                    <Layers className="w-3 h-3 text-cyan-400" />
                    <span>{inc.events_count || inc.event_ids?.length || 1} Correlated Events</span>
                  </div>

                  {inc.techniques?.map((t) => (
                    <span key={t.id} className="mitre-tag-sm" title={`${t.name} (${t.tactic})`}>
                      {t.id} — {t.name}
                    </span>
                  ))}

                  {inc.related_cves?.map((cve) => (
                    <span key={cve} className="cve-tag-sm">
                      {cve}
                    </span>
                  ))}
                </div>

                {/* Footer / Actions */}
                <div className="incident-card-footer" onClick={(e) => e.stopPropagation()}>
                  <button
                    className="btn-ai-triage"
                    onClick={() => onAiTriageIncident(inc)}
                  >
                    <Brain className="w-3.5 h-3.5" />
                    <span>AI Defensive Triage</span>
                  </button>

                  <button
                    className="btn-investigate"
                    onClick={() => onSelectIncident(inc)}
                  >
                    <span>Investigate Timeline</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
