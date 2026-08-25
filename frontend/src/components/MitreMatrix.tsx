import React, { useState, useMemo } from "react";
import { Target, Shield, ExternalLink, Activity, Layers, Search, Filter, X } from "lucide-react";
import { MitreMatrixItem } from "../types";

interface MitreMatrixProps {
  matrixData: MitreMatrixItem[];
  loading?: boolean;
  onSelectTechnique?: (item: MitreMatrixItem) => void;
}

const TACTICS_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ matrixData, loading }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "OBSERVED" | "SIMULATED">("ALL");
  const [selectedTech, setSelectedTech] = useState<MitreMatrixItem | null>(null);

  const filteredItems = useMemo(() => {
    return matrixData.filter((item) => {
      const matchStatus = statusFilter === "ALL" || item.status === statusFilter;
      if (!matchStatus) return false;
      if (!searchTerm) return true;
      const s = searchTerm.toLowerCase();
      return (
        item.id.toLowerCase().includes(s) ||
        item.name.toLowerCase().includes(s) ||
        item.tactic.toLowerCase().includes(s) ||
        item.description.toLowerCase().includes(s)
      );
    });
  }, [matrixData, statusFilter, searchTerm]);

  // Group items by Tactic
  const grouped = useMemo(() => {
    const map = new Map<string, MitreMatrixItem[]>();
    TACTICS_ORDER.forEach((tac) => map.set(tac, []));

    filteredItems.forEach((item) => {
      // Find matching tactic or fallback
      const foundTactic = TACTICS_ORDER.find(
        (t) => item.tactic.toLowerCase().includes(t.toLowerCase()) || t.toLowerCase().includes(item.tactic.toLowerCase())
      );
      const targetTactic = foundTactic || "Execution";
      if (!map.has(targetTactic)) map.set(targetTactic, []);
      map.get(targetTactic)!.push(item);
    });

    return map;
  }, [filteredItems]);

  const observedCount = matrixData.filter((i) => i.status === "OBSERVED").length;
  const simulatedCount = matrixData.filter((i) => i.status === "SIMULATED").length;

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-head">
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-emerald-400" />
          <h2>ENTERPRISE MITRE ATT&CK MATRIX COVERAGE</h2>
          <span className="pill-engine">TACTIC MAPPER</span>
        </div>

        <div className="flex items-center gap-2">
          <span className="badge badge-critical flex items-center gap-1">
            <Activity className="w-3 h-3" />
            {observedCount} Observed Active
          </span>
          <span className="badge badge-high flex items-center gap-1">
            <Shield className="w-3 h-3" />
            {simulatedCount} In Simulation
          </span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="stream-controls">
        <div className="search-box">
          <Search className="w-3.5 h-3.5 text-slate-400 search-icon" />
          <input
            type="text"
            placeholder="Search MITRE technique ID, name, or tactic..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="filter-group">
          {(["ALL", "OBSERVED", "SIMULATED"] as const).map((st) => (
            <button
              key={st}
              className={`filter-btn ${statusFilter === st ? "active" : ""}`}
              onClick={() => setStatusFilter(st)}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Tactic Columns Grid */}
      {loading && matrixData.length === 0 ? (
        <div className="loading-state">
          <div className="cyber-spinner" />
          <p className="text-xs text-slate-400 mt-2">Loading ATT&CK Matrix coverage...</p>
        </div>
      ) : (
        <div className="mitre-matrix-grid">
          {TACTICS_ORDER.map((tactic) => {
            const items = grouped.get(tactic) || [];
            const hasObserved = items.some((i) => i.status === "OBSERVED");

            return (
              <div key={tactic} className={`matrix-column ${hasObserved ? "column-active" : ""}`}>
                <div className="matrix-column-head">
                  <span className="matrix-tactic-name">{tactic}</span>
                  <span className="matrix-tactic-count">{items.length}</span>
                </div>

                <div className="matrix-items-list">
                  {items.length === 0 ? (
                    <div className="matrix-empty-slot">--</div>
                  ) : (
                    items.map((item) => (
                      <button
                        key={item.id}
                        className={`matrix-tech-cell status-${item.status.toLowerCase()} ${
                          selectedTech?.id === item.id ? "selected" : ""
                        }`}
                        onClick={() => setSelectedTech(item)}
                        title={`${item.id}: ${item.name} (${item.status})`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="tech-id">{item.id}</span>
                          {item.status === "OBSERVED" && (
                            <span className="tech-badge-dot" />
                          )}
                        </div>
                        <span className="tech-name">{item.name}</span>
                        {item.incidents_count > 0 && (
                          <span className="tech-meta">
                            {item.incidents_count} Inc · {item.events_count} Evt
                          </span>
                        )}
                      </button>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Selected Technique Detail Modal */}
      {selectedTech && (
        <div className="drawer-overlay" onClick={() => setSelectedTech(null)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-emerald-400" />
                <h3 className="drawer-title">MITRE ATT&CK TECHNIQUE SPECIFICATION</h3>
              </div>
              <button className="btn-close" onClick={() => setSelectedTech(null)}>
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="drawer-body">
              <div className="drawer-card">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-lg font-bold text-emerald-400">{selectedTech.id}</span>
                  <span
                    className={`badge ${
                      selectedTech.status === "OBSERVED"
                        ? "badge-critical"
                        : selectedTech.status === "SIMULATED"
                        ? "badge-high"
                        : "badge-medium"
                    }`}
                  >
                    STATUS: {selectedTech.status}
                  </span>
                </div>
                <h3 className="text-base font-bold text-slate-100">{selectedTech.name}</h3>
                <div className="text-xs text-cyan-400 font-mono mt-1">
                  Enterprise Tactic: {selectedTech.tactic}
                </div>
              </div>

              <div className="drawer-section">
                <h5 className="section-label">TECHNIQUE OVERVIEW</h5>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedTech.description}</p>
                {selectedTech.url && (
                  <a
                    href={selectedTech.url}
                    target="_blank"
                    rel="noreferrer"
                    className="ref-link mt-2 inline-flex items-center gap-1 text-xs"
                  >
                    <span>Read official MITRE specification</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>

              <div className="drawer-section">
                <h5 className="section-label">ACTIVE SOC CORRELATION</h5>
                <div className="grid grid-cols-2 gap-3">
                  <div className="stat-card p-3">
                    <span className="text-[10px] text-slate-500 uppercase">Correlated Incidents</span>
                    <strong className="text-sm text-cyan-400 font-mono">{selectedTech.incidents_count} Active</strong>
                  </div>
                  <div className="stat-card p-3">
                    <span className="text-[10px] text-slate-500 uppercase">Telemetry Event Count</span>
                    <strong className="text-sm text-emerald-400 font-mono">{selectedTech.events_count} Events</strong>
                  </div>
                </div>

                {selectedTech.related_incident_ids && selectedTech.related_incident_ids.length > 0 && (
                  <div className="mt-3">
                    <span className="text-[11px] text-slate-400 font-mono block mb-1">Associated Incident IDs:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedTech.related_incident_ids.map((iid) => (
                        <span key={iid} className="font-mono text-xs text-slate-200 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                          {iid}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="drawer-footer">
              <button className="btn btn-secondary w-full" onClick={() => setSelectedTech(null)}>
                Close Technique View
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
