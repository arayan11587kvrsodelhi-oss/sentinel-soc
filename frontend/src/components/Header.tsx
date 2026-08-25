import React, { useState } from "react";
import { Shield, Radio, Play, ChevronDown, RefreshCw } from "lucide-react";
import { WebSocketStatus } from "../types";

interface HeaderProps {
  wsStatus: WebSocketStatus;
  latencyMs: number | null;
  onTriggerScenario: (scenarioId: string) => void;
  onRefreshData?: () => void;
  onReconnect?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  wsStatus,
  latencyMs,
  onTriggerScenario,
  onRefreshData,
  onReconnect,
}) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const scenarios = [
    { id: "scenario_credential_brute_force", name: "Password Spray & Brute Force Chain", tag: "T1110" },
    { id: "scenario_web_cve_exploitation", name: "Web Exploit & Web Shell (CVE-2023-34362)", tag: "T1190" },
    { id: "scenario_reconnaissance_port_scan", name: "Network Reconnaissance & Service Discovery", tag: "T1046" },
    { id: "scenario_powershell_privilege_escalation", name: "PowerShell Injection & Privilege Escalation", tag: "T1059.001" },
    { id: "scenario_ransomware_execution", name: "Lateral Movement & Ransomware Deployment", tag: "T1486" },
    { id: "scenario_data_exfiltration", name: "Database Compromise & Data Exfiltration", tag: "T1041" },
  ];

  const getStatusLabel = () => {
    switch (wsStatus) {
      case "ONLINE":
        return "LIVE";
      case "CONNECTING":
      case "RECONNECTING":
        return "RECONNECTING";
      case "OFFLINE":
      default:
        return "OFFLINE";
    }
  };

  const getStatusColor = () => {
    switch (wsStatus) {
      case "ONLINE":
        return "text-emerald-400 bg-emerald-950/40 border-emerald-500/40";
      case "CONNECTING":
      case "RECONNECTING":
        return "text-amber-400 bg-amber-950/40 border-amber-500/40";
      case "OFFLINE":
      default:
        return "text-rose-400 bg-rose-950/40 border-rose-500/40";
    }
  };

  return (
    <header className="topbar">
      <div className="brand-group">
        <div className="brand">
          <div className="brand-icon">
            <Shield className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="brand-text">
            <span className="brand-title">SENTINEL <em>SOC</em></span>
            <span className="brand-tag">EDUCATIONAL CYBERSECURITY LAB</span>
          </div>
        </div>
      </div>

      <div className="header-actions">
        {/* Scenario Trigger Controller */}
        <div className="relative">
          <button
            className="btn btn-secondary flex items-center gap-2 text-xs"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            title="Trigger synthetic attack scenario for educational analysis"
          >
            <Play className="w-3.5 h-3.5 text-emerald-400" />
            <span>Launch Attack Simulation</span>
            <ChevronDown className="w-3.5 h-3.5 opacity-70" />
          </button>

          {dropdownOpen && (
            <div className="scenario-dropdown">
              <div className="dropdown-header">
                <span>SELECT ATTACK CHAIN (SIMULATION)</span>
              </div>
              {scenarios.map((scen) => (
                <button
                  key={scen.id}
                  className="dropdown-item"
                  onClick={() => {
                    onTriggerScenario(scen.id);
                    setDropdownOpen(false);
                  }}
                >
                  <div className="dropdown-item-content">
                    <span className="font-semibold text-slate-200">{scen.name}</span>
                    <span className="mitre-tag">{scen.tag}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {onRefreshData && (
          <button
            className="btn btn-icon"
            onClick={onRefreshData}
            title="Refresh Threat & Vulnerability Intelligence"
          >
            <RefreshCw className="w-4 h-4 text-slate-300" />
          </button>
        )}

        {/* WebSocket Live Status */}
        <div
          className={`ws-badge ${getStatusColor()} ${wsStatus === "OFFLINE" ? "cursor-pointer hover:brightness-110" : ""}`}
          onClick={wsStatus === "OFFLINE" ? onReconnect : undefined}
          title={wsStatus === "OFFLINE" ? "WebSocket Offline — Click to reconnect" : `WebSocket status: ${getStatusLabel()}`}
          role={wsStatus === "OFFLINE" ? "button" : undefined}
          tabIndex={wsStatus === "OFFLINE" ? 0 : undefined}
          onKeyDown={wsStatus === "OFFLINE" ? (e) => { if (e.key === "Enter" || e.key === " ") onReconnect?.(); } : undefined}
        >
          <Radio className={`w-3.5 h-3.5 ${wsStatus === "ONLINE" ? "animate-pulse" : ""}`} />
          <span className="font-bold tracking-wider">{getStatusLabel()}</span>
          {latencyMs !== null && wsStatus === "ONLINE" && (
            <span className="latency-text">{latencyMs}ms</span>
          )}
        </div>
      </div>
    </header>
  );
};
