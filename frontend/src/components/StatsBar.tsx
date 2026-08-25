import React from "react";
import { AlertOctagon, AlertTriangle, ShieldAlert, Database, Flame, Wifi } from "lucide-react";
import { WebSocketStatus } from "../types";

interface StatsBarProps {
  criticalCount: number;
  highCount: number;
  activeIncidentsCount: number;
  nvdCount: number;
  kevCount: number;
  wsStatus: WebSocketStatus;
  nvdDataSource?: string;
  kevDataSource?: string;
}

export const StatsBar: React.FC<StatsBarProps> = ({
  criticalCount,
  highCount,
  activeIncidentsCount,
  nvdCount,
  kevCount,
  wsStatus,
  nvdDataSource,
  kevDataSource,
}) => {
  const formatNumber = (num: number) => {
    if (!num) return "0";
    return num.toLocaleString();
  };

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
        return "text-emerald-400";
      case "CONNECTING":
      case "RECONNECTING":
        return "text-amber-400";
      case "OFFLINE":
      default:
        return "text-rose-400";
    }
  };
  return (
    <section className="stats-grid">
      <div className="stat-card stat-critical">
        <div className="stat-icon">
          <AlertOctagon className="w-5 h-5 text-rose-400" />
        </div>
        <div className="stat-body">
          <span className="stat-label">CRITICAL EVENTS</span>
          <strong className="stat-value text-rose-400">{criticalCount}</strong>
          <span className="stat-subtext">Immediate Action</span>
        </div>
      </div>

      <div className="stat-card stat-high">
        <div className="stat-icon">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
        </div>
        <div className="stat-body">
          <span className="stat-label">HIGH EVENTS</span>
          <strong className="stat-value text-amber-400">{highCount}</strong>
          <span className="stat-subtext">Elevated Priority</span>
        </div>
      </div>

      <div className="stat-card stat-incidents">
        <div className="stat-icon">
          <ShieldAlert className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="stat-body">
          <span className="stat-label">ACTIVE INCIDENTS</span>
          <strong className="stat-value text-cyan-400">{activeIncidentsCount}</strong>
          <span className="stat-subtext">Correlated Chains</span>
        </div>
      </div>

      <div className="stat-card stat-nvd">
        <div className="stat-icon">
          <Database className="w-5 h-5 text-emerald-400" />
        </div>
        <div className="stat-body">
          <span className="stat-label">NVD RECORDS</span>
          <strong className="stat-value text-emerald-400">{formatNumber(nvdCount)}</strong>
          <span className="stat-subtext">
            {nvdDataSource === "LIVE_NVD" ? "Live NIST Catalog" : nvdDataSource === "FALLBACK" ? "Baseline Intel" : "Cached NIST Intel"}
          </span>
        </div>
      </div>

      <div className="stat-card stat-kev">
        <div className="stat-icon">
          <Flame className="w-5 h-5 text-orange-400" />
        </div>
        <div className="stat-body">
          <span className="stat-label">CISA KEV CATALOG</span>
          <strong className="stat-value text-orange-400">{formatNumber(kevCount)}</strong>
          <span className="stat-subtext">
            {kevDataSource === "LIVE_CISA_KEV" ? "Live Exploited Catalog" : "Known Exploited"}
          </span>
        </div>
      </div>

      <div className="stat-card stat-ws">
        <div className="stat-icon">
          <Wifi className={`w-5 h-5 ${getStatusColor()}`} />
        </div>
        <div className="stat-body">
          <span className="stat-label">WEBSOCKET BUS</span>
          <strong className={`stat-value ${getStatusColor()}`}>
            {getStatusLabel()}
          </strong>
          <span className="stat-subtext">Telemetry Stream</span>
        </div>
      </div>
    </section>
  );
};
