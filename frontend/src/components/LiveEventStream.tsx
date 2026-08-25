import React, { useState, useMemo, useEffect } from "react";
import {
  Search,
  Trash2,
  Brain,
  ChevronRight,
  Activity,
  Terminal,
} from "lucide-react";
import { SecurityEvent, Severity } from "../types";

interface LiveEventStreamProps {
  events: SecurityEvent[];
  selectedEventId?: string;
  onSelectEvent: (event: SecurityEvent) => void;
  onAnalyzeEvent: (event: SecurityEvent) => void;
  onClearEvents: () => void;
}

function getRelativeTime(timestamp?: string): string {
  if (!timestamp) return "Awaiting events";
  const now = Date.now();
  const time = new Date(timestamp).getTime();
  if (isNaN(time)) return "Just now";
  const diffSec = Math.max(0, Math.floor((now - time) / 1000));
  if (diffSec < 2) return "Just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  return `${diffHours}h ago`;
}

export const LiveEventStream: React.FC<LiveEventStreamProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  onAnalyzeEvent,
  onClearEvents,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [ticker, setTicker] = useState(0);

  // Periodic ticker so relative time counter updates continuously
  useEffect(() => {
    const interval = setInterval(() => {
      setTicker((prev) => (prev + 1) % 1000);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const lastEventRelative = useMemo(() => {
    return getRelativeTime(events[0]?.timestamp);
  }, [events, ticker]);

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      const eventId = String(ev.event_id || ev.id || "");
      const eventType = String(ev.event_type || ev.type || "");
      const sourceIp = String(ev.source_ip || "");
      const target = String(ev.target || "");
      const message = String(ev.message || "");

      const search = searchTerm.toLowerCase();

      const matchesSearch =
        search === "" ||
        eventId.toLowerCase().includes(search) ||
        eventType.toLowerCase().includes(search) ||
        sourceIp.toLowerCase().includes(search) ||
        target.toLowerCase().includes(search) ||
        message.toLowerCase().includes(search);

      const matchesSeverity =
        severityFilter === "ALL" ||
        String(ev.severity || "").toUpperCase() ===
          severityFilter.toUpperCase();

      return matchesSearch && matchesSeverity;
    });
  }, [events, searchTerm, severityFilter]);

  const getSeverityClass = (sev: Severity | string) => {
    switch (String(sev || "").toUpperCase()) {
      case "CRITICAL":
        return "badge-critical";

      case "HIGH":
        return "badge-high";

      case "MEDIUM":
        return "badge-medium";

      case "LOW":
        return "badge-low";

      default:
        return "badge-info";
    }
  };

  return (
    <div className="panel flex flex-col h-full">
      {/* =========================================================
          PANEL HEADER
      ========================================================= */}
      <div className="panel-head">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />

          <h2>LIVE SECURITY TELEMETRY STREAM</h2>

          <span className="pill-sim">SIMULATION</span>
        </div>

        <div className="flex items-center gap-3">
          {events.length > 0 && (
            <span
              className="text-xs text-emerald-400/90 font-mono flex items-center gap-1.5"
              title="Time since most recent event was received"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Last event: {lastEventRelative}
            </span>
          )}

          <span className="text-xs text-slate-400">
            Showing {filteredEvents.length} of {events.length}
          </span>

          <button
            className="btn-ghost text-slate-400 hover:text-slate-200 text-xs p-1"
            onClick={onClearEvents}
            title="Clear current stream buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* =========================================================
          CONTROLS BAR
      ========================================================= */}
      <div className="stream-controls">
        <div className="search-box">
          <Search className="w-3.5 h-3.5 text-slate-400 search-icon" />

          <input
            type="text"
            placeholder="Filter by IP, Target, Type, Payload..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="filter-group">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              className={`filter-btn ${
                severityFilter === sev ? "active" : ""
              }`}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* =========================================================
          EVENTS LIST
      ========================================================= */}
      <div className="event-list">
        {filteredEvents.length === 0 ? (
          /* Empty State */
          <div className="empty-state">
            <Activity className="w-8 h-8 text-slate-600 animate-pulse mb-2" />

            <p className="text-sm text-slate-400 font-medium">
              Awaiting security telemetry...
            </p>

            <span className="text-xs text-slate-500">
              Simulated events stream automatically via WebSocket bus.
            </span>
          </div>
        ) : (
          /* Event Rows */
          filteredEvents.map((event, index) => {
            const eventId = event.event_id || event.id || "";

            const isSelected = selectedEventId === eventId;
            const isNewest = index === 0;

            const severity =
              String(event.severity || "MEDIUM").toUpperCase();

            return (
              <div
                key={eventId}
                className={`event-row ${
                  isNewest ? "new-event" : ""
                } ${
                  isSelected ? "selected" : ""
                } event-${severity.toLowerCase()}`}
                onClick={() => onSelectEvent(event)}
              >
                {/* =====================================================
                    LIVE INDICATOR
                ===================================================== */}
                <div className="event-live-indicator">
                  <span />
                </div>

                {/* =====================================================
                    TIMESTAMP / EVENT ID
                ===================================================== */}
                <div className="event-time">
                  <time>
                    {event.timestamp
                      ? new Date(event.timestamp).toLocaleTimeString()
                      : "--:--:--"}
                  </time>

                  <span className="event-id">{eventId}</span>
                </div>

                {/* =====================================================
                    SEVERITY
                ===================================================== */}
                <div className="event-severity">
                  <span
                    className={`badge ${getSeverityClass(
                      event.severity
                    )}`}
                  >
                    {severity}
                  </span>
                </div>

                {/* =====================================================
                    MAIN EVENT INFORMATION
                ===================================================== */}
                <div className="event-main">
                  <div className="event-title-row">
                    <strong className="event-type">
                      {event.event_type || event.type || "UNKNOWN_EVENT"}
                    </strong>

                    {/* MITRE Technique */}
                    {event.mitre_technique && (
                      <span
                        className="mitre-tag-sm"
                        title={event.mitre_technique.name}
                      >
                        {event.mitre_technique.id}
                      </span>
                    )}

                    {/* Simulation Badge */}
                    {event.simulation && (
                      <span className="pill-sim">SIMULATION</span>
                    )}
                  </div>

                  {/* Event Message */}
                  <p className="event-msg">
                    {event.message || "No event message available."}
                  </p>

                  {/* Network Metadata */}
                  <div className="event-meta-line">
                    <span className="meta-src">
                      <span className="text-slate-500">SRC:</span>{" "}
                      {event.source_ip || "UNKNOWN"}
                    </span>

                    <span className="meta-sep">→</span>

                    <span className="meta-tgt">
                      <span className="text-slate-500">TGT:</span>{" "}
                      {event.target || "UNKNOWN"}

                      {event.protocol &&
                        event.destination_port && (
                          <>
                            {" "}
                            ({event.protocol}:
                            {event.destination_port})
                          </>
                        )}
                    </span>
                  </div>
                </div>

                {/* =====================================================
                    ACTIONS
                ===================================================== */}
                <div
                  className="event-actions"
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    className="btn-ai-quick"
                    onClick={() => onAnalyzeEvent(event)}
                    title="Run Sentinel AI Triage on this event"
                  >
                    <Brain className="w-3.5 h-3.5" />

                    <span>AI Triage</span>
                  </button>

                  <ChevronRight
                    className={`event-chevron ${
                      isSelected ? "active" : ""
                    }`}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};