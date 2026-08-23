import React, { useState, useMemo } from "react";
import { Search, Trash2, Brain, ChevronRight, Activity, Terminal } from "lucide-react";
import { SecurityEvent, Severity } from "../types";

interface LiveEventStreamProps {
  events: SecurityEvent[];
  selectedEventId?: string;
  onSelectEvent: (event: SecurityEvent) => void;
  onAnalyzeEvent: (event: SecurityEvent) => void;
  onClearEvents: () => void;
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

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      const matchesSearch =
        searchTerm === "" ||
        ev.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.message.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesSeverity =
        severityFilter === "ALL" || ev.severity.toUpperCase() === severityFilter.toUpperCase();

      return matchesSearch && matchesSeverity;
    });
  }, [events, searchTerm, severityFilter]);

  const getSeverityClass = (sev: Severity | string) => {
    switch (sev?.toUpperCase()) {
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
      <div className="panel-head">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h2>LIVE SECURITY TELEMETRY STREAM</h2>
          <span className="pill-sim">SIMULATION</span>
        </div>
        <div className="flex items-center gap-2">
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

      {/* Controls Bar */}
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
              className={`filter-btn ${severityFilter === sev ? "active" : ""}`}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Events List */}
      <div className="event-list">
        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <Activity className="w-8 h-8 text-slate-600 animate-pulse mb-2" />
            <p className="text-sm text-slate-400 font-medium">Awaiting security telemetry...</p>
            <span className="text-xs text-slate-500">
              Simulated events stream automatically via WebSocket bus.
            </span>
          </div>
        ) : (
          filteredEvents.map((event) => {
            const isSelected = selectedEventId === (event.event_id || event.id);
            return (
              <div
                key={event.event_id || event.id}
                className={`event-row ${isSelected ? "selected" : ""}`}
                onClick={() => onSelectEvent(event)}
              >
                <div className="event-time">
                  <time>{new Date(event.timestamp).toLocaleTimeString()}</time>
                  <span className="event-id">{event.event_id || event.id}</span>
                </div>

                <div className="event-severity">
                  <span className={`badge ${getSeverityClass(event.severity)}`}>
                    {event.severity}
                  </span>
                </div>

                <div className="event-main">
                  <div className="event-title-row">
                    <strong className="event-type">{event.event_type || event.type}</strong>
                    {event.mitre_technique && (
                      <span className="mitre-tag-sm" title={event.mitre_technique.name}>
                        {event.mitre_technique.id}
                      </span>
                    )}
                  </div>
                  <p className="event-msg">{event.message}</p>
                  <div className="event-meta-line">
                    <span className="meta-src">
                      <span className="text-slate-500">SRC:</span> {event.source_ip}
                    </span>
                    <span className="meta-sep">→</span>
                    <span className="meta-tgt">
                      <span className="text-slate-500">TGT:</span> {event.target} ({event.protocol}:{event.destination_port})
                    </span>
                  </div>
                </div>

                <div className="event-actions" onClick={(e) => e.stopPropagation()}>
                  <button
                    className="btn-ai-quick"
                    onClick={() => onAnalyzeEvent(event)}
                    title="Run Sentinel AI Triage on this event"
                  >
                    <Brain className="w-3.5 h-3.5" />
                    <span>AI Triage</span>
                  </button>
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
