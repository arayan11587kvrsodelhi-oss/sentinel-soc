import { useState, useEffect, useRef } from "react";

type Provenance = "simulated" | "live" | "derived";

interface LiveEvent {
  id: number;
  time: string;
  type: string;
  source: string;
  data: string;
  provenance: Provenance;
}

const eventTypeColor: Record<string, string> = {
  AUTH_FAILURE: "#FF4D5E",
  AUTH_SUCCESS: "#42D392",
  DETECTION_TRIGGERED: "#FF8A4C",
  INCIDENT_CREATED: "#56B4FF",
  NETWORK_SCAN: "#F4C95D",
  POLICY_VIOLATION: "#FF8A4C",
  PROCESS_SPAWN: "#9AA8B8",
  AI_ANALYSIS: "#7C8CFF",
  RESPONSE_SIMULATED: "#42D392",
  CONNECTION_ATTEMPT: "#F4C95D",
};

const initialEvents: LiveEvent[] = [
  { id: 100, time: "18:43:23.109", type: "INCIDENT_CREATED", source: "sentinel-core", data: "id=INC-00842 severity=HIGH", provenance: "derived" },
  { id: 99, time: "18:43:22.841", type: "DETECTION_TRIGGERED", source: "rule-engine", data: "rule=BRUTE_FORCE_CHAIN_v2 severity=HIGH", provenance: "derived" },
  { id: 98, time: "18:43:22.017", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=root target=auth-01 attempt=12", provenance: "simulated" },
  { id: 97, time: "18:43:21.482", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=admin target=auth-01 attempt=11", provenance: "simulated" },
  { id: 96, time: "18:43:21.104", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=svc_backup target=auth-01 attempt=10", provenance: "simulated" },
  { id: 95, time: "18:43:20.783", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=admin target=auth-01 attempt=9", provenance: "simulated" },
  { id: 94, time: "18:43:19.301", type: "CONNECTION_ATTEMPT", source: "192.168.1.42", data: "port=22 target=host-04 proto=SSH", provenance: "simulated" },
  { id: 93, time: "18:43:18.544", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=administrator target=auth-01 attempt=8", provenance: "simulated" },
  { id: 92, time: "18:43:17.092", type: "NETWORK_SCAN", source: "192.168.1.42", data: "ports=1-1024 targets=192.168.1.0/24 proto=TCP", provenance: "simulated" },
  { id: 91, time: "18:43:16.481", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=admin target=auth-01 attempt=7", provenance: "simulated" },
  { id: 90, time: "18:43:15.223", type: "AI_ANALYSIS", source: "sentinel-ai", data: "incident=INC-00842 confidence=91% model=ExpertEngine", provenance: "derived" },
  { id: 89, time: "18:43:14.991", type: "PROCESS_SPAWN", source: "host-04", data: "process=powershell.exe parent=cmd.exe args=-EncodedCommand", provenance: "simulated" },
  { id: 88, time: "18:43:13.302", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=root target=auth-01 attempt=6", provenance: "simulated" },
  { id: 87, time: "18:43:12.184", type: "AUTH_SUCCESS", source: "192.168.1.42", data: "user=admin target=auth-01 method=password", provenance: "simulated" },
  { id: 86, time: "18:43:11.774", type: "POLICY_VIOLATION", source: "host-02", data: "rule=no-admin-tools process=mimikatz.exe", provenance: "simulated" },
  { id: 85, time: "18:43:10.412", type: "CONNECTION_ATTEMPT", source: "192.168.1.99", data: "port=3389 target=dc-01 proto=RDP", provenance: "simulated" },
  { id: 84, time: "18:43:09.003", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=admin target=auth-01 attempt=5", provenance: "simulated" },
  { id: 83, time: "18:43:07.882", type: "DETECTION_TRIGGERED", source: "rule-engine", data: "rule=POWERSHELL_EXEC_CHAIN severity=MEDIUM", provenance: "derived" },
  { id: 82, time: "18:43:06.110", type: "AUTH_FAILURE", source: "192.168.1.42", data: "user=svc_deploy target=auth-01 attempt=4", provenance: "simulated" },
  { id: 81, time: "18:43:04.503", type: "PROCESS_SPAWN", source: "host-07", data: "process=wmic.exe parent=explorer.exe args=process call create", provenance: "simulated" },
];

function getNewEvent(id: number): LiveEvent {
  const eventTypes: Array<{ type: string; sources: string[]; data: string; prov: Provenance }> = [
    { type: "AUTH_FAILURE", sources: ["192.168.1.42", "10.0.0.88", "192.168.2.15"], data: "user=admin target=auth-01", prov: "simulated" },
    { type: "CONNECTION_ATTEMPT", sources: ["192.168.1.42", "10.0.0.88"], data: "port=443 target=web-01 proto=HTTPS", prov: "simulated" },
    { type: "PROCESS_SPAWN", sources: ["host-04", "host-07", "host-02"], data: "process=cmd.exe parent=winlogon.exe", prov: "simulated" },
    { type: "NETWORK_SCAN", sources: ["192.168.1.42"], data: "ports=80,443,22 targets=192.168.1.0/24", prov: "simulated" },
    { type: "POLICY_VIOLATION", sources: ["host-09", "host-03"], data: "rule=no-script-exec script=invoke-expression", prov: "simulated" },
  ];
  const template = eventTypes[Math.floor(Math.random() * eventTypes.length)];
  const source = template.sources[Math.floor(Math.random() * template.sources.length)];
  const now = new Date();
  const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}.${String(now.getMilliseconds()).padStart(3, "0")}`;
  return { id, time, type: template.type, source, data: template.data, provenance: template.prov };
}

const provConfig: Record<Provenance, { label: string; color: string; icon: string }> = {
  live: { label: "LIVE", color: "#42D392", icon: "●" },
  simulated: { label: "SIMULATED", color: "#F4C95D", icon: "◆" },
  derived: { label: "DERIVED", color: "#7C8CFF", icon: "◇" },
};

export default function LiveEvents() {
  const [events, setEvents] = useState<LiveEvent[]>(initialEvents);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const nextId = useRef(101);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      const newEvent = getNewEvent(nextId.current++);
      setEvents((prev) => [newEvent, ...prev.slice(0, 199)]);
    }, 1800);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered =
    filter === "ALL"
      ? events
      : filter === "SIMULATED"
      ? events.filter((e) => e.provenance === "simulated")
      : events.filter((e) => e.type === filter);

  return (
    <div className="flex flex-col h-full space-y-4" style={{ height: "calc(100vh - 96px)" }}>
      {/* Header */}
      <div className="flex items-start justify-between flex-shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
              Live Event Stream
            </h1>
            <div
              className="flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium"
              style={{ background: "#42D39215", color: "#42D392", border: "1px solid #42D39230" }}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
              CONNECTED
            </div>
          </div>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            Real-time event telemetry — {events.length} events buffered
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(!paused)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: paused ? "#FF8A4C15" : "#1D2938",
              color: paused ? "#FF8A4C" : "#9AA8B8",
              border: `1px solid ${paused ? "#FF8A4C30" : "#1D2938"}`,
            }}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
          <button
            onClick={() => setEvents([])}
            className="px-3 py-1.5 rounded-lg text-xs font-medium"
            style={{ background: "#1D2938", color: "#9AA8B8" }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div
        className="flex items-center gap-2 px-3 py-2 rounded-lg flex-shrink-0"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <span className="text-xs" style={{ color: "#627083" }}>
          Filter:
        </span>
        {["ALL", "SIMULATED", "AUTH_FAILURE", "DETECTION_TRIGGERED", "INCIDENT_CREATED", "PROCESS_SPAWN"].map(
          (f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className="px-2.5 py-1 rounded text-xs font-medium transition-all"
              style={{
                background: filter === f ? "#1D2938" : "transparent",
                color: filter === f ? "#F4F7FA" : "#627083",
              }}
            >
              {f}
            </button>
          )
        )}
        <div className="ml-auto flex items-center gap-3">
          {(["simulated", "derived", "live"] as Provenance[]).map((p) => {
            const cfg = provConfig[p];
            return (
              <div key={p} className="flex items-center gap-1">
                <span style={{ color: cfg.color, fontSize: "8px" }}>{cfg.icon}</span>
                <span className="text-[10px] font-medium" style={{ color: cfg.color }}>
                  {cfg.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Event Stream */}
      <div
        ref={listRef}
        className="flex-1 rounded-xl overflow-y-auto"
        style={{ background: "#0A0F18", border: "1px solid #1D2938" }}
      >
        {/* Header row */}
        <div
          className="sticky top-0 flex items-center gap-4 px-4 py-2 text-[10px] font-semibold tracking-widest uppercase"
          style={{ background: "#0D131D", borderBottom: "1px solid #1D2938", color: "#627083" }}
        >
          <span className="w-28 flex-shrink-0">TIMESTAMP</span>
          <span className="w-36 flex-shrink-0">EVENT TYPE</span>
          <span className="w-32 flex-shrink-0">SOURCE</span>
          <span className="flex-1">METADATA</span>
          <span className="w-24 text-right">PROVENANCE</span>
        </div>

        <div className="divide-y" style={{ borderColor: "#1D293830" }}>
          {filtered.map((event, i) => {
            const typeColor = eventTypeColor[event.type] ?? "#9AA8B8";
            const prov = provConfig[event.provenance];
            const isNew = i === 0 && !paused;

            return (
              <div
                key={event.id}
                className="flex items-center gap-4 px-4 py-2 transition-all"
                style={{
                  background: isNew ? "#1D293820" : "transparent",
                  borderLeft: event.provenance === "simulated" ? "2px solid #F4C95D30" : "2px solid transparent",
                }}
              >
                <span
                  className="w-28 flex-shrink-0 text-xs font-mono"
                  style={{ color: "#627083" }}
                >
                  {event.time}
                </span>
                <span
                  className="w-36 flex-shrink-0 text-xs font-mono font-semibold"
                  style={{ color: typeColor }}
                >
                  {event.type}
                </span>
                <span
                  className="w-32 flex-shrink-0 text-xs font-mono"
                  style={{ color: "#9AA8B8" }}
                >
                  {event.source}
                </span>
                <span
                  className="flex-1 text-xs font-mono truncate"
                  style={{ color: "#627083" }}
                >
                  {event.data}
                </span>
                <div className="w-24 flex justify-end">
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                    style={{
                      background: prov.color + "15",
                      color: prov.color,
                      border: `1px solid ${prov.color}25`,
                    }}
                  >
                    {prov.icon} {prov.label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {filtered.length === 0 && (
          <div className="flex items-center justify-center h-32">
            <span className="text-sm font-mono" style={{ color: "#627083" }}>
              No events match current filter
            </span>
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div
        className="flex items-center gap-4 px-3 py-2 rounded-lg flex-shrink-0"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <span className="font-mono text-xs" style={{ color: "#627083" }}>
          {paused ? "⏸ PAUSED" : "▶ STREAMING"}
        </span>
        <span className="font-mono text-xs" style={{ color: "#627083" }}>
          Buffer: {events.length} / 200
        </span>
        <span className="font-mono text-xs" style={{ color: "#627083" }}>
          Rate: ~33 events/min
        </span>
        <span
          className="ml-auto text-[10px] px-2 py-0.5 rounded"
          style={{ background: "#F4C95D15", color: "#F4C95D", border: "1px solid #F4C95D20" }}
        >
          ◆ Attack telemetry is SIMULATED — not real infrastructure events
        </span>
      </div>
    </div>
  );
}
