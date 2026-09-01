import { useState, useEffect, useRef } from "react"
import { SecurityEvent, getThreats, wsManager } from "../lib/sentinel-api"
import { ProvenanceBadge } from "../components/ProvenanceBadge"

const eventTypeColor: Record<string, string> = {
  AUTH_FAILURE: "#FF4D5E",
  LOGIN_FAILURE: "#FF4D5E",
  AUTH_SUCCESS: "#42D392",
  SUSPICIOUS_LOGIN: "#42D392",
  BRUTE_FORCE: "#FF4D5E",
  DETECTION_TRIGGERED: "#FF8A4C",
  EXPLOIT_ATTEMPT: "#FF4D5E",
  SQL_INJECTION: "#FF8A4C",
  INCIDENT_CREATED: "#56B4FF",
  INCIDENT_UPDATE: "#56B4FF",
  NETWORK_SCAN: "#F4C95D",
  PORT_SCAN: "#F4C95D",
  VULNERABILITY_SCAN: "#F4C95D",
  POLICY_VIOLATION: "#FF8A4C",
  PROCESS_SPAWN: "#9AA8B8",
  POWERSHELL_EXECUTION: "#FF8A4C",
  AI_ANALYSIS: "#7C8CFF",
  C2_COMMUNICATION: "#FF4D5E",
  RANSOMWARE_ACTIVITY: "#FF4D5E",
  DATA_EXFILTRATION: "#FF4D5E",
}

interface StreamEvent {
  id: string
  time: string
  type: string
  source: string
  target?: string
  severity: string
  data: string
  provenance: "simulated" | "live" | "derived"
}

export default function LiveEvents() {
  const [events, setEvents] = useState<StreamEvent[]>([])
  const [isPaused, setIsPaused] = useState(false)
  const [filterType, setFilterType] = useState<string>("ALL")
  const [filterSev, setFilterSev] = useState<string>("ALL")
  const [search, setSearch] = useState("")
  const isPausedRef = useRef(isPaused)
  isPausedRef.current = isPaused

  useEffect(() => {
    async function init() {
      try {
        const threats = await getThreats({ limit: 25 })
        if (threats && threats.length > 0) {
          const initial = threats.map((t) => ({
            id: t.event_id || `EV-${Math.random().toString(36).substr(2, 6)}`,
            time: new Date(t.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            type: t.event_type,
            source: t.source_ip,
            target: t.target,
            severity: t.severity,
            data: t.message,
            provenance: "simulated" as const,
          }))
          setEvents(initial)
        }
      } catch (err) {
        // fallback
      }
    }
    init()

    const unsubscribe = wsManager.subscribe((msg) => {
      if (isPausedRef.current) return

      if (msg.type === "INITIAL_STATE" && msg.recent_events) {
        const mapped = msg.recent_events.map((t: SecurityEvent) => ({
          id: t.event_id,
          time: new Date(t.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          type: t.event_type,
          source: t.source_ip,
          target: t.target,
          severity: t.severity,
          data: t.message,
          provenance: "simulated" as const,
        }))
        setEvents(mapped)
      } else if (msg.event_msg_type === "SECURITY_EVENT" || msg.event_id) {
        const ev = msg as SecurityEvent
        const newStreamItem: StreamEvent = {
          id: ev.event_id || `EV-${Math.random().toString(36).substr(2, 6)}`,
          time: new Date(ev.timestamp || Date.now()).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          type: ev.event_type || "TELEMETRY_EVENT",
          source: ev.source_ip || "10.0.1.5",
          target: ev.target,
          severity: ev.severity || "MEDIUM",
          data: ev.message || "Simulated telemetry event",
          provenance: "simulated",
        }
        setEvents((prev) => [newStreamItem, ...prev.slice(0, 99)])
      } else if (msg.type === "INCIDENT_UPDATE" && msg.incident) {
        const inc = msg.incident
        const incItem: StreamEvent = {
          id: `INC-EV-${inc.incident_id}`,
          time: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          type: "INCIDENT_UPDATE",
          source: inc.source_ip || "CORRELATION_ENGINE",
          target: inc.target,
          severity: inc.severity,
          data: `${inc.title} (Status: ${inc.status})`,
          provenance: "derived",
        }
        setEvents((prev) => [incItem, ...prev.slice(0, 99)])
      }
    })

    return () => unsubscribe()
  }, [])

  const filteredEvents = events.filter((e) => {
    const q = search.toLowerCase()
    const matchSearch =
      !search ||
      e.id.toLowerCase().includes(q) ||
      e.type.toLowerCase().includes(q) ||
      e.source.toLowerCase().includes(q) ||
      (e.target && e.target.toLowerCase().includes(q)) ||
      e.data.toLowerCase().includes(q)

    const matchType = filterType === "ALL" || e.type.includes(filterType)
    const matchSev =
      filterSev === "ALL" || e.severity.toUpperCase() === filterSev

    return matchSearch && matchType && matchSev
  })

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#627083]">
              REAL-TIME SOC TELEMETRY BUS
            </span>
            <ProvenanceBadge type="live" />
          </div>
          <h1 className="text-xl font-semibold text-[#F4F7FA]">
            Live Event Stream
          </h1>
          <p className="text-sm mt-0.5 text-[#9AA8B8]">
            Streaming synthetic and correlated attack events via WebSocket
            (/ws/events)
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() =>
              wsManager.triggerScenario("scenario_web_cve_exploitation")
            }
            className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer bg-[#56B4FF15] text-[#56B4FF] border border-[#56B4FF30]"
          >
            ⚡ Trigger Web Exploit Scenario
          </button>

          <button
            onClick={() => setIsPaused(!isPaused)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer"
            style={{
              background: isPaused ? "#F4C95D20" : "#42D39215",
              color: isPaused ? "#F4C95D" : "#42D392",
              border: `1px solid ${isPaused ? "#F4C95D40" : "#42D39230"}`,
            }}
          >
            {isPaused ? "▶ RESUME STREAM" : "⏸ PAUSE STREAM"}
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div
        className="flex flex-wrap items-center gap-3 p-3 rounded-xl"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#627083]"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Search event ID, type, IP, payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg text-xs outline-none text-[#F4F7FA] bg-[#111925] border border-[#1D2938] focus:border-[#56B4FF]"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <span className="text-xs text-[#627083]">Severity:</span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSev(s)}
              className="px-2 py-1 rounded text-xs font-medium transition-all"
              style={{
                background: filterSev === s ? "#1D2938" : "transparent",
                color: filterSev === s ? "#F4F7FA" : "#627083",
              }}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="ml-auto text-xs text-[#627083]">
          Showing {filteredEvents.length} events
        </div>
      </div>

      {/* Events Table */}
      <div
        className="rounded-xl overflow-hidden font-mono"
        style={{ border: "1px solid #1D2938" }}
      >
        <table className="w-full text-left text-xs">
          <thead>
            <tr
              style={{
                background: "#0D131D",
                borderBottom: "1px solid #1D2938",
              }}
            >
              {[
                "TIME",
                "SEVERITY",
                "EVENT TYPE",
                "SOURCE IP",
                "TARGET ASSET",
                "TELEMETRY DETAILS",
              ].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-[10px] font-semibold tracking-widest uppercase text-[#627083]"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((ev, idx) => (
              <tr
                key={ev.id + "-" + idx}
                className="transition-colors"
                style={{
                  background: idx % 2 === 0 ? "#111925" : "#0F1720",
                  borderBottom: "1px solid rgba(29,41,56,0.3)",
                }}
              >
                <td className="px-4 py-2 text-[#627083] whitespace-nowrap">
                  {ev.time}
                </td>

                <td className="px-4 py-2">
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.2 rounded"
                    style={{
                      background:
                        ev.severity === "CRITICAL"
                          ? "#FF4D5E25"
                          : ev.severity === "HIGH"
                            ? "#FF8A4C25"
                            : ev.severity === "MEDIUM"
                              ? "#F4C95D25"
                              : "#56B4FF25",
                      color:
                        ev.severity === "CRITICAL"
                          ? "#FF4D5E"
                          : ev.severity === "HIGH"
                            ? "#FF8A4C"
                            : ev.severity === "MEDIUM"
                              ? "#F4C95D"
                              : "#56B4FF",
                    }}
                  >
                    {ev.severity}
                  </span>
                </td>

                <td className="px-4 py-2">
                  <span
                    className="text-xs font-semibold"
                    style={{ color: eventTypeColor[ev.type] || "#9AA8B8" }}
                  >
                    {ev.type}
                  </span>
                </td>

                <td className="px-4 py-2 text-[#9AA8B8]">{ev.source}</td>

                <td className="px-4 py-2 text-[#9AA8B8]">
                  {ev.target || "internal-asset"}
                </td>

                <td className="px-4 py-2 text-[#F4F7FA] truncate max-w-[400px]">
                  {ev.data}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredEvents.length === 0 && (
          <div className="py-16 text-center bg-[#111925]">
            <p className="text-xs text-[#627083]">
              No telemetry events matching criteria.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
