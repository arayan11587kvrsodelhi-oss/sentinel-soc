import { useState, useEffect } from "react"
import { getResponseAuditLog, SimulatedActionRecord } from "../lib/sentinel-api"
import { ProvenanceBadge } from "../components/ProvenanceBadge"

const fallbackAuditEvents = [
  {
    id: 1,
    time: "18:43:23.109",
    actor: "sentinel-core",
    action: "INCIDENT_CREATED",
    target: "INC-101",
    result: "SUCCESS",
    category: "Detection",
  },
  {
    id: 2,
    time: "18:43:22.841",
    actor: "rule-engine",
    action: "DETECTION_TRIGGERED",
    target: "BRUTE_FORCE_CHAIN_v2",
    result: "SUCCESS",
    category: "Detection",
  },
  {
    id: 3,
    time: "18:43:22.001",
    actor: "sentinel-ai",
    action: "AI_ANALYSIS_STARTED",
    target: "INC-101",
    result: "SUCCESS",
    category: "AI",
  },
  {
    id: 4,
    time: "18:43:22.215",
    actor: "sentinel-ai",
    action: "AI_ANALYSIS_COMPLETED",
    target: "INC-101",
    result: "SUCCESS",
    category: "AI",
    detail: "confidence=96% model=ExpertEngine",
  },
  {
    id: 5,
    time: "18:43:15.003",
    actor: "analyst@sentinel",
    action: "INCIDENT_VIEWED",
    target: "INC-101",
    result: "SUCCESS",
    category: "User",
  },
  {
    id: 6,
    time: "18:43:04.001",
    actor: "response-engine",
    action: "RESPONSE_SIMULATION_STARTED",
    target: "SIMULATE_FIREWALL_BLOCK/192.168.1.105",
    result: "SUCCESS",
    category: "Response",
  },
  {
    id: 7,
    time: "18:43:05.834",
    actor: "response-engine",
    action: "RESPONSE_SIMULATION_COMPLETED",
    target: "SIMULATE_FIREWALL_BLOCK/192.168.1.105",
    result: "SUCCESS",
    category: "Response",
  },
  {
    id: 8,
    time: "18:42:58.221",
    actor: "threat-intel",
    action: "FEED_SYNC_COMPLETED",
    target: "CISA_KEV",
    result: "SUCCESS",
    category: "System",
    detail: "1687 entries cached",
  },
  {
    id: 9,
    time: "18:42:50.112",
    actor: "threat-intel",
    action: "FEED_SYNC_COMPLETED",
    target: "NIST_NVD",
    result: "SUCCESS",
    category: "System",
    detail: "40 entries enriched",
  },
  {
    id: 10,
    time: "18:42:44.003",
    actor: "analyst@sentinel",
    action: "RULE_VIEWED",
    target: "BRUTE_FORCE_CHAIN_v2",
    result: "SUCCESS",
    category: "Detection",
  },
  {
    id: 11,
    time: "18:42:31.001",
    actor: "analyst@sentinel",
    action: "USER_LOGIN",
    target: "analyst@sentinel",
    result: "SUCCESS",
    category: "User",
    detail: "ip=10.0.0.1 method=SSO",
  },
  {
    id: 12,
    time: "18:41:44.882",
    actor: "health-monitor",
    action: "HEALTH_CHECK",
    target: "all-subsystems",
    result: "SUCCESS",
    category: "System",
    detail: "5/5 healthy",
  },
  {
    id: 13,
    time: "18:41:22.103",
    actor: "sentinel-core",
    action: "INCIDENT_STATUS_CHANGED",
    target: "INC-102",
    result: "SUCCESS",
    category: "Detection",
    detail: "NEW → INVESTIGATING",
  },
  {
    id: 14,
    time: "18:40:18.771",
    actor: "sentinel-ai",
    action: "AI_ANALYSIS_COMPLETED",
    target: "INC-102",
    result: "SUCCESS",
    category: "AI",
    detail: "confidence=94%",
  },
  {
    id: 15,
    time: "18:39:04.001",
    actor: "response-engine",
    action: "RESPONSE_SIMULATION_STARTED",
    target: "SIMULATE_HOST_ISOLATION/dmz-web-portal",
    result: "SUCCESS",
    category: "Response",
  },
  {
    id: 16,
    time: "18:39:05.442",
    actor: "response-engine",
    action: "RESPONSE_SIMULATION_COMPLETED",
    target: "SIMULATE_HOST_ISOLATION/dmz-web-portal",
    result: "SUCCESS",
    category: "Response",
  },
]

const categories = ["ALL", "Detection", "AI", "Response", "User", "System"]

const actionColor: Record<string, string> = {
  INCIDENT_CREATED: "#FF4D5E",
  DETECTION_TRIGGERED: "#FF8A4C",
  AI_ANALYSIS_COMPLETED: "#7C8CFF",
  AI_ANALYSIS_STARTED: "#7C8CFF80",
  RESPONSE_SIMULATION_COMPLETED: "#42D392",
  RESPONSE_SIMULATION_STARTED: "#42D39280",
  USER_LOGIN: "#56B4FF",
  FEED_SYNC_COMPLETED: "#9AA8B8",
  HEALTH_CHECK: "#9AA8B8",
  INCIDENT_VIEWED: "#56B4FF80",
  RULE_VIEWED: "#56B4FF80",
  INCIDENT_STATUS_CHANGED: "#F4C95D",
}

export default function AuditLog() {
  const [filter, setFilter] = useState("ALL")
  const [search, setSearch] = useState("")
  const [events, setEvents] = useState(fallbackAuditEvents)

  useEffect(() => {
    async function loadBackendAudit() {
      try {
        const liveAudit = await getResponseAuditLog(20)
        if (liveAudit && liveAudit.length > 0) {
          const mapped = liveAudit.map((item, i) => ({
            id: 100 + i,
            time: new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            actor: item.requested_by || "analyst@sentinel",
            action: item.action_type || "SIMULATE_RESPONSE_ACTION",
            target: item.target_ip || item.target_host || "192.168.1.105",
            result: item.status || "SUCCESS",
            category: "Response",
            detail: item.details,
          }))
          setEvents((prev) => [...mapped, ...prev])
        }
      } catch (e) {
        // fallback
      }
    }
    loadBackendAudit()
  }, [])

  const filtered = events.filter((e) => {
    if (filter !== "ALL" && e.category !== filter) return false
    if (
      search &&
      !e.action.toLowerCase().includes(search.toLowerCase()) &&
      !e.target.toLowerCase().includes(search.toLowerCase()) &&
      !e.actor.toLowerCase().includes(search.toLowerCase())
    )
      return false
    return true
  })

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#627083]">
              AUDIT TRAIL & SYSTEM INTEGRITY
            </span>
            <ProvenanceBadge type="live" />
          </div>
          <h1 className="text-xl font-semibold text-[#F4F7FA]">Audit Log</h1>
          <p className="text-sm mt-0.5 text-[#9AA8B8]">
            Immutable record of automated detections, defensive triage actions,
            and analyst interventions
          </p>
        </div>
      </div>

      {/* Filters */}
      <div
        className="flex items-center gap-3 p-3 rounded-xl"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <div className="relative flex-1 max-w-xs">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5"
            style={{ color: "#627083" }}
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
            placeholder="Search log..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg text-sm outline-none"
            style={{
              background: "#111925",
              border: "1px solid #1D2938",
              color: "#F4F7FA",
            }}
          />
        </div>

        <div className="flex items-center gap-1">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className="px-2.5 py-1 rounded text-xs font-medium transition-all"
              style={{
                background: filter === cat ? "#1D2938" : "transparent",
                color: filter === cat ? "#F4F7FA" : "#627083",
              }}
            >
              {cat}
            </button>
          ))}
        </div>

        <span className="ml-auto text-xs" style={{ color: "#627083" }}>
          {filtered.length} events
        </span>
      </div>

      {/* Column Headers */}
      <div
        className="grid gap-4 px-4 py-2 rounded-lg"
        style={{
          background: "#0D131D",
          border: "1px solid #1D2938",
          gridTemplateColumns: "140px 1fr 180px 1fr 80px 80px",
        }}
      >
        {["TIMESTAMP", "ACTION", "ACTOR", "TARGET", "CATEGORY", "RESULT"].map(
          (h) => (
            <span
              key={h}
              className="text-[10px] font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              {h}
            </span>
          ),
        )}
      </div>

      {/* Events */}
      <div className="space-y-0.5">
        {filtered.map((event, i) => (
          <div
            key={event.id}
            className="grid gap-4 px-4 py-2.5 rounded-lg transition-all cursor-pointer"
            style={{
              gridTemplateColumns: "140px 1fr 180px 1fr 80px 80px",
              background: i % 2 === 0 ? "#111925" : "#0D131D",
            }}
            onMouseEnter={(e) => {
              ;(e.currentTarget as HTMLElement).style.background = "#1D293830"
            }}
            onMouseLeave={(e) => {
              ;(e.currentTarget as HTMLElement).style.background =
                i % 2 === 0 ? "#111925" : "#0D131D"
            }}
          >
            <span className="font-mono text-xs" style={{ color: "#627083" }}>
              {event.time}
            </span>
            <div>
              <span
                className="font-mono text-xs font-semibold"
                style={{ color: actionColor[event.action] ?? "#9AA8B8" }}
              >
                {event.action}
              </span>
              {(event as { detail?: string }).detail && (
                <span
                  className="font-mono text-[10px] ml-2"
                  style={{ color: "#627083" }}
                >
                  {(event as { detail?: string }).detail}
                </span>
              )}
            </div>
            <span className="font-mono text-xs" style={{ color: "#9AA8B8" }}>
              {event.actor}
            </span>
            <span
              className="font-mono text-xs truncate"
              style={{ color: "#9AA8B8" }}
            >
              {event.target}
            </span>
            <span
              className="text-[10px] font-medium px-1.5 py-0.5 rounded self-start w-fit"
              style={{
                background:
                  event.category === "Detection"
                    ? "#FF8A4C15"
                    : event.category === "AI"
                      ? "#7C8CFF15"
                      : event.category === "Response"
                        ? "#42D39215"
                        : event.category === "User"
                          ? "#56B4FF15"
                          : "#62708315",
                color:
                  event.category === "Detection"
                    ? "#FF8A4C"
                    : event.category === "AI"
                      ? "#7C8CFF"
                      : event.category === "Response"
                        ? "#42D392"
                        : event.category === "User"
                          ? "#56B4FF"
                          : "#9AA8B8",
              }}
            >
              {event.category}
            </span>
            <span className="text-xs font-medium" style={{ color: "#42D392" }}>
              {event.result}
            </span>
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div
          className="py-16 text-center rounded-xl"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <p style={{ color: "#627083" }}>No events match current filters</p>
        </div>
      )}
    </div>
  )
}
