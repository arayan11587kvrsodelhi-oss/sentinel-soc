import { useState, useEffect, useMemo } from "react"
import {
  Incident,
  getIncidents,
  FALLBACK_INCIDENTS,
  wsManager,
} from "../lib/sentinel-api"
import IncidentDrawer from "../components/IncidentDrawer"
import { ProvenanceBadge } from "../components/ProvenanceBadge"

const sevColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
}

const statusConfig: Record<string, { color: string; bg: string }> = {
  INVESTIGATING: { color: "#FF4D5E", bg: "rgba(255,77,94,0.12)" },
  OPEN: { color: "#56B4FF", bg: "rgba(86,180,255,0.12)" },
  CONTAINED: { color: "#F4C95D", bg: "rgba(244,201,93,0.12)" },
  RESOLVED: { color: "#42D392", bg: "rgba(66,211,146,0.12)" },
}

interface IncidentsProps {
  onNavigate: (screen: string) => void
}

export default function Incidents({ onNavigate }: IncidentsProps) {
  const [incidentsList, setIncidentsList] =
    useState<Incident[]>(FALLBACK_INCIDENTS)
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState("")
  const [sevFilter, setSevFilter] = useState("ALL")
  const [statusFilter, setStatusFilter] = useState("ALL")
  const [sourceFilter, setSourceFilter] = useState("ALL")
  const [sortBy, setSortBy] = useState<"newest" | "severity" | "risk">("newest")
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(
    null,
  )
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)

  // Load incidents from backend
  const fetchIncidentData = async () => {
    try {
      const data = await getIncidents()
      if (data && data.length > 0) {
        setIncidentsList(data)
      }
    } catch (err) {
      console.warn("Using fallback incidents data:", err)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidentData()

    // Subscribe to WebSocket updates
    const unsubscribe = wsManager.subscribe((msg) => {
      if (msg.type === "INITIAL_STATE" && msg.active_incidents) {
        setIncidentsList((prev) => {
          const map = new Map(prev.map((i) => [i.incident_id, i]))
          msg.active_incidents.forEach((inc: Incident) =>
            map.set(inc.incident_id, inc),
          )
          return Array.from(map.values())
        })
      } else if (msg.type === "INCIDENT_UPDATE" && msg.incident) {
        setIncidentsList((prev) => {
          const updated = msg.incident as Incident
          const exists = prev.some((i) => i.incident_id === updated.incident_id)
          if (exists) {
            return prev.map((i) =>
              i.incident_id === updated.incident_id ? updated : i,
            )
          } else {
            return [updated, ...prev]
          }
        })
      }
    })

    return () => unsubscribe()
  }, [])

  // Compute unique sources for source filter
  const availableSources = useMemo(() => {
    const set = new Set<string>()
    incidentsList.forEach((i) => {
      if (i.source_ip) set.add(i.source_ip)
      if (i.source_ips) i.source_ips.forEach((ip) => set.add(ip))
    })
    return Array.from(set)
  }, [incidentsList])

  // Counts by severity
  const counts = useMemo(() => {
    return {
      TOTAL: incidentsList.length,
      CRITICAL: incidentsList.filter((i) => i.severity === "CRITICAL").length,
      HIGH: incidentsList.filter((i) => i.severity === "HIGH").length,
      MEDIUM: incidentsList.filter((i) => i.severity === "MEDIUM").length,
      LOW: incidentsList.filter((i) => i.severity === "LOW").length,
    }
  }, [incidentsList])

  // Filter and sort incidents
  const filteredAndSorted = useMemo(() => {
    return incidentsList
      .filter((inc) => {
        const q = search.toLowerCase()
        const matchSearch =
          !search ||
          inc.title.toLowerCase().includes(q) ||
          inc.incident_id.toLowerCase().includes(q) ||
          inc.target.toLowerCase().includes(q) ||
          inc.source_ip.toLowerCase().includes(q) ||
          (inc.category && inc.category.toLowerCase().includes(q)) ||
          (inc.summary && inc.summary.toLowerCase().includes(q))

        const matchSev = sevFilter === "ALL" || inc.severity === sevFilter
        const matchStatus =
          statusFilter === "ALL" || inc.status === statusFilter
        const matchSource =
          sourceFilter === "ALL" ||
          inc.source_ip === sourceFilter ||
          (inc.source_ips && inc.source_ips.includes(sourceFilter))

        return matchSearch && matchSev && matchStatus && matchSource
      })
      .sort((a, b) => {
        if (sortBy === "severity") {
          const weights: Record<string, number> = {
            CRITICAL: 4,
            HIGH: 3,
            MEDIUM: 2,
            LOW: 1,
          }
          return (weights[b.severity] || 0) - (weights[a.severity] || 0)
        }
        if (sortBy === "risk") {
          return (b.risk_score || 0) - (a.risk_score || 0)
        }
        // default "newest"
        return (
          new Date(b.updated_at || 0).getTime() -
          new Date(a.updated_at || 0).getTime()
        )
      })
  }, [incidentsList, search, sevFilter, statusFilter, sourceFilter, sortBy])

  const handleOpenIncident = (inc: Incident) => {
    setSelectedIncident(inc)
    setIsDrawerOpen(true)
  }

  const handleIncidentUpdated = (updated: Incident) => {
    setIncidentsList((prev) =>
      prev.map((i) => (i.incident_id === updated.incident_id ? updated : i)),
    )
    setSelectedIncident(updated)
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#627083]">
              INCIDENT INTELLIGENCE & INVESTIGATION
            </span>
            <ProvenanceBadge type="live" />
          </div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Security Incidents
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            {filteredAndSorted.length} matching investigations ·{" "}
            {counts.CRITICAL} Critical Active
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() =>
              wsManager.triggerScenario("scenario_credential_brute_force")
            }
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer hover:bg-[#56B4FF25]"
            style={{
              background: "#56B4FF15",
              color: "#56B4FF",
              border: "1px solid #56B4FF30",
            }}
          >
            <span>⚡</span> Trigger Test Scenario
          </button>
        </div>
      </div>

      {/* Severity Metric Cards */}
      <div className="grid grid-cols-5 gap-3">
        {[
          {
            label: "ALL INCIDENTS",
            count: counts.TOTAL,
            color: "#F4F7FA",
            filterKey: "ALL",
          },
          {
            label: "CRITICAL",
            count: counts.CRITICAL,
            color: "#FF4D5E",
            filterKey: "CRITICAL",
          },
          {
            label: "HIGH",
            count: counts.HIGH,
            color: "#FF8A4C",
            filterKey: "HIGH",
          },
          {
            label: "MEDIUM",
            count: counts.MEDIUM,
            color: "#F4C95D",
            filterKey: "MEDIUM",
          },
          {
            label: "LOW",
            count: counts.LOW,
            color: "#56B4FF",
            filterKey: "LOW",
          },
        ].map((c) => {
          const isSelected = sevFilter === c.filterKey
          return (
            <button
              key={c.label}
              onClick={() => setSevFilter(c.filterKey)}
              className="rounded-xl p-3 text-left transition-all cursor-pointer focus:outline-none"
              style={{
                background: isSelected ? "#1D2938" : "#111925",
                border: isSelected
                  ? `1px solid ${c.color}60`
                  : "1px solid #1D2938",
                boxShadow: isSelected ? `0 0 12px ${c.color}20` : "none",
              }}
            >
              <div className="text-[10px] font-semibold uppercase tracking-wider text-[#627083]">
                {c.label}
              </div>
              <div
                className="text-2xl font-bold font-mono mt-1 tabular-nums"
                style={{ color: c.color }}
              >
                {c.count}
              </div>
            </button>
          )
        })}
      </div>

      {/* Filters Bar */}
      <div
        className="flex flex-wrap items-center gap-3 p-3 rounded-xl"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        {/* Search Input */}
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
            placeholder="Search incident, target, IP, summary..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg text-xs outline-none transition-all text-[#F4F7FA] bg-[#111925] border border-[#1D2938] focus:border-[#56B4FF]"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-[#627083]">Status:</span>
          {["ALL", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"].map(
            (st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className="px-2 py-1 rounded text-xs font-medium transition-all"
                style={{
                  background: statusFilter === st ? "#1D2938" : "transparent",
                  color: statusFilter === st ? "#F4F7FA" : "#627083",
                  border:
                    statusFilter === st
                      ? "1px solid #1D2938"
                      : "1px solid transparent",
                }}
              >
                {st}
              </button>
            ),
          )}
        </div>

        {/* Source Filter if multiple */}
        {availableSources.length > 1 && (
          <div className="flex items-center gap-1.5 ml-auto">
            <span className="text-xs text-[#627083]">Source:</span>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="text-xs px-2 py-1 rounded bg-[#111925] border border-[#1D2938] text-[#9AA8B8] outline-none"
            >
              <option value="ALL">All Sources</option>
              {availableSources.map((ip) => (
                <option key={ip} value={ip}>
                  {ip}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Sort selector */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-[#627083]">Sort:</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="text-xs px-2 py-1 rounded bg-[#111925] border border-[#1D2938] text-[#9AA8B8] outline-none"
          >
            <option value="newest">Newest First</option>
            <option value="severity">Highest Severity</option>
            <option value="risk">Highest Risk Score</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ border: "1px solid #1D2938" }}
      >
        <table className="w-full text-left">
          <thead>
            <tr
              style={{
                background: "#0D131D",
                borderBottom: "1px solid #1D2938",
              }}
            >
              {[
                "SEVERITY",
                "INCIDENT & TITLE",
                "AFFECTED TARGET",
                "SOURCE IP",
                "MITRE / CVE",
                "RISK",
                "STATUS",
                "LAST UPDATED",
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
            {filteredAndSorted.map((inc, i) => {
              const rScore = inc.risk_score ?? 80
              const primaryTech =
                inc.techniques && inc.techniques.length > 0
                  ? inc.techniques[0].id
                  : null
              const primaryCve =
                inc.related_cves && inc.related_cves.length > 0
                  ? inc.related_cves[0]
                  : null

              return (
                <tr
                  key={inc.incident_id}
                  className="cursor-pointer transition-colors group"
                  style={{
                    background: i % 2 === 0 ? "#111925" : "#0F1720",
                    borderBottom: "1px solid rgba(29,41,56,0.4)",
                  }}
                  onClick={() => handleOpenIncident(inc)}
                  onMouseEnter={(e) => {
                    ;(e.currentTarget as HTMLElement).style.background =
                      "#182333"
                  }}
                  onMouseLeave={(e) => {
                    ;(e.currentTarget as HTMLElement).style.background =
                      i % 2 === 0 ? "#111925" : "#0F1720"
                  }}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-1.5 h-5 rounded-sm"
                        style={{
                          background: sevColor[inc.severity] || "#56B4FF",
                        }}
                      />
                      <span
                        className="text-xs font-bold font-mono"
                        style={{ color: sevColor[inc.severity] || "#56B4FF" }}
                      >
                        {inc.severity}
                      </span>
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <div>
                      <div className="text-sm font-semibold text-[#F4F7FA] group-hover:text-[#56B4FF] transition-colors">
                        {inc.title}
                      </div>
                      <div className="flex items-center gap-2 text-[11px] font-mono text-[#627083] mt-0.5">
                        <span>{inc.incident_id}</span>
                        <span>·</span>
                        <span>{inc.category}</span>
                      </div>
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-[#9AA8B8]">
                      {inc.target}
                    </span>
                  </td>

                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-[#9AA8B8]">
                      {inc.source_ip}
                    </span>
                  </td>

                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {primaryTech && (
                        <span
                          className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded"
                          style={{
                            background: "rgba(124,140,255,0.15)",
                            color: "#7C8CFF",
                            border: "1px solid rgba(124,140,255,0.25)",
                          }}
                        >
                          {primaryTech}
                        </span>
                      )}
                      {primaryCve && (
                        <span
                          className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded"
                          style={{
                            background: "rgba(255,138,76,0.15)",
                            color: "#FF8A4C",
                            border: "1px solid rgba(255,138,76,0.25)",
                          }}
                        >
                          KEV
                        </span>
                      )}
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1 rounded-full bg-[#1D2938]">
                        <div
                          className="h-1 rounded-full"
                          style={{
                            width: `${rScore}%`,
                            background:
                              rScore >= 90
                                ? "#FF4D5E"
                                : rScore >= 70
                                  ? "#FF8A4C"
                                  : rScore >= 40
                                    ? "#F4C95D"
                                    : "#56B4FF",
                          }}
                        />
                      </div>
                      <span className="text-xs font-mono font-semibold text-[#F4F7FA] tabular-nums">
                        {rScore}
                      </span>
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <span
                      className="text-[11px] font-medium px-2 py-0.5 rounded"
                      style={{
                        color: statusConfig[inc.status]?.color ?? "#9AA8B8",
                        background: statusConfig[inc.status]?.bg ?? "#1D2938",
                      }}
                    >
                      {inc.status}
                    </span>
                  </td>

                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-[#627083]">
                      {new Date(
                        inc.updated_at || Date.now(),
                      ).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {filteredAndSorted.length === 0 && (
          <div className="py-16 text-center bg-[#111925]">
            <p className="text-sm text-[#627083]">
              No incidents match the active filters.
            </p>
          </div>
        )}

        <div
          className="flex items-center justify-between px-4 py-2.5 bg-[#0D131D]"
          style={{ borderTop: "1px solid #1D2938" }}
        >
          <span className="text-xs text-[#627083]">
            Showing {filteredAndSorted.length} of {incidentsList.length}{" "}
            incidents
          </span>
          <span className="text-[11px] font-mono text-[#42D392] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
            LIVE TELEMETRY STREAM
          </span>
        </div>
      </div>

      {/* Investigation Drawer / Modal */}
      <IncidentDrawer
        incident={selectedIncident}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onIncidentUpdated={handleIncidentUpdated}
      />
    </div>
  )
}
