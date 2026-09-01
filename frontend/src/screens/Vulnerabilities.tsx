import { useState, useEffect, useMemo, type KeyboardEvent } from "react"
import {
  VulnerabilityItem,
  getVulnerabilities,
  getKevCatalog,
  type KevItem,
} from "../lib/sentinel-api"
import { ProvenanceBadge } from "../components/ProvenanceBadge"

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const
const riskColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
  INFO: "#7AA2FF",
}

function toSeverityRank(value: string) {
  const index = severityOrder.indexOf(value as typeof severityOrder[number])
  return index === -1 ? -1 : index
}

function formatDate(value?: string | null) {
  if (!value) return "Not provided"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  })
}

function getVendorProductLabel(
  item: VulnerabilityItem,
  kevItem?: KevItem,
): string {
  if (kevItem?.vendorProject || kevItem?.product) {
    return [kevItem.vendorProject, kevItem.product].filter(Boolean).join(" ")
  }
  if (item.affected_products && item.affected_products.length > 0) {
    return item.affected_products[0]
  }
  return "General enterprise asset"
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<VulnerabilityItem[]>([])
  const [kevCatalog, setKevCatalog] = useState<KevItem[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sortField, setSortField] = useState<"severity" | "newest" | "cve">(
    "severity",
  )
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc")
  const [riskFilter, setRiskFilter] = useState("ALL")
  const [statusFilter, setStatusFilter] =
    useState<"ALL" | "KNOWN_EXPLOITED" | "GENERAL">("ALL")
  const [kevOnly, setKevOnly] = useState(false)
  const [search, setSearch] = useState("")
  const [dataSource, setDataSource] = useState("CACHED_NVD")
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityItem | null>(
    null,
  )

  async function fetchVulns() {
    setIsLoading(true)
    setError(null)

    try {
      const [vulnResult, kevResult] = await Promise.allSettled([
        getVulnerabilities({ limit: 120 }),
        getKevCatalog({ limit: 200 }),
      ])

      const nextVulns =
        vulnResult.status === "fulfilled"
          ? (vulnResult.value.vulnerabilities ?? [])
          : []
      const nextKev =
        kevResult.status === "fulfilled"
          ? (kevResult.value.vulnerabilities ?? [])
          : []

      setVulns(nextVulns)
      setKevCatalog(nextKev)

      const source =
        vulnResult.status === "fulfilled"
          ? vulnResult.value.data_source || "LIVE_NVD"
          : "CACHED_NVD"
      setDataSource(source)

      const hasData = nextVulns.length > 0 || nextKev.length > 0
      if (!hasData) {
        setError(
          "No vulnerability intelligence is available from the current data feed.",
        )
      }

      if (vulnResult.status === "rejected" && kevResult.status === "rejected") {
        throw new Error("Unable to load NVD and KEV feeds.")
      }
    } catch (err) {
      console.warn("Failed to load vulnerabilities:", err)
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load vulnerability intelligence.",
      )
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    void fetchVulns()
  }, [])

  const kevLookup = useMemo(
    () => new Map(kevCatalog.map((item) => [item.cveID.toUpperCase(), item])),
    [kevCatalog],
  )

  const handleSort = (field: "severity" | "newest" | "cve") => {
    if (sortField === field) {
      setSortDir((current) => (current === "asc" ? "desc" : "asc"))
      return
    }

    setSortField(field)
    setSortDir(field === "cve" ? "asc" : "desc")
  }

  const filteredAndSorted = useMemo(() => {
    return [...vulns]
      .filter((v) => {
        const q = search.trim().toLowerCase()
        const kevMeta = kevLookup.get(v.id.toUpperCase())
        const matchSearch =
          !q ||
          v.id.toLowerCase().includes(q) ||
          v.description.toLowerCase().includes(q) ||
          (kevMeta?.vulnerabilityName || "").toLowerCase().includes(q) ||
          (v.affected_products ?? []).some((p) => p.toLowerCase().includes(q))

        const matchRisk = riskFilter === "ALL" || v.severity === riskFilter
        const matchStatus =
          statusFilter === "ALL" ||
          (statusFilter === "KNOWN_EXPLOITED" && v.is_kev) ||
          (statusFilter === "GENERAL" && !v.is_kev)
        const matchKev = !kevOnly || v.is_kev

        return matchSearch && matchRisk && matchStatus && matchKev
      })
      .sort((a, b) => {
        if (sortField === "cve") {
          return sortDir === "desc"
            ? b.id.localeCompare(a.id)
            : a.id.localeCompare(b.id)
        }

        if (sortField === "newest") {
          const aTime = new Date(a.modified || a.published || 0).getTime()
          const bTime = new Date(b.modified || b.published || 0).getTime()
          return sortDir === "desc" ? bTime - aTime : aTime - bTime
        }

        const severityRankA = toSeverityRank(a.severity || "MEDIUM")
        const severityRankB = toSeverityRank(b.severity || "MEDIUM")
        const diff = severityRankA - severityRankB
        if (diff !== 0) {
          return sortDir === "desc" ? -diff : diff
        }

        const cvssA = a.cvss ?? 0
        const cvssB = b.cvss ?? 0
        return sortDir === "desc" ? cvssB - cvssA : cvssA - cvssB
      })
  }, [
    vulns,
    search,
    riskFilter,
    statusFilter,
    kevOnly,
    sortField,
    sortDir,
    kevLookup,
  ])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    }
    vulns.forEach((v) => {
      if (counts[v.severity]) {
        counts[v.severity] += 1
      } else if (
        v.severity === "CRITICAL" ||
        v.severity === "HIGH" ||
        v.severity === "MEDIUM" ||
        v.severity === "LOW"
      ) {
        counts[v.severity] = 1
      }
    })
    return counts
  }, [vulns])

  const maxSeverityCount = Math.max(...Object.values(severityCounts), 1)
  const totalSeverity = Object.values(severityCounts).reduce(
    (sum, value) => sum + value,
    0,
  )
  const kevCount = vulns.filter((v) => v.is_kev).length
  const pendingRemediation = vulns.filter(
    (v) => v.is_kev && v.kev_details?.due_date,
  ).length
  const avgCvss =
    vulns.length > 0
      ? (
          vulns.reduce((sum, item) => sum + (item.cvss ?? 0), 0) / vulns.length
        ).toFixed(1)
      : "0.0"

  const immediateAttention = useMemo(
    () =>
      [...vulns]
        .filter(
          (v) =>
            v.is_kev && (v.severity === "CRITICAL" || v.severity === "HIGH"),
        )
        .sort((a, b) => {
          const priorityA = (a.cvss ?? 0) + (a.is_kev ? 10 : 0)
          const priorityB = (b.cvss ?? 0) + (b.is_kev ? 10 : 0)
          return priorityB - priorityA
        })
        .slice(0, 4),
    [vulns],
  )

  const summaryCards = [
    {
      label: "TOTAL VULNERABILITIES",
      value: vulns.length,
      color: "#F4F7FA",
      sub: "Live NVD catalog",
    },
    {
      label: "CRITICAL",
      value: severityCounts.CRITICAL,
      color: "#FF4D5E",
      sub: "CVSS >= 9.0",
    },
    {
      label: "HIGH",
      value: severityCounts.HIGH,
      color: "#FF8A4C",
      sub: "Priority exposure",
    },
    {
      label: "MEDIUM",
      value: severityCounts.MEDIUM,
      color: "#F4C95D",
      sub: "Monitor and patch",
    },
    {
      label: "LOW",
      value: severityCounts.LOW,
      color: "#56B4FF",
      sub: "Lower urgency",
    },
    {
      label: "KEV / EXPLOITED",
      value: kevCount,
      color: "#FF8A4C",
      sub: "CISA exploited",
    },
    {
      label: "REMEDIATION STATUS",
      value: pendingRemediation,
      color: "#7AA2FF",
      sub: "Due-date tracked",
    },
  ]

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="mb-1 flex items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.24em] text-[#627083]">
              Vulnerability intelligence & exposure
            </span>
            <ProvenanceBadge type="live" />
          </div>
          <h1 className="text-xl font-semibold text-[#F4F7FA]">
            Vulnerabilities
          </h1>
          <p className="mt-1 text-sm text-[#9AA8B8]">
            {vulns.length} records tracked • Feed: {dataSource}
          </p>
        </div>
      </div>

      {isLoading && (
        <div className="rounded-xl border border-[#1D2938] bg-[#111925] p-8 text-center text-sm text-[#9AA8B8]">
          Loading vulnerability intelligence…
        </div>
      )}

      {!isLoading && error && (
        <div
          className="rounded-xl border border-[#FF4D5E33] bg-[#0F1720] p-6 text-[#F4F7FA]"
          style={{ boxShadow: "inset 0 0 0 1px rgba(255,77,94,0.08)" }}
        >
          <div className="text-xs font-semibold uppercase tracking-[0.22em] text-[#FF4D5E]">
            API error
          </div>
          <h2 className="mt-2 text-lg font-semibold">
            Unable to load the current vulnerability feed
          </h2>
          <p className="mt-2 text-sm text-[#9AA8B8]">{error}</p>
          <button
            type="button"
            onClick={() => void fetchVulns()}
            className="mt-4 rounded-lg border border-[#1D2938] bg-[#111925] px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-[#F4F7FA]"
          >
            Retry
          </button>
        </div>
      )}

      {!isLoading && !error && (
        <>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {summaryCards.map((card, index) => (
              <div
                key={card.label}
                className="rounded-xl border border-[#1D2938] bg-[#111925] p-4"
                style={{
                  transform: index === 0 ? undefined : undefined,
                }}
              >
                <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#627083]">
                  {card.label}
                </div>
                <div
                  className="mt-2 text-2xl font-semibold font-mono tabular-nums"
                  style={{ color: card.color }}
                >
                  {card.value}
                </div>
                <div className="mt-1 text-[11px] text-[#627083]">
                  {card.sub}
                </div>
              </div>
            ))}
          </div>

          <div className="grid gap-4 xl:grid-cols-[1.5fr_0.8fr]">
            <div className="rounded-xl border border-[#1D2938] bg-[#0D131D] p-4">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#627083]">
                    Severity distribution
                  </div>
                  <div className="mt-1 text-sm font-medium text-[#F4F7FA]">
                    Live mix of exploited and general exposure
                  </div>
                </div>
                <div className="text-xs text-[#627083]">
                  {totalSeverity} total
                </div>
              </div>

              <div className="space-y-3">
                {severityOrder.map((severity) => {
                  const count = severityCounts[severity] || 0
                  const pct = (count / maxSeverityCount) * 100
                  return (
                    <div key={severity}>
                      <div className="mb-1 flex items-center justify-between text-[11px] text-[#9AA8B8]">
                        <span
                          className="font-medium"
                          style={{ color: riskColor[severity] }}
                        >
                          {severity}
                        </span>
                        <span>{count}</span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-[#111925]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${pct}%`,
                            background: riskColor[severity],
                          }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="rounded-xl border border-[#FF4D5E22] bg-[#111925] p-4">
              <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#FF4D5E]">
                Immediate attention
              </div>
              <div className="mt-3 space-y-3">
                {immediateAttention.length === 0 ? (
                  <div className="text-sm text-[#9AA8B8]">
                    No critical KEV issues are currently active.
                  </div>
                ) : (
                  immediateAttention.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setSelectedVuln(item)}
                      className="w-full rounded-lg border border-[#1D2938] bg-[#0D131D] p-3 text-left transition-colors hover:border-[#FF4D5E55]"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold text-[#FF8A4C]">
                          {item.id}
                        </span>
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                          style={{
                            background: "rgba(255,77,94,0.12)",
                            color: "#FF4D5E",
                          }}
                        >
                          KEV
                        </span>
                      </div>
                      <div className="mt-2 text-sm font-medium text-[#F4F7FA]">
                        {item.description}
                      </div>
                      <div className="mt-2 flex items-center justify-between text-[11px] text-[#9AA8B8]">
                        <span>{item.severity}</span>
                        <span>{item.cvss?.toFixed(1) ?? "N/A"}</span>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#1D2938] bg-[#0D131D] p-3">
            <div className="relative min-w-[180px] flex-1 max-w-sm">
              <svg
                className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#627083]"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <circle cx="11" cy="11" r="6" />
                <path d="m16 16 5 5" />
              </svg>
              <input
                type="text"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search CVE ID, title, product…"
                className="w-full rounded-lg border border-[#1D2938] bg-[#111925] py-1.5 pl-9 pr-3 text-xs text-[#F4F7FA] outline-none transition-colors focus:border-[#56B4FF]"
                aria-label="Search vulnerabilities"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-xs text-[#627083]">Severity:</span>
              {["ALL", ...severityOrder].map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setRiskFilter(level)}
                  className="rounded px-2.5 py-1 text-[11px] font-medium transition-colors"
                  style={{
                    background:
                      riskFilter === level ? "#1D2938" : "transparent",
                    color: riskFilter === level ? "#F4F7FA" : "#627083",
                    border:
                      riskFilter === level
                        ? "1px solid #1D2938"
                        : "1px solid transparent",
                  }}
                >
                  {level}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-xs text-[#627083]">Status:</span>
              {["ALL", "KNOWN_EXPLOITED", "GENERAL"].map((state) => (
                <button
                  key={state}
                  type="button"
                  onClick={() => setStatusFilter(state as typeof statusFilter)}
                  className="rounded px-2.5 py-1 text-[11px] font-medium transition-colors"
                  style={{
                    background:
                      statusFilter === state ? "#1D2938" : "transparent",
                    color: statusFilter === state ? "#F4F7FA" : "#627083",
                    border:
                      statusFilter === state
                        ? "1px solid #1D2938"
                        : "1px solid transparent",
                  }}
                >
                  {state === "ALL"
                    ? "ALL"
                    : state === "KNOWN_EXPLOITED"
                      ? "KEV"
                      : "GENERAL"}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setKevOnly((current) => !current)}
              className="rounded border px-3 py-1.5 text-[11px] font-semibold"
              style={{
                background: kevOnly ? "rgba(255,138,76,0.15)" : "#111925",
                color: kevOnly ? "#FF8A4C" : "#627083",
                borderColor: kevOnly ? "rgba(255,138,76,0.4)" : "#1D2938",
              }}
            >
              🔥 KEV only
            </button>

            <div className="ml-auto flex items-center gap-2 text-xs text-[#627083]">
              <button
                type="button"
                onClick={() => handleSort("severity")}
                className="rounded border border-[#1D2938] bg-[#111925] px-2 py-1 text-[10px] uppercase tracking-[0.15em]"
              >
                Severity
              </button>
              <button
                type="button"
                onClick={() => handleSort("newest")}
                className="rounded border border-[#1D2938] bg-[#111925] px-2 py-1 text-[10px] uppercase tracking-[0.15em]"
              >
                Newest
              </button>
              <button
                type="button"
                onClick={() => handleSort("cve")}
                className="rounded border border-[#1D2938] bg-[#111925] px-2 py-1 text-[10px] uppercase tracking-[0.15em]"
              >
                CVE
              </button>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-[#1D2938]">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr
                  style={{
                    background: "#0D131D",
                    borderBottom: "1px solid #1D2938",
                  }}
                >
                  {[
                    "CVE ID",
                    "CVSS",
                    "Severity",
                    "Description",
                    "Affected product",
                    "Status",
                    "KEV",
                  ].map((header) => (
                    <th
                      key={header}
                      className="px-4 py-2.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-[#627083]"
                    >
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAndSorted.map((v, index) => {
                  const kevMeta = kevLookup.get(v.id.toUpperCase())
                  const severityColor = riskColor[v.severity] || "#56B4FF"
                  return (
                    <tr
                      key={v.id}
                      tabIndex={0}
                      role="button"
                      onClick={() => setSelectedVuln(v)}
                      onKeyDown={(
                        event: KeyboardEvent<HTMLTableRowElement>,
                      ) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault()
                          setSelectedVuln(v)
                        }
                      }}
                      className="cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-[#56B4FF]"
                      style={{
                        background: index % 2 === 0 ? "#111925" : "#0F1720",
                        borderBottom: "1px solid rgba(29, 41, 56, 0.6)",
                      }}
                    >
                      <td className="px-4 py-3">
                        <div className="font-mono text-xs font-bold text-[#FF8A4C]">
                          {v.id}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div
                          className="font-mono text-xs font-semibold"
                          style={{ color: severityColor }}
                        >
                          {v.cvss?.toFixed(1) ?? "—"}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="rounded px-2 py-0.5 text-[10px] font-semibold"
                          style={{
                            background: `${severityColor}20`,
                            color: severityColor,
                          }}
                        >
                          {v.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="max-w-[420px]">
                          <div className="text-xs text-[#F4F7FA]">
                            {v.description}
                          </div>
                          {kevMeta?.shortDescription && (
                            <div className="mt-1 text-[10px] text-[#627083]">
                              {kevMeta.shortDescription}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-xs text-[#9AA8B8]">
                          {getVendorProductLabel(v, kevMeta)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className="rounded px-2 py-0.5 text-[10px] font-semibold"
                          style={{
                            background: v.is_kev
                              ? "rgba(255,138,76,0.12)"
                              : "rgba(86,180,255,0.12)",
                            color: v.is_kev ? "#FF8A4C" : "#56B4FF",
                          }}
                        >
                          {v.is_kev ? "Known Exploited" : "General"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {v.is_kev ? (
                          <span className="rounded border border-[#FF8A4C40] bg-[#FF8A4C1A] px-2 py-0.5 text-[10px] font-semibold text-[#FF8A4C]">
                            KEV
                          </span>
                        ) : (
                          <span className="text-[10px] text-[#627083]">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>

            {filteredAndSorted.length === 0 && (
              <div className="bg-[#111925] p-12 text-center">
                <div className="text-lg font-semibold text-[#F4F7FA]">
                  No matching vulnerabilities
                </div>
                <p className="mt-2 text-sm text-[#9AA8B8]">
                  Adjust filters to widen the set or clear the search to review
                  additional CVEs.
                </p>
              </div>
            )}
          </div>
        </>
      )}

      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#02070d]/80 p-4">
          <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-xl border border-[#1D2938] bg-[#0D131D] p-5 shadow-2xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#627083]">
                  {selectedVuln.is_kev
                    ? "Known Exploited Vulnerability"
                    : "General Vulnerability"}
                </div>
                <h3 className="mt-2 font-mono text-lg font-semibold text-[#F4F7FA]">
                  {selectedVuln.id}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedVuln(null)}
                className="rounded border border-[#1D2938] bg-[#111925] px-2 py-1 text-xs text-[#9AA8B8]"
              >
                Close
              </button>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-lg border border-[#1D2938] bg-[#111925] p-3">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                  Title
                </div>
                <div className="mt-2 text-sm text-[#F4F7FA]">
                  {kevLookup.get(selectedVuln.id.toUpperCase())
                    ?.vulnerabilityName || selectedVuln.id}
                </div>
              </div>
              <div className="rounded-lg border border-[#1D2938] bg-[#111925] p-3">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                  Severity
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <span
                    className="rounded px-2 py-0.5 text-[10px] font-semibold"
                    style={{
                      background: `${riskColor[selectedVuln.severity] || "#56B4FF"}20`,
                      color: riskColor[selectedVuln.severity] || "#56B4FF",
                    }}
                  >
                    {selectedVuln.severity}
                  </span>
                  <span className="font-mono text-xs text-[#9AA8B8]">
                    CVSS {selectedVuln.cvss?.toFixed(1) ?? "N/A"}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-lg border border-[#1D2938] bg-[#111925] p-4">
              <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                Description
              </div>
              <p className="mt-2 text-sm leading-6 text-[#D7E0EA]">
                {selectedVuln.description}
              </p>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-lg border border-[#1D2938] bg-[#111925] p-3">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                  Vendor / product
                </div>
                <div className="mt-2 text-sm text-[#F4F7FA]">
                  {getVendorProductLabel(
                    selectedVuln,
                    kevLookup.get(selectedVuln.id.toUpperCase()),
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-[#1D2938] bg-[#111925] p-3">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                  Published
                </div>
                <div className="mt-2 text-sm text-[#F4F7FA]">
                  {formatDate(selectedVuln.published)}
                </div>
              </div>
            </div>

            {(selectedVuln.is_kev ||
              selectedVuln.kev_details ||
              kevLookup.get(selectedVuln.id.toUpperCase())) && (
              <div className="mt-4 rounded-lg border border-[#FF8A4C40] bg-[#111925] p-4">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#FF8A4C]">
                  Remediation
                </div>
                <div className="mt-2 text-sm text-[#F4F7FA]">
                  {kevLookup.get(selectedVuln.id.toUpperCase())
                    ?.requiredAction ||
                    selectedVuln.kev_details?.short_description ||
                    "Apply vendor remediation guidance and verify impacted systems are patched."}
                </div>
                {selectedVuln.kev_details?.due_date && (
                  <div className="mt-2 text-[11px] text-[#9AA8B8]">
                    Due date: {formatDate(selectedVuln.kev_details.due_date)}
                  </div>
                )}
              </div>
            )}

            {selectedVuln.references && selectedVuln.references.length > 0 && (
              <div className="mt-4 rounded-lg border border-[#1D2938] bg-[#111925] p-4">
                <div className="text-[10px] uppercase tracking-[0.2em] text-[#627083]">
                  References
                </div>
                <ul className="mt-3 space-y-2">
                  {selectedVuln.references.map((reference) => (
                    <li key={reference}>
                      <a
                        href={reference}
                        target="_blank"
                        rel="noreferrer"
                        className="break-all text-xs text-[#56B4FF] underline-offset-2 hover:underline"
                      >
                        {reference}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mt-4 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.18em] text-[#627083]">
              {selectedVuln.cwe && (
                <span className="rounded border border-[#1D2938] bg-[#0D131D] px-2 py-1">
                  {selectedVuln.cwe}
                </span>
              )}
              <span className="rounded border border-[#1D2938] bg-[#0D131D] px-2 py-1">
                {selectedVuln.is_kev
                  ? "KEV / known exploited"
                  : "General vulnerability"}
              </span>
              <span className="rounded border border-[#1D2938] bg-[#0D131D] px-2 py-1">
                Source: {selectedVuln.source || "NVD"}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
