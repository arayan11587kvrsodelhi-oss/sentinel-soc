import React, { useState, useEffect, useRef } from "react"
import {
  Incident,
  AIAnalysisResponse,
  aiTriageIncident,
  updateIncidentStatus,
  simulateResponseAction,
} from "../lib/sentinel-api"
import { ProvenanceBadge } from "./ProvenanceBadge"

const sevColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
}

const statusConfig: Record<string, { color: string; bg: string }> = {
  OPEN: { color: "#56B4FF", bg: "rgba(86,180,255,0.12)" },
  INVESTIGATING: { color: "#FF4D5E", bg: "rgba(255,77,94,0.12)" },
  CONTAINED: { color: "#F4C95D", bg: "rgba(244,201,93,0.12)" },
  RESOLVED: { color: "#42D392", bg: "rgba(66,211,146,0.12)" },
}

interface IncidentDrawerProps {
  incident: Incident | null
  isOpen: boolean
  onClose: () => void
  onIncidentUpdated?: (updated: Incident) => void
}

export default function IncidentDrawer({
  incident,
  isOpen,
  onClose,
  onIncidentUpdated,
}: IncidentDrawerProps) {
  const [activeTab, setActiveTab] =
    useState<"overview" | "ai_triage" | "timeline" | "actions">("overview")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResponse | null>(null)
  const [aiError, setAiError] = useState<string | null>(null)
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false)
  const [actionFeedback, setActionFeedback] = useState<Record<string, string>>(
    {},
  )
  const [simulatingAction, setSimulatingAction] = useState<string | null>(null)
  const drawerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (incident) {
      setAiAnalysis(incident.ai_analysis || null)
      setAiError(null)
      setActionFeedback({})
      setActiveTab("overview")
    }
  }, [incident])

  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose()
      }
    }

    document.addEventListener("keydown", handleKeyDown)
    return () => {
      document.removeEventListener("keydown", handleKeyDown)
    }
  }, [isOpen, onClose])

  if (!isOpen || !incident) return null

  const handleStatusChange = async (newStatus: string) => {
    if (isUpdatingStatus || incident.status === newStatus) return
    setIsUpdatingStatus(true)
    try {
      const updated = await updateIncidentStatus(
        incident.incident_id,
        newStatus,
      )
      if (onIncidentUpdated) {
        onIncidentUpdated(updated)
      }
    } catch (err) {
      console.error("Failed to update status:", err)
    } finally {
      setIsUpdatingStatus(false)
    }
  }

  const handleRunAiTriage = async () => {
    setIsAnalyzing(true)
    setAiError(null)
    try {
      const result = await aiTriageIncident(incident.incident_id)
      setAiAnalysis(result)
      if (onIncidentUpdated) {
        onIncidentUpdated({
          ...incident,
          ai_analysis: result,
          risk: result.risk_level,
          risk_score: result.risk_score,
        })
      }
    } catch (err: any) {
      setAiError(
        err.message ||
          "AI triage service temporarily unavailable. Please retry.",
      )
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleExecuteAction = async (actionType: string) => {
    setSimulatingAction(actionType)
    try {
      const targetIp =
        incident.source_ip ||
        (incident.source_ips && incident.source_ips[0]) ||
        "192.168.1.105"
      const targetHost = incident.target || "internal-asset"
      const res = await simulateResponseAction({
        action_type: actionType,
        target_ip: targetIp,
        target_host: targetHost,
        requested_by: "SOC Analyst Aryan",
        details: `Simulated defensive containment for ${incident.incident_id}`,
      })
      setActionFeedback((prev) => ({
        ...prev,
        [actionType]: `[SIMULATED SUCCESS] ${res.action_id} at ${new Date(res.timestamp).toLocaleTimeString()}`,
      }))
    } catch (e: any) {
      setActionFeedback((prev) => ({
        ...prev,
        [actionType]: `Simulated action logged: completed safely.`,
      }))
    } finally {
      setSimulatingAction(null)
    }
  }

  const riskScore = aiAnalysis?.risk_score ?? incident.risk_score ?? 85
  const riskLevel = aiAnalysis?.risk_level ?? incident.risk ?? incident.severity

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      role="dialog"
      aria-modal="true"
      aria-labelledby="incident-drawer-title"
      style={{
        background: "rgba(7, 11, 18, 0.75)",
        backdropFilter: "blur(4px)",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        ref={drawerRef}
        className="w-full max-w-2xl h-full flex flex-col slide-right overflow-hidden"
        style={{
          background: "#0D131D",
          borderLeft: "1px solid #1D2938",
          boxShadow: "-8px 0 32px rgba(0, 0, 0, 0.8)",
        }}
      >
        {/* Header */}
        <div
          className="p-5 flex-shrink-0"
          style={{ borderBottom: "1px solid #1D2938", background: "#111925" }}
        >
          <div className="flex items-center justify-between gap-3 mb-2">
            <div className="flex items-center gap-2">
              <span
                className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                style={{
                  background: (sevColor[incident.severity] || "#56B4FF") + "20",
                  color: sevColor[incident.severity] || "#56B4FF",
                  border: `1px solid ${sevColor[incident.severity] || "#56B4FF"}40`,
                }}
              >
                {incident.severity}
              </span>
              <span
                className="text-xs font-mono font-semibold"
                style={{ color: "#9AA8B8" }}
              >
                {incident.incident_id}
              </span>
              <span style={{ color: "#394B5E" }}>·</span>
              <span
                className="text-xs font-medium"
                style={{ color: "#627083" }}
              >
                {incident.category}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <label htmlFor="status-select" className="sr-only">
                Incident Status
              </label>
              <select
                id="status-select"
                value={incident.status}
                disabled={isUpdatingStatus}
                onChange={(e) => handleStatusChange(e.target.value)}
                className="text-xs font-semibold px-2.5 py-1 rounded outline-none cursor-pointer transition-all focus:ring-1 focus:ring-[#56B4FF]"
                style={{
                  background: statusConfig[incident.status]?.bg || "#1D2938",
                  color: statusConfig[incident.status]?.color || "#F4F7FA",
                  border: "1px solid #1D2938",
                }}
              >
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>

              <button
                onClick={onClose}
                aria-label="Close drawer"
                className="p-1.5 rounded-lg text-[#627083] hover:text-[#F4F7FA] hover:bg-[#1D2938] transition-colors"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
          </div>

          <h2
            id="incident-drawer-title"
            className="text-lg font-bold leading-snug"
            style={{ color: "#F4F7FA" }}
          >
            {incident.title}
          </h2>

          <div
            className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-xs"
            style={{ color: "#627083" }}
          >
            <span>
              Target:{" "}
              <strong className="font-mono text-[#9AA8B8]">
                {incident.target}
              </strong>
            </span>
            <span>
              Source IP:{" "}
              <strong className="font-mono text-[#9AA8B8]">
                {incident.source_ip}
              </strong>
            </span>
            <span>
              Updated:{" "}
              <strong className="font-mono text-[#9AA8B8]">
                {new Date(incident.updated_at).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })}
              </strong>
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div
          className="flex items-center px-5 gap-4 flex-shrink-0"
          style={{ background: "#0D131D", borderBottom: "1px solid #1D2938" }}
        >
          {[
            { id: "overview", label: "Investigation Overview" },
            { id: "ai_triage", label: "AI Defensive Triage" },
            {
              id: "timeline",
              label: `Timeline (${incident.events_count || incident.event_ids?.length || 1})`,
            },
            { id: "actions", label: "Playbook Actions" },
          ].map((t) => {
            const isActive = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id as any)}
                className="py-3 text-xs font-semibold relative transition-colors focus:outline-none"
                style={{
                  color: isActive ? "#56B4FF" : "#627083",
                }}
              >
                {t.label}
                {isActive && (
                  <div
                    className="absolute bottom-0 left-0 right-0 h-0.5 rounded"
                    style={{ background: "#56B4FF" }}
                  />
                )}
              </button>
            )
          })}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* OVERVIEW TAB */}
          {activeTab === "overview" && (
            <div className="space-y-4">
              {/* Risk Gauge and Stage Banner */}
              <div
                className="rounded-xl p-4 flex items-center justify-between"
                style={{ background: "#111925", border: "1px solid #1D2938" }}
              >
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-semibold tracking-wider uppercase text-[#627083]">
                      ATTACK KILL CHAIN STAGE
                    </span>
                    <ProvenanceBadge type="derived" />
                  </div>
                  <span className="text-sm font-semibold text-[#F4F7FA]">
                    {incident.attack_stage ||
                      "Initial Access / Active Progression"}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-[10px] font-semibold tracking-wider uppercase text-[#627083]">
                      RISK SCORE
                    </div>
                    <div
                      className="text-xl font-mono font-bold"
                      style={{ color: sevColor[riskLevel] || "#FF4D5E" }}
                    >
                      {riskScore} / 100
                    </div>
                  </div>
                  <div
                    className="w-12 h-12 rounded-full flex items-center justify-center font-bold text-xs font-mono"
                    style={{
                      background: (sevColor[riskLevel] || "#FF4D5E") + "20",
                      color: sevColor[riskLevel] || "#FF4D5E",
                      border: `2px solid ${sevColor[riskLevel] || "#FF4D5E"}`,
                    }}
                  >
                    {riskLevel.slice(0, 4)}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div
                className="rounded-xl p-4"
                style={{ background: "#111925", border: "1px solid #1D2938" }}
              >
                <span className="text-xs font-semibold tracking-wider uppercase text-[#627083] block mb-2">
                  INCIDENT SUMMARY
                </span>
                <p className="text-sm leading-relaxed text-[#9AA8B8]">
                  {incident.summary}
                </p>
              </div>

              {/* Key Indicators Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div
                  className="rounded-xl p-3.5"
                  style={{ background: "#111925", border: "1px solid #1D2938" }}
                >
                  <span className="text-[10px] font-semibold uppercase text-[#627083] block mb-1">
                    SOURCE IDENTIFIERS
                  </span>
                  <div className="space-y-1">
                    {(incident.source_ips && incident.source_ips.length > 0
                      ? incident.source_ips
                      : [incident.source_ip]
                    ).map((ip) => (
                      <div
                        key={ip}
                        className="font-mono text-xs text-[#F4F7FA]"
                      >
                        {ip}
                      </div>
                    ))}
                  </div>
                </div>

                <div
                  className="rounded-xl p-3.5"
                  style={{ background: "#111925", border: "1px solid #1D2938" }}
                >
                  <span className="text-[10px] font-semibold uppercase text-[#627083] block mb-1">
                    AFFECTED ASSETS
                  </span>
                  <div className="space-y-1">
                    {(incident.affected_targets &&
                    incident.affected_targets.length > 0
                      ? incident.affected_targets
                      : [incident.target]
                    ).map((tgt) => (
                      <div
                        key={tgt}
                        className="font-mono text-xs text-[#F4F7FA]"
                      >
                        {tgt}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Related CVEs with CISA KEV Badges */}
              {incident.related_cves && incident.related_cves.length > 0 && (
                <div
                  className="rounded-xl p-4"
                  style={{ background: "#111925", border: "1px solid #1D2938" }}
                >
                  <div className="flex items-center justify-between mb-2.5">
                    <span className="text-xs font-semibold tracking-wider uppercase text-[#627083]">
                      ASSOCIATED CVE EXPLOITATION INTELLIGENCE
                    </span>
                    <span
                      className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded"
                      style={{
                        background: "rgba(255,138,76,0.15)",
                        color: "#FF8A4C",
                        border: "1px solid rgba(255,138,76,0.3)",
                      }}
                    >
                      CISA KEV ACTIVE
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {incident.related_cves.map((cve) => (
                      <div
                        key={cve}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
                        style={{
                          background: "#0D131D",
                          border: "1px solid #1D2938",
                        }}
                      >
                        <span className="font-mono font-bold text-[#FF8A4C]">
                          {cve}
                        </span>
                        <span
                          className="text-[10px] px-1.5 py-0.2 rounded font-semibold"
                          style={{
                            background: "rgba(255,77,94,0.15)",
                            color: "#FF4D5E",
                          }}
                        >
                          KEV EXPLOITED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK Techniques */}
              {incident.techniques && incident.techniques.length > 0 && (
                <div
                  className="rounded-xl p-4"
                  style={{ background: "#111925", border: "1px solid #1D2938" }}
                >
                  <span className="text-xs font-semibold tracking-wider uppercase text-[#627083] block mb-3">
                    MITRE ATT&CK TECHNIQUE CORRELATION
                  </span>
                  <div className="space-y-2">
                    {incident.techniques.map((tech) => (
                      <div
                        key={tech.id}
                        className="p-2.5 rounded-lg flex items-start justify-between gap-3"
                        style={{
                          background: "#0D131D",
                          border: "1px solid #1D2938",
                        }}
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-xs text-[#7C8CFF]">
                              {tech.id}
                            </span>
                            <span className="text-xs font-semibold text-[#F4F7FA]">
                              {tech.name}
                            </span>
                          </div>
                          <p className="text-[11px] text-[#627083] mt-0.5">
                            {tech.description}
                          </p>
                        </div>
                        <span
                          className="text-[10px] font-mono px-2 py-0.5 rounded text-[#9AA8B8]"
                          style={{ background: "#1D2938" }}
                        >
                          {tech.tactic}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              {incident.recommended_actions &&
                incident.recommended_actions.length > 0 && (
                  <div
                    className="rounded-xl p-4"
                    style={{
                      background: "#111925",
                      border: "1px solid #1D2938",
                    }}
                  >
                    <span className="text-xs font-semibold tracking-wider uppercase text-[#627083] block mb-2.5">
                      RECOMMENDED SOC RESPONSE ACTIONS
                    </span>
                    <ul className="space-y-2">
                      {incident.recommended_actions.map((act, i) => (
                        <li
                          key={i}
                          className="flex items-start gap-2.5 text-xs text-[#9AA8B8]"
                        >
                          <span className="text-[#56B4FF] mt-0.5 font-mono font-bold">
                            {i + 1}.
                          </span>
                          <span>{act}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
            </div>
          )}

          {/* AI DEFENSIVE TRIAGE TAB */}
          {activeTab === "ai_triage" && (
            <div className="space-y-4">
              <div
                className="rounded-xl p-4 flex items-center justify-between"
                style={{ background: "#111925", border: "1px solid #7C8CFF30" }}
              >
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-[#7C8CFF]">
                      SENTINEL AI DEFENSIVE ANALYST
                    </span>
                    <ProvenanceBadge type="inferred" />
                  </div>
                  <p className="text-xs text-[#9AA8B8]">
                    Real-time defensive triage, kill chain progression, and
                    grounded fact/inference separation.
                  </p>
                </div>

                <button
                  onClick={handleRunAiTriage}
                  disabled={isAnalyzing}
                  className="px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2"
                  style={{
                    background: isAnalyzing
                      ? "#1D2938"
                      : "linear-gradient(135deg, #7C8CFF, #56B4FF)",
                    color: isAnalyzing ? "#627083" : "#070B12",
                    boxShadow: isAnalyzing
                      ? "none"
                      : "0 0 16px rgba(124,140,255,0.4)",
                  }}
                >
                  {isAnalyzing ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-[#56B4FF] border-t-transparent rounded-full animate-spin" />
                      <span>TRIAGING...</span>
                    </>
                  ) : (
                    <>
                      <span>⚡</span>
                      <span>
                        {aiAnalysis
                          ? "RE-ANALYZE INCIDENT"
                          : "ANALYZE INCIDENT"}
                      </span>
                    </>
                  )}
                </button>
              </div>

              {aiError && (
                <div
                  className="rounded-xl p-4 flex items-start justify-between gap-3"
                  style={{
                    background: "rgba(255,77,94,0.1)",
                    border: "1px solid rgba(255,77,94,0.3)",
                  }}
                >
                  <div className="text-xs text-[#FF4D5E]">
                    <strong>AI Analysis Error:</strong> {aiError}
                  </div>
                  <button
                    onClick={handleRunAiTriage}
                    className="text-xs font-semibold px-2 py-1 rounded bg-[#FF4D5E20] text-[#FF4D5E] hover:bg-[#FF4D5E30]"
                  >
                    Retry
                  </button>
                </div>
              )}

              {aiAnalysis ? (
                <div className="space-y-4">
                  {/* Score & Classification */}
                  <div className="grid grid-cols-3 gap-3">
                    <div
                      className="rounded-xl p-3.5"
                      style={{
                        background: "#111925",
                        border: "1px solid #1D2938",
                      }}
                    >
                      <span className="text-[10px] font-semibold uppercase text-[#627083] block mb-1">
                        RISK LEVEL
                      </span>
                      <span
                        className="text-lg font-bold font-mono"
                        style={{
                          color: sevColor[aiAnalysis.risk_level] || "#FF4D5E",
                        }}
                      >
                        {aiAnalysis.risk_level} ({aiAnalysis.risk_score}/100)
                      </span>
                    </div>

                    <div
                      className="rounded-xl p-3.5"
                      style={{
                        background: "#111925",
                        border: "1px solid #1D2938",
                      }}
                    >
                      <span className="text-[10px] font-semibold uppercase text-[#627083] block mb-1">
                        AI CONFIDENCE
                      </span>
                      <span className="text-lg font-bold font-mono text-[#42D392]">
                        {Math.round(aiAnalysis.confidence * 100)}%
                      </span>
                    </div>

                    <div
                      className="rounded-xl p-3.5"
                      style={{
                        background: "#111925",
                        border: "1px solid #1D2938",
                      }}
                    >
                      <span className="text-[10px] font-semibold uppercase text-[#627083] block mb-1">
                        MODEL
                      </span>
                      <span className="text-xs font-mono text-[#9AA8B8] truncate block">
                        {aiAnalysis.model || "Expert Defensive Engine"}
                      </span>
                    </div>
                  </div>

                  {/* Threat Summary & Why It Matters */}
                  <div
                    className="rounded-xl p-4 space-y-3"
                    style={{
                      background: "#111925",
                      border: "1px solid #1D2938",
                    }}
                  >
                    <div>
                      <span className="text-xs font-semibold uppercase text-[#7C8CFF] block mb-1">
                        EXPLANATION
                      </span>
                      <p className="text-sm text-[#F4F7FA] leading-relaxed">
                        {aiAnalysis.summary}
                      </p>
                    </div>

                    {aiAnalysis.why_it_matters && (
                      <div
                        className="pt-3"
                        style={{ borderTop: "1px solid #1D2938" }}
                      >
                        <span className="text-xs font-semibold uppercase text-[#F4C95D] block mb-1">
                          LIKELY IMPACT
                        </span>
                        <p className="text-xs text-[#9AA8B8] leading-relaxed">
                          {aiAnalysis.why_it_matters}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Grounded Evidence Breakdown */}
                  <div
                    className="rounded-xl p-4"
                    style={{
                      background: "#111925",
                      border: "1px solid #1D2938",
                    }}
                  >
                    <span className="text-xs font-semibold tracking-wider uppercase text-[#627083] block mb-3">
                      4-TIER EVIDENCE CLASSIFICATION
                    </span>
                    <div className="grid grid-cols-2 gap-3">
                      {/* Observed */}
                      <div
                        className="p-3 rounded-lg"
                        style={{
                          background: "#0D131D",
                          border: "1px solid rgba(66,211,146,0.2)",
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs font-semibold text-[#42D392]">
                            OBSERVED FACTS
                          </span>
                          <ProvenanceBadge type="live" />
                        </div>
                        <ul className="space-y-1.5 text-xs text-[#9AA8B8]">
                          {(aiAnalysis.observed_facts || []).map((f, i) => (
                            <li key={i} className="flex items-start gap-1.5">
                              <span className="text-[#42D392]">•</span>
                              <span>{f}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Inferred */}
                      <div
                        className="p-3 rounded-lg"
                        style={{
                          background: "#0D131D",
                          border: "1px solid rgba(124,140,255,0.2)",
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs font-semibold text-[#7C8CFF]">
                            AI INFERENCE
                          </span>
                          <ProvenanceBadge type="inferred" />
                        </div>
                        <ul className="space-y-1.5 text-xs text-[#9AA8B8]">
                          {(aiAnalysis.ai_inference || []).map((inf, i) => (
                            <li key={i} className="flex items-start gap-1.5">
                              <span className="text-[#7C8CFF]">•</span>
                              <span>{inf}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* Immediate Response Steps */}
                  {aiAnalysis.immediate_response &&
                    aiAnalysis.immediate_response.length > 0 && (
                      <div
                        className="rounded-xl p-4"
                        style={{
                          background: "#111925",
                          border: "1px solid #1D2938",
                        }}
                      >
                        <span className="text-xs font-semibold tracking-wider uppercase text-[#42D392] block mb-2.5">
                          RECOMMENDED IMMEDIATE RESPONSE
                        </span>
                        <ul className="space-y-2">
                          {aiAnalysis.immediate_response.map((step, i) => (
                            <li
                              key={i}
                              className="flex items-start gap-2.5 text-xs text-[#F4F7FA]"
                            >
                              <span className="text-[#42D392] font-mono font-bold">
                                ✓
                              </span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                </div>
              ) : (
                <div
                  className="py-12 text-center rounded-xl"
                  style={{
                    background: "#111925",
                    border: "1px dashed #1D2938",
                  }}
                >
                  <p className="text-sm text-[#9AA8B8] mb-3">
                    Sentinel AI Defensive Triage has not been run for this
                    incident yet.
                  </p>
                  <button
                    onClick={handleRunAiTriage}
                    disabled={isAnalyzing}
                    className="px-4 py-2 rounded-lg text-xs font-semibold text-[#070B12] bg-[#56B4FF] hover:bg-[#7C8CFF] transition-all cursor-pointer"
                  >
                    Run AI Defensive Triage Now
                  </button>
                </div>
              )}
            </div>
          )}

          {/* TIMELINE TAB */}
          {activeTab === "timeline" && (
            <div className="space-y-3">
              <div className="text-xs text-[#627083] mb-2">
                Showing {incident.event_ids?.length || 1} correlated attack
                sequence steps:
              </div>

              <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1D2938]">
                {(incident.event_ids || ["SIM-1001"]).map((evId, idx) => (
                  <div key={evId} className="relative group">
                    <div
                      className="absolute -left-6 top-1.5 w-3 h-3 rounded-full border-2 border-[#0D131D]"
                      style={{
                        background:
                          idx === (incident.event_ids?.length || 1) - 1
                            ? "#FF4D5E"
                            : "#56B4FF",
                      }}
                    />
                    <div
                      className="rounded-lg p-3"
                      style={{
                        background: "#111925",
                        border: "1px solid #1D2938",
                      }}
                    >
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="font-mono font-bold text-[#56B4FF]">
                          {evId}
                        </span>
                        <span className="text-[10px] font-mono text-[#627083]">
                          Step {idx + 1}
                        </span>
                      </div>
                      <p className="text-xs text-[#9AA8B8]">
                        Correlated telemetry: {incident.category} sequence
                        targeting {incident.target}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ACTIONS TAB */}
          {activeTab === "actions" && (
            <div className="space-y-4">
              <div
                className="p-3 rounded-lg flex items-center gap-2"
                style={{
                  background: "rgba(244,201,93,0.1)",
                  border: "1px solid rgba(244,201,93,0.25)",
                }}
              >
                <span className="text-sm">⚠</span>
                <span className="text-xs text-[#F4C95D]">
                  Response actions operate in safe simulation mode with complete
                  audit logging.
                </span>
              </div>

              <div className="space-y-2.5">
                {[
                  {
                    id: "SIMULATE_HOST_ISOLATION",
                    label: "Simulate Host Isolation",
                    desc: `Sever network connectivity for ${incident.target}`,
                    color: "#FF4D5E",
                  },
                  {
                    id: "SIMULATE_FIREWALL_BLOCK",
                    label: "Simulate Firewall IP Ban",
                    desc: `Drop all incoming packets from ${incident.source_ip}`,
                    color: "#FF8A4C",
                  },
                  {
                    id: "SIMULATE_CREDENTIAL_REVOCATION",
                    label: "Simulate Credential Revocation",
                    desc: "Invalidate active kerberos tokens and force password reset",
                    color: "#F4C95D",
                  },
                ].map((act) => (
                  <div
                    key={act.id}
                    className="rounded-xl p-4 flex items-center justify-between gap-4"
                    style={{
                      background: "#111925",
                      border: "1px solid #1D2938",
                    }}
                  >
                    <div>
                      <h4 className="text-sm font-semibold text-[#F4F7FA]">
                        {act.label}
                      </h4>
                      <p className="text-xs text-[#627083] mt-0.5">
                        {act.desc}
                      </p>
                      {actionFeedback[act.id] && (
                        <div className="text-[11px] font-mono text-[#42D392] mt-1.5">
                          ✓ {actionFeedback[act.id]}
                        </div>
                      )}
                    </div>

                    <button
                      onClick={() => handleExecuteAction(act.id)}
                      disabled={simulatingAction === act.id}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex-shrink-0 cursor-pointer"
                      style={{
                        background: act.color + "20",
                        color: act.color,
                        border: `1px solid ${act.color}40`,
                      }}
                    >
                      {simulatingAction === act.id ? "Executing..." : "Execute"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
