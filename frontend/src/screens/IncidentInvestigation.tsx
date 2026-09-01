import { useState } from "react"

import { ProvenanceBadge } from "../components/ProvenanceBadge"

const timelineEvents = [
  {
    time: "10:31:04",
    title: "Multiple Failed Logins",
    desc: "12 failed authentication attempts from 192.168.1.42",
    type: "warning",
    critical: false,
  },

  {
    time: "10:31:08",
    title: "Password Spray Detected",
    desc: "4 distinct usernames targeted within 4 seconds",
    type: "alert",
    critical: false,
  },

  {
    time: "10:31:12",
    title: "Account Enumeration",
    desc: "Systematic enumeration of account names detected",
    type: "alert",
    critical: false,
  },

  {
    time: "10:31:18",
    title: "Successful Authentication",
    desc: "admin account authenticated from attack source IP",
    type: "critical",
    critical: true,
  },

  {
    time: "10:31:21",
    title: "Privileged Resource Accessed",
    desc: "/api/admin/users endpoint accessed — 47 records returned",
    type: "critical",
    critical: true,
  },
]

const eventTypeColor: Record<string, string> = {
  warning: "#F4C95D",

  alert: "#FF8A4C",

  critical: "#FF4D5E",
}

const detectionConditions = [
  { label: "12 failed authentication attempts", met: true },

  { label: "4 usernames targeted", met: true },

  { label: "Same source IP (192.168.1.42)", met: true },

  { label: "Window ≤ 90 seconds", met: true },

  { label: "Successful login after failures", met: true },
]

const evidence = [
  { key: "Source IP", value: "192.168.1.42", mono: true },

  { key: "Target System", value: "auth-01", mono: true },

  { key: "Affected Account", value: "admin", mono: true },

  { key: "Total Events", value: "17", mono: false },

  { key: "First Seen", value: "10:31:04 UTC", mono: true },

  { key: "Last Seen", value: "10:31:21 UTC", mono: true },

  { key: "Detection Rule", value: "BRUTE_FORCE_CHAIN_v2", mono: true },

  { key: "Confidence", value: "91%", mono: false },
]

interface IncidentInvestigationProps {
  onNavigate: (screen: string) => void
}

export default function IncidentInvestigation({
  onNavigate,
}: IncidentInvestigationProps) {
  const [activeTab, setActiveTab] =
    useState<"overview" | "timeline" | "evidence">("overview")

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <button
              onClick={() => onNavigate("incidents")}
              className="text-xs transition-colors"
              style={{ color: "#627083" }}
            >
              ← Incidents
            </button>
            <span style={{ color: "#1D2938" }}>/</span>
            <span className="text-xs font-mono" style={{ color: "#9AA8B8" }}>
              INC-2026-00842
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div
              className="px-2 py-0.5 rounded text-xs font-semibold"
              style={{
                background: "#FF4D5E20",
                color: "#FF4D5E",
                border: "1px solid #FF4D5E30",
              }}
            >
              CRITICAL INCIDENT
            </div>
            <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
              Credential Attack
            </h1>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium"
            style={{
              background: "#FF4D5E15",
              color: "#FF4D5E",
              border: "1px solid #FF4D5E25",
            }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#FF4D5E] animate-pulse" />
            INVESTIGATING
          </div>
          <button
            onClick={() => onNavigate("response")}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: "#FF8A4C15",
              color: "#FF8A4C",
              border: "1px solid #FF8A4C30",
            }}
          >
            Respond
          </button>
          <button
            onClick={() => onNavigate("ai-analyst")}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
            style={{
              background: "#7C8CFF15",
              color: "#7C8CFF",
              border: "1px solid #7C8CFF30",
            }}
          >
            AI Analyst
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-4 gap-4">
        {/* Risk Score with gauge bar */}
        <div
          className="rounded-xl p-4"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-start justify-between mb-2">
            <span
              className="text-[10px] font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              RISK SCORE
            </span>
            <ProvenanceBadge type="derived" />
          </div>
          <div className="flex items-baseline gap-1 mb-2">
            <span
              className="text-2xl font-semibold font-mono"
              style={{ color: "#FF4D5E" }}
            >
              94
            </span>
            <span className="text-sm" style={{ color: "#627083" }}>
              / 100
            </span>
          </div>
          <div
            className="h-1 rounded-full overflow-hidden"
            style={{ background: "#1D2938" }}
          >
            <div
              className="h-1 rounded-full"
              style={{
                width: "94%",
                background: "linear-gradient(90deg, #FF8A4C, #FF4D5E)",
              }}
            />
          </div>
        </div>

        {/* Severity */}
        <div
          className="rounded-xl p-4"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-start justify-between mb-2">
            <span
              className="text-[10px] font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              SEVERITY
            </span>
            <ProvenanceBadge type="derived" />
          </div>
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-[#FF4D5E] animate-pulse" />
            <span
              className="text-xl font-semibold font-mono"
              style={{ color: "#FF4D5E" }}
            >
              CRITICAL
            </span>
          </div>
          <span className="text-[10px]" style={{ color: "#627083" }}>
            Highest severity level
          </span>
        </div>

        {/* MITRE */}
        <div
          className="rounded-xl p-4"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-start justify-between mb-2">
            <span
              className="text-[10px] font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              MITRE ATT&CK
            </span>
            <ProvenanceBadge type="live" />
          </div>
          <span
            className="text-2xl font-semibold font-mono"
            style={{ color: "#7C8CFF" }}
          >
            T1110
          </span>
          <p className="text-xs mt-1" style={{ color: "#627083" }}>
            Brute Force · Credential Access
          </p>
        </div>

        {/* Confidence with bar */}
        <div
          className="rounded-xl p-4"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-start justify-between mb-2">
            <span
              className="text-[10px] font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              AI CONFIDENCE
            </span>
            <ProvenanceBadge type="inferred" />
          </div>
          <div className="flex items-baseline gap-1 mb-2">
            <span
              className="text-2xl font-semibold font-mono"
              style={{ color: "#42D392" }}
            >
              91%
            </span>
          </div>
          <div
            className="h-1 rounded-full overflow-hidden"
            style={{ background: "#1D2938" }}
          >
            <div
              className="h-1 rounded-full"
              style={{
                width: "91%",
                background: "linear-gradient(90deg, #7C8CFF, #42D392)",
              }}
            />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div
        className="flex items-center gap-1"
        style={{ borderBottom: "1px solid #1D2938", paddingBottom: "0" }}
      >
        {(["overview", "timeline", "evidence"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className="px-4 py-2 text-sm font-medium capitalize transition-all relative"
            style={{
              color: activeTab === tab ? "#F4F7FA" : "#627083",

              borderBottom:
                activeTab === tab
                  ? "2px solid #56B4FF"
                  : "2px solid transparent",

              marginBottom: "-1px",
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="grid grid-cols-5 gap-4">
          {/* Attack Timeline (left) */}
          <div className="col-span-3 space-y-4">
            <div
              className="rounded-xl p-5"
              style={{ background: "#111925", border: "1px solid #1D2938" }}
            >
              <div className="flex items-center justify-between mb-5">
                <span
                  className="text-xs font-semibold tracking-widest uppercase"
                  style={{ color: "#627083" }}
                >
                  ATTACK TIMELINE
                </span>
                <ProvenanceBadge type="simulated" />
              </div>

              <div className="relative pl-5">
                {/* Vertical connector line */}
                <div
                  className="absolute left-2 top-3 bottom-3 w-px"
                  style={{
                    background:
                      "linear-gradient(to bottom, #FF8A4C40, #FF4D5E)",
                  }}
                />

                <div className="space-y-0">
                  {timelineEvents.map((event, i) => (
                    <div key={i} className="relative flex gap-4 pb-5 last:pb-0">
                      {/* Node */}
                      <div
                        className="absolute -left-3 flex-shrink-0 w-3 h-3 rounded-full border-2 mt-0.5 z-10"
                        style={{
                          background: event.critical
                            ? eventTypeColor[event.type]
                            : "#0D131D",

                          borderColor: eventTypeColor[event.type],

                          boxShadow: event.critical
                            ? `0 0 8px ${eventTypeColor[event.type]}60`
                            : "none",
                        }}
                      />

                      <div className="ml-2">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className="text-xs font-mono font-medium"
                            style={{ color: "#627083" }}
                          >
                            {event.time}
                          </span>
                          {event.critical && (
                            <span
                              className="text-[10px] px-1.5 py-0 rounded font-semibold"
                              style={{
                                background: "#FF4D5E20",
                                color: "#FF4D5E",
                              }}
                            >
                              KEY EVENT
                            </span>
                          )}
                        </div>
                        <div
                          className="rounded-lg p-3"
                          style={{
                            background: event.critical
                              ? "#FF4D5E08"
                              : "#0D131D",

                            border: `1px solid ${
                              event.critical ? "#FF4D5E30" : "#1D2938"
                            }`,
                          }}
                        >
                          <p
                            className="text-sm font-medium"
                            style={{ color: eventTypeColor[event.type] }}
                          >
                            {event.title}
                          </p>
                          <p
                            className="text-xs mt-1"
                            style={{ color: "#9AA8B8" }}
                          >
                            {event.desc}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Why Was This Detected */}
            <div
              className="rounded-xl p-5"
              style={{ background: "#111925", border: "1px solid #1D2938" }}
            >
              <div className="flex items-center justify-between mb-4">
                <span
                  className="text-xs font-semibold tracking-widest uppercase"
                  style={{ color: "#627083" }}
                >
                  WHY WAS THIS DETECTED?
                </span>
                <ProvenanceBadge type="derived" />
              </div>

              <div
                className="rounded-lg p-3 mb-4"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="text-[10px] uppercase font-semibold"
                    style={{ color: "#627083" }}
                  >
                    Rule
                  </span>
                </div>
                <span
                  className="font-mono text-sm font-medium"
                  style={{ color: "#7C8CFF" }}
                >
                  BRUTE_FORCE_CHAIN_v2
                </span>
              </div>

              <div className="mb-4">
                <p className="text-xs mb-2" style={{ color: "#627083" }}>
                  Conditions matched:
                </p>
                <div className="space-y-1.5">
                  {detectionConditions.map((cond, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div
                        className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                        style={{ background: "#42D39220" }}
                      >
                        <svg
                          className="w-2.5 h-2.5"
                          style={{ color: "#42D392" }}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={3}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                      </div>
                      <span className="text-sm" style={{ color: "#9AA8B8" }}>
                        {cond.label}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div
                className="flex items-center gap-3 p-3 rounded-lg"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
              >
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Detection confidence
                    </span>
                    <span
                      className="text-sm font-semibold"
                      style={{ color: "#42D392" }}
                    >
                      91%
                    </span>
                  </div>
                  <div
                    className="h-1.5 rounded-full"
                    style={{ background: "#1D2938" }}
                  >
                    <div
                      className="h-1.5 rounded-full"
                      style={{ width: "91%", background: "#42D392" }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right column: Evidence + AI snippet */}
          <div className="col-span-2 space-y-4">
            {/* Evidence */}
            <div
              className="rounded-xl p-4"
              style={{ background: "#111925", border: "1px solid #1D2938" }}
            >
              <div className="flex items-center justify-between mb-4">
                <span
                  className="text-xs font-semibold tracking-widest uppercase"
                  style={{ color: "#627083" }}
                >
                  EVIDENCE
                </span>
                <ProvenanceBadge type="simulated" />
              </div>
              <div className="space-y-2.5">
                {evidence.map((e, i) => (
                  <div
                    key={i}
                    className="flex items-start justify-between gap-3"
                    style={{
                      borderBottom:
                        i < evidence.length - 1
                          ? "1px solid #1D293840"
                          : "none",
                      paddingBottom: i < evidence.length - 1 ? "8px" : "0",
                    }}
                  >
                    <span
                      className="text-xs flex-shrink-0"
                      style={{ color: "#627083" }}
                    >
                      {e.key}
                    </span>
                    <span
                      className={`text-xs font-medium text-right ${
                        e.mono ? "font-mono" : ""
                      }`}
                      style={{ color: "#F4F7FA" }}
                    >
                      {e.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* AI Insight */}
            <div
              className="rounded-xl p-4"
              style={{ background: "#111925", border: "1px solid #7C8CFF25" }}
            >
              <div className="flex items-center justify-between mb-3">
                <span
                  className="text-xs font-semibold tracking-widest uppercase"
                  style={{ color: "#627083" }}
                >
                  AI ASSESSMENT
                </span>
                <ProvenanceBadge type="inferred" />
              </div>
              <p
                className="text-sm leading-relaxed mb-3"
                style={{ color: "#9AA8B8" }}
              >
                High-confidence credential attack. Password spraying pattern
                with 4 targeted accounts followed by successful admin login.
                Immediate response recommended.
              </p>
              <div className="mb-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs" style={{ color: "#627083" }}>
                    Confidence
                  </span>
                  <span
                    className="text-sm font-semibold"
                    style={{ color: "#42D392" }}
                  >
                    91%
                  </span>
                </div>
                <div
                  className="h-1 rounded-full"
                  style={{ background: "#1D2938" }}
                >
                  <div
                    className="h-1 rounded-full"
                    style={{ width: "91%", background: "#42D392" }}
                  />
                </div>
              </div>
              <button
                onClick={() => onNavigate("ai-analyst")}
                className="w-full py-2 rounded-lg text-xs font-medium transition-all"
                style={{
                  background: "#7C8CFF15",
                  color: "#7C8CFF",
                  border: "1px solid #7C8CFF25",
                }}
              >
                Open Full Analysis →
              </button>
            </div>

            {/* Quick Actions */}
            <div
              className="rounded-xl p-4"
              style={{ background: "#111925", border: "1px solid #1D2938" }}
            >
              <span
                className="text-xs font-semibold tracking-widest uppercase block mb-3"
                style={{ color: "#627083" }}
              >
                QUICK ACTIONS
              </span>
              <div className="space-y-2">
                <button
                  onClick={() => onNavigate("response")}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{
                    background: "#FF4D5E10",
                    color: "#FF4D5E",
                    border: "1px solid #FF4D5E25",
                  }}
                >
                  <span>⚠</span> Simulate Response
                </button>
                <button
                  onClick={() => onNavigate("ai-analyst")}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{
                    background: "#7C8CFF10",
                    color: "#7C8CFF",
                    border: "1px solid #7C8CFF25",
                  }}
                >
                  <span>△</span> AI Analysis
                </button>
                <button
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
                  style={{ background: "#1D2938", color: "#9AA8B8" }}
                >
                  <span>↗</span> Export Report
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "timeline" && (
        <div
          className="rounded-xl p-6"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-center justify-between mb-6">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              FULL ATTACK TIMELINE
            </span>
            <ProvenanceBadge type="simulated" />
          </div>
          <div className="space-y-0 relative pl-8">
            <div
              className="absolute left-3.5 top-3 bottom-0 w-px"
              style={{ background: "#1D2938" }}
            />
            {timelineEvents.map((event, i) => (
              <div key={i} className="relative pb-8 last:pb-0">
                <div
                  className="absolute left-0 w-7 h-7 rounded-full flex items-center justify-center border-2 z-10"
                  style={{
                    background: "#0D131D",

                    borderColor: eventTypeColor[event.type],
                  }}
                >
                  <div
                    className="w-2 h-2 rounded-full"
                    style={{ background: eventTypeColor[event.type] }}
                  />
                </div>
                <div className="ml-4">
                  <span
                    className="text-xs font-mono"
                    style={{ color: "#627083" }}
                  >
                    {event.time} UTC
                  </span>
                  <h3
                    className="text-sm font-semibold mt-0.5"
                    style={{ color: eventTypeColor[event.type] }}
                  >
                    {event.title}
                  </h3>
                  <p className="text-sm mt-1" style={{ color: "#9AA8B8" }}>
                    {event.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "evidence" && (
        <div className="grid grid-cols-2 gap-4">
          <div
            className="rounded-xl p-5"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <div className="flex items-center justify-between mb-4">
              <span
                className="text-xs font-semibold tracking-widest uppercase"
                style={{ color: "#627083" }}
              >
                EVIDENCE SUMMARY
              </span>
              <ProvenanceBadge type="simulated" />
            </div>
            <div className="space-y-3">
              {evidence.map((e, i) => (
                <div
                  key={i}
                  className="rounded-lg p-3"
                  style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                >
                  <span
                    className="text-[11px] uppercase font-semibold"
                    style={{ color: "#627083" }}
                  >
                    {e.key}
                  </span>
                  <div
                    className={`text-sm mt-0.5 font-medium ${
                      e.mono ? "font-mono" : ""
                    }`}
                    style={{ color: "#F4F7FA" }}
                  >
                    {e.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div
            className="rounded-xl p-5"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <span
              className="text-xs font-semibold tracking-widest uppercase block mb-4"
              style={{ color: "#627083" }}
            >
              RAW LOG EXCERPTS
            </span>
            <div
              className="rounded-lg p-3 text-xs font-mono space-y-1.5"
              style={{
                background: "#0D131D",
                border: "1px solid #1D2938",
                color: "#9AA8B8",
              }}
            >
              {[
                "10:31:04.182 AUTH_FAILURE src=192.168.1.42 user=admin",

                "10:31:04.644 AUTH_FAILURE src=192.168.1.42 user=root",

                "10:31:05.091 AUTH_FAILURE src=192.168.1.42 user=svc_backup",

                "10:31:05.523 AUTH_FAILURE src=192.168.1.42 user=admin",

                "10:31:08.204 DETECTION_TRIGGERED rule=BRUTE_FORCE_CHAIN_v2",

                "10:31:18.042 AUTH_SUCCESS src=192.168.1.42 user=admin",

                "10:31:21.188 RESOURCE_ACCESS path=/api/admin/users user=admin",
              ].map((log, i) => (
                <div
                  key={i}
                  style={{
                    color: log.includes("AUTH_FAILURE")
                      ? "#FF4D5E80"
                      : log.includes("AUTH_SUCCESS")
                        ? "#42D39280"
                        : "#9AA8B8",
                  }}
                >
                  {log}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
