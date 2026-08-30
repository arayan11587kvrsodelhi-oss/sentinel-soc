import { useState } from "react";
import { ProvenanceBadge } from "../components/ProvenanceBadge";

interface AIAnalystProps {
  onNavigate: (screen: string) => void;
}

export default function AIAnalyst({ onNavigate }: AIAnalystProps) {
  const [dismissed, setDismissed] = useState(false);
  const [addedToInvestigation, setAddedToInvestigation] = useState(false);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span
              className="text-xs px-2 py-0.5 rounded font-semibold"
              style={{ background: "#7C8CFF15", color: "#7C8CFF", border: "1px solid #7C8CFF25" }}
            >
              △ AI GENERATED
            </span>
            <span className="text-xs" style={{ color: "#627083" }}>
              Powered by Sentinel Expert Engine
            </span>
          </div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            SENTINEL ANALYST
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            AI-Assisted Investigation — INC-2026-00842
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium"
            style={{ background: "#42D39215", color: "#42D392", border: "1px solid #42D39230" }}
          >
            <div className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
            ANALYSIS COMPLETE
          </div>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-5">
        {/* Main AI Analysis Panel */}
        <div className="col-span-3 space-y-4">
          {/* Assessment */}
          <div
            className="rounded-xl p-5"
            style={{ background: "#111925", border: "1px solid #7C8CFF30" }}
          >
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                ASSESSMENT
              </span>
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs" style={{ color: "#627083" }}>
                    Confidence
                  </span>
                  <span className="text-sm font-semibold font-mono" style={{ color: "#42D392" }}>
                    91%
                  </span>
                </div>
                <ProvenanceBadge type="inferred" />
              </div>
            </div>

            {/* Confidence bar — segmented */}
            <div className="mb-4">
              <div className="flex gap-0.5">
                {Array.from({ length: 20 }).map((_, i) => (
                  <div
                    key={i}
                    className="flex-1 h-1.5 rounded-sm"
                    style={{
                      background: i < 18
                        ? `hsl(${220 + i * 5}, 80%, ${50 + i * 1.5}%)`
                        : "#1D2938",
                    }}
                  />
                ))}
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-[9px] font-mono" style={{ color: "#394B5E" }}>0%</span>
                <span className="text-[9px] font-mono" style={{ color: "#394B5E" }}>100%</span>
              </div>
            </div>

            <div
              className="rounded-lg p-4"
              style={{ background: "#0D131D", border: "1px solid #1D2938" }}
            >
              <p className="text-sm leading-relaxed" style={{ color: "#9AA8B8" }}>
                <span className="font-semibold" style={{ color: "#F4F7FA" }}>
                  High-confidence credential attack targeting an internal authentication service.
                </span>{" "}
                The attack pattern is consistent with an automated password spraying campaign originating
                from a single internal IP address. The subsequent successful authentication and privileged
                resource access indicates probable account compromise. The attack timeline spans 17 seconds
                with 12 failed attempts across 4 accounts before a successful login.
              </p>
            </div>
          </div>

          {/* Evidence */}
          <div className="rounded-xl p-5" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                SUPPORTING EVIDENCE
              </span>
              <ProvenanceBadge type="simulated" />
            </div>
            <div className="space-y-2">
              {[
                { point: "12 failed authentication attempts in a 17-second window", severity: "high" },
                { point: "4 distinct usernames targeted — consistent with spray pattern", severity: "high" },
                { point: "All attempts originating from single IP: 192.168.1.42", severity: "critical" },
                { point: "Successful login from same source IP immediately following failures", severity: "critical" },
                { point: "Privileged endpoint accessed within 3 seconds of authentication", severity: "critical" },
                { point: "47 user records returned from /api/admin/users — potential data exfil", severity: "high" },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <div
                    className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0"
                    style={{
                      background: item.severity === "critical" ? "#FF4D5E" : "#FF8A4C",
                    }}
                  />
                  <span className="text-sm" style={{ color: "#9AA8B8" }}>
                    {item.point}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div
            className="rounded-xl p-5"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                RECOMMENDED ACTIONS
              </span>
              <ProvenanceBadge type="inferred" />
            </div>
            <div className="space-y-3">
              {[
                {
                  num: "01",
                  title: "Isolate Source IP",
                  desc: "Block 192.168.1.42 at the network perimeter to prevent further attack attempts.",
                  urgency: "IMMEDIATE",
                  urgencyColor: "#FF4D5E",
                },
                {
                  num: "02",
                  title: "Review Affected Account",
                  desc: "Audit all actions taken by the admin account during and after the attack window (10:31–present).",
                  urgency: "HIGH",
                  urgencyColor: "#FF8A4C",
                },
                {
                  num: "03",
                  title: "Rotate Credentials",
                  desc: "Force password reset for admin and all 3 other targeted accounts as a precaution.",
                  urgency: "HIGH",
                  urgencyColor: "#FF8A4C",
                },
                {
                  num: "04",
                  title: "Review Exfiltrated Data",
                  desc: "Assess exposure from /api/admin/users endpoint — 47 records accessed.",
                  urgency: "MEDIUM",
                  urgencyColor: "#F4C95D",
                },
                {
                  num: "05",
                  title: "Enhance Authentication Controls",
                  desc: "Consider rate limiting, MFA enforcement, and geo-fencing on auth-01.",
                  urgency: "PLANNED",
                  urgencyColor: "#56B4FF",
                },
              ].map((rec) => (
                <div
                  key={rec.num}
                  className="flex gap-4 rounded-lg p-3"
                  style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                >
                  <span className="text-xl font-semibold font-mono flex-shrink-0 mt-0.5" style={{ color: "#1D2938" }}>
                    {rec.num}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold" style={{ color: "#F4F7FA" }}>
                        {rec.title}
                      </span>
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded font-semibold"
                        style={{
                          background: rec.urgencyColor + "15",
                          color: rec.urgencyColor,
                        }}
                      >
                        {rec.urgency}
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed" style={{ color: "#9AA8B8" }}>
                      {rec.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          {!dismissed && (
            <div className="flex items-center gap-3">
              <button
                onClick={() => onNavigate("response")}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all"
                style={{ background: "#FF8A4C15", color: "#FF8A4C", border: "1px solid #FF8A4C30" }}
              >
                <span>⚠</span> Simulate Response
              </button>
              <button
                onClick={() => {
                  setAddedToInvestigation(true);
                }}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all"
                style={{
                  background: addedToInvestigation ? "#42D39215" : "#1D2938",
                  color: addedToInvestigation ? "#42D392" : "#9AA8B8",
                  border: `1px solid ${addedToInvestigation ? "#42D39230" : "#1D2938"}`,
                }}
              >
                {addedToInvestigation ? "✓ Added" : "Add to Investigation"}
              </button>
              <button
                onClick={() => setDismissed(true)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all"
                style={{ background: "transparent", color: "#627083" }}
              >
                Dismiss
              </button>
            </div>
          )}

          {dismissed && (
            <div
              className="flex items-center gap-2 p-3 rounded-lg text-sm"
              style={{ background: "#1D2938", color: "#627083" }}
            >
              Analysis dismissed.{" "}
              <button
                onClick={() => setDismissed(false)}
                style={{ color: "#56B4FF" }}
              >
                Undo
              </button>
            </div>
          )}
        </div>

        {/* Incident Context Panel */}
        <div className="col-span-2 space-y-4">
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <span className="text-xs font-semibold tracking-widest uppercase block mb-3" style={{ color: "#627083" }}>
              INCIDENT CONTEXT
            </span>
            <div className="space-y-3">
              {[
                { label: "Incident ID", value: "INC-2026-00842", mono: true },
                { label: "Severity", value: "CRITICAL", mono: false, color: "#FF4D5E" },
                { label: "Status", value: "INVESTIGATING", mono: false },
                { label: "Source IP", value: "192.168.1.42", mono: true },
                { label: "Target", value: "auth-01", mono: true },
                { label: "Account", value: "admin", mono: true },
                { label: "Events", value: "17", mono: false },
                { label: "MITRE", value: "T1110", mono: true, color: "#7C8CFF" },
                { label: "Risk Score", value: "94 / 100", mono: false, color: "#FF4D5E" },
              ].map((item, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between"
                  style={{ borderBottom: i < 8 ? "1px solid #1D293840" : "none", paddingBottom: i < 8 ? "8px" : "0" }}
                >
                  <span className="text-xs" style={{ color: "#627083" }}>
                    {item.label}
                  </span>
                  <span
                    className={`text-xs font-medium ${item.mono ? "font-mono" : ""}`}
                    style={{ color: (item as { color?: string }).color ?? "#F4F7FA" }}
                  >
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE Context */}
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <span className="text-xs font-semibold tracking-widest uppercase block mb-3" style={{ color: "#627083" }}>
              MITRE ATT&CK
            </span>
            <div
              className="rounded-lg p-3 mb-3"
              style={{ background: "#7C8CFF0A", border: "1px solid #7C8CFF25" }}
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-sm font-semibold" style={{ color: "#7C8CFF" }}>
                    T1110
                  </span>
                  <p className="text-sm font-medium mt-0.5" style={{ color: "#F4F7FA" }}>
                    Brute Force
                  </p>
                  <p className="text-xs mt-1" style={{ color: "#9AA8B8" }}>
                    Credential Access
                  </p>
                </div>
                <div className="text-xs font-semibold" style={{ color: "#42D392" }}>
                  91% conf.
                </div>
              </div>
            </div>
            <div
              className="rounded-lg p-2.5"
              style={{ background: "#0D131D", border: "1px solid #1D2938" }}
            >
              <span className="font-mono text-xs" style={{ color: "#7C8CFF" }}>
                T1110.003
              </span>
              <p className="text-xs mt-0.5" style={{ color: "#9AA8B8" }}>
                Password Spraying — Sub-technique
              </p>
            </div>
          </div>

          {/* Related Incidents */}
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <span className="text-xs font-semibold tracking-widest uppercase block mb-3" style={{ color: "#627083" }}>
              RELATED INCIDENTS
            </span>
            {[
              { id: "INC-00838", title: "Lateral Movement — SMB", time: "31m ago", sev: "#FF8A4C" },
              { id: "INC-00835", title: "Privilege Escalation", time: "1h 12m ago", sev: "#FF8A4C" },
            ].map((r) => (
              <div
                key={r.id}
                className="flex items-center gap-2 mb-2 p-2 rounded-lg cursor-pointer"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                onClick={() => onNavigate("incident-investigation")}
              >
                <div className="w-1 h-6 rounded-sm" style={{ background: r.sev }} />
                <div>
                  <p className="text-xs font-medium" style={{ color: "#F4F7FA" }}>
                    {r.title}
                  </p>
                  <p className="text-[10px] font-mono" style={{ color: "#627083" }}>
                    {r.id} · {r.time}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
