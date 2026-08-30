import { useState } from "react";

const attackChain = [
  {
    phase: "Initial Access",
    tactic: "TA0001",
    technique: "T1190",
    name: "Exploit Public-Facing Application",
    status: "confirmed",
    time: "10:28:44",
    confidence: 87,
  },
  {
    phase: "Credential Access",
    tactic: "TA0006",
    technique: "T1110",
    name: "Brute Force",
    status: "confirmed",
    time: "10:31:04",
    confidence: 91,
    subtech: "T1110.003",
    subtechName: "Password Spraying",
  },
  {
    phase: "Discovery",
    tactic: "TA0007",
    technique: "T1046",
    name: "Network Service Discovery",
    status: "confirmed",
    time: "10:31:08",
    confidence: 84,
  },
  {
    phase: "Execution",
    tactic: "TA0002",
    technique: "T1059.001",
    name: "PowerShell",
    status: "suspected",
    time: "10:43:21",
    confidence: 72,
  },
  {
    phase: "Persistence",
    tactic: "TA0003",
    technique: "T1053.005",
    name: "Scheduled Task",
    status: "suspected",
    time: "—",
    confidence: 51,
  },
];

const matrixTechniques = [
  { tactic: "Initial Access", techs: ["T1190", "T1078", "T1566"] },
  { tactic: "Execution", techs: ["T1059.001", "T1053.005", "T1204"] },
  { tactic: "Persistence", techs: ["T1078", "T1543", "T1547"] },
  { tactic: "Privilege Escalation", techs: ["T1068", "T1078", "T1484"] },
  { tactic: "Defense Evasion", techs: ["T1036", "T1070", "T1112"] },
  { tactic: "Credential Access", techs: ["T1110", "T1003", "T1555"] },
  { tactic: "Discovery", techs: ["T1046", "T1018", "T1082"] },
  { tactic: "Lateral Movement", techs: ["T1021.002", "T1080", "T1210"] },
];

const detectedTechs = ["T1190", "T1110", "T1046", "T1059.001"];

export default function MitreAttack() {
  const [selectedStep, setSelectedStep] = useState(attackChain[1]);
  const [showMatrix, setShowMatrix] = useState(false);

  const statusColor = (status: string) =>
    status === "confirmed" ? "#42D392" : status === "suspected" ? "#F4C95D" : "#627083";

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            MITRE ATT&CK
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            Incident INC-2026-00842 — Attack Path Analysis
          </p>
        </div>
        <button
          onClick={() => setShowMatrix(!showMatrix)}
          className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
          style={{
            background: showMatrix ? "#7C8CFF15" : "#1D2938",
            color: showMatrix ? "#7C8CFF" : "#9AA8B8",
            border: showMatrix ? "1px solid #7C8CFF30" : "1px solid #1D2938",
          }}
        >
          {showMatrix ? "Hide Matrix" : "Show ATT&CK Matrix"}
        </button>
      </div>

      <div className="grid grid-cols-5 gap-5">
        {/* Attack Path */}
        <div className="col-span-2 space-y-3">
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <span className="text-xs font-semibold tracking-widest uppercase block mb-4" style={{ color: "#627083" }}>
              INCIDENT ATT&CK PATH
            </span>

            <div className="relative">
              {/* Connection line */}
              <div
                className="absolute left-4 top-6 bottom-4 w-0.5"
                style={{ background: "linear-gradient(to bottom, #42D392, #F4C95D, #627083)" }}
              />

              <div className="space-y-3">
                {attackChain.map((step, i) => (
                  <div
                    key={i}
                    onClick={() => setSelectedStep(step)}
                    className="relative flex items-start gap-3 cursor-pointer group pl-8"
                  >
                    {/* Node */}
                    <div
                      className="absolute left-2 w-4 h-4 rounded-full border-2 flex-shrink-0 transition-all z-10 mt-1"
                      style={{
                        background:
                          selectedStep.technique === step.technique
                            ? statusColor(step.status)
                            : "#0D131D",
                        borderColor: statusColor(step.status),
                        boxShadow:
                          selectedStep.technique === step.technique
                            ? `0 0 8px ${statusColor(step.status)}60`
                            : "none",
                      }}
                    />

                    <div
                      className="flex-1 rounded-lg p-2.5 transition-all"
                      style={{
                        background:
                          selectedStep.technique === step.technique ? "#1A2333" : "#0D131D",
                        border: `1px solid ${
                          selectedStep.technique === step.technique ? statusColor(step.status) + "40" : "#1D2938"
                        }`,
                      }}
                    >
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-[10px]" style={{ color: "#627083" }}>
                          {step.phase}
                        </span>
                        <span
                          className="text-[10px] font-medium"
                          style={{ color: statusColor(step.status) }}
                        >
                          {step.status === "confirmed" ? "● Confirmed" : "◌ Suspected"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold" style={{ color: "#7C8CFF" }}>
                          {step.technique}
                        </span>
                        <span className="text-xs" style={{ color: "#F4F7FA" }}>
                          {step.name}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-[10px] font-mono" style={{ color: "#627083" }}>
                          {step.time !== "—" ? step.time + " UTC" : "Not observed"}
                        </span>
                        <span className="text-[10px]" style={{ color: statusColor(step.status) }}>
                          {step.confidence}%
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Technique Detail */}
        <div className="col-span-3 space-y-4">
          <div
            className="rounded-xl p-5"
            style={{ background: "#111925", border: "1px solid #7C8CFF25" }}
          >
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                TECHNIQUE DETAIL
              </span>
              <span
                className="text-xs font-medium"
                style={{ color: statusColor(selectedStep.status) }}
              >
                {selectedStep.status === "confirmed" ? "● Confirmed" : "◌ Suspected"}
              </span>
            </div>

            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-2xl font-semibold" style={{ color: "#7C8CFF" }}>
                    {selectedStep.technique}
                  </span>
                </div>
                <h2 className="text-lg font-semibold" style={{ color: "#F4F7FA" }}>
                  {selectedStep.name}
                </h2>
                <p className="text-xs mt-0.5" style={{ color: "#9AA8B8" }}>
                  {selectedStep.phase} · {selectedStep.tactic}
                </p>
              </div>
              <div className="text-right">
                <div className="text-2xl font-semibold font-mono" style={{ color: statusColor(selectedStep.status) }}>
                  {selectedStep.confidence}%
                </div>
                <div className="text-[10px]" style={{ color: "#627083" }}>
                  confidence
                </div>
              </div>
            </div>

            {/* Confidence Bar */}
            <div className="mb-4">
              <div className="h-1.5 rounded-full" style={{ background: "#1D2938" }}>
                <div
                  className="h-1.5 rounded-full transition-all"
                  style={{
                    width: `${selectedStep.confidence}%`,
                    background: statusColor(selectedStep.status),
                  }}
                />
              </div>
            </div>

            {selectedStep.subtech && (
              <div
                className="rounded-lg p-3 mb-4"
                style={{ background: "#7C8CFF0A", border: "1px solid #7C8CFF25" }}
              >
                <span className="text-[10px] font-semibold uppercase tracking-wider block mb-1" style={{ color: "#627083" }}>
                  SUB-TECHNIQUE
                </span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-semibold" style={{ color: "#7C8CFF" }}>
                    {selectedStep.subtech}
                  </span>
                  <span className="text-sm" style={{ color: "#F4F7FA" }}>
                    {selectedStep.subtechName}
                  </span>
                </div>
              </div>
            )}

            {/* Evidence for this technique */}
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider block mb-2" style={{ color: "#627083" }}>
                EVIDENCE
              </span>
              <div className="space-y-2">
                {selectedStep.technique === "T1110" && [
                  "12 failed authentication attempts from 192.168.1.42",
                  "4 distinct usernames targeted (admin, root, svc_backup, administrator)",
                  "All attempts within 17-second window",
                  "Password spray pattern — low frequency per account",
                ].map((ev, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: "#42D392" }} />
                    <span className="text-sm" style={{ color: "#9AA8B8" }}>{ev}</span>
                  </div>
                ))}
                {selectedStep.technique !== "T1110" && (
                  <div
                    className="rounded-lg p-3"
                    style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                  >
                    <p className="text-sm" style={{ color: "#627083" }}>
                      {selectedStep.status === "suspected"
                        ? "Technique suspected based on behavioral indicators. Additional evidence collection in progress."
                        : "Evidence collected. Detection confidence: " + selectedStep.confidence + "%"}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Phase Progress */}
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <span className="text-xs font-semibold tracking-widest uppercase block mb-3" style={{ color: "#627083" }}>
              KILL CHAIN PROGRESS
            </span>
            <div className="flex items-center gap-1">
              {attackChain.map((step, i) => (
                <div key={i} className="flex-1 group">
                  <div
                    className="h-1.5 rounded transition-all"
                    style={{
                      background: step.status === "confirmed"
                        ? statusColor(step.status)
                        : step.status === "suspected"
                        ? statusColor(step.status) + "60"
                        : "#1D2938",
                    }}
                  />
                  <div className="text-[9px] mt-1 text-center truncate" style={{ color: "#627083" }}>
                    {step.phase.split(" ")[0]}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Matrix Panel */}
      {showMatrix && (
        <div className="rounded-xl p-5" style={{ background: "#111925", border: "1px solid #1D2938" }}>
          <span className="text-xs font-semibold tracking-widest uppercase block mb-4" style={{ color: "#627083" }}>
            ATT&CK MATRIX — ENTERPRISE (PARTIAL)
          </span>
          <div className="overflow-x-auto">
            <div className="flex gap-2 min-w-max">
              {matrixTechniques.map((col) => (
                <div key={col.tactic} className="w-36">
                  <div
                    className="text-[10px] font-semibold uppercase tracking-wider mb-2 px-1"
                    style={{ color: "#627083" }}
                  >
                    {col.tactic}
                  </div>
                  <div className="space-y-1">
                    {col.techs.map((tech) => {
                      const isDetected = detectedTechs.includes(tech);
                      return (
                        <div
                          key={tech}
                          className="px-2 py-1 rounded text-[10px] font-mono cursor-pointer transition-all"
                          style={{
                            background: isDetected ? "#FF4D5E20" : "#0D131D",
                            color: isDetected ? "#FF4D5E" : "#627083",
                            border: `1px solid ${isDetected ? "#FF4D5E40" : "#1D2938"}`,
                          }}
                        >
                          {tech}
                          {isDetected && <span className="ml-1">●</span>}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <p className="text-xs mt-3" style={{ color: "#627083" }}>
            ● Techniques detected in INC-2026-00842
          </p>
        </div>
      )}
    </div>
  );
}
