import { useState } from "react";

const rules = [
  {
    id: "BRUTE_FORCE_CHAIN_v2",
    category: "Authentication",
    enabled: true,
    matches: 24,
    incidents: 6,
    precision: 91,
    severity: "HIGH",
    mitre: "T1110",
    description: "Detects credential brute force and password spray attacks with successful login correlation",
    conditions: [
      { type: "WHEN", field: "failed_login", op: ">", value: "10" },
      { type: "AND", field: "unique_users", op: ">=", value: "3" },
      { type: "AND", field: "window", op: "<=", value: "90 seconds" },
      { type: "AND", field: "successful_login", op: "=", value: "true" },
    ],
    outputs: [
      { key: "severity", value: "HIGH" },
      { key: "mitre", value: "T1110" },
      { key: "confidence_boost", value: "+15%" },
    ],
  },
  {
    id: "POWERSHELL_EXEC_CHAIN",
    category: "Execution",
    enabled: true,
    matches: 11,
    incidents: 3,
    precision: 84,
    severity: "HIGH",
    mitre: "T1059.001",
    description: "Detects suspicious PowerShell execution with encoded commands or unusual parent processes",
    conditions: [
      { type: "WHEN", field: "process_name", op: "=", value: "powershell.exe" },
      { type: "AND", field: "encoded_command", op: "=", value: "true" },
      { type: "OR", field: "parent_process", op: "NOT IN", value: "explorer, cmd, svchost" },
    ],
    outputs: [
      { key: "severity", value: "HIGH" },
      { key: "mitre", value: "T1059.001" },
    ],
  },
  {
    id: "NETWORK_SCAN_DETECT",
    category: "Discovery",
    enabled: true,
    matches: 38,
    incidents: 9,
    precision: 78,
    severity: "MEDIUM",
    mitre: "T1046",
    description: "Detects port scanning and network discovery activity from internal sources",
    conditions: [
      { type: "WHEN", field: "dest_ports_unique", op: ">", value: "50" },
      { type: "AND", field: "window", op: "<=", value: "60 seconds" },
      { type: "AND", field: "src_internal", op: "=", value: "true" },
    ],
    outputs: [
      { key: "severity", value: "MEDIUM" },
      { key: "mitre", value: "T1046" },
    ],
  },
  {
    id: "LATERAL_MOVE_SMB",
    category: "Lateral Movement",
    enabled: true,
    matches: 7,
    incidents: 2,
    precision: 88,
    severity: "HIGH",
    mitre: "T1021.002",
    description: "Identifies lateral movement via SMB and administrative shares",
    conditions: [
      { type: "WHEN", field: "protocol", op: "=", value: "SMB" },
      { type: "AND", field: "path", op: "CONTAINS", value: "ADMIN$ or C$" },
      { type: "AND", field: "new_connection", op: "=", value: "true" },
    ],
    outputs: [
      { key: "severity", value: "HIGH" },
      { key: "mitre", value: "T1021.002" },
    ],
  },
  {
    id: "DATA_EXFIL_OUTBOUND",
    category: "Exfiltration",
    enabled: false,
    matches: 2,
    incidents: 1,
    precision: 72,
    severity: "CRITICAL",
    mitre: "T1048",
    description: "Detects large outbound data transfers to external destinations",
    conditions: [
      { type: "WHEN", field: "bytes_out", op: ">", value: "100MB" },
      { type: "AND", field: "dest_external", op: "=", value: "true" },
      { type: "AND", field: "window", op: "<=", value: "300 seconds" },
    ],
    outputs: [
      { key: "severity", value: "CRITICAL" },
      { key: "mitre", value: "T1048" },
    ],
  },
];

const sevColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
};

const condTypeColor: Record<string, string> = {
  WHEN: "#7C8CFF",
  AND: "#56B4FF",
  OR: "#F4C95D",
};

export default function DetectionRules() {
  const [selectedRule, setSelectedRule] = useState(rules[0]);
  const [enabledStates, setEnabledStates] = useState<Record<string, boolean>>(
    Object.fromEntries(rules.map((r) => [r.id, r.enabled]))
  );

  const toggleRule = (id: string) => {
    setEnabledStates((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Detection Rules
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            {rules.filter((r) => enabledStates[r.id]).length} active rules
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium"
          style={{ background: "#56B4FF15", color: "#56B4FF", border: "1px solid #56B4FF30" }}
        >
          + Create Rule
        </button>
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* Rules List */}
        <div className="col-span-2 space-y-2">
          {rules.map((rule) => (
            <div
              key={rule.id}
              onClick={() => setSelectedRule(rule)}
              className="rounded-xl p-4 cursor-pointer transition-all"
              style={{
                background: selectedRule.id === rule.id ? "#1A2333" : "#111925",
                border: `1px solid ${selectedRule.id === rule.id ? "#56B4FF40" : "#1D2938"}`,
              }}
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span
                    className="font-mono text-xs font-semibold"
                    style={{ color: selectedRule.id === rule.id ? "#56B4FF" : "#9AA8B8" }}
                  >
                    {rule.id}
                  </span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <span
                      className="text-[10px] px-1.5 py-0 rounded"
                      style={{
                        background: sevColor[rule.severity] + "15",
                        color: sevColor[rule.severity],
                      }}
                    >
                      {rule.severity}
                    </span>
                    <span className="text-[10px]" style={{ color: "#627083" }}>
                      {rule.category}
                    </span>
                  </div>
                </div>
                {/* Toggle */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleRule(rule.id);
                  }}
                  className="relative flex-shrink-0 w-9 h-5 rounded-full transition-all"
                  style={{
                    background: enabledStates[rule.id] ? "#42D39240" : "#1D2938",
                    border: `1px solid ${enabledStates[rule.id] ? "#42D39260" : "#1D2938"}`,
                  }}
                >
                  <div
                    className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
                    style={{
                      background: enabledStates[rule.id] ? "#42D392" : "#627083",
                      left: enabledStates[rule.id] ? "calc(100% - 18px)" : "2px",
                    }}
                  />
                </button>
              </div>

              <div className="flex items-center gap-3 mt-2 pt-2" style={{ borderTop: "1px solid #1D293840" }}>
                <div className="text-center">
                  <div className="text-base font-semibold tabular-nums" style={{ color: "#F4F7FA" }}>
                    {rule.matches}
                  </div>
                  <div className="text-[10px]" style={{ color: "#627083" }}>
                    matches
                  </div>
                </div>
                <div className="w-px h-6" style={{ background: "#1D2938" }} />
                <div className="text-center">
                  <div className="text-base font-semibold tabular-nums" style={{ color: "#F4F7FA" }}>
                    {rule.incidents}
                  </div>
                  <div className="text-[10px]" style={{ color: "#627083" }}>
                    incidents
                  </div>
                </div>
                <div className="w-px h-6" style={{ background: "#1D2938" }} />
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-0.5">
                    <div className="text-[10px]" style={{ color: "#627083" }}>precision</div>
                    <div className="text-xs font-semibold tabular-nums" style={{ color: rule.precision >= 80 ? "#42D392" : rule.precision >= 65 ? "#F4C95D" : "#FF8A4C" }}>
                      {rule.precision}%
                    </div>
                  </div>
                  <div className="h-1 rounded-full overflow-hidden" style={{ background: "#1D2938" }}>
                    <div
                      className="h-1 rounded-full"
                      style={{
                        width: `${rule.precision}%`,
                        background: rule.precision >= 80 ? "#42D392" : rule.precision >= 65 ? "#F4C95D" : "#FF8A4C",
                        opacity: 0.7,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Rule Detail */}
        <div className="col-span-3 space-y-4">
          <div className="rounded-xl p-5" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-semibold" style={{ color: "#7C8CFF" }}>
                    {selectedRule.id}
                  </span>
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                    style={{
                      background: enabledStates[selectedRule.id] ? "#42D39215" : "#1D2938",
                      color: enabledStates[selectedRule.id] ? "#42D392" : "#627083",
                    }}
                  >
                    {enabledStates[selectedRule.id] ? "● ENABLED" : "○ DISABLED"}
                  </span>
                </div>
                <p className="text-sm mt-1" style={{ color: "#9AA8B8" }}>
                  {selectedRule.description}
                </p>
              </div>
            </div>

            {/* Stats row */}
            <div className="flex gap-6 mb-5 pb-4" style={{ borderBottom: "1px solid #1D2938" }}>
              {[
                { label: "Category", value: selectedRule.category, mono: false },
                { label: "MITRE", value: selectedRule.mitre, mono: true, color: "#7C8CFF" },
                { label: "Matches", value: String(selectedRule.matches), mono: false },
                { label: "Precision", value: `${selectedRule.precision}%`, mono: false, color: "#42D392" },
                { label: "Severity", value: selectedRule.severity, mono: false, color: sevColor[selectedRule.severity] },
              ].map((s) => (
                <div key={s.label}>
                  <div className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: "#627083" }}>
                    {s.label}
                  </div>
                  <div
                    className={`text-sm font-semibold ${s.mono ? "font-mono" : ""}`}
                    style={{ color: (s as { color?: string }).color ?? "#F4F7FA" }}
                  >
                    {s.value}
                  </div>
                </div>
              ))}
            </div>

            {/* Rule Logic */}
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-widest block mb-3" style={{ color: "#627083" }}>
                RULE LOGIC
              </span>
              <div className="space-y-2">
                {selectedRule.conditions.map((cond, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span
                      className="w-12 text-center text-xs font-mono font-semibold px-1.5 py-1 rounded flex-shrink-0"
                      style={{
                        background: condTypeColor[cond.type] + "15",
                        color: condTypeColor[cond.type],
                      }}
                    >
                      {cond.type}
                    </span>
                    <div
                      className="flex-1 flex items-center gap-2 px-3 py-2 rounded-lg"
                      style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                    >
                      <span className="font-mono text-sm" style={{ color: "#9AA8B8" }}>
                        {cond.field}
                      </span>
                      <span className="font-mono text-xs font-semibold" style={{ color: "#627083" }}>
                        {cond.op}
                      </span>
                      <span className="font-mono text-sm font-semibold" style={{ color: "#F4C95D" }}>
                        {cond.value}
                      </span>
                    </div>
                  </div>
                ))}

                {/* THEN */}
                <div className="mt-2 pt-2" style={{ borderTop: "1px solid #1D2938" }}>
                  <div className="flex items-start gap-2">
                    <span
                      className="w-12 text-center text-xs font-mono font-semibold px-1.5 py-1 rounded flex-shrink-0"
                      style={{ background: "#42D39215", color: "#42D392" }}
                    >
                      THEN
                    </span>
                    <div className="flex-1 space-y-1.5">
                      {selectedRule.outputs.map((out, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 px-3 py-2 rounded-lg"
                          style={{ background: "#0D131D", border: "1px solid #1D293870" }}
                        >
                          <span className="font-mono text-sm" style={{ color: "#9AA8B8" }}>
                            {out.key}
                          </span>
                          <span className="font-mono text-xs" style={{ color: "#627083" }}>
                            =
                          </span>
                          <span className="font-mono text-sm font-semibold" style={{ color: "#42D392" }}>
                            {out.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Precision Trend */}
          <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                PRECISION TREND
              </span>
              <span className="text-xs font-semibold" style={{ color: "#42D392" }}>
                {selectedRule.precision}% last 7 days
              </span>
            </div>
            <div className="h-1.5 rounded-full" style={{ background: "#1D2938" }}>
              <div
                className="h-1.5 rounded-full transition-all"
                style={{
                  width: `${selectedRule.precision}%`,
                  background: selectedRule.precision >= 80 ? "#42D392" : selectedRule.precision >= 60 ? "#F4C95D" : "#FF4D5E",
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
