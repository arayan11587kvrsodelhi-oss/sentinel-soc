import { useState } from "react";

const sevColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
};

const statusConfig: Record<string, { color: string; bg: string }> = {
  INVESTIGATING: { color: "#FF4D5E", bg: "#FF4D5E15" },
  NEW: { color: "#FF8A4C", bg: "#FF8A4C15" },
  REVIEW: { color: "#56B4FF", bg: "#56B4FF15" },
  RESOLVED: { color: "#42D392", bg: "#42D39215" },
  CLOSED: { color: "#627083", bg: "#62708315" },
};

const incidents = [
  { id: "INC-00842", severity: "CRITICAL", title: "Credential Attack", source: "auth-01", technique: "T1110", risk: 94, status: "INVESTIGATING", time: "2m" },
  { id: "INC-00841", severity: "HIGH", title: "Suspicious PowerShell Execution", source: "host-04", technique: "T1059.001", risk: 81, status: "NEW", time: "8m" },
  { id: "INC-00840", severity: "MEDIUM", title: "Network Scan Detected", source: "fw-02", technique: "T1046", risk: 57, status: "REVIEW", time: "14m" },
  { id: "INC-00839", severity: "LOW", title: "DNS Enumeration Activity", source: "dns-01", technique: "T1018", risk: 32, status: "REVIEW", time: "22m" },
  { id: "INC-00838", severity: "HIGH", title: "Lateral Movement — SMB", source: "host-07", technique: "T1021.002", risk: 78, status: "INVESTIGATING", time: "31m" },
  { id: "INC-00837", severity: "MEDIUM", title: "Scheduled Task Creation", source: "host-02", technique: "T1053.005", risk: 52, status: "REVIEW", time: "45m" },
  { id: "INC-00836", severity: "CRITICAL", title: "Data Exfiltration Attempt", source: "proxy-01", technique: "T1048", risk: 96, status: "INVESTIGATING", time: "58m" },
  { id: "INC-00835", severity: "HIGH", title: "Privilege Escalation", source: "host-03", technique: "T1068", risk: 83, status: "INVESTIGATING", time: "1h 12m" },
  { id: "INC-00834", severity: "MEDIUM", title: "Registry Modification", source: "host-09", technique: "T1112", risk: 48, status: "REVIEW", time: "1h 34m" },
  { id: "INC-00833", severity: "LOW", title: "Unusual Process Spawn", source: "host-11", technique: "T1036", risk: 28, status: "REVIEW", time: "2h 05m" },
  { id: "INC-00832", severity: "HIGH", title: "Credential Dumping", source: "host-06", technique: "T1003", risk: 87, status: "REVIEW", time: "2h 41m" },
  { id: "INC-00831", severity: "MEDIUM", title: "Suspicious Outbound Connection", source: "host-14", technique: "T1071", risk: 61, status: "RESOLVED", time: "3h 18m" },
];

interface IncidentsProps {
  onNavigate: (screen: string) => void;
}

export default function Incidents({ onNavigate }: IncidentsProps) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const filtered = incidents.filter((inc) => {
    const matchSearch =
      !search ||
      inc.title.toLowerCase().includes(search.toLowerCase()) ||
      inc.id.toLowerCase().includes(search.toLowerCase()) ||
      inc.technique.toLowerCase().includes(search.toLowerCase());
    const matchSev = sevFilter === "ALL" || inc.severity === sevFilter;
    const matchStatus = statusFilter === "ALL" || inc.status === statusFilter;
    return matchSearch && matchSev && matchStatus;
  });

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Incidents
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            {filtered.length} active investigations
          </p>
        </div>
        <button
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all"
          style={{ background: "#56B4FF15", color: "#56B4FF", border: "1px solid #56B4FF30" }}
        >
          <span>+</span> New Incident
        </button>
      </div>

      {/* Filters */}
      <div
        className="flex items-center gap-3 p-3 rounded-xl"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <div className="relative flex-1 max-w-sm">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5"
            style={{ color: "#627083" }}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search incidents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg text-sm outline-none transition-all"
            style={{
              background: "#111925",
              border: "1px solid #1D2938",
              color: "#F4F7FA",
            }}
          />
        </div>

        <div className="flex items-center gap-2 ml-2">
          <span className="text-xs" style={{ color: "#627083" }}>
            Severity:
          </span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
            <button
              key={s}
              onClick={() => setSevFilter(s)}
              className="px-2.5 py-1 rounded-md text-xs font-medium transition-all"
              style={{
                background:
                  sevFilter === s
                    ? s === "ALL"
                      ? "#1D2938"
                      : sevColor[s] + "20"
                    : "transparent",
                color:
                  sevFilter === s
                    ? s === "ALL"
                      ? "#F4F7FA"
                      : sevColor[s]
                    : "#627083",
                border: sevFilter === s ? `1px solid ${s === "ALL" ? "#1D2938" : sevColor[s] + "40"}` : "1px solid transparent",
              }}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs" style={{ color: "#627083" }}>
            Status:
          </span>
          {["ALL", "NEW", "INVESTIGATING", "REVIEW", "RESOLVED"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className="px-2.5 py-1 rounded-md text-xs font-medium transition-all"
              style={{
                background: statusFilter === s ? "#1D2938" : "transparent",
                color: statusFilter === s ? "#F4F7FA" : "#627083",
                border: statusFilter === s ? "1px solid #1D2938" : "1px solid transparent",
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: "1px solid #1D2938" }}>
        <table className="w-full">
          <thead>
            <tr style={{ background: "#0D131D", borderBottom: "1px solid #1D2938" }}>
              {["SEVERITY", "INCIDENT", "SOURCE", "MITRE", "RISK", "STATUS", "TIME"].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase"
                  style={{ color: "#627083" }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((inc, i) => (
              <tr
                key={inc.id}
                className="cursor-pointer transition-all group"
                style={{
                  background: i % 2 === 0 ? "#111925" : "#0F1720",
                  borderBottom: "1px solid #1D293840",
                }}
                onClick={() => onNavigate("incident-investigation")}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "#1D293830";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? "#111925" : "#0F1720";
                }}
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-1.5 h-5 rounded-sm"
                      style={{ background: sevColor[inc.severity] }}
                    />
                    <span
                      className="text-xs font-semibold"
                      style={{ color: sevColor[inc.severity] }}
                    >
                      {inc.severity}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div>
                    <div className="text-sm font-medium" style={{ color: "#F4F7FA" }}>
                      {inc.title}
                    </div>
                    <div className="text-[11px] font-mono mt-0.5" style={{ color: "#627083" }}>
                      {inc.id}
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm font-mono" style={{ color: "#9AA8B8" }}>
                    {inc.source}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span
                    className="text-xs font-mono px-1.5 py-0.5 rounded"
                    style={{ background: "#7C8CFF15", color: "#7C8CFF", border: "1px solid #7C8CFF20" }}
                  >
                    {inc.technique}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1 rounded-full" style={{ background: "#1D2938" }}>
                      <div
                        className="h-1 rounded-full"
                        style={{
                          width: `${inc.risk}%`,
                          background:
                            inc.risk >= 80
                              ? "#FF4D5E"
                              : inc.risk >= 60
                              ? "#FF8A4C"
                              : inc.risk >= 40
                              ? "#F4C95D"
                              : "#56B4FF",
                        }}
                      />
                    </div>
                    <span className="text-sm font-semibold tabular-nums" style={{ color: "#F4F7FA" }}>
                      {inc.risk}
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
                  <span className="text-sm" style={{ color: "#627083" }}>
                    {inc.time}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="py-16 text-center" style={{ background: "#111925" }}>
            <p style={{ color: "#627083" }}>No incidents match current filters</p>
          </div>
        )}

        {/* Pagination */}
        <div
          className="flex items-center justify-between px-4 py-2.5"
          style={{ background: "#0D131D", borderTop: "1px solid #1D2938" }}
        >
          <span className="text-xs" style={{ color: "#627083" }}>
            Showing {filtered.length} of {incidents.length} incidents
          </span>
          <div className="flex items-center gap-1">
            {[1, 2, 3].map((p) => (
              <button
                key={p}
                className="w-7 h-7 rounded text-xs font-medium"
                style={{
                  background: p === 1 ? "#1D2938" : "transparent",
                  color: p === 1 ? "#F4F7FA" : "#627083",
                }}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
