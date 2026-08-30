import { useState } from "react";

const vulns = [
  { cve: "CVE-2026-11234", cvss: 9.8, kev: true, asset: "API-01", risk: "CRITICAL", status: "OPEN", vendor: "Apache", product: "HTTP Server" },
  { cve: "CVE-2026-10891", cvss: 9.1, kev: true, asset: "DC-01", risk: "CRITICAL", status: "OPEN", vendor: "Microsoft", product: "Windows Server" },
  { cve: "CVE-2026-08774", cvss: 8.1, kev: true, asset: "VMWARE-01", risk: "CRITICAL", status: "IN_PROGRESS", vendor: "VMware", product: "vCenter" },
  { cve: "CVE-2026-09234", cvss: 8.6, kev: false, asset: "WEB-03", risk: "HIGH", status: "OPEN", vendor: "OpenSSL", product: "OpenSSL 3.x" },
  { cve: "CVE-2026-07441", cvss: 7.8, kev: false, asset: "DB-01", risk: "HIGH", status: "IN_PROGRESS", vendor: "Linux", product: "Kernel 6.x" },
  { cve: "CVE-2026-07102", cvss: 7.5, kev: false, asset: "HOST-04", risk: "HIGH", status: "OPEN", vendor: "Python", product: "Python 3.12" },
  { cve: "CVE-2026-06218", cvss: 7.5, kev: false, asset: "WEB-01", risk: "HIGH", status: "OPEN", vendor: "NGINX", product: "nginx 1.25" },
  { cve: "CVE-2026-05884", cvss: 6.8, kev: false, asset: "DB-02", risk: "MEDIUM", status: "OPEN", vendor: "PostgreSQL", product: "PostgreSQL 16" },
  { cve: "CVE-2026-04901", cvss: 6.4, kev: false, asset: "HOST-09", risk: "MEDIUM", status: "ACCEPTED", vendor: "curl", product: "curl 8.x" },
  { cve: "CVE-2026-04217", cvss: 5.9, kev: false, asset: "API-02", risk: "MEDIUM", status: "IN_PROGRESS", vendor: "Express.js", product: "Express 4.x" },
  { cve: "CVE-2026-03512", cvss: 4.3, kev: false, asset: "WEB-02", risk: "LOW", status: "OPEN", vendor: "jQuery", product: "jQuery 3.x" },
  { cve: "CVE-2026-02881", cvss: 3.7, kev: false, asset: "HOST-11", risk: "LOW", status: "ACCEPTED", vendor: "OpenSSH", product: "OpenSSH 9.x" },
];

const riskColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH: "#FF8A4C",
  MEDIUM: "#F4C95D",
  LOW: "#56B4FF",
};

const statusConfig: Record<string, { color: string; label: string }> = {
  OPEN: { color: "#FF4D5E", label: "OPEN" },
  IN_PROGRESS: { color: "#FF8A4C", label: "IN PROGRESS" },
  ACCEPTED: { color: "#627083", label: "ACCEPTED" },
  RESOLVED: { color: "#42D392", label: "RESOLVED" },
};

export default function Vulnerabilities() {
  const [sortField, setSortField] = useState<"cvss" | "risk">("cvss");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [kevOnly, setKevOnly] = useState(false);

  const handleSort = (field: "cvss" | "risk") => {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const sorted = [...vulns]
    .filter((v) => {
      if (riskFilter !== "ALL" && v.risk !== riskFilter) return false;
      if (kevOnly && !v.kev) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortField === "cvss") {
        return sortDir === "desc" ? b.cvss - a.cvss : a.cvss - b.cvss;
      }
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const ai = order.indexOf(a.risk);
      const bi = order.indexOf(b.risk);
      return sortDir === "desc" ? ai - bi : bi - ai;
    });

  const critCount = vulns.filter((v) => v.risk === "CRITICAL").length;
  const kevCount = vulns.filter((v) => v.kev).length;

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Vulnerabilities
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            {vulns.length} vulnerabilities tracked across {new Set(vulns.map((v) => v.asset)).size} assets
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "TOTAL", value: vulns.length, color: "#F4F7FA" },
          { label: "CRITICAL", value: critCount, color: "#FF4D5E" },
          { label: "KEV", value: kevCount, color: "#FF8A4C", sub: "Known Exploited" },
          { label: "IN PROGRESS", value: vulns.filter((v) => v.status === "IN_PROGRESS").length, color: "#F4C95D" },
        ].map((card) => (
          <div key={card.label} className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: "#627083" }}>
              {card.label}
            </div>
            <div className="text-2xl font-semibold font-mono tabular-nums" style={{ color: card.color }}>
              {card.value}
            </div>
            {(card as { sub?: string }).sub && (
              <div className="text-xs mt-1" style={{ color: "#627083" }}>
                {(card as { sub?: string }).sub}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Filters */}
      <div
        className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <span className="text-xs" style={{ color: "#627083" }}>
          Risk:
        </span>
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((r) => (
          <button
            key={r}
            onClick={() => setRiskFilter(r)}
            className="px-2.5 py-1 rounded text-xs font-medium transition-all"
            style={{
              background:
                riskFilter === r
                  ? r === "ALL"
                    ? "#1D2938"
                    : riskColor[r] + "20"
                  : "transparent",
              color: riskFilter === r ? (r === "ALL" ? "#F4F7FA" : riskColor[r]) : "#627083",
            }}
          >
            {r}
          </button>
        ))}

        <div className="w-px h-4" style={{ background: "#1D2938" }} />

        <button
          onClick={() => setKevOnly(!kevOnly)}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all"
          style={{
            background: kevOnly ? "#FF4D5E15" : "transparent",
            color: kevOnly ? "#FF4D5E" : "#627083",
          }}
        >
          KEV Only
        </button>

        <span className="ml-auto text-xs" style={{ color: "#627083" }}>
          {sorted.length} results
        </span>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: "1px solid #1D2938" }}>
        <table className="w-full">
          <thead>
            <tr style={{ background: "#0D131D", borderBottom: "1px solid #1D2938" }}>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                CVE
              </th>
              <th
                className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase cursor-pointer select-none"
                style={{ color: sortField === "cvss" ? "#F4F7FA" : "#627083" }}
                onClick={() => handleSort("cvss")}
              >
                CVSS {sortField === "cvss" ? (sortDir === "desc" ? "↓" : "↑") : ""}
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                KEV
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                ASSET
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                PRODUCT
              </th>
              <th
                className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase cursor-pointer select-none"
                style={{ color: sortField === "risk" ? "#F4F7FA" : "#627083" }}
                onClick={() => handleSort("risk")}
              >
                RISK {sortField === "risk" ? (sortDir === "desc" ? "↓" : "↑") : ""}
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                STATUS
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((v, i) => (
              <tr
                key={v.cve}
                className="transition-all cursor-pointer"
                style={{
                  background: i % 2 === 0 ? "#111925" : "#0F1720",
                  borderBottom: "1px solid #1D293840",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.background = "#1D293830";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? "#111925" : "#0F1720";
                }}
              >
                <td className="px-4 py-3">
                  <span className="font-mono text-sm font-medium" style={{ color: "#F4F7FA" }}>
                    {v.cve}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-1 rounded-full" style={{ background: "#1D2938" }}>
                      <div
                        className="h-1 rounded-full"
                        style={{ width: `${(v.cvss / 10) * 100}%`, background: riskColor[v.risk] }}
                      />
                    </div>
                    <span className="font-mono text-sm font-semibold" style={{ color: riskColor[v.risk] }}>
                      {v.cvss}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  {v.kev ? (
                    <span
                      className="text-[10px] px-1.5 py-0.5 rounded font-semibold"
                      style={{ background: "#FF4D5E20", color: "#FF4D5E" }}
                    >
                      YES
                    </span>
                  ) : (
                    <span className="text-[10px]" style={{ color: "#627083" }}>
                      —
                    </span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-sm" style={{ color: "#9AA8B8" }}>
                    {v.asset}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div>
                    <div className="text-xs" style={{ color: "#9AA8B8" }}>
                      {v.product}
                    </div>
                    <div className="text-[10px]" style={{ color: "#627083" }}>
                      {v.vendor}
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <div
                      className="w-1.5 h-5 rounded-sm"
                      style={{ background: riskColor[v.risk] }}
                    />
                    <span className="text-xs font-semibold" style={{ color: riskColor[v.risk] }}>
                      {v.risk}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className="text-[11px] font-medium px-2 py-0.5 rounded"
                    style={{
                      color: statusConfig[v.status].color,
                      background: statusConfig[v.status].color + "15",
                    }}
                  >
                    {statusConfig[v.status].label}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div
          className="flex items-center justify-between px-4 py-2.5"
          style={{ background: "#0D131D", borderTop: "1px solid #1D2938" }}
        >
          <span className="text-xs" style={{ color: "#627083" }}>
            {sorted.length} vulnerabilities shown
          </span>
          <span className="text-xs" style={{ color: "#627083" }}>
            Source: CISA KEV + NIST NVD · Last updated 18:42 UTC
          </span>
        </div>
      </div>
    </div>
  );
}
