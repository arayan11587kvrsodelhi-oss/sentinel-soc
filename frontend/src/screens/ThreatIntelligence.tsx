import { useState } from "react";
import { ProvenanceBadge } from "../components/ProvenanceBadge";

const cveData = [
  {
    id: "CVE-2026-11234",
    cvss: 9.8,
    kev: true,
    vendor: "Apache",
    product: "HTTP Server",
    description: "Remote code execution via path traversal in mod_proxy module",
    published: "2026-08-12",
    affected: ["api-01", "web-01"],
    category: "RCE",
  },
  {
    id: "CVE-2026-10891",
    cvss: 9.1,
    kev: true,
    vendor: "Microsoft",
    product: "Windows Server",
    description: "Privilege escalation through Windows kernel driver vulnerability",
    published: "2026-08-18",
    affected: ["host-04", "dc-01"],
    category: "Privilege Escalation",
  },
  {
    id: "CVE-2026-09234",
    cvss: 8.6,
    kev: false,
    vendor: "OpenSSL",
    product: "OpenSSL 3.x",
    description: "Buffer overflow in TLS handshake processing",
    published: "2026-08-20",
    affected: ["web-03", "api-02"],
    category: "Buffer Overflow",
  },
  {
    id: "CVE-2026-08774",
    cvss: 8.1,
    kev: true,
    vendor: "VMware",
    product: "vCenter Server",
    description: "Authentication bypass via improper session validation",
    published: "2026-08-22",
    affected: ["vmware-01"],
    category: "Auth Bypass",
  },
  {
    id: "CVE-2026-07441",
    cvss: 7.8,
    kev: false,
    vendor: "Linux",
    product: "Kernel 6.x",
    description: "Local privilege escalation via use-after-free in netfilter",
    published: "2026-08-24",
    affected: ["db-01", "host-09"],
    category: "Privilege Escalation",
  },
  {
    id: "CVE-2026-06218",
    cvss: 7.5,
    kev: false,
    vendor: "NGINX",
    product: "nginx 1.25",
    description: "Denial of service via crafted HTTP/3 QUIC packets",
    published: "2026-08-26",
    affected: ["web-01"],
    category: "DoS",
  },
];

const sources = [
  {
    name: "CISA KEV",
    status: "CONNECTED",
    description: "Known Exploited Vulnerabilities Catalog",
    lastSync: "18:42 UTC",
    count: 3,
    provenance: "live" as const,
  },
  {
    name: "NIST NVD",
    status: "CONNECTED",
    description: "National Vulnerability Database",
    lastSync: "18:40 UTC",
    count: 6,
    provenance: "live" as const,
  },
  {
    name: "MISP Feed",
    status: "CONNECTED",
    description: "Threat intelligence sharing platform",
    lastSync: "18:35 UTC",
    count: 12,
    provenance: "live" as const,
  },
];

const cvssColor = (score: number) =>
  score >= 9 ? "#FF4D5E" : score >= 7 ? "#FF8A4C" : score >= 4 ? "#F4C95D" : "#56B4FF";

export default function ThreatIntelligence() {
  const [cvssFilter, setCvssFilter] = useState(0);
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedCve, setSelectedCve] = useState<(typeof cveData)[0] | null>(null);

  const filtered = cveData.filter((c) => {
    if (kevOnly && !c.kev) return false;
    if (c.cvss < cvssFilter) return false;
    return true;
  });

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Threat Intelligence
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            Live threat feeds and vulnerability intelligence
          </p>
        </div>
        <ProvenanceBadge type="live" />
      </div>

      {/* Source Cards */}
      <div className="grid grid-cols-3 gap-4">
        {sources.map((src) => (
          <div key={src.name} className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #1D2938" }}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold" style={{ color: "#F4F7FA" }}>
                  {src.name}
                </h3>
                <p className="text-xs mt-0.5" style={{ color: "#9AA8B8" }}>
                  {src.description}
                </p>
              </div>
              <ProvenanceBadge type={src.provenance} />
            </div>
            <div className="flex items-center justify-between mt-3 pt-2" style={{ borderTop: "1px solid #1D2938" }}>
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-[#42D392]" />
                <span className="text-xs font-medium" style={{ color: "#42D392" }}>
                  {src.status}
                </span>
              </div>
              <div className="text-right">
                <div className="text-sm font-semibold tabular-nums" style={{ color: "#F4F7FA" }}>
                  {src.count}
                </div>
                <div className="text-[10px]" style={{ color: "#627083" }}>
                  new today
                </div>
              </div>
            </div>
            <div className="text-[10px] mt-1" style={{ color: "#627083" }}>
              Last sync: {src.lastSync}
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div
        className="flex items-center gap-4 px-3 py-2.5 rounded-lg"
        style={{ background: "#0D131D", border: "1px solid #1D2938" }}
      >
        <span className="text-xs" style={{ color: "#627083" }}>
          CVSS ≥
        </span>
        {[0, 7, 8, 9].map((v) => (
          <button
            key={v}
            onClick={() => setCvssFilter(v)}
            className="px-2.5 py-1 rounded text-xs font-medium transition-all"
            style={{
              background: cvssFilter === v ? "#1D2938" : "transparent",
              color: cvssFilter === v ? "#F4F7FA" : "#627083",
            }}
          >
            {v === 0 ? "All" : v + "+"}
          </button>
        ))}

        <div className="w-px h-4 mx-1" style={{ background: "#1D2938" }} />

        <button
          onClick={() => setKevOnly(!kevOnly)}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all"
          style={{
            background: kevOnly ? "#FF4D5E15" : "transparent",
            color: kevOnly ? "#FF4D5E" : "#627083",
            border: kevOnly ? "1px solid #FF4D5E30" : "1px solid transparent",
          }}
        >
          KEV Only
        </button>

        <span className="ml-auto text-xs" style={{ color: "#627083" }}>
          {filtered.length} vulnerabilities
        </span>
      </div>

      {/* CVE Cards + Detail */}
      <div className={selectedCve ? "grid grid-cols-5 gap-4" : "block"}>
        <div className={selectedCve ? "col-span-3" : "col-span-5"}>
          <div className="grid grid-cols-2 gap-3">
            {filtered.map((cve) => (
              <div
                key={cve.id}
                onClick={() => setSelectedCve(selectedCve?.id === cve.id ? null : cve)}
                className="rounded-xl p-4 cursor-pointer transition-all"
                style={{
                  background: selectedCve?.id === cve.id ? "#1A2333" : "#111925",
                  border: `1px solid ${selectedCve?.id === cve.id ? "#56B4FF40" : "#1D2938"}`,
                }}
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className="font-mono text-sm font-semibold" style={{ color: "#F4F7FA" }}>
                      {cve.id}
                    </span>
                    {cve.kev && (
                      <span
                        className="ml-2 text-[10px] px-1.5 py-0.5 rounded font-semibold"
                        style={{ background: "#FF4D5E20", color: "#FF4D5E" }}
                      >
                        KEV
                      </span>
                    )}
                  </div>
                  <ProvenanceBadge type="live" />
                </div>

                <div className="flex items-center gap-2 mb-2">
                  <div
                    className="flex items-center gap-1 px-2 py-0.5 rounded"
                    style={{
                      background: cvssColor(cve.cvss) + "15",
                      border: `1px solid ${cvssColor(cve.cvss)}30`,
                    }}
                  >
                    <span className="text-xs font-semibold font-mono" style={{ color: cvssColor(cve.cvss) }}>
                      CVSS {cve.cvss}
                    </span>
                  </div>
                  <span className="text-xs" style={{ color: "#627083" }}>
                    {cve.category}
                  </span>
                </div>

                <p className="text-xs leading-relaxed mb-2" style={{ color: "#9AA8B8" }}>
                  {cve.description}
                </p>

                <div className="flex items-center justify-between text-[10px]">
                  <span style={{ color: "#627083" }}>
                    {cve.vendor} · {cve.product}
                  </span>
                  <span style={{ color: "#627083" }}>{cve.published}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {selectedCve && (
          <div className="col-span-2 space-y-4">
            <div className="rounded-xl p-4" style={{ background: "#111925", border: "1px solid #56B4FF30" }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold tracking-widest uppercase" style={{ color: "#627083" }}>
                  VULNERABILITY DETAIL
                </span>
                <button onClick={() => setSelectedCve(null)} className="text-xs" style={{ color: "#627083" }}>
                  ✕
                </button>
              </div>

              <div className="space-y-3">
                <div>
                  <span className="font-mono text-lg font-semibold" style={{ color: "#F4F7FA" }}>
                    {selectedCve.id}
                  </span>
                  {selectedCve.kev && (
                    <span
                      className="ml-2 text-xs px-2 py-0.5 rounded font-semibold"
                      style={{ background: "#FF4D5E20", color: "#FF4D5E" }}
                    >
                      Known Exploited
                    </span>
                  )}
                </div>

                <div
                  className="flex items-center gap-3 p-3 rounded-lg"
                  style={{ background: cvssColor(selectedCve.cvss) + "0A", border: `1px solid ${cvssColor(selectedCve.cvss)}25` }}
                >
                  <div className="text-center">
                    <div className="text-2xl font-semibold font-mono" style={{ color: cvssColor(selectedCve.cvss) }}>
                      {selectedCve.cvss}
                    </div>
                    <div className="text-[10px]" style={{ color: "#627083" }}>
                      CVSS Score
                    </div>
                  </div>
                  <div className="flex-1">
                    <div
                      className="h-2 rounded-full"
                      style={{ background: "#1D2938" }}
                    >
                      <div
                        className="h-2 rounded-full"
                        style={{ width: `${(selectedCve.cvss / 10) * 100}%`, background: cvssColor(selectedCve.cvss) }}
                      />
                    </div>
                    <div className="flex justify-between mt-1 text-[9px]" style={{ color: "#627083" }}>
                      <span>0.0</span>
                      <span>10.0</span>
                    </div>
                  </div>
                </div>

                <p className="text-sm leading-relaxed" style={{ color: "#9AA8B8" }}>
                  {selectedCve.description}
                </p>

                <div className="space-y-2">
                  {[
                    { label: "Vendor", value: selectedCve.vendor },
                    { label: "Product", value: selectedCve.product },
                    { label: "Category", value: selectedCve.category },
                    { label: "Published", value: selectedCve.published },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center justify-between">
                      <span className="text-xs" style={{ color: "#627083" }}>
                        {item.label}
                      </span>
                      <span className="text-xs font-medium" style={{ color: "#F4F7FA" }}>
                        {item.value}
                      </span>
                    </div>
                  ))}
                </div>

                <div>
                  <span className="text-[10px] font-semibold uppercase tracking-wider block mb-2" style={{ color: "#627083" }}>
                    AFFECTED ASSETS
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedCve.affected.map((asset) => (
                      <span
                        key={asset}
                        className="font-mono text-xs px-2 py-0.5 rounded"
                        style={{ background: "#FF4D5E10", color: "#FF4D5E", border: "1px solid #FF4D5E20" }}
                      >
                        {asset}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <button
                    className="flex-1 py-2 rounded-lg text-xs font-medium"
                    style={{ background: "#FF4D5E15", color: "#FF4D5E", border: "1px solid #FF4D5E25" }}
                  >
                    View Intelligence
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
