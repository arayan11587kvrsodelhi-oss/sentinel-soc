import { ProvenanceBadge } from "../components/ProvenanceBadge"

const subsystems = [
  {
    name: "API Gateway",

    status: "OPERATIONAL",

    latency: "14ms",

    uptime: "99.97%",

    requests: "2,847/min",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",
  },

  {
    name: "WebSocket Server",

    status: "OPERATIONAL",

    latency: "4ms",

    uptime: "99.99%",

    connections: "12 active",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",
  },

  {
    name: "Primary Database",

    status: "OPERATIONAL",

    latency: "8ms",

    uptime: "100%",

    queries: "342/min",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",
  },

  {
    name: "AI Engine",

    status: "READY",

    latency: "220ms",

    uptime: "99.91%",

    model: "ExpertEngine v3.1",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",

    badge: "EXPERT ENGINE",
  },

  {
    name: "Event Pipeline",

    status: "ACTIVE",

    latency: "2ms",

    uptime: "99.98%",

    throughput: "128 events/min",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",
  },

  {
    name: "Rule Engine",

    status: "OPERATIONAL",

    latency: "31ms",

    uptime: "99.96%",

    evaluations: "47/min",

    lastCheck: "18:35:02 UTC",

    color: "#42D392",
  },
]

const metrics = [
  { label: "Total Events Processed", value: "2.4M", sub: "last 24h" },

  { label: "Detections Generated", value: "83", sub: "last 24h" },

  { label: "Incidents Created", value: "12", sub: "active" },

  { label: "AI Analyses Run", value: "41", sub: "last 24h" },

  { label: "Average API Latency", value: "14ms", sub: "p50" },

  { label: "System Uptime", value: "99.97%", sub: "30d SLA" },
]

const statusBg: Record<string, string> = {
  OPERATIONAL: "#42D39215",

  ACTIVE: "#42D39215",

  READY: "#42D39215",

  DEGRADED: "#FF8A4C15",

  OFFLINE: "#FF4D5E15",

  RECONNECTING: "#F4C95D15",
}

const statusBorder: Record<string, string> = {
  OPERATIONAL: "#42D39230",

  ACTIVE: "#42D39230",

  READY: "#42D39230",

  DEGRADED: "#FF8A4C30",

  OFFLINE: "#FF4D5E30",

  RECONNECTING: "#F4C95D30",
}

export default function SystemHealth() {
  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            System Health
          </h1>
          <p className="text-sm mt-0.5" style={{ color: "#9AA8B8" }}>
            Infrastructure monitoring and service status
          </p>
        </div>
        <ProvenanceBadge type="live" />
      </div>

      {/* Overall Status Banner */}
      <div
        className="rounded-xl p-4 flex items-center gap-4"
        style={{ background: "#42D39208", border: "1px solid #42D39225" }}
      >
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
          style={{ background: "#42D39220" }}
        >
          <div className="w-4 h-4 rounded-full bg-[#42D392] animate-pulse" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span
              className="text-base font-semibold"
              style={{ color: "#42D392" }}
            >
              ● HEALTHY
            </span>
            <span className="text-xs" style={{ color: "#627083" }}>
              All systems operational
            </span>
          </div>
          <div
            className="flex items-center gap-4 mt-1 text-xs"
            style={{ color: "#627083" }}
          >
            <span className="font-mono">
              Last check: 2026-08-29 18:35:02 UTC
            </span>
            <span>•</span>
            <span>6 / 6 services healthy</span>
          </div>
        </div>
        <div className="ml-auto">
          <ProvenanceBadge type="live" />
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-6 gap-3">
        {metrics.map((m) => (
          <div
            key={m.label}
            className="rounded-xl p-3"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <div
              className="text-[10px] font-semibold uppercase tracking-wider mb-1"
              style={{ color: "#627083" }}
            >
              {m.label}
            </div>
            <div
              className="text-xl font-semibold font-mono tabular-nums"
              style={{ color: "#F4F7FA" }}
            >
              {m.value}
            </div>
            <div className="text-[10px]" style={{ color: "#627083" }}>
              {m.sub}
            </div>
          </div>
        ))}
      </div>

      {/* Subsystem Cards */}
      <div>
        <span
          className="text-xs font-semibold tracking-widest uppercase block mb-3"
          style={{ color: "#627083" }}
        >
          SUBSYSTEM STATUS
        </span>
        <div className="grid grid-cols-3 gap-4">
          {subsystems.map((sys) => (
            <div
              key={sys.name}
              className="rounded-xl p-4"
              style={{ background: "#111925", border: "1px solid #1D2938" }}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3
                    className="text-sm font-semibold"
                    style={{ color: "#F4F7FA" }}
                  >
                    {sys.name}
                  </h3>
                  {(sys as { badge?: string }).badge && (
                    <span className="text-[10px]" style={{ color: "#627083" }}>
                      {(sys as { badge?: string }).badge}
                    </span>
                  )}
                </div>
                <div
                  className="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-semibold"
                  style={{
                    background: statusBg[sys.status] ?? "#42D39215",

                    color: sys.color,

                    border: `1px solid ${statusBorder[sys.status] ?? "#42D39230"}`,
                  }}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ background: sys.color }}
                  />
                  {sys.status}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "#627083" }}>
                    Latency
                  </span>
                  <span
                    className="font-mono text-xs font-medium"
                    style={{ color: "#42D392" }}
                  >
                    {sys.latency}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "#627083" }}>
                    Uptime
                  </span>
                  <span
                    className="font-mono text-xs font-medium"
                    style={{ color: "#F4F7FA" }}
                  >
                    {sys.uptime}
                  </span>
                </div>
                {(sys as { requests?: string }).requests && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Requests
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { requests?: string }).requests}
                    </span>
                  </div>
                )}
                {(sys as { connections?: string }).connections && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Connections
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { connections?: string }).connections}
                    </span>
                  </div>
                )}
                {(sys as { queries?: string }).queries && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Queries
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { queries?: string }).queries}
                    </span>
                  </div>
                )}
                {(sys as { model?: string }).model && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Model
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { model?: string }).model}
                    </span>
                  </div>
                )}
                {(sys as { throughput?: string }).throughput && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Throughput
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { throughput?: string }).throughput}
                    </span>
                  </div>
                )}
                {(sys as { evaluations?: string }).evaluations && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs" style={{ color: "#627083" }}>
                      Evaluations
                    </span>
                    <span
                      className="font-mono text-xs"
                      style={{ color: "#9AA8B8" }}
                    >
                      {(sys as { evaluations?: string }).evaluations}
                    </span>
                  </div>
                )}
              </div>

              <div
                className="mt-3 pt-2"
                style={{ borderTop: "1px solid #1D293840" }}
              >
                <span
                  className="text-[10px] font-mono"
                  style={{ color: "#627083" }}
                >
                  {sys.lastCheck}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Status reference */}
      <div
        className="rounded-xl p-4"
        style={{ background: "#111925", border: "1px solid #1D2938" }}
      >
        <span
          className="text-xs font-semibold tracking-widest uppercase block mb-3"
          style={{ color: "#627083" }}
        >
          STATUS LEGEND
        </span>
        <div className="flex items-center gap-6">
          {[
            {
              status: "OPERATIONAL",
              color: "#42D392",
              desc: "Fully functional",
            },

            {
              status: "DEGRADED",
              color: "#FF8A4C",
              desc: "Reduced performance",
            },

            {
              status: "OFFLINE",
              color: "#FF4D5E",
              desc: "Service unavailable",
            },

            {
              status: "RECONNECTING",
              color: "#F4C95D",
              desc: "Attempting reconnection",
            },
          ].map((s) => (
            <div key={s.status} className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ background: s.color }}
              />
              <span
                className="text-xs font-semibold"
                style={{ color: s.color }}
              >
                {s.status}
              </span>
              <span className="text-xs" style={{ color: "#627083" }}>
                — {s.desc}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
