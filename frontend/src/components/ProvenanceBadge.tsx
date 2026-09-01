import { useState, useEffect, useRef } from "react"

type ProvenanceType = "live" | "simulated" | "derived" | "inferred"

interface ProvenanceBadgeProps {
  type: ProvenanceType

  source?: string

  retrieved?: string

  transformation?: string
}

const configs: Record<ProvenanceType, {
  icon: string
  label: string
  color: string
  classification: string
  defaultSource: string
  defaultTransformation: string
}> = {
  live: {
    icon: "●",

    label: "LIVE",

    color: "#42D392",

    classification: "LIVE",

    defaultSource: "External data feed",

    defaultTransformation: "None",
  },

  simulated: {
    icon: "◆",

    label: "SIMULATED",

    color: "#F4C95D",

    classification: "SIMULATED",

    defaultSource: "Sentinel attack simulator",

    defaultTransformation: "None — generated telemetry",
  },

  derived: {
    icon: "◇",

    label: "DERIVED",

    color: "#7C8CFF",

    classification: "DERIVED",

    defaultSource: "Sentinel analytics engine",

    defaultTransformation: "Calculated from raw event data",
  },

  inferred: {
    icon: "△",

    label: "INFERRED",

    color: "#9AA8B8",

    classification: "INFERRED",

    defaultSource: "Sentinel AI Expert Engine",

    defaultTransformation: "AI inference from evidence",
  },
}

export function ProvenanceBadge({
  type,
  source,
  retrieved,
  transformation,
}: ProvenanceBadgeProps) {
  const [open, setOpen] = useState(false)

  const ref = useRef<HTMLDivElement>(null)

  const cfg = configs[type]

  useEffect(() => {
    if (!open) return

    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }

    document.addEventListener("mousedown", handler)

    return () => document.removeEventListener("mousedown", handler)
  }, [open])

  const now = new Date()

  const syncTime = `2026-08-29 ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")} UTC`

  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded transition-all select-none"
        style={{
          color: cfg.color,

          background: cfg.color + "12",

          border: `1px solid ${cfg.color}25`,
        }}
      >
        <span style={{ fontSize: "7px" }}>{cfg.icon}</span>
        {cfg.label}
      </button>

      {open && (
        <div
          className="absolute z-50 right-0 top-full mt-1 rounded-lg p-3 shadow-2xl pop-in"
          style={{
            background: "#0D131D",

            border: "1px solid #1D2938",

            width: "220px",

            boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
          }}
        >
          <div className="flex items-center justify-between mb-2">
            <span
              className="text-xs font-semibold"
              style={{ color: "#F4F7FA" }}
            >
              DATA PROVENANCE
            </span>
            <button
              onClick={() => setOpen(false)}
              className="text-[10px]"
              style={{ color: "#627083" }}
            >
              ✕
            </button>
          </div>
          <div className="space-y-1.5 text-[11px]">
            <div>
              <div style={{ color: "#627083" }}>Classification</div>
              <div
                className="font-semibold mt-0.5"
                style={{ color: cfg.color }}
              >
                {cfg.icon} {cfg.classification}
              </div>
            </div>
            <div>
              <div style={{ color: "#627083" }}>Source</div>
              <div className="font-mono mt-0.5" style={{ color: "#F4F7FA" }}>
                {source ?? cfg.defaultSource}
              </div>
            </div>
            <div>
              <div style={{ color: "#627083" }}>Retrieved</div>
              <div className="font-mono mt-0.5" style={{ color: "#9AA8B8" }}>
                {retrieved ?? syncTime}
              </div>
            </div>
            <div>
              <div style={{ color: "#627083" }}>Transformation</div>
              <div className="mt-0.5" style={{ color: "#9AA8B8" }}>
                {transformation ?? cfg.defaultTransformation}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
