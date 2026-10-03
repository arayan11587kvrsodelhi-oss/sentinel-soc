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
        type="button"
        onClick={() => setOpen(!open)}
        aria-haspopup="dialog"
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 text-xs font-semibold leading-4 px-2 py-1 rounded-md cursor-pointer transition-all select-none hover:brightness-125 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#56B4FF]"
        style={{
          color: cfg.color,

          background: cfg.color + "12",

          border: `1px solid ${cfg.color}25`,
        }}
      >
        <span aria-hidden="true" className="leading-none">
          {cfg.icon}
        </span>
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
              Data provenance
            </span>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close provenance details"
              className="text-xs leading-none px-1 py-0.5 rounded-lg cursor-pointer transition-colors text-[#627083] hover:text-[#F4F7FA]"
            >
              ✕
            </button>
          </div>
          <div className="space-y-1.5 text-xs">
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
