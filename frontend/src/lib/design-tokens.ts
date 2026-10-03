/**
 * Sentinel SOC v2.2 — shared design tokens.
 *
 * Single source of truth for the dark SOC palette, type scale, radius scale
 * and the display formatters used across every screen. Inline hex values that
 * used to be scattered through ~1900 lines of JSX now resolve here so the
 * dashboard reads as one coherent system instead of 13 near-identical greys.
 *
 * The palette keeps its security meaning on purpose:
 *   danger  -> incident / critical
 *   caution -> high severity / attention
 *   warning -> degraded / advisory
 *   success -> healthy / operational
 *   accent  -> Sentinel-specific + interactive/selected
 */

/* ── Semantic text colours ────────────────────────────────────────────
   13 raw hex values collapsed into 10 intentional roles.               */
export const text = {
  /** Main information: headings, values, primary copy. */
  primary: "#F4F7FA",
  /** Emphasised body copy inside dense panels. */
  strong: "#E8EEF7",
  /** Supporting prose: descriptions, event messages. */
  secondary: "#9AA8B8",
  /** Metadata: labels, timestamps, helper copy. */
  muted: "#627083",
  /** Lowest-emphasis metadata (chart captions, de-emphasised notes). */
  faint: "#394B5E",
  /** Sentinel-specific indigo: derived data, AI, brand chrome. */
  accent: "#7C8CFF",
  /** Interactive / selected affordance (links, active nav, focus). */
  link: "#56B4FF",
  /** Healthy / operational. */
  success: "#42D392",
  /** Degraded / advisory. */
  warning: "#F4C95D",
  /** High severity / requires attention. */
  caution: "#FF8A4C",
  /** Incident / critical. */
  danger: "#FF4D5E",
  /** Text on saturated fills. */
  inverse: "#FFFFFF",
} as const

/** Surfaces & structure. */
export const surface = {
  base: "#070B12",
  chrome: "#0D131D",
  panel: "#111925",
  raised: "#131C2A",
  border: "#1D2938",
  borderStrong: "#2D3F55",
} as const

/** Radius scale — cards use `lg`, controls/badges use `md`. */
export const radius = {
  sm: "6px",
  md: "8px",
  lg: "12px",
} as const

/**
 * Type scale. 12 arbitrary sizes -> 8 intentional steps.
 * 12 compact metadata · 14 secondary UI · 16 body · 18 emphasized
 * 20 card heading · 24 section heading · 30 major heading
 */
export const type = {
  meta: "text-xs", // 12px
  ui: "text-sm", // 14px
  body: "text-base", // 16px
  emphasis: "text-lg", // 18px
  card: "text-xl", // 20px
  section: "text-2xl", // 24px
  major: "text-3xl", // 30px
} as const

/** Severity palette — shared by every incident / event surface. */
export const severityColor: Record<string, string> = {
  CRITICAL: text.danger,
  HIGH: text.caution,
  MEDIUM: text.warning,
  LOW: text.link,
}

/* ── System health terminology ────────────────────────────────────────
   The dashboard reported the same healthy state as OPERATIONAL, LIVE,
   HEALTHY, RUNNING, READY and ACTIVE — all painted the same green. They
   are the same state, so the *display* label is normalised to
   "Operational". Degraded / offline / reconnecting stay distinct.      */

/** Raw (backend/WS) values that all mean "healthy". */
const HEALTHY_STATUSES = new Set([
  "OPERATIONAL",
  "LIVE",
  "HEALTHY",
  "RUNNING",
  "READY",
  "ACTIVE",
  "UP",
  "ONLINE",
])

/** True when a raw status value represents a healthy component. */
export function isHealthyStatus(status: string): boolean {
  return HEALTHY_STATUSES.has(String(status).trim().toUpperCase())
}

/**
 * Display label for a system-health value. Never mutates the underlying
 * value that travels over the API / WebSocket.
 */
export function formatHealthStatus(status: string): string {
  const raw = String(status ?? "").trim()
  if (!raw) return "Unknown"
  if (isHealthyStatus(raw)) return "Operational"
  // Preserve meaning for every non-healthy state, just normalise casing.
  return raw
    .toLowerCase()
    .split(/[\s_-]+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ")
}

/** Tone token used to colour a health indicator dot / tag. */
export function healthTone(status: string): "success" | "danger" {
  return isHealthyStatus(status) ? "success" : "danger"
}

/* ── Event type presentation ──────────────────────────────────────────
   C2_COMMUNICATION reads as noise at a glance. The wire value is never
   changed — only how it is rendered.                                    */

const ACRONYMS = new Set([
  "ai",
  "api",
  "c2",
  "cve",
  "cisa",
  "dns",
  "edr",
  "ex",
  "http",
  "https",
  "ids",
  "ips",
  "ip",
  "kev",
  "lfi",
  "mitre",
  "nvd",
  "os",
  "rce",
  "rfi",
  "siem",
  "soc",
  "sql",
  "ssh",
  "ssl",
  "ui",
  "xss",
])

/**
 * "C2_COMMUNICATION" -> "C2 Communication"
 * "SQL_INJECTION" -> "SQL Injection"
 * Falls back to the original string for anything already human-readable.
 */
export function formatEventType(value: string): string {
  const raw = String(value ?? "").trim()
  if (!raw) return ""
  if (!/[_\-]/.test(raw)) return raw
  return raw
    .toLowerCase()
    .split(/[_\-]+/)
    .map((word) =>
      ACRONYMS.has(word)
        ? word.toUpperCase()
        : word.charAt(0).toUpperCase() + word.slice(1),
    )
    .join(" ")
}

/** `Api` -> `API` for short technical identifiers (SOC, API, NVD, ...). */
export function formatAcronym(value: string): string {
  return ACRONYMS.has(value.trim().toLowerCase())
    ? value.trim().toUpperCase()
    : value
}