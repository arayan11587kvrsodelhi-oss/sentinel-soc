import React from "react"
import { radius, surface, text } from "../lib/design-tokens"

/* =========================================================
   SENTINEL ICON SYSTEM
   Monochrome line icons, 24x24 viewBox, stroke="currentColor",
   aria-hidden by default. This is the exact icon language the
   sidebar already used — Quick Actions now share it instead of
   shipping colourful 3D/emoji glyphs.
   ========================================================= */

const ICON_PATHS = {
  overview:
    "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
  incidents:
    "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
  detections: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  "live-events": "M13 10V3L4 14h7v7l9-11h-7z",
  "threat-intel":
    "M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064",
  vulnerabilities:
    "M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
  mitre: "M4 6h16M4 10h16M4 14h16M4 18h16",
  "ai-analyst":
    "M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z",
  response:
    "M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  "audit-log":
    "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2",
  health:
    "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
  search: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z",
  bell: "M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0.538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9",
  close: "M6 18L18 6M6 6l12 12",
  clock: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
  warning:
    "M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z",
  network: "M4 4h6v6H4zM14 14h6v6h-6zM14 4h6v6h-6zM4 14h6v6H4zM10 7h4M7 10v4M17 10v4M10 17h4",
} as const

export type IconName = keyof typeof ICON_PATHS

export interface SOCIconProps {
  name: IconName
  className?: string
  /**
   * Provide a label only when the icon carries meaning that is not
   * already present as adjacent text. Decorative icons stay hidden.
   */
  label?: string
}

export function SOCIcon({ name, className = "w-4 h-4", label }: SOCIconProps) {
  return (
    <svg
      className={`flex-shrink-0 ${className}`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
      strokeWidth={1.8}
      aria-hidden={label ? undefined : true}
      role={label ? "img" : undefined}
      aria-label={label}
      focusable="false"
    >
      <path strokeLinecap="round" strokeLinejoin="round" d={ICON_PATHS[name]} />
    </svg>
  )
}
/* =========================================================
   BUTTON SYSTEM
   Four intentional variants — primary, secondary, ghost, icon.
   Shared typography (text-sm), radius (8px), transitions, focus
   ring, disabled state and minimum hit area.
   ========================================================= */

export type ButtonVariant = "primary" | "secondary" | "ghost" | "icon"
export type ButtonSize = "sm" | "md" | "lg"

interface ButtonStyle {
  background: string
  color: string
  border: string
  hoverBackground: string
  hoverColor: string
  hoverBorder: string
}

const BUTTON_VARIANTS: Record<ButtonVariant, ButtonStyle> = {
  primary: {
    background: "#56B4FF1F",
    color: text.link,
    border: "#56B4FF59",
    hoverBackground: "#56B4FF33",
    hoverColor: "#8FCDFF",
    hoverBorder: "#56B4FF80",
  },
  secondary: {
    background: surface.panel,
    color: text.secondary,
    border: surface.border,
    hoverBackground: surface.raised,
    hoverColor: text.primary,
    hoverBorder: surface.borderStrong,
  },
  ghost: {
    background: "transparent",
    color: text.secondary,
    border: "transparent",
    hoverBackground: "#FFFFFF0A",
    hoverColor: text.primary,
    hoverBorder: "transparent",
  },
  icon: {
    background: "transparent",
    color: text.secondary,
    border: "transparent",
    hoverBackground: surface.raised,
    hoverColor: text.primary,
    hoverBorder: surface.border,
  },
}

/** 44px where practical; `sm` is reserved for dense in-panel toolbars. */
const BUTTON_SIZES: Record<
  ButtonSize,
  { minHeight: string; padding: string; font: string }
> = {
  sm: { minHeight: "32px", padding: "0 10px", font: "text-xs" },
  md: { minHeight: "36px", padding: "0 12px", font: "text-sm" },
  lg: { minHeight: "44px", padding: "0 14px", font: "text-sm" },
}

export interface ButtonProps
  extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "style"> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** Leading line icon; `false`/omitted renders no icon. */
  icon?: IconName | false
  fullWidth?: boolean
}

export function Button({
  variant = "secondary",
  size = "md",
  icon,
  fullWidth = false,
  className = "",
  children,
  type = "button",
  disabled,
  ...rest
}: ButtonProps) {
  const v = BUTTON_VARIANTS[variant]
  const s = BUTTON_SIZES[size]
  const isIconOnly = variant === "icon" || (Boolean(icon) && !children)
  const square = isIconOnly && !children

  return (
    <button
      type={type}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 font-medium ${s.font} select-none transition-colors duration-150 disabled:opacity-45 disabled:cursor-not-allowed ${className}`}
      style={{
        minHeight: s.minHeight,
        minWidth: isIconOnly ? s.minHeight : undefined,
        width: fullWidth ? "100%" : square ? s.minHeight : undefined,
        padding: square ? 0 : s.padding,
        borderRadius: radius.md,
        background: v.background,
        color: v.color,
        border: `1px solid ${v.border}`,
        cursor: disabled ? "not-allowed" : "pointer",
      }}
      onMouseEnter={(e) => {
        if (disabled) return
        const el = e.currentTarget
        el.style.background = v.hoverBackground
        el.style.color = v.hoverColor
        el.style.borderColor = v.hoverBorder
      }}
      onMouseLeave={(e) => {
        const el = e.currentTarget
        el.style.background = v.background
        el.style.color = v.color
        el.style.borderColor = v.border
      }}
      {...rest}
    >
      {icon ? <SOCIcon name={icon} className="w-4 h-4" /> : null}
      {children}
    </button>
  )
}
/* =========================================================
   STATUS TAG
   Non-interactive by definition: renders a <span>, never a
   <button>. No hover, no pointer cursor, no transition — just
   semantic colour, background and readable text.
   ========================================================= */

export type Tone =
  | "neutral"
  | "muted"
  | "accent"
  | "link"
  | "success"
  | "warning"
  | "caution"
  | "danger"

export const TONE_COLOR: Record<Tone, string> = {
  neutral: text.primary,
  muted: text.muted,
  accent: text.accent,
  link: text.link,
  success: text.success,
  warning: text.warning,
  caution: text.caution,
  danger: text.danger,
}

export interface StatusTagProps {
  tone?: Tone
  /** Leading glyph, hidden from assistive tech (status is in the text). */
  glyph?: string
  /** Leading status dot indicator. */
  dot?: boolean
  pulse?: boolean
  mono?: boolean
  className?: string
  children: React.ReactNode
  /** Tooltip repeating the same information as the visible text. */
  title?: string
}

export function StatusTag({
  tone = "neutral",
  glyph,
  dot = false,
  pulse = false,
  mono = false,
  className = "",
  children,
  title,
}: StatusTagProps) {
  const color = TONE_COLOR[tone]
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-semibold leading-4 whitespace-nowrap ${mono ? "font-mono" : ""} ${className}`}
      style={{
        padding: "2px 8px",
        borderRadius: radius.sm,
        color,
        background: `${color}14`,
        border: `1px solid ${color}33`,
      }}
      title={title}
    >
      {dot ? (
        <span
          aria-hidden="true"
          className={`w-1.5 h-1.5 rounded-full ${pulse ? "animate-pulse" : ""}`}
          style={{ background: color }}
        />
      ) : null}
      {glyph ? (
        <span aria-hidden="true" className="text-[0.75em] leading-none">
          {glyph}
        </span>
      ) : null}
      {children}
    </span>
  )
}

/* =========================================================
   PANEL + HEADING
   One card treatment for every block on the dashboard.
   ========================================================= */

export interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Gradient treatment for the command-center shell. */
  accentBorder?: string
  background?: string
}

export function Panel({
  accentBorder,
  background = surface.panel,
  className = "",
  style,
  children,
  ...rest
}: PanelProps) {
  return (
    <div
      className={`rounded-xl p-4 md:p-5 min-w-0 ${className}`}
      style={{
        background,
        border: `1px solid ${accentBorder ?? surface.border}`,
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  )
}

export interface PanelHeadingProps {
  title: React.ReactNode
  /** Secondary line under the title. */
  subtitle?: React.ReactNode
  icon?: IconName
  /** Heading tint — defaults to muted metadata. */
  tone?: Tone
  /** Trailing content: view-all link, badge, filter, ... */
  action?: React.ReactNode
  className?: string
  /** Heading level. Cards use `h2`, nested blocks use `h3`. */
  as?: "h2" | "h3"
}

/**
 * Section heading. Sentence case + `tracking-wide` replaces the previous
 * 10px `uppercase tracking-widest` eyebrows: identical hierarchy, legible
 * size, no screaming caps.
 */
export function PanelHeading({
  title,
  subtitle,
  icon,
  tone = "muted",
  action,
  className = "",
  as: Heading = "h2",
}: PanelHeadingProps) {
  const color = TONE_COLOR[tone]
  return (
    <div className={`flex items-start justify-between gap-3 mb-4 ${className}`}>
      <div className="min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          {icon ? (
            <span style={{ color }}>
              <SOCIcon name={icon} className="w-3.5 h-3.5" />
            </span>
          ) : null}
          <Heading
            className="text-xs font-semibold tracking-wide truncate"
            style={{ color }}
          >
            {title}
          </Heading>
        </div>
        {subtitle ? (
          <p className="text-xs mt-1 break-words" style={{ color: text.faint }}>
            {subtitle}
          </p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}

/* =========================================================
   METRIC TILE
   Compact label / value / supporting status, used by the
   threat-intelligence strip and the metric rows.
   ========================================================= */

export interface MetricTileProps {
  label: string
  value: React.ReactNode
  /** Optional supporting status line. */
  status?: React.ReactNode
  statusTone?: Tone
  valueTone?: Tone
  className?: string
}

export function MetricTile({
  label,
  value,
  status,
  statusTone = "muted",
  valueTone = "neutral",
  className = "",
}: MetricTileProps) {
  return (
    <div
      className={`rounded-lg p-3 min-w-0 ${className}`}
      style={{ background: surface.base, border: `1px solid ${surface.border}` }}
    >
      <span
        className="block text-xs font-semibold leading-4 break-words"
        style={{ color: text.muted }}
      >
        {label}
      </span>
      <div
        className="text-xl font-bold font-mono mt-1 leading-tight tabular-nums break-words"
        style={{ color: TONE_COLOR[valueTone] }}
      >
        {value}
      </div>
      {status ? (
        <span
          className="block text-xs leading-4 mt-1 break-words"
          style={{ color: TONE_COLOR[statusTone] }}
        >
          {status}
        </span>
      ) : null}
    </div>
  )
}