import React, { useState, useRef, useCallback } from "react";
import { ProvenanceBadge } from "../components/ProvenanceBadge";

// ─── Data ─────────────────────────────────────────────────

const sparkData = {
  score:     [80, 82, 81, 83, 85, 84, 85, 86, 87],
  incidents: [9, 8, 7, 8, 6, 7, 6, 5, 4],
  threats:   [0, 1, 1, 2, 1, 2, 2, 1, 2],
  events:    [90, 95, 88, 102, 108, 115, 112, 120, 128],
};

const eventsData = [
  45, 52, 48, 61, 58, 68, 72, 69, 75, 80, 77, 82,
  90, 85, 91, 88, 95, 100, 108, 115, 112, 120, 125,
  118, 128, 122, 130, 128, 125, 128,
];
const authFailures = [
  2, 3, 2, 4, 3, 5, 4, 6, 8, 5, 7, 9, 14, 11, 18,
  16, 22, 28, 35, 32, 40, 45, 12, 5, 3, 2, 2, 3, 3, 2,
];

const incidents = [
  { id: "INC-00842", severity: "CRITICAL", title: "Credential Attack",       technique: "T1110",     time: "2m ago",  status: "INVESTIGATING" },
  { id: "INC-00841", severity: "HIGH",     title: "Suspicious PowerShell",   technique: "T1059.001", time: "8m ago",  status: "NEW" },
  { id: "INC-00840", severity: "MEDIUM",   title: "Network Scan",            technique: "T1046",     time: "14m ago", status: "REVIEW" },
  { id: "INC-00839", severity: "LOW",      title: "DNS Enumeration",         technique: "T1018",     time: "22m ago", status: "REVIEW" },
];

const sevColor: Record<string, string> = {
  CRITICAL: "#FF4D5E",
  HIGH:     "#FF8A4C",
  MEDIUM:   "#F4C95D",
  LOW:      "#56B4FF",
};

// ─── Interactive Sparkline ─────────────────────────────────

interface SparklineProps {
  data: number[];
  color: string;
  name: string;
  unit?: string;
}

function Sparkline({ data, color, name, unit = "" }: SparklineProps) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const W = 72;
  const H = 24;
  const vMin = Math.min(...data);
  const vMax = Math.max(...data);
  const range = vMax - vMin || 1;

  const pts = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * W;
      const y = H - 2 - ((v - vMin) / range) * (H - 5);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const lastX = W;
  const lastY = H - 2 - ((data[data.length - 1] - vMin) / range) * (H - 5);

  const handlePointer = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const clientX = e.clientX;
    const relX = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    const idx = Math.round(relX * (data.length - 1));
    setHoverIdx(idx);
  };

  const handleLeave = () => {
    setHoverIdx(null);
  };

  const activeIdx = hoverIdx !== null ? hoverIdx : null;
  const activeVal = activeIdx !== null ? data[activeIdx] : null;
  const activeX = activeIdx !== null ? (activeIdx / (data.length - 1)) * W : lastX;
  const activeY = activeIdx !== null ? H - 2 - ((data[activeIdx] - vMin) / range) * (H - 5) : lastY;

  return (
    <div className="relative group/spark" data-cursor="graph">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        width={W}
        height={H}
        className="cursor-crosshair overflow-visible block touch-none"
        onPointerMove={handlePointer}
        onPointerDown={handlePointer}
        onPointerLeave={handleLeave}
      >
        <polyline
          points={pts}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity={hoverIdx !== null ? "0.75" : "0.55"}
        />

        {/* Hover Crosshair Guide */}
        {activeIdx !== null && (
          <line
            x1={activeX}
            y1={0}
            x2={activeX}
            y2={H}
            stroke={color}
            strokeWidth="0.8"
            strokeDasharray="1.5,1.5"
            opacity="0.8"
          />
        )}

        {/* Active Dot with Glow */}
        {activeIdx !== null ? (
          <g>
            <circle cx={activeX} cy={activeY} r="4.5" fill={color} fillOpacity="0.3" />
            <circle cx={activeX} cy={activeY} r="2.2" fill={color} stroke="#0D131D" strokeWidth="1" />
          </g>
        ) : (
          <circle cx={lastX} cy={lastY} r="2" fill={color} opacity="0.9" />
        )}
      </svg>

      {/* Floating Tooltip */}
      {activeIdx !== null && (
        <div
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 px-2 py-1 rounded text-[10px] font-mono pointer-events-none z-30 whitespace-nowrap shadow-lg flex items-center gap-1.5"
          style={{
            background: "#0D131D",
            border: "1px solid #1D2938",
            boxShadow: "0 4px 12px rgba(0,0,0,0.6)",
            color: "#F4F7FA",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
          <span>
            {activeVal}
            {unit}
          </span>
          <span className="text-[9px]" style={{ color: "#627083" }}>
            (t-{data.length - 1 - activeIdx})
          </span>
        </div>
      )}
    </div>
  );
}

// ─── Interactive Activity Chart ───────────────────────────

function ActivityChart() {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const VW = 740;
  const VH = 148;
  const PL = 44;  // Y-axis label space
  const PR = 12;
  const PT = 28;  // annotation label space
  const PB = 22;  // X-axis label space
  const CW = VW - PL - PR; // 684
  const CH = VH - PT - PB; // 98
  const yMax = 150;

  const toX = (i: number) => PL + (i / (eventsData.length - 1)) * CW;
  const toY = (v: number) => PT + CH - (v / yMax) * CH;

  const eventsCoords = eventsData.map((v, i) => ({ x: toX(i), y: toY(v) }));
  // Scale auth failures (0–45) × 3.2 to fit the 0–150 chart range nicely
  const authCoords = authFailures.map((v, i) => ({ x: toX(i), y: toY(v * 3.2) }));

  const eventsLine = "M " + eventsCoords.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" L ");
  const eventsArea =
    `${eventsLine} L ${toX(eventsData.length - 1).toFixed(1)},${(PT + CH).toFixed(1)}` +
    ` L ${PL},${(PT + CH).toFixed(1)} Z`;
  const authLine = "M " + authCoords.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" L ");

  const detX = toX(21);
  const incX = toX(23);

  const yGrid = [0, 50, 100, 150];
  const xLabels = [
    { idx: 0,  label: "12:14" },
    { idx: 5,  label: "12:19" },
    { idx: 10, label: "12:24" },
    { idx: 15, label: "12:29" },
    { idx: 20, label: "12:34" },
    { idx: 25, label: "12:39" },
    { idx: 29, label: "12:43" },
  ];

  const updatePointer = useCallback((clientX: number) => {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const svgX = ((clientX - rect.left) / rect.width) * VW;
    const clampedX = Math.max(PL, Math.min(VW - PR, svgX));
    const relProgress = (clampedX - PL) / CW;
    const idx = Math.round(relProgress * (eventsData.length - 1));
    const safeIdx = Math.max(0, Math.min(eventsData.length - 1, idx));
    setHoverIdx(safeIdx);
  }, [CW, PL, PR, VW]);

  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    updatePointer(e.clientX);
  };

  const handlePointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    updatePointer(e.clientX);
  };

  const handlePointerLeave = () => {
    setHoverIdx(null);
  };

  const activeIdx = hoverIdx;
  const hasActive = activeIdx !== null;
  const activeX = hasActive ? toX(activeIdx) : null;
  const activeEventsVal = hasActive ? eventsData[activeIdx] : null;
  const activeEventsY = hasActive ? toY(eventsData[activeIdx]) : null;
  const activeAuthVal = hasActive ? authFailures[activeIdx] : null;
  const activeAuthY = hasActive ? toY(authFailures[activeIdx] * 3.2) : null;

  // Compute minute time string from base time 12:14 UTC
  const activeTimeStr = hasActive
    ? `12:${String(14 + activeIdx).padStart(2, "0")} UTC`
    : null;

  // Annotation if on specific index
  const activeAnnotation =
    activeIdx === 21
      ? { text: "⚑ DETECTION: Brute Force Password Spray", color: "#FF8A4C" }
      : activeIdx === 23
      ? { text: "◆ INCIDENT: INC-00842 Created", color: "#FF4D5E" }
      : null;

  const defaultLastPt = eventsCoords[eventsCoords.length - 1];

  return (
    <div
      ref={containerRef}
      className="relative w-full select-none"
      data-cursor="graph"
      data-chart="activity-chart"
      style={{ touchAction: "none" }}
    >
      <svg
        ref={svgRef}
        viewBox={`0 0 ${VW} ${VH}`}
        className="w-full cursor-crosshair"
        style={{ height: "148px", display: "block" }}
        onPointerMove={handlePointerMove}
        onPointerDown={handlePointerDown}
        onPointerLeave={handlePointerLeave}
      >
        <defs>
          <linearGradient id="evtAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#56B4FF" stopOpacity="0.14" />
            <stop offset="100%" stopColor="#56B4FF" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="evtLineGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor="#7C8CFF" />
            <stop offset="55%"  stopColor="#56B4FF" />
            <stop offset="100%" stopColor="#42D392" />
          </linearGradient>
          <clipPath id="chartArea">
            <rect x={PL} y={PT} width={CW} height={CH} />
          </clipPath>
        </defs>

        {/* Y-axis grid */}
        {yGrid.map((v) => {
          const y = toY(v);
          return (
            <g key={v}>
              <line
                x1={PL} y1={y} x2={VW - PR} y2={y}
                stroke="#1D2938"
                strokeWidth={v === 0 ? "1" : "0.5"}
                strokeDasharray={v === 0 ? undefined : "3,6"}
              />
              <text
                x={PL - 7} y={y + 3.5}
                textAnchor="end"
                fontSize="9"
                fill="#394B5E"
                fontFamily="'JetBrains Mono', monospace"
              >
                {v}
              </text>
            </g>
          );
        })}

        {/* Y-axis label */}
        <text
          x={8} y={PT + CH / 2}
          textAnchor="middle"
          fontSize="8"
          fill="#394B5E"
          fontFamily="'JetBrains Mono', monospace"
          transform={`rotate(-90, 8, ${PT + CH / 2})`}
        >
          events/min
        </text>

        {/* Detection annotation background flag */}
        <line
          x1={detX} y1={PT}
          x2={detX} y2={PT + CH}
          stroke="#FF8A4C" strokeWidth="0.8"
          strokeDasharray="4,3" opacity="0.65"
        />
        <rect x={detX - 32} y={5} width="64" height="15" rx="3" fill="#FF8A4C14" />
        <text
          x={detX} y={15.5}
          textAnchor="middle" fontSize="8" fill="#FF8A4C"
          fontFamily="'JetBrains Mono', monospace" fontWeight="600"
        >
          ⚑ DETECTION
        </text>

        {/* Incident annotation background flag */}
        <line
          x1={incX} y1={PT}
          x2={incX} y2={PT + CH}
          stroke="#FF4D5E" strokeWidth="0.8"
          strokeDasharray="4,3" opacity="0.65"
        />
        <rect x={incX - 28} y={5} width="56" height="15" rx="3" fill="#FF4D5E14" />
        <text
          x={incX} y={15.5}
          textAnchor="middle" fontSize="8" fill="#FF4D5E"
          fontFamily="'JetBrains Mono', monospace" fontWeight="600"
        >
          ◆ INCIDENT
        </text>

        {/* Area fill */}
        <path d={eventsArea} fill="url(#evtAreaGrad)" clipPath="url(#chartArea)" />

        {/* Auth failures secondary line */}
        <path
          d={authLine}
          fill="none"
          stroke="#FF4D5E"
          strokeWidth="1"
          strokeDasharray="2,3"
          opacity="0.45"
          clipPath="url(#chartArea)"
        />

        {/* Main events line */}
        <path
          d={eventsLine}
          fill="none"
          stroke="url(#evtLineGrad)"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
          clipPath="url(#chartArea)"
        />

        {/* Interactive Crosshair & Active Dots */}
        {hasActive && activeX !== null && activeEventsY !== null && activeAuthY !== null ? (
          <g>
            {/* Vertical crosshair line */}
            <line
              x1={activeX}
              y1={PT}
              x2={activeX}
              y2={PT + CH}
              stroke="#56B4FF"
              strokeWidth="1"
              strokeDasharray="2,3"
              opacity="0.85"
            />

            {/* Auth Failures Active Dot */}
            <circle cx={activeX} cy={activeAuthY} r="7" fill="#FF4D5E" fillOpacity="0.25" />
            <circle cx={activeX} cy={activeAuthY} r="3" fill="#FF4D5E" stroke="#0D131D" strokeWidth="1.5" />

            {/* Event Volume Active Dot */}
            <circle cx={activeX} cy={activeEventsY} r="8" fill="#56B4FF" fillOpacity="0.25" />
            <circle cx={activeX} cy={activeEventsY} r="3.5" fill="#42D392" stroke="#0D131D" strokeWidth="1.5" />
          </g>
        ) : (
          /* Default state last point */
          <g>
            <circle cx={defaultLastPt.x} cy={defaultLastPt.y} r="7" fill="#42D392" fillOpacity="0.1" />
            <circle cx={defaultLastPt.x} cy={defaultLastPt.y} r="2.5" fill="#42D392" />
          </g>
        )}

        {/* X-axis labels */}
        {xLabels.map(({ idx, label }) => (
          <text
            key={label}
            x={toX(idx)} y={VH - 4}
            textAnchor="middle" fontSize="9"
            fill={hasActive && Math.abs(activeIdx - idx) <= 1 ? "#56B4FF" : "#394B5E"}
            fontFamily="'JetBrains Mono', monospace"
            fontWeight={hasActive && activeIdx === idx ? "bold" : "normal"}
          >
            {label}
          </text>
        ))}
      </svg>

      {/* Floating Interactive Tooltip */}
      {hasActive && activeX !== null && activeEventsVal !== null && activeAuthVal !== null && (
        <div
          className="absolute pointer-events-none z-30 rounded-xl p-3 text-xs shadow-2xl transition-all"
          style={{
            background: "#0D131D",
            border: "1px solid #1D2938",
            boxShadow: "0 8px 32px rgba(0,0,0,0.75)",
            left: `${Math.max(14, Math.min(86, (activeX / VW) * 100))}%`,
            top: "8px",
            transform: "translateX(-50%)",
            minWidth: "175px",
          }}
        >
          <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-[#1D2938]">
            <span className="font-mono font-bold text-xs" style={{ color: "#F4F7FA" }}>
              {activeTimeStr}
            </span>
            <span
              className="text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded"
              style={{ background: "#42D39215", color: "#42D392", border: "1px solid #42D39230" }}
            >
              ● LIVE
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-[11px]" style={{ color: "#9AA8B8" }}>
                <span className="w-2 h-2 rounded-full" style={{ background: "#56B4FF" }} />
                Event Volume:
              </span>
              <span className="font-mono font-semibold text-xs" style={{ color: "#56B4FF" }}>
                {activeEventsVal} <span className="text-[10px] font-normal" style={{ color: "#627083" }}>/min</span>
              </span>
            </div>

            <div className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-[11px]" style={{ color: "#9AA8B8" }}>
                <span className="w-2 h-2 rounded-full" style={{ background: "#FF4D5E" }} />
                Auth Failures:
              </span>
              <span className="font-mono font-semibold text-xs" style={{ color: "#FF4D5E" }}>
                {activeAuthVal} <span className="text-[10px] font-normal" style={{ color: "#627083" }}>/min</span>
              </span>
            </div>
          </div>

          {activeAnnotation && (
            <div
              className="mt-2 pt-1.5 text-[10px] font-semibold tracking-tight"
              style={{ borderTop: "1px dashed #1D2938", color: activeAnnotation.color }}
            >
              {activeAnnotation.text}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Overview Screen ──────────────────────────────────────

interface OverviewProps {
  onNavigate: (screen: string) => void;
}

export default function Overview({ onNavigate }: OverviewProps) {
  const [hoveredThreat, setHoveredThreat] = useState<string | null>(null);

  const threatData = [
    { level: "Critical", count: 2,  color: "#FF4D5E", pct: 14, desc: "Active credential spray & brute force attempts" },
    { level: "High",     count: 7,  color: "#FF8A4C", pct: 30, desc: "Suspicious PowerShell execution & policy alerts" },
    { level: "Medium",   count: 19, color: "#F4C95D", pct: 56, desc: "Network port sweeps and abnormal connection rates" },
    { level: "Low",      count: 43, color: "#56B4FF", pct: 100, desc: "DNS enumeration and low-confidence telemetry logs" },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: "#F4F7FA" }}>
            Security Overview
          </h1>
          <p className="mt-0.5 text-sm" style={{ color: "#9AA8B8" }}>
            Good evening, Aryan. Here is what is happening across your environment.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs" style={{ color: "#627083" }}>
            Last sync{" "}
            <span className="font-mono" style={{ color: "#9AA8B8" }}>12s ago</span>
          </span>
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium"
            style={{ background: "#42D39215", color: "#42D392", border: "1px solid #42D39230" }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse block" />
            LIVE
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 md:gap-4">
        {[
          {
            label: "SECURITY SCORE",
            value: "87",
            unit: "/ 100",
            delta: "▲ +4 this week",
            deltaColor: "#42D392",
            prov: "derived" as const,
            color: "#42D392",
            spark: sparkData.score,
            name: "Security Score",
          },
          {
            label: "ACTIVE INCIDENTS",
            value: "04",
            unit: "",
            delta: "▼ 2 resolved today",
            deltaColor: "#42D392",
            prov: "derived" as const,
            color: "#F4C95D",
            spark: sparkData.incidents,
            name: "Active Incidents",
          },
          {
            label: "CRITICAL THREATS",
            value: "02",
            unit: "",
            delta: "▲ +1 from yesterday",
            deltaColor: "#FF4D5E",
            prov: "live" as const,
            color: "#FF4D5E",
            spark: sparkData.threats,
            name: "Critical Threats",
          },
          {
            label: "EVENTS / MIN",
            value: "128",
            unit: "",
            delta: "● LIVE · trending up",
            deltaColor: "#42D392",
            prov: "live" as const,
            color: "#56B4FF",
            spark: sparkData.events,
            name: "Event Stream",
          },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-xl p-4 transition-all"
            data-cursor="card"
            style={{ background: "#111925", border: "1px solid #1D2938" }}
          >
            <div className="flex items-start justify-between mb-2">
              <span
                className="text-[10px] font-semibold tracking-widest uppercase"
                style={{ color: "#627083" }}
              >
                {card.label}
              </span>
              <ProvenanceBadge type={card.prov} />
            </div>
            <div className="flex items-end justify-between gap-3">
              <div>
                <div className="flex items-baseline gap-1">
                  <span
                    className="text-[2rem] font-semibold tabular-nums leading-none"
                    style={{ color: card.color }}
                  >
                    {card.value}
                  </span>
                  {card.unit && (
                    <span className="text-base" style={{ color: "#394B5E" }}>
                      {card.unit}
                    </span>
                  )}
                </div>
                <p className="mt-1.5 text-[11px]" style={{ color: card.deltaColor }}>
                  {card.delta}
                </p>
              </div>
              <div className="flex-shrink-0">
                <Sparkline data={card.spark} color={card.color} name={card.name} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Activity Chart */}
      <div
        className="rounded-xl p-5"
        data-cursor="card"
        style={{ background: "#111925", border: "1px solid #1D2938" }}
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              LIVE SECURITY ACTIVITY
            </span>
            <p className="text-[11px] mt-0.5" style={{ color: "#394B5E" }}>
              Events per minute over the last 30 minutes — interactive inspection with hover & touch crosshair
            </p>
          </div>
          <div className="flex items-center gap-4 flex-shrink-0">
            <div className="flex items-center gap-3 text-[11px]" style={{ color: "#627083" }}>
              <span className="flex items-center gap-1.5">
                <span
                  style={{
                    display: "inline-block",
                    width: "18px",
                    height: "2px",
                    background: "linear-gradient(90deg, #7C8CFF, #56B4FF, #42D392)",
                    borderRadius: "1px",
                  }}
                />
                Event volume
              </span>
              <span className="flex items-center gap-1.5">
                <span
                  style={{
                    display: "inline-block",
                    width: "14px",
                    height: "1.5px",
                    borderTop: "1.5px dashed #FF4D5E80",
                  }}
                />
                Auth failures
              </span>
            </div>
            <ProvenanceBadge type="live" />
          </div>
        </div>
        <ActivityChart />
      </div>

      {/* Threat Distribution + Active Incidents */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
        {/* Threat Distribution */}
        <div
          className="col-span-2 rounded-xl p-4 relative"
          data-cursor="card"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-center justify-between mb-4">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              THREAT DISTRIBUTION
            </span>
            <ProvenanceBadge type="derived" />
          </div>
          <div className="space-y-3">
            {threatData.map((item) => {
              const isHovered = hoveredThreat === item.level;
              return (
                <div
                  key={item.level}
                  className="group cursor-pointer rounded-lg p-1.5 -mx-1.5 transition-all"
                  style={{
                    background: isHovered ? "#1D293840" : "transparent",
                  }}
                  onPointerEnter={() => setHoveredThreat(item.level)}
                  onPointerLeave={() => setHoveredThreat(null)}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-1.5 h-1.5 rounded-full transition-transform"
                        style={{
                          background: item.color,
                          transform: isHovered ? "scale(1.4)" : "scale(1)",
                        }}
                      />
                      <span
                        className="text-xs font-medium transition-colors"
                        style={{ color: isHovered ? "#F4F7FA" : "#9AA8B8" }}
                      >
                        {item.level}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span
                        className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded transition-all"
                        style={{
                          background: item.color + (isHovered ? "30" : "18"),
                          color: item.color,
                          boxShadow: isHovered ? `0 0 8px ${item.color}40` : "none",
                        }}
                      >
                        {String(item.count).padStart(2, "0")} ({item.pct}%)
                      </span>
                    </div>
                  </div>
                  <div
                    className="h-1 rounded-full overflow-hidden"
                    style={{ background: "#1D2938" }}
                  >
                    <div
                      className="h-1 rounded-full transition-all duration-300"
                      style={{
                        width: `${item.pct}%`,
                        background: item.color,
                        opacity: isHovered ? 1 : 0.6,
                        boxShadow: isHovered ? `0 0 8px ${item.color}80` : "none",
                      }}
                    />
                  </div>

                  {isHovered && (
                    <p className="text-[10px] mt-1.5 transition-opacity" style={{ color: "#627083" }}>
                      {item.desc}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
          <div className="mt-4 pt-3" style={{ borderTop: "1px solid #1D2938" }}>
            <div className="flex justify-between items-center">
              <span className="text-xs" style={{ color: "#627083" }}>Total detected</span>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold font-mono" style={{ color: "#9AA8B8" }}>
                  71 threats
                </span>
                <span className="text-[9px] font-mono" style={{ color: "#7C8CFF" }}>
                  ◇ DERIVED
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Active Incidents List */}
        <div
          className="col-span-3 rounded-xl p-4"
          data-cursor="card"
          style={{ background: "#111925", border: "1px solid #1D2938" }}
        >
          <div className="flex items-center justify-between mb-4">
            <span
              className="text-xs font-semibold tracking-widest uppercase"
              style={{ color: "#627083" }}
            >
              ACTIVE INCIDENTS
            </span>
            <button
              onClick={() => onNavigate("incidents")}
              className="text-xs transition-colors hover:underline"
              style={{ color: "#56B4FF" }}
            >
              View all 4 →
            </button>
          </div>

          <div className="space-y-2">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => onNavigate("incident-investigation")}
                className="flex items-center justify-between p-3 rounded-lg cursor-pointer transition-all"
                style={{ background: "#0D131D", border: "1px solid #1D2938" }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = "#2D3F55";
                  (e.currentTarget as HTMLElement).style.background = "#131C2A";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = "#1D2938";
                  (e.currentTarget as HTMLElement).style.background = "#0D131D";
                }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ background: sevColor[inc.severity] }}
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold" style={{ color: "#F4F7FA" }}>
                        {inc.title}
                      </span>
                      <span
                        className="text-[10px] font-mono px-1 py-0.2 rounded font-semibold"
                        style={{
                          background: sevColor[inc.severity] + "20",
                          color: sevColor[inc.severity],
                        }}
                      >
                        {inc.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] font-mono" style={{ color: "#627083" }}>
                        {inc.id}
                      </span>
                      <span style={{ color: "#1D2938" }}>·</span>
                      <span className="text-[10px] font-mono" style={{ color: "#7C8CFF" }}>
                        MITRE {inc.technique}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-[11px]" style={{ color: "#627083" }}>
                    {inc.time}
                  </span>
                  <span
                    className="text-[10px] font-mono px-2 py-0.5 rounded font-medium"
                    style={{
                      background: inc.status === "INVESTIGATING" ? "#FF4D5E15" : "#56B4FF15",
                      color: inc.status === "INVESTIGATING" ? "#FF4D5E" : "#56B4FF",
                      border: `1px solid ${inc.status === "INVESTIGATING" ? "#FF4D5E30" : "#56B4FF30"}`,
                    }}
                  >
                    {inc.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
