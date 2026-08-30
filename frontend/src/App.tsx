import React, { useState, useEffect } from "react";
import Overview from "./screens/Overview";
import Incidents from "./screens/Incidents";
import IncidentInvestigation from "./screens/IncidentInvestigation";
import AIAnalyst from "./screens/AIAnalyst";
import DetectionRules from "./screens/DetectionRules";
import LiveEvents from "./screens/LiveEvents";
import ThreatIntelligence from "./screens/ThreatIntelligence";
import Vulnerabilities from "./screens/Vulnerabilities";
import MitreAttack from "./screens/MitreAttack";
import ResponseCenter from "./screens/ResponseCenter";
import SystemHealth from "./screens/SystemHealth";
import AuditLog from "./screens/AuditLog";
import { CustomCursor } from "./components/CustomCursor";

type Screen =
  | "overview"
  | "incidents"
  | "incident-investigation"
  | "ai-analyst"
  | "detection-rules"
  | "live-events"
  | "threat-intel"
  | "vulnerabilities"
  | "mitre"
  | "response"
  | "audit-log"
  | "health";

const navItems: {
  group?: string;
  id: Screen;
  label: string;
  indent?: boolean;
}[] = [
  { id: "overview", label: "Overview" },
  { group: "OPERATIONS" } as never,
  { id: "incidents", label: "Incidents", indent: true },
  { id: "detection-rules", label: "Detections", indent: true },
  { id: "live-events", label: "Live Events", indent: true },
  { group: "INTELLIGENCE" } as never,
  { id: "threat-intel", label: "Threat Intelligence", indent: true },
  { id: "vulnerabilities", label: "Vulnerabilities", indent: true },
  { id: "mitre", label: "MITRE ATT&CK", indent: true },
  { group: "ANALYSIS" } as never,
  { id: "ai-analyst", label: "AI Analyst", indent: true },
  { group: "RESPONSE" } as never,
  { id: "response", label: "Playbooks", indent: true },
  { id: "audit-log", label: "Audit Log", indent: true },
  { group: "SYSTEM" } as never,
  { id: "health", label: "Health", indent: true },
];

const pageTitles: Record<Screen, string> = {
  overview: "Security Overview",
  incidents: "Incidents",
  "incident-investigation": "Incident Investigation",
  "ai-analyst": "AI Analyst",
  "detection-rules": "Detection Rules",
  "live-events": "Live Event Stream",
  "threat-intel": "Threat Intelligence",
  vulnerabilities: "Vulnerabilities",
  mitre: "MITRE ATT&CK",
  response: "Response Center",
  "audit-log": "Audit Log",
  health: "System Health",
};

function SentinelLogo() {
  return (
    <div className="px-5 py-4" style={{ borderBottom: "1px solid #1D2938" }}>
      <div className="flex items-center gap-3">
        <img
          src="/sentinel-emblem.png"
          alt="SENTINEL SOC"
          className="w-10 h-10 rounded-lg flex-shrink-0"
          style={{
            objectFit: "contain",
            border: "1px solid rgba(124, 140, 255, 0.3)",
            boxShadow: "0 0 12px rgba(86, 180, 255, 0.25)",
            background: "rgba(13, 19, 29, 0.6)",
          }}
        />
        <div>
          <div className="text-sm font-bold tracking-tight" style={{ color: "#F4F7FA" }}>
            SENTINEL
          </div>
          <div className="text-[10px] font-mono" style={{ color: "#627083" }}>
            SOC v2.2
          </div>
        </div>
      </div>
    </div>
  );
}

interface SidebarProps {
  current: Screen;
  onNavigate: (s: Screen) => void;
}

function Sidebar({ current, onNavigate }: SidebarProps) {
  return (
    <aside
      className="flex flex-col h-screen flex-shrink-0"
      style={{
        width: "240px",
        background: "#0D131D",
        borderRight: "1px solid #1D2938",
      }}
    >
      <SentinelLogo />

      <nav className="flex-1 overflow-y-auto py-3">
        {navItems.map((item, i) => {
          if ((item as { group?: string }).group) {
            return (
              <div
                key={i}
                className="px-5 pt-5 pb-1.5 text-[10px] font-semibold tracking-widest uppercase"
                style={{ color: "#627083" }}
              >
                {(item as { group: string }).group}
              </div>
            );
          }

          const navItem = item as { id: Screen; label: string; indent?: boolean };
          const isActive = current === navItem.id;

          return (
            <button
              key={navItem.id}
              onClick={() => onNavigate(navItem.id)}
              className="w-full text-left flex items-center gap-2.5 py-2 transition-all relative"
              style={{
                paddingLeft: navItem.indent ? "28px" : "20px",
                paddingRight: "20px",
                color: isActive ? "#F4F7FA" : "#627083",
                background: isActive ? "#56B4FF08" : "transparent",
              }}
              onMouseEnter={(e) => {
                if (!isActive) (e.currentTarget as HTMLElement).style.color = "#9AA8B8";
              }}
              onMouseLeave={(e) => {
                if (!isActive) (e.currentTarget as HTMLElement).style.color = "#627083";
              }}
            >
              {isActive && (
                <div
                  className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r"
                  style={{ background: "#56B4FF" }}
                />
              )}
              {navItem.id === "overview" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
              )}
              {navItem.id === "incidents" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              )}
              {navItem.id === "detection-rules" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
              {navItem.id === "live-events" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              )}
              {navItem.id === "threat-intel" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064" />
                </svg>
              )}
              {navItem.id === "vulnerabilities" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              )}
              {navItem.id === "mitre" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                </svg>
              )}
              {navItem.id === "ai-analyst" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              )}
              {navItem.id === "response" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
              {navItem.id === "audit-log" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              )}
              {navItem.id === "health" && (
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              )}
              <span className="text-sm">{navItem.label}</span>
              {navItem.id === "incidents" && (
                <span
                  className="ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded"
                  style={{ background: "#FF4D5E20", color: "#FF4D5E" }}
                >
                  4
                </span>
              )}
              {navItem.id === "live-events" && (
                <span className="ml-auto">
                  <div className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Status Footer */}
      <div className="px-4 py-4" style={{ borderTop: "1px solid #1D2938" }}>
        <div className="flex items-center gap-1.5 mb-2.5">
          <div className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
          <span className="text-xs font-semibold" style={{ color: "#42D392" }}>
            LIVE
          </span>
        </div>
        <div className="space-y-1">
          {[
            { label: "API", status: "OPERATIONAL", color: "#42D392" },
            { label: "WS", status: "CONNECTED", color: "#42D392" },
            { label: "DB", status: "OPERATIONAL", color: "#42D392" },
          ].map((s) => (
            <div key={s.label} className="flex items-center justify-between">
              <span className="font-mono text-[11px]" style={{ color: "#627083" }}>
                {s.label}
              </span>
              <div className="flex items-center gap-1">
                <div className="w-1 h-1 rounded-full" style={{ background: s.color }} />
                <span className="text-[10px] font-medium" style={{ color: s.color }}>
                  {s.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}

interface TopBarProps {
  title: string;
  onNavigate: (s: Screen) => void;
}

function TopBar({ title, onNavigate }: TopBarProps) {
  const [searchVal, setSearchVal] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);

  return (
    <header
      className="flex items-center gap-4 px-6 flex-shrink-0"
      style={{
        height: "56px",
        background: "#0D131D",
        borderBottom: "1px solid #1D2938",
      }}
    >
      {/* Title */}
      <span className="text-sm font-semibold" style={{ color: "#F4F7FA" }}>
        {title}
      </span>

      {/* Search */}
      <div className="relative flex-1 max-w-sm ml-4">
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
          placeholder="Search incidents, CVEs, IPs..."
          value={searchVal}
          onChange={(e) => setSearchVal(e.target.value)}
          className="w-full pl-9 pr-3 py-1.5 rounded-lg text-sm outline-none"
          style={{
            background: "#111925",
            border: "1px solid #1D2938",
            color: "#F4F7FA",
          }}
        />
      </div>

      <div className="ml-auto flex items-center gap-3">
        {/* Environment Badge */}
        <div
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold"
          style={{ background: "#F4C95D0A", color: "#F4C95D", border: "1px solid #F4C95D25" }}
        >
          <span style={{ fontSize: "8px" }}>◆</span>
          TRAINING ENV
        </div>

        {/* Connection Status */}
        <div
          className="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs"
          style={{ background: "#42D39210", color: "#42D392" }}
        >
          <div className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
          <span className="font-mono text-[11px]">LIVE</span>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative w-8 h-8 flex items-center justify-center rounded-lg transition-all"
            style={{ background: showNotifications ? "#1D2938" : "transparent" }}
          >
            <svg className="w-4 h-4" style={{ color: "#9AA8B8" }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            <span
              className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full text-[9px] font-bold flex items-center justify-center"
              style={{ background: "#FF4D5E", color: "#fff" }}
            >
              3
            </span>
          </button>

          {showNotifications && (
            <div
              className="absolute right-0 top-full mt-1 rounded-xl overflow-hidden shadow-2xl z-50"
              style={{
                background: "#0D131D",
                border: "1px solid #1D2938",
                width: "280px",
                boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
              }}
            >
              <div className="px-4 py-2.5" style={{ borderBottom: "1px solid #1D2938" }}>
                <span className="text-xs font-semibold" style={{ color: "#F4F7FA" }}>
                  Notifications
                </span>
              </div>
              {[
                { title: "Credential Attack — CRITICAL", sub: "INC-00842 requires investigation", color: "#FF4D5E", time: "2m ago", onClick: () => { onNavigate("incident-investigation"); setShowNotifications(false); } },
                { title: "New KEV published", sub: "CVE-2026-11234 added to CISA catalog", color: "#FF8A4C", time: "12m ago", onClick: () => { onNavigate("threat-intel"); setShowNotifications(false); } },
                { title: "AI Analysis complete", sub: "High-confidence assessment for INC-00842", color: "#7C8CFF", time: "14m ago", onClick: () => { onNavigate("ai-analyst"); setShowNotifications(false); } },
              ].map((n, i) => (
                <div
                  key={i}
                  className="flex items-start gap-3 px-4 py-3 cursor-pointer transition-all"
                  style={{ borderBottom: i < 2 ? "1px solid #1D293840" : "none" }}
                  onClick={n.onClick}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "#1D293840"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                >
                  <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: n.color }} />
                  <div className="flex-1">
                    <p className="text-xs font-medium" style={{ color: "#F4F7FA" }}>{n.title}</p>
                    <p className="text-[11px] mt-0.5" style={{ color: "#9AA8B8" }}>{n.sub}</p>
                  </div>
                  <span className="text-[10px] flex-shrink-0 mt-0.5" style={{ color: "#627083" }}>{n.time}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Avatar */}
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0"
          style={{ background: "linear-gradient(135deg, #56B4FF30, #7C8CFF40)", color: "#7C8CFF", border: "1px solid #7C8CFF30" }}
        >
          A
        </div>
      </div>
    </header>
  );
}

function MobileNav({ current, onNavigate }: { current: Screen; onNavigate: (s: Screen) => void }) {
  const items: { id: Screen; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "incidents", label: "Incidents" },
    { id: "live-events", label: "Events" },
    { id: "threat-intel", label: "Intel" },
    { id: "health", label: "System" },
  ];

  const icons: Record<string, React.ReactNode> = {
    overview: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
    incidents: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
    "live-events": (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    "threat-intel": (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064" />
      </svg>
    ),
    health: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    ),
  };

  return (
    <nav
      className="flex items-center justify-around px-2 flex-shrink-0"
      style={{
        height: "60px",
        background: "#0D131D",
        borderTop: "1px solid #1D2938",
      }}
    >
      {items.map((item) => {
        const isActive = current === item.id;
        return (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-lg transition-all"
            style={{
              color: isActive ? "#56B4FF" : "#627083",
              background: isActive ? "#56B4FF10" : "transparent",
            }}
          >
            {icons[item.id]}
            <span className="text-[9px] font-medium tracking-wide">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("overview");
  const [isMobile, setIsMobile] = useState(() => window.innerWidth < 768);

  useEffect(() => {
    const handler = () => setIsMobile(window.innerWidth < 768);
    window.addEventListener("resize", handler);
    return () => window.removeEventListener("resize", handler);
  }, []);

  const navigate = (s: string) => setScreen(s as Screen);

  const renderScreen = () => {
    switch (screen) {
      case "overview":
        return <Overview onNavigate={navigate} />;
      case "incidents":
        return <Incidents onNavigate={navigate} />;
      case "incident-investigation":
        return <IncidentInvestigation onNavigate={navigate} />;
      case "ai-analyst":
        return <AIAnalyst onNavigate={navigate} />;
      case "detection-rules":
        return <DetectionRules />;
      case "live-events":
        return <LiveEvents />;
      case "threat-intel":
        return <ThreatIntelligence />;
      case "vulnerabilities":
        return <Vulnerabilities />;
      case "mitre":
        return <MitreAttack />;
      case "response":
        return <ResponseCenter />;
      case "health":
        return <SystemHealth />;
      case "audit-log":
        return <AuditLog />;
      default:
        return <Overview onNavigate={navigate} />;
    }
  };

  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{ background: "#070B12", fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      <CustomCursor />
      {!isMobile && <Sidebar current={screen} onNavigate={(s) => setScreen(s)} />}

      <div className="flex flex-col flex-1 overflow-hidden">
        {isMobile ? (
          <header
            className="flex items-center justify-between px-4 flex-shrink-0"
            style={{ height: "52px", background: "#0D131D", borderBottom: "1px solid #1D2938" }}
          >
            <div className="flex items-center gap-2.5">
              <img
                src="/sentinel-emblem.png"
                alt="SENTINEL SOC"
                className="w-8 h-8 rounded-lg flex-shrink-0"
                style={{
                  objectFit: "contain",
                  border: "1px solid rgba(124, 140, 255, 0.3)",
                  boxShadow: "0 0 8px rgba(86, 180, 255, 0.2)",
                  background: "rgba(13, 19, 29, 0.6)",
                }}
              />
              <span className="text-sm font-bold" style={{ color: "#F4F7FA" }}>SENTINEL</span>
              <span className="text-[10px] font-mono" style={{ color: "#627083" }}>SOC v2.2</span>
            </div>
            <div className="flex items-center gap-2">
              <div
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold"
                style={{ background: "#F4C95D0A", color: "#F4C95D", border: "1px solid #F4C95D25" }}
              >
                ◆ TRAINING
              </div>
              <div className="w-1.5 h-1.5 rounded-full bg-[#42D392] animate-pulse" />
            </div>
          </header>
        ) : (
          <TopBar title={pageTitles[screen]} onNavigate={(s) => setScreen(s)} />
        )}

        <main
          key={screen}
          className="flex-1 overflow-y-auto screen-enter"
          style={{
            padding: isMobile ? "16px" : "32px",
            background: "#070B12",
          }}
        >
          {renderScreen()}
        </main>

        {isMobile && <MobileNav current={screen} onNavigate={(s) => setScreen(s)} />}
      </div>
    </div>
  );
}
